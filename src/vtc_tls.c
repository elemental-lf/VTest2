/*-
 * Copyright (c) 2021 Varnish Software
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 */

#include "config.h"

#include <openssl/bio.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>

#include "vtc.h"
#include "vtc_http.h"

#include "vfil.h"
#include "vtcp.h"
#include "vtim.h"

#include "builtin_cert.h"

struct tls_server {
	unsigned		magic;
#define TLS_SERVER_MAGIC	0x4a1f6cec

	unsigned		has_cert;
	struct vsb		*alpn;
	unsigned char		*ocsp_resp;
	int			ocsp_len;
};

struct tls_client {
	unsigned		magic;
#define TLS_CLIENT_MAGIC	0xe7d7d3b1
	const char		*servername;
	const char		*sess_out;
	const char		*sess_in;
	unsigned		cert_status;
	unsigned		has_alpn;
};

static const char *TLS_CLIENT = "client";
static const char *TLS_SERVER = "server";

struct tlsctx {
	unsigned		magic;
#define TLSCTX_MAGIC		0xace4f111
	const char		*type;

	SSL_CTX			*ctx;

	const char 		*alert;
	union {
		struct tls_client c[1];
		struct tls_server s[1];
	};
};

struct tlsconn {
	unsigned		magic;
#define TLSCONN_MAGIC		0xcb266c5f
	SSL			*ssl;
	struct tlsctx		*cfg;
	unsigned		failed;
	unsigned		write_as_early_data;
	struct vtclog		*vl;
	char			*subject_name;
	char			*issuer_name;
	char			*alpn;
	struct vsb		*subject_alt_names;
	/* QUIC transport parameters stored beside the session (sess_out) */
	unsigned char		*quic_tp;
	size_t			quic_tp_len;
};

#define QUIC_TP_PEM_NAME	"QUIC TRANSPORT PARAMETERS"

/*
 * SSL ex_data index for the tlsconn. Index 0 (SSL_get_app_data()) belongs
 * to ngtcp2's crypto backend on QUIC connections.
 */
static int tls_ex_conn = -1;

/* Forward declarations */
static void tls_ctx_free(struct tlsctx **);

static struct tlsconn *
tls_ssl_conn(const SSL *ssl)
{
	struct tlsconn *conn;

	assert(tls_ex_conn >= 0);
	CAST_OBJ_NOTNULL(conn, SSL_get_ex_data(ssl, tls_ex_conn),
	    TLSCONN_MAGIC);
	return (conn);
}

static void
vtc_tlserr(struct vtclog *vl)
{
	unsigned long e;
	char buf[256];

	while ((e = ERR_get_error())) {
		ERR_error_string_n(e, buf, sizeof(buf));
		vtc_log(vl, 3, "%s", buf);
	}
}

static void
cert_load(struct vtclog *vl, struct tlsctx *cfg, BIO *src)
{
	X509 *x509;
	EVP_PKEY *pk;
	unsigned long e;

	CHECK_OBJ_NOTNULL(cfg, TLSCTX_MAGIC);

	x509 = PEM_read_bio_X509_AUX(src, NULL, NULL, NULL);
	if (SSL_CTX_use_certificate(cfg->ctx, x509) != 1) {
		ERR_print_errors_fp(stderr);
		vtc_fatal(vl, "Unable to configure certificate");
	}

	while ((x509 = PEM_read_bio_X509_AUX(src, NULL, NULL, NULL)) != NULL) {
		if (SSL_CTX_add_extra_chain_cert(cfg->ctx, x509) != 1) {
			vtc_tlserr(vl);
			vtc_fatal(vl, "Unable to configure cert chain");
		}
	}
	e = ERR_peek_last_error();
	if (ERR_GET_LIB(e) == ERR_LIB_PEM
	    && ERR_GET_REASON(e) == PEM_R_NO_START_LINE)
		/* EOF: This is the expected error when there are no
		 * more certs to read. */
		ERR_clear_error();
	else {
		/* some real error */
		vtc_tlserr(vl);
		vtc_fatal(vl, "Unable to configure cert chain");
	}

	BIO_reset(src);
	pk = PEM_read_bio_PrivateKey(src, NULL, NULL, NULL);
	if (pk == NULL) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "Unable to read private key");
	}
	if (SSL_CTX_use_PrivateKey(cfg->ctx, pk) != 1) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "Unable to load private key");
	}

	if (cfg->type == TLS_SERVER)
		cfg->s->has_cert = 1;

	/*
	 * NB: Since we also want to be able to configure invalid
	 * cert/chain setups, we don't make any attempt at checking
	 * the private key or verifying the certificate chain here.
	 */
}

static void
cmd_tls_cfg_cert_builtin(struct vtclog *vl, struct tlsctx *cfg)
{
	BIO *bio;

	bio = BIO_new_mem_buf(BUILTIN_CERT, -1);
	AN(bio);
	cert_load(vl, cfg, bio);
	BIO_free(bio);
}

/* SECTION: tls_config.spec.cert
 *
 * cert
 *	cert = FILENAME
 *
 *	Load a pem-formatted private key/subject certificate bundle.
 *	If the file also contains a certificate chain, that will also be
 *	loaded.
 *
 *	If defined in a client configuration, the certificate will be
 *	configured as a client certificate.
 *
 *	If omitted in a server configuration, a self-signed built-in
 *	certificate (CN=example.com) recognized by a client will be
 *	presented.
 *
 *	.. XXX: allow an explicit "@builtin" token to also allow clients
 *	..      to present a working certificate out of the box?
 *
 *	.. TODO: sni, dhparams ? (DRIDI: isn't SNI implemented already?)
 */
static void
cmd_tls_cfg_cert(CMD_ARGS)
{
	struct tlsctx *cfg;
	BIO *bio;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "cert"));
	AZ(strcmp(av[1], "="));

	bio = BIO_new_file(av[2], "r");
	if (!bio)
		vtc_fatal(vl, "Unable to open file '%s'", av[2]);
	cert_load(vl, cfg, bio);
	BIO_free(bio);
}

static int
string2version(struct vtclog *vl, const char *spec)
{
#define TLS_PROTO(v, s, o)			\
	if (!strcasecmp(spec, s))		\
		return (v);
#include "tbl/tls_proto_tbl.h"
	vtc_fatal(vl, "unknown TLS version '%s'", spec);
}

/* SECTION: tls_config.spec.version
 *
 * version
 *	version = PROTO_MIN [PROTO_MAX]
 *
 *	Valid tokens are SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3.
 *
 *	If only one protocol is specified it will be used as both
 *	min and max.
 */
static void
cmd_tls_cfg_version(CMD_ARGS)
{
	struct tlsctx *cfg;
	int proto_min, proto_max;
	long opts;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "version"));
	AZ(strcmp(av[1], "="));
	proto_min = string2version(vl, av[2]);
	proto_max = proto_min;
	if (av[3] != NULL) {
		AZ(av[4]);
		proto_max = string2version(vl, av[3]);
	}

	if (proto_min > proto_max)
		vtc_fatal(vl, "TLS version min greater than max");

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	(void)opts;
	AN(SSL_CTX_set_min_proto_version(cfg->ctx, proto_min));
	AN(SSL_CTX_set_max_proto_version(cfg->ctx, proto_max));
#else
	opts = 0;
#  define TLS_PROTO(v, s, o)			\
	if (v < proto_min || v > proto_max)	\
		opts |= o;
#  include "tbl/tls_proto_tbl.h"
	if (opts)
		(void)SSL_CTX_set_options(cfg->ctx, opts);
#endif
}

static int
vtc_alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *priv)
{
	struct tlsctx *cfg;
	int r;

	(void) ssl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_SERVER);
	AN(cfg->s->alpn);

	r = SSL_select_next_proto(TRUST_ME(out), outlen,
	    (const unsigned char *)VSB_data(cfg->s->alpn),
	    VSB_len(cfg->s->alpn), in, inlen);

	if (r != OPENSSL_NPN_NEGOTIATED)
		return (SSL_TLSEXT_ERR_NOACK);

	return (SSL_TLSEXT_ERR_OK);
}

/* SECTION: tls_config.spec.alpn
 *
 * alpn
 *	alpn = PROTO [PROTO...]
 *
 *	The list of ALPN protocols supported by the client or the server.
 *	The most relevant tokens are ``h2`` and ``http/1.1``. ALPN tokens
 *	are ordered by preference.
 */
static void
cmd_tls_cfg_alpn(CMD_ARGS)
{
	struct tlsctx *cfg;
	struct vsb *vsb;
	size_t l;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "alpn"));
	AZ(strcmp(av[1], "="));

	vsb = VSB_new_auto();
	while (av[2] != NULL) {
		l = strlen(av[2]);
		assert(l < 255);	/* XXX: lower or equal? */
		AZ(VSB_putc(vsb, l));
		AZ(VSB_bcat(vsb, av[2], l));
		av++;
	}
	AZ(VSB_finish(vsb));

	if (cfg->type == TLS_CLIENT) {
		if (SSL_CTX_set_alpn_protos(cfg->ctx,
		    (const unsigned char *)VSB_data(vsb),
		    (unsigned int)VSB_len(vsb)) != 0) {
			vtc_tlserr(vl);
			vtc_fatal(vl, "invalid 'alpn' specifier");
		}
		cfg->c->has_alpn = 1;
		VSB_destroy(&vsb);
	} else {
		assert(cfg->type == TLS_SERVER);
		cfg->s->alpn = vsb;
		SSL_CTX_set_alpn_select_cb(cfg->ctx, vtc_alpn_cb, cfg);
	}
}

/* SECTION: tls_config.spec.cipher_list
 *
 * cipher_list
 *	cipher_list = CIPHER[:CIPHER...]
 *
 *	The cipher suites for TLS up to version 1.2, separated by colons, in
 *	order of preference.
 *
 *	.. XXX: why not a list of tokens like ALPN?
 *	..      ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384
 *	..      it's more convenient to break long lines
 */
static void
cmd_tls_cfg_cipher_list(CMD_ARGS)
{
	struct tlsctx *cfg;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "cipher_list"));
	AZ(strcmp(av[1], "="));
	if (SSL_CTX_set_cipher_list(cfg->ctx, av[2]) != 1) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "invalid 'cipher_list' configuration '%s'",
		    av[2]);
	}
}

#if defined(TLS1_3_VERSION) || OPENSSL_VERSION_NUMBER >= 0x10101000L
/* SECTION: tls_config.spec.ciphersuites
 *
 * ciphersuites
 *	ciphersuites = CIPHER[:CIPHER...]
 *
 *	The cipher suites for TLS version 1.3, separated by colons, in
 *	order of preference.
 *
 *	.. XXX: why not a list of tokens like ALPN?
 *	..      TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384
 *	..      it's more convenient to break long lines
 *
 *	.. XXX: why not rename cipher_list to tls_ciphers and ciphersuites
 *	..      to tls_1_3_ciphers? or something else not tied to openssl's
 *	..      api choices? Can we have only one setting and sort things
 *	..      out automatically? For example - vs _ in the CIPHER.
 *
 *	.. XXX: should we have no-op or failure fallback when built without
 *	..      TLS 1.3? Probably a failure assuming one didn't add the
 *	..      mandated `feature tls_1_3` to the test case.
 */
static void
cmd_tls_cfg_ciphersuites(CMD_ARGS)
{
	struct tlsctx *cfg;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "ciphersuites"));
	AZ(strcmp(av[1], "="));
	if (SSL_CTX_set_ciphersuites(cfg->ctx, av[2]) != 1) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "invalid 'ciphersuites' configuration '%s'",
		    av[2]);
	}
}
#endif

/* SECTION: tls_config.spec.servername
 *
 * servername (client only)
 *	servername = HOST
 *
 *	The host name presented for Server Name Indication (SNI).
 */
static void
cmd_tls_cfg_servername(CMD_ARGS)
{
	struct tlsctx *cfg;

	(void) vl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);


	AZ(strcmp(av[0], "servername"));
	AZ(strcmp(av[1], "="));
	cfg->c->servername = av[2];
}

/* SECTION: tls_config.spec.verify_peer
 *
 * verify_peer (client only)
 *	verify_peer = true|false
 *
 *	Verify the peer's certificate chain (defaults to false).
 *
 *	.. XXX: why client only if the client can also present a certificate?
 *	..      how could it better interact with client_vfy for a server?
 */
static void
cmd_tls_cfg_verify_peer(CMD_ARGS)
{
	struct tlsctx *cfg;
	int mode;

	(void) vl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "verify_peer"));
	AZ(strcmp(av[1], "="));
	if (!strcasecmp(av[2], "true"))
		mode = SSL_VERIFY_PEER;
	else if (!strcasecmp(av[2], "false"))
		mode = SSL_VERIFY_NONE;
	else
		vtc_fatal(vl, "verify_peer: expected one of 'true' or 'false'");

	SSL_CTX_set_verify(cfg->ctx, mode, NULL);
}

static int
sess_new_cb(SSL *ssl, SSL_SESSION *sess)
{
	struct tlsconn *conn;
	struct tlsctx *cfg;
	BIO *out;

	conn = tls_ssl_conn(ssl);
	CAST_OBJ_NOTNULL(cfg, conn->cfg, TLSCTX_MAGIC);

	AN(cfg->c->sess_out);
	out = BIO_new_file(cfg->c->sess_out, "w");
	AN(out);
	AN(PEM_write_bio_SSL_SESSION(out, sess));
	if (conn->quic_tp != NULL)
		AN(PEM_write_bio(out, QUIC_TP_PEM_NAME, "", conn->quic_tp,
		    conn->quic_tp_len));
	BIO_free(out);

	return (0);
}

/* SECTION: tls_config.spec.sess_out
 *
 * sess_out (client only)
 *	sess_out = filename
 *
 *	Writes the TLS session to this file.
 */
static void
cmd_tls_cfg_sess_out(CMD_ARGS)
{
	struct tlsctx *cfg;

	(void) vl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "sess_out"));
	AZ(strcmp(av[1], "="));
	cfg->c->sess_out = av[2];

	(void)SSL_CTX_set_session_cache_mode(cfg->ctx, SSL_SESS_CACHE_CLIENT
	    | SSL_SESS_CACHE_NO_INTERNAL);

	/* This approach works for both TLSv1.3 and <=TLSv1.2. The
	 * difference being that for TLSv1.3 we get called
	 * post-handshake, and during the handshake for the older
	 * versions. */
	SSL_CTX_sess_set_new_cb(cfg->ctx, sess_new_cb);
}

/* SECTION: tls_config.spec.sess_in
 *
 * sess_in (client only)
 *	sess_in = filename
 *
 *	Reads a TLS session from file and attempts session reuse.
 */
static void
cmd_tls_cfg_sess_in(CMD_ARGS)
{
	struct tlsctx *cfg;

	(void) vl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "sess_in"));
	AZ(strcmp(av[1], "="));
	cfg->c->sess_in = av[2];

}

static void
vtc_sess_set(struct tlsconn *conn, const char *fn)
{
	SSL_SESSION *sess;
	BIO *in;

	in = BIO_new_file(fn, "r");
	if (!in)
		vtc_fatal(conn->vl, "sess_in: Unable to open file '%s'", fn);
	sess = PEM_read_bio_SSL_SESSION(in, NULL, 0, NULL);
	BIO_free(in);
	if (!sess)
		vtc_fatal(conn->vl, "sess_in: Unable to read file '%s'", fn);
	if (!SSL_set_session(conn->ssl, sess)) {
		vtc_tlserr(conn->vl);
		vtc_fatal(conn->vl, "Unable to set session from file.");
	}

	/* SSL_set_session takes its own reference */
	SSL_SESSION_free(sess);
}


/* SECTION: tls_config.spec.cert_status
 *
 * cert_status (client only)
 *	cert_status = true|false
 *
 *	Configure the client to request an OCSP staple as part of the
 *	handshake.
 */
static void
cmd_tls_cfg_cert_status(CMD_ARGS)
{
	struct tlsctx *cfg;

	(void) vl;
	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "cert_status"));
	AZ(strcmp(av[1], "="));

	if (!strcasecmp(av[2], "true"))
		cfg->c->cert_status = 1;
	else if (!strcasecmp(av[2], "false"))
		cfg->c->cert_status = 0;
	else
		vtc_fatal(vl, "cert_status: expected one of 'true' or 'false'");
}


/* SECTION: tls_config.spec.client_vfy
 *
 * client_vfy (server only)
 *	client_vfy = none|optional|required
 *
 *	Configures client certificate verification.
 *
 *	Default is 'none', in which case the server will not send any
 *	client certificate request.
 *
 *	For both 'required' and 'optional' the server will send a client
 *	certificate request. 'required' terminates the handshake if no
 *	certificate is provided, whereas 'optional' lets us continue
 *	without one.
 *
 *	This option is used in combination with the client_vfy_ca option.
 *
 *	.. XXX: either rename to verify_client or merge with verify_peer
 */
static void
cmd_tls_cfg_client_vfy(CMD_ARGS)
{
	struct tlsctx *cfg;
	int mode;


	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_SERVER);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "client_vfy"));
	AZ(strcmp(av[1], "="));
	if (!strcmp(av[2], "none")) {
		mode = SSL_VERIFY_NONE;
	} else if (!strcmp(av[2], "required")) {
		mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	} else if (!strcmp(av[2], "optional")) {
		mode = SSL_VERIFY_PEER;
	} else
		vtc_fatal(vl, "client_vfy: unexpected setting '%s'. "
		    "Valid settings are 'none', 'optional', 'required'", av[2]);

	SSL_CTX_set_verify(cfg->ctx, mode, NULL);
}

/*
 * client_vfy_ca = file.pem
 *
 * Server only.
 *
 * Used in combination with client_vfy, this configures the list of
 * CAs the server presents in its certificate request.
 *
 * This will also be used for verifying a presented client
 * certificate.
 */

/* SECTION: tls_config.spec.client_vfy_ca
 *
 * client_vfy_ca (server only)
 *	client_vfy_ca = FILENAME
 *
 *	Configure the list of Certificate Authorities (CA) from a PEM file
 *	to verify client certificates with client_vfy or CAs to present in
 *	a server's certificate request.
 *
 *	.. XXX: rename to something more intuitive/descriptive?
 */
static void
cmd_tls_cfg_client_vfy_ca(CMD_ARGS)
{
	struct tlsctx *cfg;
	X509_STORE *vfy;
	STACK_OF(X509_NAME) *cert_names;


	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	assert(cfg->type == TLS_SERVER);
	AN(av[0]);
	AN(av[1]);
	AN(av[2]);
	AZ(av[3]);

	AZ(strcmp(av[0], "client_vfy_ca"));
	AZ(strcmp(av[1], "="));

	cert_names = SSL_load_client_CA_file(av[2]);
	if (cert_names == NULL) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "client_vfy_ca: unable to load '%s'", av[2]);
	}
	SSL_CTX_set_client_CA_list(cfg->ctx, cert_names);

	vfy = X509_STORE_new();
	AN(vfy);
	AN(X509_STORE_load_locations(vfy, av[2], NULL));
	AN(SSL_CTX_set0_verify_cert_store(cfg->ctx, vfy));

	/* Note: both cert_names and vfy have their ownership
	 * transfered, thus no freeing here. */
}


static int
server_ocsp_cb(SSL *ssl, void *priv)
{
	struct tlsctx *cfg;
	unsigned char *buf;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);
	if (!cfg->s->ocsp_resp)
		return (SSL_TLSEXT_ERR_NOACK);

	/* SSL_set_tlsext_status_ocsp_resp will issue a free, so we
	 * need to pass a copy. */
	buf = OPENSSL_malloc(cfg->s->ocsp_len);
	AN(buf);
	memcpy(buf, cfg->s->ocsp_resp, cfg->s->ocsp_len);
	if (SSL_set_tlsext_status_ocsp_resp(ssl, buf,
	    cfg->s->ocsp_len) == 0) {
		OPENSSL_free(buf);
		return (SSL_TLSEXT_ERR_ALERT_FATAL);
	}
	return (SSL_TLSEXT_ERR_OK);
}

/* SECTION: tls_config.spec.staple
 *
 * staple (server only)
 *	staple = FILENAME
 *
 *	Configure the server to provide a stapled OCSP response.
 *
 */
static void
cmd_tls_cfg_staple(CMD_ARGS)
{
	struct tlsctx *cfg;
	char *staple;
	ssize_t l = 0;

	CAST_OBJ_NOTNULL(cfg, priv, TLSCTX_MAGIC);

	AN(av[0]);
	AN(av[1]);
	AN(av[2]);

	AZ(strcmp(av[0], "staple"));
	AZ(strcmp(av[1], "="));

	staple = VFIL_readfile(NULL, av[2], &l);
	if (staple == NULL)
		vtc_fatal(vl, "staple: Error loading file '%s': %d (%s)\n",
		    av[2], errno, strerror(errno));

	cfg->s->ocsp_resp = (unsigned char *) staple;
	cfg->s->ocsp_len = l;

	/* We ignore any sort of validation here to allow us to serve
	 * also broken ocsp responses */

	AN(SSL_CTX_set_tlsext_status_cb(cfg->ctx, server_ocsp_cb));
	AN(SSL_CTX_set_tlsext_status_arg(cfg->ctx, cfg));
}


static const struct cmds tls_cfg_cmds_s[] = {
#define TLS_SERVER
#define TLS_CMD(n) \
	{ CMDS_MAGIC, #n, cmd_tls_cfg_##n, CMDS_F_NONE },
#include "tbl/tls_cmds_tbl.h"
	{ CMDS_MAGIC, NULL, NULL, CMDS_F_NONE }
};

static const struct cmds tls_cfg_cmds_c[] = {
#define TLS_CLIENT
#define TLS_CMD(n) \
	{ CMDS_MAGIC, #n, cmd_tls_cfg_##n, CMDS_F_NONE },
#include "tbl/tls_cmds_tbl.h"
	{ CMDS_MAGIC, NULL, NULL, CMDS_F_NONE }
};

static void
tls_conn_free(struct tlsconn **cp)
{
	struct tlsconn *c;

	TAKE_OBJ_NOTNULL(c, cp, TLSCONN_MAGIC);
	SSL_free(c->ssl);
	free(c->subject_name);
	free(c->issuer_name);
	free(c->alpn);
	free(c->quic_tp);

	if (c->subject_alt_names != NULL)
		VSB_destroy(&c->subject_alt_names);

	FREE_OBJ(c);
}

static int
tlsconn_poll(const struct http *hp, short *events, vtim_real deadline)
{
	struct tlsconn *c;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);

	if (hp->tlsconn != NULL) {
		CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);
		AN(c->ssl);

		if ((*events & POLLIN) && SSL_pending(c->ssl) > 0) {
			*events = POLLIN;
			return (1);
		}
	}

	/* XXX: a successful poll() at this point doesn't guarantee a
	 * non-blocking SSL_read(), but OpenSSL 1.0 compatibility makes
	 * this too challenging. This is probably something we can
	 * address upstream instead with 1.1 as the baseline.
	 */
	return (http_fd_poll(hp, events, deadline));
}

static ssize_t
tlsconn_read(const struct http *hp, void *buf, size_t len)
{
	struct tlsconn *c;
	int err;
	int i;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);
	AN(c->ssl);
	assert(*hp->sess->fd == SSL_get_fd(c->ssl));
	i = SSL_read(c->ssl, buf, len);
	if (i <= 0) {
		err = SSL_get_error(c->ssl, i);
		/* A peer's close_notify is reported as a clean SSL read EOF. */
		if (err != SSL_ERROR_ZERO_RETURN) {
			c->failed = 1;
			vtc_tlserr(c->vl);
		}
	}
	return (i);
}

static ssize_t
tlsconn_write(const struct http *hp, const void *buf, size_t len)
{
	struct tlsconn *c;
	int i;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);
	AN(c->ssl);
	assert(*hp->sess->fd == SSL_get_fd(c->ssl));
	if (c->write_as_early_data) {
		size_t written;

		c->write_as_early_data = 0;
		i = SSL_write_early_data(c->ssl, buf, len, &written);
		if (i == 1) {
			i = (ssize_t) written;
		}
	} else {
		i = SSL_write(c->ssl, buf, len);
	}
	if (i <= 0) {
		c->failed = 1;
		vtc_tlserr(c->vl);
	}
	return (i);
}

static void
tlsconn_close(struct http *hp)
{
	struct tlsconn *c;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	TAKE_OBJ_NOTNULL(c, &hp->tlsconn, TLSCONN_MAGIC);
	AN(c->ssl);
	if (!c->failed)
		(void)SSL_shutdown(c->ssl);
	tls_conn_free(&c);
	VTCP_close(hp->sess->fd);
}

static const struct sess_ops tlsconn_so = {
	.poll = tlsconn_poll,
	.read = tlsconn_read,
	.write = tlsconn_write,
	.close = tlsconn_close,
};

static void
msg_cb(int write_p, int version, int content_type, const void *buf,
    size_t len, SSL *ssl, void *arg)
{
	struct tlsctx *cfg;
	const unsigned char *bp;

	CAST_OBJ_NOTNULL(cfg, tls_ssl_conn(ssl)->cfg, TLSCTX_MAGIC);
	bp = buf;

	(void) write_p;
	(void) version;
	(void) len;
	(void) arg;

	if (content_type == SSL3_RT_ALERT) {
		switch ((int)bp[1]) {
#define ALERT(S, n)				\
		case n:				\
			cfg->alert = S;		\
			break;
#include "tbl/tls_alert_tbl.h"
#undef ALERT
		default:
			cfg->alert = "<undef>";
			break;
		}

	}
}

/* Append key material to $SSLKEYLOGFILE, for Wireshark */
static void
keylog_cb(const SSL *ssl, const char *line)
{
	static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
	const char *fn;
	FILE *f;

	(void)ssl;
	fn = getenv("SSLKEYLOGFILE");
	if (fn == NULL || *fn == '\0')
		return;
	PTOK(pthread_mutex_lock(&mtx));
	f = fopen(fn, "a");
	if (f != NULL) {
		(void)fprintf(f, "%s\n", line);
		(void)fclose(f);
	}
	PTOK(pthread_mutex_unlock(&mtx));
}

static void
tls_ctx_keylog(SSL_CTX *ctx)
{
	const char *fn;

	fn = getenv("SSLKEYLOGFILE");
	if (fn != NULL && *fn != '\0')
		SSL_CTX_set_keylog_callback(ctx, keylog_cb);
}

static void *
tls_server_setup(const char *spec, struct vtclog *vl)
{
	struct tlsctx *cfg;

	ALLOC_OBJ(cfg, TLSCTX_MAGIC);
	AN(cfg);
	cfg->type = TLS_SERVER;
	cfg->s->magic = TLS_SERVER_MAGIC;

	cfg->ctx = SSL_CTX_new(SSLv23_server_method());
	if (!cfg->ctx) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "SSL_CTX_new failed");
	}

	AN(SSL_CTX_set_session_id_context(cfg->ctx,
		(const unsigned char *) "VTEST", strlen("VTEST")));
	tls_ctx_keylog(cfg->ctx);

	vtc_log_set_cmd(vl, tls_cfg_cmds_s);
	parse_string(vl, cfg, spec);

	if (!cfg->s->has_cert)
		cmd_tls_cfg_cert_builtin(vl, cfg);

	return (cfg);
}

static void *
tls_client_setup(const char *spec, struct vtclog *vl)
{
	struct tlsctx *cfg;

	ALLOC_OBJ(cfg, TLSCTX_MAGIC);
	AN(cfg);
	cfg->type = TLS_CLIENT;
	cfg->s->magic = TLS_CLIENT_MAGIC;

	cfg->ctx = SSL_CTX_new(SSLv23_client_method());
	if (!cfg->ctx) {
		vtc_tlserr(vl);
		vtc_fatal(vl, "SSL_CTX_new failed");
	}

	SSL_CTX_set_verify(cfg->ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_default_verify_paths(cfg->ctx);
	tls_ctx_keylog(cfg->ctx);

	vtc_log_set_cmd(vl, tls_cfg_cmds_c);
	parse_string(vl, cfg, spec);

	return (cfg);
}

static X509 *
cert_resolve(SSL *s, unsigned long idx)
{
	STACK_OF(X509) *sk;
	X509 *x;

	if (SSL_is_server(s)) {
		if (idx == 0) {
			x = SSL_get_peer_certificate(s);
			/*
			 * This deref is OK since the session still
			 * holds a reference.
			 */
			X509_free(x);
			return (x);
		}
		else
			idx--;
	}

	sk = SSL_get_peer_cert_chain(s);
	if (!sk || sk_X509_num(sk) == -1)
		return (NULL);
	x = sk_X509_value(sk, idx);
	return (x);
}

static char *
get_CN(X509_NAME *n)
{
	int i;
	X509_NAME_ENTRY *x509_ne;
	char *p, *r;

	if (!n)
		return (NULL);
	i = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
	if (i < 0)
		return (NULL);
	x509_ne = X509_NAME_get_entry(n, i);
	if (!x509_ne)
		return (NULL);
	ASN1_STRING_to_UTF8((unsigned char **)&p,
	    X509_NAME_ENTRY_get_data(x509_ne));
	AN(p);
	r = strdup(p);
	AN(r);
	OPENSSL_free(p);
	return (r);
}

#define GET_CN(field)				\
static const char *				\
get_##field(struct tlsconn *c, X509 *x)		\
{						\
	char *p;				\
						\
	CHECK_OBJ_NOTNULL(c, TLSCONN_MAGIC);	\
	p = get_CN(X509_get_##field(x));	\
	if (p == NULL)				\
		return ("<undef>");		\
	free(c->field);				\
	c->field = p;				\
	return (c->field);			\
}

GET_CN(subject_name)
GET_CN(issuer_name)

static const char *
get_subject_alt_names(struct tlsconn *c, X509 *x, struct vtclog *vl)
{
	int i;
	unsigned char *p;
	const char *sep = "";
	char b[INET6_ADDRSTRLEN];

	CHECK_OBJ_NOTNULL(c, TLSCONN_MAGIC);
	if (c->subject_alt_names != NULL)
		VSB_destroy(&c->subject_alt_names);

	c->subject_alt_names = VSB_new_auto();
	AN(c->subject_alt_names);

	STACK_OF(GENERAL_NAME) *names;
	names = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);

	for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
		GENERAL_NAME *n;
		n = sk_GENERAL_NAME_value(names, i);
		switch (n->type) {
		case GEN_DNS:
			ASN1_STRING_to_UTF8((unsigned char **)&p, n->d.dNSName);
			AN(p);

			VSB_cat(c->subject_alt_names, sep);
			sep = ", ";

			VSB_printf(c->subject_alt_names, "DNS:%s", p);
			OPENSSL_free(p);

			break;
		case GEN_IPADD:
			p = (unsigned char *)ASN1_STRING_get0_data(n->d.ip);
			AN(p);

			if (inet_ntop(ASN1_STRING_length(n->d.ip) == 16 ? AF_INET6 : AF_INET,
			    p, b, INET6_ADDRSTRLEN) == 0)
				continue;

			VSB_cat(c->subject_alt_names, sep);
			sep = ", ";

			VSB_printf(c->subject_alt_names,  "IP:%s", b);
			break;
		default:
			vtc_fatal(vl, "Unknown subject alt type: %i", n->type);
		}
	}

	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);

	AZ(VSB_finish(c->subject_alt_names));
	return (VSB_data(c->subject_alt_names));
}

/*
 * tls.cert.*
 * tls.certN.*
 */
static const char *
cert_var_resolve(const struct http *hp, SSL *ssl, const char *spec)
{
	struct tlsconn *c;
	unsigned long idx = 0;
	const char *p, *r = NULL;
	char *q;
	X509 *x;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);

	AZ(strncmp(spec, "tls.cert", 8));
	p = spec + 8;

	if (*p != '.') {
		idx = strtoul(p, &q, 10);
		if (*q != '.')
			vtc_fatal(hp->vl, "syntax error: '%s'", spec);
		p = TRUST_ME(q);
	}

	x = cert_resolve(ssl, idx);
	if (!x)
		return ("<undef>");

	p++;
	if (!strcmp(p, "subject")) {
		r = get_subject_name(c, x);
	} else if (!strcmp(p, "issuer")) {
		r = get_issuer_name(c, x);
	} else if (!strcmp(p, "notafter")) {
		INCOMPL();
	} else if (!strcmp(p, "notbefore")) {
		INCOMPL();
	} else if (!strcmp(p, "subject_alt_names")){
		r = get_subject_alt_names(c, x, hp->vl);
	} else
		vtc_fatal(hp->vl, "unknown operand '%s'", spec);

	return (r ? r : "<undef>");
}

/*
 * tls.ocsp_status
 */

static const char *OCSP_CERT_STATUS = "tls.ocsp_cert_status";
static const char *OCSP_RESP_STATUS = "tls.ocsp_resp_status";
static const char *OCSP_VERIFY = "tls.ocsp_verify";
static const char *OCSP_THIS_UPDATE = "tls.ocsp_this_update";

int
VTC_ASN1_TIME_to_tm(const ASN1_GENERALIZEDTIME *d, struct tm *tm);

static const char *
var_ocsp_status(const char *what, const struct http *hp,
    struct tlsctx *cfg, struct tlsconn *c)
{
	const unsigned char *b = NULL;
	long n;
	int i, rstatus, status, reason;
	OCSP_RESPONSE *resp;
	OCSP_BASICRESP *br = NULL;
	OCSP_CERTID *cid = NULL;
	X509 *subj = NULL, *x, *issuer = NULL;
	STACK_OF(X509) *chain = NULL;
	X509_STORE *store;
	ASN1_GENERALIZEDTIME *asn_thisupd;
	struct tm tm;
	struct vsb *vsb;
	const char *ret = "<undef>";

	CHECK_OBJ_NOTNULL(cfg, TLSCTX_MAGIC);
	CHECK_OBJ_NOTNULL(c, TLSCONN_MAGIC);

	assert (what == OCSP_CERT_STATUS ||
	    what == OCSP_RESP_STATUS ||
	    what == OCSP_VERIFY ||
	    what == OCSP_THIS_UPDATE);

	if (cfg->type == TLS_SERVER)
		vtc_fatal(hp->vl, "%s: Not available in server{}", what);

	n = SSL_get_tlsext_status_ocsp_resp(c->ssl, &b);
	if (n == -1)
		return ("<undef>");
	AN(b);
	resp = d2i_OCSP_RESPONSE(NULL, &b, n);
	if (resp == NULL)
		return ("malformed");

	rstatus = OCSP_response_status(resp);
	switch (rstatus) {
	case OCSP_RESPONSE_STATUS_MALFORMEDREQUEST:
		ret = "malformed";
		break;
	case OCSP_RESPONSE_STATUS_INTERNALERROR:
		ret = "internalerror";
		break;
	case OCSP_RESPONSE_STATUS_TRYLATER:
		ret = "trylater";
		break;
	case OCSP_RESPONSE_STATUS_SIGREQUIRED:
		ret = "sigrequired";
		break;
	case OCSP_RESPONSE_STATUS_UNAUTHORIZED:
		ret = "unauthorized";
		break;
	case OCSP_RESPONSE_STATUS_SUCCESSFUL:
		ret = "successful";
		break;
	}

	if (what == OCSP_RESP_STATUS)
		goto end;

	if (rstatus != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
		ret = "<undef>";
		goto end;
	}

	br = OCSP_response_get1_basic(resp);
	AN(br);
	store = SSL_CTX_get_cert_store(cfg->ctx);
	AN(store);
	chain = SSL_get_peer_cert_chain(c->ssl);
	AN(chain);

	i = OCSP_basic_verify(br, chain, store, 0);
	if (what == OCSP_VERIFY) {
		if (i == 1)
			ret = "OK";
		else if (i == 0)
			ret = "failed";
		else
			ret = "error";
		goto end;
	}


	subj = SSL_get_peer_certificate(c->ssl);
	AN(subj);

	for (i = 0; i < sk_X509_num(chain); i++) {
		x = sk_X509_value(chain, i);
		if (X509_check_issued(x, subj) == X509_V_OK) {
			issuer = x;
			break;
		}
	}
	if (issuer == NULL) {
		ret = "issuer-not-found";
		goto end;
	}
	cid = OCSP_cert_to_id(NULL, subj, issuer);
	AN(cid);

	if (OCSP_resp_find_status(br, cid, &status, &reason,
	    NULL, &asn_thisupd, NULL) == 0) {
		ret = "ocsp-not-found";
		goto end;
	}

	if (what == OCSP_CERT_STATUS) {
		switch (status) {
		case V_OCSP_CERTSTATUS_GOOD:
			ret = "good";
			break;
		case V_OCSP_CERTSTATUS_REVOKED:
			ret = "revoked";
			break;
		case V_OCSP_CERTSTATUS_UNKNOWN:
			ret = "unknown";
			break;
		}
	} else {
		assert(what == OCSP_THIS_UPDATE);
		vsb = VSB_new_auto();
		AN(vsb);
		VTC_ASN1_TIME_to_tm(asn_thisupd, &tm);
		/*
		 * Replace with OpenSSL's ASN1_TIME_to_tm once we get
		 * rid of EL7.
		 *
		 * (git blame and revert the commit matching these
		 * lines)
		 */
		VSB_printf(vsb, "%d-%.02d-%.02dT%.02d:%.02d:%.02dZ",
		    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		    tm.tm_hour, tm.tm_min, tm.tm_sec);
		AZ(VSB_finish(vsb));
		ret = VSB_data(vsb);
		/* 'vsb' leaks */
	}


end:
	if (resp)
		OCSP_RESPONSE_free(resp);
	if (br)
		OCSP_BASICRESP_free(br);
	if (cid)
		OCSP_CERTID_free(cid);
	X509_free(subj);

	return (ret);
}

/*
 * tls.alpn helper
 */
static const char *
cert_var_alpn(struct tlsconn *c)
{
	const unsigned char *a;
	unsigned l = 0;
	char *p = NULL;

	CHECK_OBJ_NOTNULL(c, TLSCONN_MAGIC);
	AN(c->ssl);
	SSL_get0_alpn_selected(c->ssl, &a, &l);
	if (a == NULL || l == 0)
		return ("<undef>");

	p = strndup((const char *)a, l);
	AN(p);
	assert(strlen(p) == l);

	free(c->alpn);
	c->alpn = p;
	return (c->alpn);
}

/*
 * tls.version
 * tls.cipher
 * tls.servername
 * tls.alpn
 * tls.alert
 * tls.failed
 * tls.cert*.subject
 * tls.cert*.issuer
 * tls.sess_reused
 * tls.early_data_status
 */
const char *
vtc_tls_var_resolve(const struct http *hp, const char *spec)
{
	struct tlsconn *c;
	struct tlsctx *cfg;
	const char *r = NULL;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(cfg, hp->tlsconf, TLSCTX_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);

	if (!strcmp(spec, "tls.failed"))
		return (c->failed ? "true" : "false");

	if (!c->ssl)
		return ("<undef>");

	if (!strcmp(spec, "tls.version")) {
		r = SSL_get_version(c->ssl);
	} else if (!strcmp(spec, "tls.cipher")) {
		r = SSL_get_cipher_name(c->ssl);
	} else if (!strcmp(spec, "tls.servername")) {
		if (SSL_get_servername_type(c->ssl) != -1)
			r = SSL_get_servername(c->ssl,
			    TLSEXT_NAMETYPE_host_name);
	} else if (!strcmp(spec, "tls.alpn"))
		return (cert_var_alpn(c));
	else if (!strncmp(spec, "tls.cert", 8))
		return (cert_var_resolve(hp, c->ssl, spec));
	else if (!strcmp(spec, "tls.alert"))
		r = cfg->alert;
	else if (!strcmp(spec, "tls.sess_reused"))
		r = (SSL_session_reused(c->ssl) ? "true" : "false");
	else if (!strcmp(spec, "tls.early_data_status")) {
		int s = SSL_get_early_data_status(c->ssl);
		if (s == SSL_EARLY_DATA_ACCEPTED)
			r = "accepted";
		else if (s == SSL_EARLY_DATA_REJECTED)
			r = "rejected";
		else if (s == SSL_EARLY_DATA_NOT_SENT)
			r = "not-sent";
		else
			WRONG("Unknown return value from SSL_get_early_data_status");
	} else if (!strcmp(spec, "tls.staple_requested")) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		r = (SSL_get_tlsext_status_type(c->ssl) != -1
		    ? "true" : "false");
#else
		r = (c->ssl->tlsext_status_type == TLSEXT_STATUSTYPE_ocsp)
		    ? "true" : "false";

#endif
	} else if (!strcmp(spec, OCSP_CERT_STATUS))
		r = var_ocsp_status(OCSP_CERT_STATUS, hp, cfg, c);
	else if (!strcmp(spec, OCSP_RESP_STATUS))
		r = var_ocsp_status(OCSP_RESP_STATUS, hp, cfg, c);
	else if (!strcmp(spec, OCSP_VERIFY))
		r = var_ocsp_status(OCSP_VERIFY, hp, cfg, c);
	else if (!strcmp(spec, OCSP_THIS_UPDATE))
		r = var_ocsp_status(OCSP_THIS_UPDATE, hp, cfg, c);
	else
		vtc_fatal(hp->vl, "unknown command: '%s'", spec);

	if (!r)
		r = "<undef>";
	return (r);
}

/* SECTION: client-server.spec.tls_config
 *
 * tls_config
 *	Configure a TLS session the client or server current connection.
 *	The TLS session is established with the tls_handshake command. TLS
 *	settings are described in their own top-level section.
 *
 * SECTION: tls_config tls_config
 *
 * (note: this section is at the top-level for easier navigation, but
 * it's part of the client/server tls_config specification)
 *
 * The tls_config command uses a specification for convenience::
 *
 *	tls_config SPEC
 *
 * The specification expects commands in the following form::
 *
 *	tls_config {
 *		SETTING = VALUE [VALUE...]
 *	}
 *
 * An empty configuration yields undefined platform-dependent settings,
 * except for a server certificate.
 *
 * .. XXX: should we have explicit defaults for all settings?
 *
 * Once an HTTP connection tries to establish a TLS session, or after
 * any operation on the connection after a successful handshake, the
 * following names are recognized by the expect command of the client
 * and server specifications:
 *
 * - tls.version
 *
 *   The negotiated TLS version.
 *
 * - tls.cipher
 *
 *   The negotiated TLS cipher.
 *
 * - tls.servername
 *
 *   The servername the client presents for SNI.
 *
 * - tls.alpn
 *
 *   The protocol selected during ALPN negotiation.
 *
 * - tls.alert
 *
 *   The latest encountered alert message. Legal values
 *   are the lower-case ``AlertDescription`` names listed here,
 *   https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.2.
 *
 *   Note: Different OpenSSL versions differ in which alerts are sent in
 *   what scenarios. Use of tls.alert is therefore discouraged if the
 *   test case should run across multiple openssl versions. We instead
 *   recommend the generic tls.failed.
 *
 *   .. XXX: we might as well remove tls.alert altogether.
 *
 * - tls.failed
 *
 *   Handshake and/or ``SSL_read``/``SSL_write`` failure.
 *
 *   .. XXX: not a big fan of mentioning specific OpenSSL APIs.
 *
 * - tls.cert*.subject
 *
 *   The CN/subject name property of a transmitted certificate.
 *
 * - tls.cert*.issuer
 *
 *   The issuer name property of a transmitted certificate.
 *
 * The transmitted certificate chain is represented as ``tls.cert0`` for
 * the peer's certificate, ``tls.cert1`` for the first intermediate, and
 * so one. The plain ``tls.cert`` is a short-hand for ``tls.cert0``.
 *
 * - tls.staple_requested
 *
 *   Returns ``true`` or ``false`` for whether the client asked for a
 *   stapled OCSP response.
 *
 * - tls.ocsp_cert_status
 *
 *   A stapled OCSP response's stated status of the server certificate.
 *   Returns one 'good', 'revoked', 'unknown', 'malformed', 'ocsp-not-found',
 *   'issuer-not-found' or '<undef>'.
 *
 *   Only available in client {}.
 *
 * - tls.ocsp_resp_status
 *
 *   Status of a stapled OCSP response, if present. Returns one of '<undef>',
 *   'malformed', 'internalerror', 'trylater', 'sigrequired', 'unauthorized',
 *   or 'successful'.
 *
 *   Only available in client {}.
 *
 * - tls.ocsp_verify
 *
 *   Verification status for signature and certificate chain of the
 *   OCSP response. Returns one of '<undef>', 'malformed', 'OK', 'failed'
 *   or 'error'.
 *
 *   Only available in client {}.
 *
 */
extern const struct cmds http_cmds[];

void
cmd_http_tls_config(CMD_ARGS)
{
	struct http *hp;


	AN(av[1]);
	CAST_OBJ_NOTNULL(hp, priv, HTTP_MAGIC);
	if (hp->tlsconf != NULL && *hp->sess->fd >= 0)
		vtc_fatal(vl, "Cannot reconfigure TLS with an ongoing session");
	tls_ctx_free(&hp->tlsconf);
	if (hp->sfd)
		hp->tlsconf = tls_server_setup(av[1], vl);
	else
		hp->tlsconf = tls_client_setup(av[1], vl);
	AN(hp->tlsconf);
	/* Restore http command list after TLS config parsing */
	http_set_cmds(hp, vl);
}

/* SECTION: client-server.spec.tls_handshake
 *
 * tls_handshake
 *	Perform a client or server TLS handshake. A handshake initiated
 *	without a prior tls_config is equivalent to a handshake based on
 *	an empty configuration, relying on undefined default settings.
 *
 *	A TLS handshake may be performed after plain data transfers, like
 *	for example a PROXY protocol preamble.
 *
 *	Performing a handshake is the minimal requirement to enable TLS
 *	sessions.
 *
 *	.. XXX: do we have PROXY+TLS test coverage?
 */
static int
tls_handshake(struct http *hp, struct tlsconn *conn)
{
	vtim_real deadline;
	short ev;
	int i;

	deadline = VTIM_real() + hp->timeout;

	while (1) {
		i = SSL_do_handshake(conn->ssl);
		if (i > 0)
			return (1); /* handshake success */
		if (i == 0) {
			vtc_tlserr(hp->vl);
			return (-1); /* clean handshake failure */
		}

		switch (SSL_get_error(conn->ssl, i)) {
		case SSL_ERROR_WANT_READ:
			ev = POLLIN;
			break;
		case SSL_ERROR_WANT_WRITE:
			ev = POLLOUT;
			break;
		default:
			vtc_tlserr(hp->vl); /* handshake error */
			return (-1);
		}

		i = hp->so->poll(hp, &ev, deadline);
		assert(i >= 0);
		if (i == 0)
			vtc_fatal(hp->vl, "TLS handshake timeout");
	}

	WRONG("unreachable");
}

/* SECTION: client-server.spec.tls_shutdown
 *
 * tls_shutdown
 *	Perform a bidirectional TLS shutdown. This sends a ``close_notify``
 *	alert and waits for the peer's ``close_notify`` alert. The TCP
 *	connection remains open for subsequent socket-level handling.
 *
 *	-passive
 *		Wait for the peer to send its ``close_notify`` alert before
 *		sending the local alert.
 */
static int
tls_shutdown(struct http *hp, struct tlsconn *conn)
{
	vtim_real deadline;
	short ev;
	int i;

	deadline = VTIM_real() + hp->timeout;

	while (1) {
		i = SSL_shutdown(conn->ssl);
		if (i == 1)
			return (1);
		if (i == 0)
			continue;

		switch (SSL_get_error(conn->ssl, i)) {
		case SSL_ERROR_WANT_READ:
			ev = POLLIN;
			break;
		case SSL_ERROR_WANT_WRITE:
			ev = POLLOUT;
			break;
		default:
			vtc_tlserr(hp->vl);
			return (-1);
		}

		i = hp->so->poll(hp, &ev, deadline);
		assert(i >= 0);
		if (i == 0)
			vtc_fatal(hp->vl, "TLS shutdown timeout");
	}

	WRONG("unreachable");
}

static int
tls_shutdown_passive(struct http *hp, struct tlsconn *conn)
{
	vtim_real deadline;
	short ev;
	char c;
	int i;

	deadline = VTIM_real() + hp->timeout;

	while (1) {
		i = SSL_read(conn->ssl, &c, 1);
		if (i > 0) {
			vtc_log(hp->vl, 3,
			    "TLS shutdown received application data");
			return (-1);
		}

		switch (SSL_get_error(conn->ssl, i)) {
		case SSL_ERROR_ZERO_RETURN:
			return (tls_shutdown(hp, conn));
		case SSL_ERROR_WANT_READ:
			ev = POLLIN;
			break;
		case SSL_ERROR_WANT_WRITE:
			ev = POLLOUT;
			break;
		default:
			vtc_tlserr(hp->vl);
			return (-1);
		}

		i = hp->so->poll(hp, &ev, deadline);
		assert(i >= 0);
		if (i == 0)
			vtc_fatal(hp->vl, "TLS passive shutdown timeout");
	}

	WRONG("unreachable");
}

static struct tlsconn *
tls_conn_alloc(struct http *hp, struct vtclog *vl)
{
	struct tlsctx *cfg;
	struct tlsconn *conn;

	if (hp->tlsconf)
		CAST_OBJ_NOTNULL(cfg, hp->tlsconf, TLSCTX_MAGIC);
	else {
		if (hp->sfd)
			cfg = tls_server_setup("", vl);
		else
			cfg = tls_client_setup("", vl);
		hp->tlsconf = cfg;
		http_set_cmds(hp, vl);
	}

	ALLOC_OBJ(conn, TLSCONN_MAGIC);
	AN(conn);
	conn->ssl = SSL_new(cfg->ctx);
	AN(conn->ssl);
	conn->cfg = cfg;
	conn->vl = vl;
	if (cfg->type == TLS_CLIENT) {
		SSL_set_connect_state(conn->ssl);
		if (cfg->c->servername)
			AN(SSL_set_tlsext_host_name(conn->ssl,
				TRUST_ME(cfg->c->servername)));
		if (cfg->c->cert_status)
			AN(SSL_set_tlsext_status_type(conn->ssl,
				TLSEXT_STATUSTYPE_ocsp));
	} else {
		assert (cfg->type == TLS_SERVER);
		SSL_set_accept_state(conn->ssl);
	}

	AN(SSL_set_ex_data(conn->ssl, tls_ex_conn, conn));
	SSL_set_msg_callback(conn->ssl, msg_cb);

	if (cfg->type == TLS_CLIENT && cfg->c->sess_in)
		vtc_sess_set(conn, cfg->c->sess_in);

	return (conn);
}

static struct tlsconn *
tls_conn_new(struct http *hp, struct vtclog *vl)
{
	struct tlsconn *conn;

	conn = tls_conn_alloc(hp, vl);
	AN(SSL_set_fd(conn->ssl, *hp->sess->fd));

	AZ(hp->tlsconn);
	hp->so = &tlsconn_so;
	hp->tlsconn = conn;
	return (conn);
}

void
cmd_http_tls_handshake(CMD_ARGS)
{
	struct http *hp;
	struct tlsconn *conn;
	int i;

	(void) av;

	CAST_OBJ_NOTNULL(hp, priv, HTTP_MAGIC);

#ifdef VTEST_WITH_QUIC
	if (hp->quic != NULL) {
		AZ(av[1]);
		quic_handshake(hp, vl);
		return;
	}
#endif
	if (hp->tlsconn != NULL)
		CAST_OBJ_NOTNULL(conn, hp->tlsconn, TLSCONN_MAGIC);
	else
		conn = tls_conn_new(hp, vl);

	VTCP_nonblocking(*hp->sess->fd);
	i = tls_handshake(hp, conn);
	VTCP_blocking(*hp->sess->fd);
	if (i != 1) {
		vtc_tlserr(vl);
		vtc_log(vl, 3, "TLS handshake failed");
		conn->failed = 1;
	} else
		vtc_log(vl, 3, "TLS handshake complete: %s %s",
		    SSL_get_version(conn->ssl),
		    SSL_get_cipher_name(conn->ssl));
}

void
cmd_http_tls_shutdown(CMD_ARGS)
{
	struct http *hp;
	struct tlsconn *conn;
	unsigned passive = 0;
	int i;

	CAST_OBJ_NOTNULL(hp, priv, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(conn, hp->tlsconn, TLSCONN_MAGIC);
	AN(av[0]);
	if (av[1] != NULL) {
		if (strcmp(av[1], "-passive"))
			vtc_fatal(vl, "Unknown tls_shutdown option: %s", av[1]);
		AZ(av[2]);
		passive = 1;
	}

	VTCP_nonblocking(*hp->sess->fd);
	if (passive)
		i = tls_shutdown_passive(hp, conn);
	else
		i = tls_shutdown(hp, conn);
	VTCP_blocking(*hp->sess->fd);
	if (i != 1) {
		vtc_log(vl, 3, "TLS shutdown failed");
		conn->failed = 1;
	} else
		vtc_log(vl, 3, "TLS shutdown complete");
}

void
tls_txreq_early_data(struct http *hp)
{
	struct tlsconn *conn;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	if (hp->tlsconn != NULL)
		CAST_OBJ_NOTNULL(conn, hp->tlsconn, TLSCONN_MAGIC);
	else {
		conn = tls_conn_new(hp, hp->vl);
	}

	conn->write_as_early_data = 1;
}

void
tls_ctx_free(struct tlsctx **ctxp)
{
	struct tlsctx *ctx;

	AN(ctxp);
	if (*ctxp == NULL)
		return;

	TAKE_OBJ_NOTNULL(ctx, ctxp, TLSCTX_MAGIC);
	if (ctx->type == TLS_SERVER)
		free(ctx->s->ocsp_resp);
	SSL_CTX_free(ctx->ctx);
	FREE_OBJ(ctx);
}

void
vtc_tls_init(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	/* OpenSSL < 1.1.0 requires explicit initialization */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_all_algorithms();
#else
	/* OpenSSL >= 1.1.0 initializes automatically */
	OPENSSL_init_ssl(0, NULL);
#endif
	tls_ex_conn = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
	assert(tls_ex_conn > 0);
}

#ifdef VTEST_WITH_QUIC
/*
 * QUIC uses the TLS configuration and the tls.* variables, but the TLS
 * records travel in CRYPTO frames: the SSL is not bound to the socket
 * and hp->so stays the plain one.
 */
SSL *
vtc_tls_quic_new(struct http *hp, struct vtclog *vl, int *early)
{
	struct tlsconn *conn;
	SSL_SESSION *sess;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	AN(early);
	AZ(hp->sfd);
	AZ(hp->tlsconn);
	conn = tls_conn_alloc(hp, vl);
	assert(conn->cfg->type == TLS_CLIENT);
	if (!conn->cfg->c->has_alpn)
		AZ(SSL_set_alpn_protos(conn->ssl,
		    (const unsigned char *)"\x02h3", 3));
	sess = SSL_get_session(conn->ssl);
	*early = sess != NULL && SSL_SESSION_get_max_early_data(sess) > 0;
	hp->tlsconn = conn;
	return (conn->ssl);
}

void
vtc_tls_quic_free(struct http *hp)
{
	struct tlsconn *c;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	TAKE_OBJ_NOTNULL(c, &hp->tlsconn, TLSCONN_MAGIC);
	tls_conn_free(&c);
}

const char *
vtc_tls_quic_sess_in(const struct http *hp)
{
	struct tlsctx *cfg;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(cfg, hp->tlsconf, TLSCTX_MAGIC);
	assert(cfg->type == TLS_CLIENT);
	return (cfg->c->sess_in);
}

void
vtc_tls_quic_failed(const struct http *hp)
{
	struct tlsconn *c;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);
	c->failed = 1;
	vtc_tlserr(c->vl);
}

/* Remember the 0-RTT transport parameters for the next sess_out write */
void
vtc_tls_quic_set_tp(const struct http *hp, const void *tp, size_t len)
{
	struct tlsconn *c;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(c, hp->tlsconn, TLSCONN_MAGIC);
	AN(tp);
	free(c->quic_tp);
	c->quic_tp = malloc(len);
	AN(c->quic_tp);
	memcpy(c->quic_tp, tp, len);
	c->quic_tp_len = len;
}

/* Read the 0-RTT transport parameters stored beside a session */
int
vtc_tls_quic_read_tp(const char *fn, unsigned char **tp, long *len)
{
	char *name, *header;
	BIO *in;
	int r = -1;

	AN(fn);
	AN(tp);
	AN(len);
	in = BIO_new_file(fn, "r");
	if (in == NULL)
		return (-1);
	while (PEM_read_bio(in, &name, &header, tp, len) == 1) {
		OPENSSL_free(header);
		if (!strcmp(name, QUIC_TP_PEM_NAME)) {
			OPENSSL_free(name);
			r = 0;
			break;
		}
		OPENSSL_free(name);
		OPENSSL_free(*tp);
		*tp = NULL;
	}
	ERR_clear_error();
	BIO_free(in);
	return (r);
}
#endif
