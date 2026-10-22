/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HTTP/3 client: the QUIC transport (ngtcp2 over OpenSSL's QUIC TLS API).
 *
 * One engine thread per connection owns the UDP socket and the timer. It
 * polls the socket and an eventfd, feeds received datagrams to ngtcp2,
 * handles expiry and writes whatever ngtcp2 and nghttp3 have to send.
 * Stream threads call the libraries under qc->mtx and kick the eventfd so
 * that the engine writes and recomputes its timeout.
 */

#ifdef VTEST_WITH_QUIC

#include "config.h"

#include <sys/eventfd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <math.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "vtc.h"
#include "vtc_http.h"
#include "vtc_quic.h"

#include "vfil.h"
#include "vnum.h"
#include "vsa.h"
#include "vss.h"
#include "vtcp.h"
#include "vtim.h"

#define QUIC_SCID_LEN		17
#define QUIC_DCID_LEN		18
#define QUIC_RXBUF		65536
#define QUIC_TXBUF		65536

static const char * const quic_close_types[] = {
	[QUIC_OPEN] = "open",
#define QUIC_CLOSE_TYPE(U, l)	[QUIC_CLOSE_##U] = #l,
#include "tbl/quic_close.h"
};

static pthread_once_t quic_once = PTHREAD_ONCE_INIT;

static void
quic_init_once(void)
{

	AZ(ngtcp2_crypto_ossl_init());
}

static ngtcp2_tstamp
quic_ts(void)
{
	struct timespec ts;

	AZ(clock_gettime(CLOCK_MONOTONIC, &ts));
	return ((uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec);
}

/* SECTION: client-server.args.quic HTTP/3 (QUIC) client arguments
 *
 * These client arguments need varnishtest built with QUIC support (see
 * ``feature quic``). They must be given before the client starts.
 *
 * \-quic
 *	Connect over QUIC and speak HTTP/3. The QUIC handshake happens on
 *	``tls_handshake``, or when the first ``stream`` is started. The
 *	``tls_config`` settings apply; the ALPN defaults to ``h3``.
 *	``-keepalive`` and ``-proxy1``/``-proxy2`` are not available.
 *
 * \-quic_param NAME=VALUE
 *	Set a QUIC transport parameter we send to the server. Repeatable.
 *	NAME is one of ``initial_max_data``,
 *	``initial_max_stream_data_bidi_local``,
 *	``initial_max_stream_data_bidi_remote``,
 *	``initial_max_stream_data_uni``, ``initial_max_streams_bidi``,
 *	``initial_max_streams_uni``, ``max_udp_payload_size``,
 *	``active_connection_id_limit``, ``disable_active_migration``
 *	(0 or 1), ``max_idle_timeout`` (seconds) and ``handshake_timeout``
 *	(seconds, a local setting that defaults to the client timeout).
 *
 * \-token_out FILE
 *	Write the token of the server's NEW_TOKEN frame to FILE.
 *
 * \-token_in FILE
 *	Send the token in FILE in the Initial packets, if FILE exists.
 *
 * \-0rtt
 *	Attempt 0-RTT. Needs ``tls_config { sess_in = FILE }`` with a
 *	session written by ``sess_out`` from a QUIC connection, which
 *	stores the server's transport parameters beside the session.
 *	Requests sent with ``txreq -early`` then travel in 0-RTT packets.
 *
 * \-quic_drop SPEC
 *	Drop chosen datagrams, to exercise loss recovery. SPEC is a comma
 *	separated list of ``out:N`` (the Nth datagram we send), ``in:N``
 *	(the Nth datagram we receive), ``out:every:N`` and ``in:every:N``.
 *	Repeatable.
 *
 * \-quic_debug
 *	Log ngtcp2's own debug output.
 *
 * Every datagram is logged at level 4. If the environment variable
 * SSLKEYLOGFILE is set, the TLS secrets are appended to that file.
 */

struct quic_cfg *
quic_cfg_new(void)
{
	struct quic_cfg *cfg;
	ngtcp2_transport_params *p;

	ALLOC_OBJ(cfg, QUIC_CFG_MAGIC);
	AN(cfg);
	VTAILQ_INIT(&cfg->drops);
	p = &cfg->params;
	ngtcp2_transport_params_default(p);
	p->initial_max_data = 16 * 1024 * 1024;
	p->initial_max_stream_data_bidi_local = 1024 * 1024;
	p->initial_max_stream_data_bidi_remote = 256 * 1024;
	p->initial_max_stream_data_uni = 256 * 1024;
	p->initial_max_streams_bidi = 0;
	p->initial_max_streams_uni = 100;
	p->max_idle_timeout = 30 * NGTCP2_SECONDS;
	p->active_connection_id_limit = 7;
	return (cfg);
}

void
quic_cfg_free(struct quic_cfg **cfgp)
{
	struct quic_cfg *cfg;
	struct quic_drop *d, *d2;

	TAKE_OBJ_NOTNULL(cfg, cfgp, QUIC_CFG_MAGIC);
	VTAILQ_FOREACH_SAFE(d, &cfg->drops, list, d2) {
		VTAILQ_REMOVE(&cfg->drops, d, list);
		FREE_OBJ(d);
	}
	free(cfg->token_in);
	free(cfg->token_out);
	FREE_OBJ(cfg);
}

static void
quic_cfg_param(struct quic_cfg *cfg, const char *arg, struct vtclog *vl)
{
	ngtcp2_transport_params *p;
	const char *v;
	size_t l;
	double d;

	p = &cfg->params;
	v = strchr(arg, '=');
	if (v == NULL)
		vtc_fatal(vl, "-quic_param: expected NAME=VALUE, got %s", arg);
	l = v - arg;
	v++;
	d = VNUM(v);
	if (isnan(d) || d < 0)
		vtc_fatal(vl, "-quic_param: bad value in %s", arg);

#define QP_IS(n)	(l == strlen(n) && !strncmp(arg, n, l))
	if (QP_IS("initial_max_data"))
		p->initial_max_data = (uint64_t)d;
	else if (QP_IS("initial_max_stream_data_bidi_local"))
		p->initial_max_stream_data_bidi_local = (uint64_t)d;
	else if (QP_IS("initial_max_stream_data_bidi_remote"))
		p->initial_max_stream_data_bidi_remote = (uint64_t)d;
	else if (QP_IS("initial_max_stream_data_uni"))
		p->initial_max_stream_data_uni = (uint64_t)d;
	else if (QP_IS("initial_max_streams_bidi"))
		p->initial_max_streams_bidi = (uint64_t)d;
	else if (QP_IS("initial_max_streams_uni"))
		p->initial_max_streams_uni = (uint64_t)d;
	else if (QP_IS("max_udp_payload_size")) {
		p->max_udp_payload_size = (uint64_t)d;
		cfg->max_udp_payload_size = (size_t)d;
	} else if (QP_IS("active_connection_id_limit"))
		p->active_connection_id_limit = (uint64_t)d;
	else if (QP_IS("disable_active_migration"))
		p->disable_active_migration = d != 0;
	else if (QP_IS("max_idle_timeout"))
		p->max_idle_timeout = (ngtcp2_duration)(d * NGTCP2_SECONDS);
	else if (QP_IS("handshake_timeout"))
		cfg->handshake_timeout = d;
	else
		vtc_fatal(vl, "-quic_param: unknown parameter in %s", arg);
#undef QP_IS
}

static void
quic_cfg_drop(struct quic_cfg *cfg, const char *arg, struct vtclog *vl)
{
	struct quic_drop *d;
	char *buf, *tok, *save, *p;

	buf = strdup(arg);
	AN(buf);
	for (tok = strtok_r(buf, ",", &save); tok != NULL;
	    tok = strtok_r(NULL, ",", &save)) {
		ALLOC_OBJ(d, QUIC_DROP_MAGIC);
		AN(d);
		if (!strncmp(tok, "out:", 4))
			d->out = 1;
		else if (strncmp(tok, "in:", 3))
			vtc_fatal(vl, "-quic_drop: bad spec %s", tok);
		p = strchr(tok, ':') + 1;
		if (!strncmp(p, "every:", 6)) {
			d->every = 1;
			p += 6;
		}
		d->n = strtoul(p, &p, 0);
		if (*p != '\0' || d->n == 0)
			vtc_fatal(vl, "-quic_drop: bad spec %s", tok);
		VTAILQ_INSERT_TAIL(&cfg->drops, d, list);
	}
	free(buf);
}

int
quic_cfg_opt(struct quic_cfg *cfg, char * const **avp, struct vtclog *vl)
{
	char * const *av;

	CHECK_OBJ_NOTNULL(cfg, QUIC_CFG_MAGIC);
	AN(avp);
	av = *avp;
	AN(*av);
	if (!strcmp(*av, "-0rtt")) {
		cfg->zero_rtt = 1;
		return (1);
	}
	if (!strcmp(*av, "-quic_debug")) {
		cfg->debug = 1;
		return (1);
	}
	if (!strcmp(*av, "-quic_param") || !strcmp(*av, "-token_in") ||
	    !strcmp(*av, "-token_out") || !strcmp(*av, "-quic_drop")) {
		if (av[1] == NULL)
			vtc_fatal(vl, "%s needs an argument", *av);
		if (!strcmp(*av, "-quic_param"))
			quic_cfg_param(cfg, av[1], vl);
		else if (!strcmp(*av, "-quic_drop"))
			quic_cfg_drop(cfg, av[1], vl);
		else if (!strcmp(*av, "-token_in"))
			REPLACE(cfg->token_in, av[1]);
		else
			REPLACE(cfg->token_out, av[1]);
		*avp = av + 1;
		return (1);
	}
	return (0);
}

/**********************************************************************
 * UDP socket
 */

static int
quic_udp_socket(const struct sockaddr *sa, socklen_t sl)
{
	int fd, e;

	fd = socket(sa->sa_family, SOCK_DGRAM, 0);
	if (fd < 0)
		return (-1);
	if (connect(fd, sa, sl) != 0) {
		e = errno;
		closefd(&fd);
		errno = e;
		return (-1);
	}
	return (fd);
}

static int v_matchproto_(vss_resolved_f)
quic_udp_cb(void *priv, const struct suckaddr *sa)
{
	const struct sockaddr *so;
	socklen_t sl;
	int fd;

	(void)priv;
	so = VSA_Get_Sockaddr(sa, &sl);
	AN(so);
	fd = quic_udp_socket(so, sl);
	return (fd > 0 ? fd : 0);
}

/* A connected UDP socket, resolved like VTCP_open() */
int
quic_udp_connect(struct vtclog *vl, const char *addr, const char **errp)
{
	char mabuf[VTCP_ADDRBUFSIZE], mpbuf[VTCP_PORTBUFSIZE];
	int fd;

	AN(addr);
	AN(errp);
	*errp = NULL;
	fd = VSS_resolver_socktype(addr, NULL, quic_udp_cb, NULL, errp,
	    SOCK_DGRAM);
	if (fd <= 0) {
		if (*errp == NULL)
			*errp = errno ? strerror(errno) : "no usable address";
		return (-1);
	}
	VTCP_myname(fd, mabuf, sizeof mabuf, mpbuf, sizeof mpbuf);
	vtc_log(vl, 3, "connected UDP fd %d from %s %s to %s", fd, mabuf,
	    mpbuf, addr);
	return (fd);
}

/**********************************************************************
 * Helpers
 */

int
quic_cond_wait(pthread_cond_t *cond, struct quic_conn *qc, double deadline)
{
	struct timespec ts;
	double s;

	AN(cond);
	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	s = floor(deadline);
	ts.tv_sec = (time_t)s;
	ts.tv_nsec = (long)((deadline - s) * 1e9);
	return (pthread_cond_timedwait(cond, &qc->mtx, &ts));
}

void
quic_kick(const struct quic_conn *qc)
{
	uint64_t u = 1;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	assert(write(qc->efd, &u, sizeof u) == sizeof u);
}

static void
quic_log_pkt(const struct quic_conn *qc, const char *dir, const uint8_t *p,
    size_t len)
{
	static const char * const lt[4] = {
	    "Initial", "0-RTT", "Handshake", "Retry"
	};
	ngtcp2_version_cid vc;
	char cid[2 * NGTCP2_MAX_CIDLEN + 1];
	size_t u;

	if (len == 0)
		return;
	if (!(p[0] & 0x80)) {
		vtc_log(qc->vl, 4, "%s %zu bytes: 1-RTT", dir, len);
		return;
	}
	if (ngtcp2_pkt_decode_version_cid(&vc, p, len, QUIC_SCID_LEN) != 0) {
		vtc_log(qc->vl, 4, "%s %zu bytes: undecodable", dir, len);
		return;
	}
	for (u = 0; u < vc.dcidlen; u++)
		(void)snprintf(cid + 2 * u, 3, "%02x", vc.dcid[u]);
	cid[2 * vc.dcidlen] = '\0';
	if (vc.version == 0)
		vtc_log(qc->vl, 4, "%s %zu bytes: Version Negotiation dcid=%s",
		    dir, len, cid);
	else
		vtc_log(qc->vl, 4, "%s %zu bytes: %s v0x%x dcid=%s", dir, len,
		    lt[(p[0] & 0x30) >> 4], vc.version, cid);
}

static int
quic_drop(const struct quic_conn *qc, unsigned out, unsigned long n)
{
	const struct quic_drop *d;

	VTAILQ_FOREACH(d, &qc->cfg->drops, list) {
		if (d->out != out)
			continue;
		if (d->every ? n % d->n == 0 : n == d->n)
			return (1);
	}
	return (0);
}

static void v_matchproto_(ngtcp2_printf)
quic_log_printf(void *user_data, const char *fmt, ...)
{
	struct quic_conn *qc;
	char buf[1024];
	va_list ap;

	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	vtc_log(qc->vl, 4, "ngtcp2: %s", buf);
}

static void
quic_closed(struct quic_conn *qc)
{

	assert(qc->close_type != QUIC_OPEN);
	vtc_log(qc->vl, 3, "QUIC connection closed (%s): err=0x%jx%s%s%s",
	    quic_close_types[qc->close_type], (uintmax_t)qc->close_err,
	    qc->close_app ? " (application)" : "",
	    *qc->close_reason ? " reason=" : "", qc->close_reason);
	if (!qc->handshake_done && qc->hp->tlsconn != NULL)
		vtc_tls_quic_failed(qc->hp);
	PTOK(pthread_cond_broadcast(&qc->cond));
	h3_conn_closed(qc);
}

static void
quic_send(struct quic_conn *qc, const uint8_t *buf, size_t len)
{
	ssize_t l;

	qc->pkts_out++;
	quic_log_pkt(qc, "tx", buf, len);
	if (quic_drop(qc, 1, qc->pkts_out)) {
		qc->drops_out++;
		vtc_log(qc->vl, 3, "tx datagram #%lu dropped", qc->pkts_out);
		return;
	}
	do {
		l = send(*qc->hp->sess->fd, buf, len, 0);
	} while (l < 0 && errno == EINTR);
	if (l < 0)
		vtc_log(qc->vl, 3, "QUIC send failed: %s", strerror(errno));
}

/* Send CONNECTION_CLOSE carrying qc->last_error */
static void
quic_write_close(struct quic_conn *qc)
{
	uint8_t buf[NGTCP2_MAX_UDP_PAYLOAD_SIZE];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_ssize n;

	if (qc->conn == NULL || ngtcp2_conn_in_closing_period2(qc->conn) ||
	    ngtcp2_conn_in_draining_period2(qc->conn))
		return;
	ngtcp2_path_storage_zero(&ps);
	n = ngtcp2_conn_write_connection_close(qc->conn, &ps.path, &pi, buf,
	    sizeof buf, &qc->last_error, quic_ts());
	if (n < 0) {
		vtc_log(qc->vl, 3, "ngtcp2_conn_write_connection_close: %s",
		    ngtcp2_strerror((int)n));
		return;
	}
	if (n > 0)
		quic_send(qc, buf, n);
}

static void
quic_set_reason(struct quic_conn *qc, const uint8_t *r, size_t l)
{

	if (l >= sizeof qc->close_reason)
		l = sizeof qc->close_reason - 1;
	if (l > 0)
		memcpy(qc->close_reason, r, l);
	qc->close_reason[l] = '\0';
}

/* A library call failed with liberr: the connection is gone */
void
quic_fail_locked(struct quic_conn *qc, int liberr)
{
	const ngtcp2_ccerr *ccerr;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	if (qc->close_type != QUIC_OPEN)
		return;
	vtc_log(qc->vl, 3, "QUIC error: %s", ngtcp2_strerror(liberr));
	switch (liberr) {
	case NGTCP2_ERR_DRAINING:
		ccerr = ngtcp2_conn_get_ccerr2(qc->conn);
		if (qc->stateless_reset)
			qc->close_type = QUIC_CLOSE_STATELESS_RESET;
		else if (ccerr->type == NGTCP2_CCERR_TYPE_APPLICATION)
			qc->close_type = QUIC_CLOSE_APPLICATION;
		else
			qc->close_type = QUIC_CLOSE_TRANSPORT;
		qc->close_err = ccerr->error_code;
		qc->close_app = ccerr->type == NGTCP2_CCERR_TYPE_APPLICATION;
		quic_set_reason(qc, ccerr->reason, ccerr->reasonlen);
		break;
	case NGTCP2_ERR_RECV_VERSION_NEGOTIATION:
		qc->close_type = QUIC_CLOSE_VERSION_NEGOTIATION;
		break;
	case NGTCP2_ERR_IDLE_CLOSE:
		qc->close_type = QUIC_CLOSE_IDLE;
		break;
	case NGTCP2_ERR_HANDSHAKE_TIMEOUT:
		qc->close_type = QUIC_CLOSE_HANDSHAKE_TIMEOUT;
		break;
	case NGTCP2_ERR_DROP_CONN:
		qc->close_type = QUIC_CLOSE_LOCAL;
		break;
	default:
		if (qc->last_error.error_code == 0) {
			if (liberr == NGTCP2_ERR_CRYPTO)
				ngtcp2_ccerr_set_tls_alert(&qc->last_error,
				    ngtcp2_conn_get_tls_alert2(qc->conn),
				    NULL, 0);
			else
				ngtcp2_ccerr_set_liberr(&qc->last_error,
				    liberr, NULL, 0);
		}
		quic_write_close(qc);
		qc->close_type = QUIC_CLOSE_LOCAL;
		qc->close_err = qc->last_error.error_code;
		qc->close_app =
		    qc->last_error.type == NGTCP2_CCERR_TYPE_APPLICATION;
		break;
	}
	quic_closed(qc);
}

/* An nghttp3 call failed: close with the matching HTTP/3 error */
void
quic_h3_error_locked(struct quic_conn *qc, int liberr)
{

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	vtc_log(qc->vl, 3, "HTTP/3 error: %s", nghttp3_strerror(liberr));
	ngtcp2_ccerr_set_application_error(&qc->last_error,
	    nghttp3_err_infer_quic_app_error_code(liberr), NULL, 0);
}

void
quic_close_locked(struct quic_conn *qc, int app, uint64_t err,
    const char *reason)
{
	size_t l;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	if (qc->close_type != QUIC_OPEN)
		return;
	l = reason != NULL ? strlen(reason) : 0;
	if (app)
		ngtcp2_ccerr_set_application_error(&qc->last_error, err,
		    (const uint8_t *)reason, l);
	else
		ngtcp2_ccerr_set_transport_error(&qc->last_error, err,
		    (const uint8_t *)reason, l);
	quic_write_close(qc);
	qc->close_type = QUIC_CLOSE_LOCAL;
	qc->close_err = err;
	qc->close_app = app;
	quic_set_reason(qc, (const uint8_t *)reason, l);
	quic_closed(qc);
}

/**********************************************************************
 * ngtcp2 callbacks, connection level. The stream level ones are in
 * vtc_http3.c.
 */

static ngtcp2_conn *
quic_get_conn(ngtcp2_crypto_conn_ref *ref)
{
	struct quic_conn *qc;

	CAST_OBJ_NOTNULL(qc, ref->user_data, QUIC_CONN_MAGIC);
	return (qc->conn);
}

static void v_matchproto_(ngtcp2_rand)
quic_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{

	(void)rand_ctx;
	assert(RAND_bytes(dest, (int)destlen) == 1);
}

static int v_matchproto_(ngtcp2_get_new_connection_id2)
quic_get_new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
    ngtcp2_stateless_reset_token *token, size_t cidlen, void *user_data)
{

	(void)conn;
	(void)user_data;
	if (RAND_bytes(cid->data, (int)cidlen) != 1 ||
	    RAND_bytes(token->data, sizeof token->data) != 1)
		return (NGTCP2_ERR_CALLBACK_FAILURE);
	cid->datalen = cidlen;
	return (0);
}

static int v_matchproto_(ngtcp2_handshake_completed)
quic_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_conn *qc;
	uint8_t tp[256];
	ngtcp2_ssize l;
	int i;

	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->handshake_done = 1;
	qc->resumed = SSL_session_reused(qc->ssl);
	vtc_log(qc->vl, 3, "QUIC handshake complete: %s %s%s",
	    SSL_get_version(qc->ssl), SSL_get_cipher_name(qc->ssl),
	    qc->resumed ? " (resumed)" : "");

	if (qc->early_enabled &&
	    SSL_get_early_data_status(qc->ssl) != SSL_EARLY_DATA_ACCEPTED) {
		/* OpenSSL only tells after the handshake */
		vtc_log(qc->vl, 3, "QUIC early data rejected");
		i = ngtcp2_conn_tls_early_data_rejected(conn);
		if (i != 0)
			return (NGTCP2_ERR_CALLBACK_FAILURE);
		if (h3_setup(qc))
			return (NGTCP2_ERR_CALLBACK_FAILURE);
	}

	l = ngtcp2_conn_encode_0rtt_transport_params2(conn, tp, sizeof tp);
	if (l > 0)
		vtc_tls_quic_set_tp(qc->hp, tp, l);

	PTOK(pthread_cond_broadcast(&qc->cond));
	return (0);
}

static int v_matchproto_(ngtcp2_handshake_confirmed)
quic_handshake_confirmed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->handshake_confirmed = 1;
	vtc_log(qc->vl, 3, "QUIC handshake confirmed");
	PTOK(pthread_cond_broadcast(&qc->cond));
	return (0);
}

static int v_matchproto_(ngtcp2_recv_retry)
quic_recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd,
    void *user_data)
{
	struct quic_conn *qc;

	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->retry = 1;
	vtc_log(qc->vl, 3, "QUIC Retry received");
	return (ngtcp2_crypto_recv_retry_cb(conn, hd, user_data));
}

static int v_matchproto_(ngtcp2_recv_new_token)
quic_recv_new_token_cb(ngtcp2_conn *conn, const uint8_t *token,
    size_t tokenlen, void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->new_token = 1;
	vtc_log(qc->vl, 3, "QUIC NEW_TOKEN received (%zu bytes)", tokenlen);
	if (qc->cfg->token_out != NULL &&
	    VFIL_writefile(NULL, qc->cfg->token_out, (const char *)token,
	    tokenlen) != 0)
		vtc_log(qc->vl, 3, "Cannot write token to %s: %s",
		    qc->cfg->token_out, strerror(errno));
	return (0);
}

static int v_matchproto_(ngtcp2_recv_key)
quic_recv_rx_key_cb(ngtcp2_conn *conn, ngtcp2_encryption_level level,
    void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (level != NGTCP2_ENCRYPTION_LEVEL_1RTT)
		return (0);
	return (h3_setup(qc) ? NGTCP2_ERR_CALLBACK_FAILURE : 0);
}

static int v_matchproto_(ngtcp2_tls_early_data_rejected)
quic_early_data_rejected_cb(ngtcp2_conn *conn, void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->early_rejected = 1;
	h3_early_rejected(qc);
	return (0);
}

static int v_matchproto_(ngtcp2_recv_stateless_reset2)
quic_recv_stateless_reset_cb(ngtcp2_conn *conn,
    const ngtcp2_pkt_stateless_reset2 *sr, void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	(void)sr;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	qc->stateless_reset = 1;
	vtc_log(qc->vl, 3, "QUIC stateless reset received");
	return (0);
}

static const ngtcp2_callbacks quic_callbacks = {
	.client_initial = ngtcp2_crypto_client_initial_cb,
	.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
	.handshake_completed = quic_handshake_completed_cb,
	.encrypt = ngtcp2_crypto_encrypt_cb,
	.decrypt = ngtcp2_crypto_decrypt_cb,
	.hp_mask = ngtcp2_crypto_hp_mask_cb,
	.recv_stream_data = h3_recv_stream_data_cb,
	.acked_stream_data_offset = h3_acked_stream_data_offset_cb,
	.recv_retry = quic_recv_retry_cb,
	.extend_max_local_streams_bidi = h3_extend_max_local_streams_bidi_cb,
	.rand = quic_rand_cb,
	.update_key = ngtcp2_crypto_update_key_cb,
	.stream_reset = h3_stream_reset_cb,
	.extend_max_stream_data = h3_extend_max_stream_data_cb,
	.handshake_confirmed = quic_handshake_confirmed_cb,
	.recv_new_token = quic_recv_new_token_cb,
	.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
	.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
	.stream_stop_sending = h3_stream_stop_sending_cb,
	.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
	.recv_rx_key = quic_recv_rx_key_cb,
	.tls_early_data_rejected = quic_early_data_rejected_cb,
	.recv_stateless_reset2 = quic_recv_stateless_reset_cb,
	.get_new_connection_id2 = quic_get_new_cid_cb,
	.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
	.recv_stop_sending = h3_recv_stop_sending_cb,
	.stream_close2 = h3_stream_close_cb,
};

/**********************************************************************
 * Engine
 */

static void
quic_read(struct quic_conn *qc)
{
	uint8_t buf[QUIC_RXBUF];
	struct sockaddr_storage ss;
	socklen_t sl;
	ngtcp2_pkt_info pi;
	ngtcp2_path path;
	ssize_t n;
	int i;

	while (qc->close_type == QUIC_OPEN) {
		sl = sizeof ss;
		n = recvfrom(*qc->hp->sess->fd, buf, sizeof buf, MSG_DONTWAIT,
		    (struct sockaddr *)&ss, &sl);
		if (n < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK &&
			    errno != EINTR)
				vtc_log(qc->vl, 3, "QUIC recv failed: %s",
				    strerror(errno));
			return;
		}
		qc->pkts_in++;
		quic_log_pkt(qc, "rx", buf, n);
		if (quic_drop(qc, 0, qc->pkts_in)) {
			qc->drops_in++;
			vtc_log(qc->vl, 3, "rx datagram #%lu dropped",
			    qc->pkts_in);
			continue;
		}
		memset(&pi, 0, sizeof pi);
		path.local.addr = (struct sockaddr *)&qc->local;
		path.local.addrlen = qc->locallen;
		path.remote.addr = (struct sockaddr *)&ss;
		path.remote.addrlen = sl;
		path.user_data = NULL;
		i = ngtcp2_conn_read_pkt(qc->conn, &path, &pi, buf, n,
		    quic_ts());
		if (i != 0)
			quic_fail_locked(qc, i);
	}
}

static void
quic_write(struct quic_conn *qc)
{
	uint8_t buf[QUIC_TXBUF];
	nghttp3_vec vec[16];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_ssize n, ndatalen;
	nghttp3_ssize nvec;
	ngtcp2_tstamp ts;
	int64_t sid;
	uint32_t flags;
	size_t max;
	int fin, i;

	ts = quic_ts();
	ngtcp2_path_storage_zero(&ps);
	max = ngtcp2_conn_get_path_max_tx_udp_payload_size2(qc->conn);
	assert(max <= sizeof buf);
	while (qc->close_type == QUIC_OPEN) {
		sid = -1;
		fin = 0;
		nvec = 0;
		if (qc->h3 != NULL &&
		    ngtcp2_conn_get_max_data_left2(qc->conn)) {
			nvec = nghttp3_conn_writev_stream(qc->h3, &sid, &fin,
			    vec, 16);
			if (nvec < 0) {
				quic_h3_error_locked(qc, (int)nvec);
				quic_fail_locked(qc,
				    NGTCP2_ERR_CALLBACK_FAILURE);
				return;
			}
		}
		flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
		if (fin)
			flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
		n = ngtcp2_conn_writev_stream(qc->conn, &ps.path, &pi, buf, max,
		    &ndatalen, flags, sid, (const ngtcp2_vec *)vec,
		    (size_t)nvec, ts);
		if (n < 0) {
			switch (n) {
			case NGTCP2_ERR_STREAM_DATA_BLOCKED:
				nghttp3_conn_block_stream(qc->h3, sid);
				continue;
			case NGTCP2_ERR_STREAM_SHUT_WR:
				nghttp3_conn_shutdown_stream_write(qc->h3, sid);
				continue;
			case NGTCP2_ERR_WRITE_MORE:
				i = nghttp3_conn_add_write_offset(qc->h3, sid,
				    (uint64_t)ndatalen);
				if (i != 0) {
					quic_h3_error_locked(qc, i);
					quic_fail_locked(qc,
					    NGTCP2_ERR_CALLBACK_FAILURE);
					return;
				}
				continue;
			default:
				quic_fail_locked(qc, (int)n);
				return;
			}
		}
		if (ndatalen >= 0) {
			i = nghttp3_conn_add_write_offset(qc->h3, sid,
			    (uint64_t)ndatalen);
			if (i != 0) {
				quic_h3_error_locked(qc, i);
				quic_fail_locked(qc,
				    NGTCP2_ERR_CALLBACK_FAILURE);
				return;
			}
		}
		if (n == 0)
			break;
		quic_send(qc, buf, n);
	}
	if (qc->close_type == QUIC_OPEN)
		ngtcp2_conn_update_pkt_tx_time(qc->conn, ts);
}

static void
quic_expiry(struct quic_conn *qc)
{
	int i;

	i = ngtcp2_conn_handle_expiry(qc->conn, quic_ts());
	if (i != 0)
		quic_fail_locked(qc, i);
}

static void
quic_do_rebind(struct quic_conn *qc)
{
	struct sockaddr_storage ss;
	socklen_t sl;
	ngtcp2_path path;
	ngtcp2_addr addr;
	int fd, i;

	fd = quic_udp_socket((struct sockaddr *)&qc->remote, qc->remotelen);
	if (fd < 0) {
		vtc_log(qc->vl, 3, "quic_rebind: socket: %s", strerror(errno));
		qc->rebind = 0;
		return;
	}
	sl = sizeof ss;
	AZ(getsockname(fd, (struct sockaddr *)&ss, &sl));
	memcpy(&qc->local, &ss, sl);
	qc->locallen = sl;
	closefd(qc->hp->sess->fd);
	*qc->hp->sess->fd = fd;

	if (qc->rebind == 2) {
		path.local.addr = (struct sockaddr *)&qc->local;
		path.local.addrlen = qc->locallen;
		path.remote.addr = (struct sockaddr *)&qc->remote;
		path.remote.addrlen = qc->remotelen;
		path.user_data = NULL;
		i = ngtcp2_conn_initiate_immediate_migration(qc->conn, &path,
		    quic_ts());
		if (i != 0)
			vtc_log(qc->vl, 3, "quic_rebind: migration: %s",
			    ngtcp2_strerror(i));
	} else {
		addr.addr = (struct sockaddr *)&qc->local;
		addr.addrlen = qc->locallen;
		ngtcp2_conn_set_local_addr(qc->conn, &addr);
	}
	vtc_log(qc->vl, 3, "QUIC socket rebound, fd %d", fd);
	qc->rebind = 0;
	PTOK(pthread_cond_broadcast(&qc->cond));
}

static int
quic_poll_timeout(const struct quic_conn *qc)
{
	ngtcp2_tstamp expiry, now;
	uint64_t ms;

	if (qc->close_type != QUIC_OPEN)
		return (-1);
	expiry = ngtcp2_conn_get_expiry2(qc->conn);
	if (expiry == UINT64_MAX)
		return (-1);
	now = quic_ts();
	if (expiry <= now)
		return (0);
	ms = (expiry - now + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS;
	return (ms > INT_MAX ? INT_MAX : (int)ms);
}

static void *
quic_engine(void *priv)
{
	struct quic_conn *qc;
	struct pollfd pfd[2];
	uint64_t u;
	int i;

	CAST_OBJ_NOTNULL(qc, priv, QUIC_CONN_MAGIC);
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (!qc->stop) {
		if (qc->rebind)
			quic_do_rebind(qc);
		if (qc->close_type == QUIC_OPEN)
			quic_write(qc);
		pfd[0].fd = qc->efd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;
		pfd[1].fd = qc->close_type == QUIC_OPEN ?
		    *qc->hp->sess->fd : -1;
		pfd[1].events = POLLIN;
		pfd[1].revents = 0;
		i = quic_poll_timeout(qc);
		PTOK(pthread_mutex_unlock(&qc->mtx));
		i = poll(pfd, 2, i);
		PTOK(pthread_mutex_lock(&qc->mtx));
		if (i < 0) {
			assert(errno == EINTR);
			continue;
		}
		if ((pfd[0].revents & POLLIN) &&
		    read(qc->efd, &u, sizeof u) != sizeof u)
			assert(errno == EAGAIN || errno == EINTR);
		if (qc->close_type == QUIC_OPEN &&
		    (pfd[1].revents & (POLLIN | POLLERR)))
			quic_read(qc);
		if (qc->close_type == QUIC_OPEN &&
		    ngtcp2_conn_get_expiry2(qc->conn) <= quic_ts())
			quic_expiry(qc);
	}
	PTOK(pthread_mutex_unlock(&qc->mtx));
	return (NULL);
}

/**********************************************************************
 * Connection setup and teardown
 */

static void
quic_setup_0rtt(struct quic_conn *qc, int early)
{
	const char *fn;
	unsigned char *tp = NULL;
	long len = 0;
	int i;

	fn = vtc_tls_quic_sess_in(qc->hp);
	if (fn == NULL || !early) {
		vtc_log(qc->vl, 3, "-0rtt: no session with early data");
		return;
	}
	if (vtc_tls_quic_read_tp(fn, &tp, &len)) {
		vtc_log(qc->vl, 3,
		    "-0rtt: no QUIC transport parameters in %s", fn);
		return;
	}
	i = ngtcp2_conn_decode_and_set_0rtt_transport_params(qc->conn, tp,
	    (size_t)len);
	OPENSSL_free(tp);
	if (i != 0) {
		vtc_log(qc->vl, 3, "-0rtt: transport parameters: %s",
		    ngtcp2_strerror(i));
		return;
	}
	AN(SSL_set_quic_tls_early_data_enabled(qc->ssl, 1));
	qc->early_enabled = 1;
	vtc_log(qc->vl, 3, "QUIC 0-RTT enabled");
	AZ(h3_setup(qc));
}

/* Create the connection and start the engine. Called by the client thread. */
void
quic_start(struct http *hp)
{
	struct quic_conn *qc;
	const struct quic_cfg *cfg;
	ngtcp2_settings settings;
	ngtcp2_cid dcid, scid;
	ngtcp2_path path;
	char *token = NULL;
	ssize_t tokenlen = 0;
	double tmo;
	int early, i;
	SSL *ssl;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	if (qc->started)
		return;
	cfg = qc->cfg;

	ssl = vtc_tls_quic_new(hp, hp->vl, &early);
	AN(ssl);
	if (cfg->token_in != NULL) {
		token = VFIL_readfile(NULL, cfg->token_in, &tokenlen);
		if (token == NULL)
			vtc_log(hp->vl, 3, "-token_in: cannot read %s",
			    cfg->token_in);
	}

	dcid.datalen = QUIC_DCID_LEN;
	scid.datalen = QUIC_SCID_LEN;
	assert(RAND_bytes(dcid.data, (int)dcid.datalen) == 1);
	assert(RAND_bytes(scid.data, (int)scid.datalen) == 1);

	ngtcp2_settings_default(&settings);
	settings.initial_ts = quic_ts();
	if (cfg->debug)
		settings.log_printf = quic_log_printf;
	tmo = cfg->handshake_timeout > 0 ? cfg->handshake_timeout :
	    hp->timeout;
	settings.handshake_timeout = (ngtcp2_duration)(tmo * NGTCP2_SECONDS);
	if (cfg->max_udp_payload_size > 0) {
		settings.max_tx_udp_payload_size = cfg->max_udp_payload_size;
		settings.no_tx_udp_payload_size_shaping = 1;
	}
	if (token != NULL) {
		settings.token = (const uint8_t *)token;
		settings.tokenlen = tokenlen;
		settings.token_type = NGTCP2_TOKEN_TYPE_NEW_TOKEN;
	}

	path.local.addr = (struct sockaddr *)&qc->local;
	path.local.addrlen = qc->locallen;
	path.remote.addr = (struct sockaddr *)&qc->remote;
	path.remote.addrlen = qc->remotelen;
	path.user_data = NULL;

	PTOK(pthread_mutex_lock(&qc->mtx));
	i = ngtcp2_conn_client_new(&qc->conn, &dcid, &scid, &path,
	    NGTCP2_PROTO_VER_V1, &quic_callbacks, &settings, &cfg->params,
	    NULL, qc);
	free(token);
	if (i != 0) {
		PTOK(pthread_mutex_unlock(&qc->mtx));
		vtc_fatal(hp->vl, "ngtcp2_conn_client_new: %s",
		    ngtcp2_strerror(i));
	}
	qc->ssl = ssl;
	AZ(ngtcp2_crypto_ossl_ctx_new(&qc->ossl_ctx, NULL));
	ngtcp2_crypto_ossl_ctx_set_ssl(qc->ossl_ctx, ssl);
	AZ(ngtcp2_crypto_ossl_configure_client_session(ssl));
	qc->conn_ref.get_conn = quic_get_conn;
	qc->conn_ref.user_data = qc;
	AN(SSL_set_app_data(ssl, &qc->conn_ref));
	ngtcp2_conn_set_tls_native_handle(qc->conn, qc->ossl_ctx);

	if (cfg->zero_rtt)
		quic_setup_0rtt(qc, early);

	qc->started = 1;
	PTOK(pthread_create(&qc->tp, NULL, quic_engine, qc));
	PTOK(pthread_mutex_unlock(&qc->mtx));
}

/* Returns 1 when the handshake completed, 0 if the connection closed. */
int
quic_wait_handshake(struct quic_conn *qc, double deadline)
{
	int i;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	/* ngtcp2's handshake timeout defaults to ours: let it close first */
	deadline += 1.0;
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (!qc->handshake_done && qc->close_type == QUIC_OPEN &&
	    !qc->stop) {
		i = quic_cond_wait(&qc->cond, qc, deadline);
		if (i == ETIMEDOUT)
			break;
		PTOK(i);
	}
	i = qc->handshake_done;
	if (!i && qc->close_type == QUIC_OPEN) {
		PTOK(pthread_mutex_unlock(&qc->mtx));
		vtc_fatal(qc->vl, "QUIC handshake timeout");
	}
	PTOK(pthread_mutex_unlock(&qc->mtx));
	return (i);
}

void
quic_handshake(struct http *hp, struct vtclog *vl)
{
	struct quic_conn *qc;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	quic_start(hp);
	if (!quic_wait_handshake(qc, VTIM_real() + hp->timeout))
		vtc_log(vl, 3, "QUIC handshake failed");
}

void
quic_http_init(struct http *hp, const struct quic_cfg *cfg)
{
	struct quic_conn *qc;
	struct sockaddr_in6 *sin6;
	char abuf[VTCP_ADDRBUFSIZE];

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CHECK_OBJ_NOTNULL(cfg, QUIC_CFG_MAGIC);
	AZ(hp->quic);
	PTOK(pthread_once(&quic_once, quic_init_once));

	ALLOC_OBJ(qc, QUIC_CONN_MAGIC);
	AN(qc);
	qc->hp = hp;
	qc->vl = hp->vl;
	qc->cfg = cfg;
	PTOK(pthread_mutex_init(&qc->mtx, NULL));
	PTOK(pthread_cond_init(&qc->cond, NULL));
	qc->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	assert(qc->efd >= 0);
	ngtcp2_ccerr_default(&qc->last_error);
	VTAILQ_INIT(&qc->streams);

	qc->locallen = sizeof qc->local;
	AZ(getsockname(*hp->sess->fd, (struct sockaddr *)&qc->local,
	    &qc->locallen));
	qc->remotelen = sizeof qc->remote;
	AZ(getpeername(*hp->sess->fd, (struct sockaddr *)&qc->remote,
	    &qc->remotelen));
	if (qc->remote.ss_family == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)&qc->remote;
		AN(inet_ntop(AF_INET6, &sin6->sin6_addr, abuf, sizeof abuf));
		bprintf(qc->authority, "[%s]:%u", abuf,
		    ntohs(sin6->sin6_port));
	} else
		bprintf(qc->authority, "%s:%s", hp->rem_ip, hp->rem_port);
	hp->quic = qc;
}

void
quic_http_fini(struct http *hp)
{
	struct quic_conn *qc;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);

	if (vtc_error) {
		/* Unblock the stream threads, they bail out */
		PTOK(pthread_mutex_lock(&qc->mtx));
		qc->stop = 1;
		h3_conn_closed(qc);
		PTOK(pthread_mutex_unlock(&qc->mtx));
	}
	h3_stop(hp);

	PTOK(pthread_mutex_lock(&qc->mtx));
	if (qc->started)
		quic_close_locked(qc, 1, NGHTTP3_H3_NO_ERROR, NULL);
	qc->stop = 1;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (qc->started) {
		quic_kick(qc);
		PTOK(pthread_join(qc->tp, NULL));
	}

	if (qc->h3 != NULL) {
		nghttp3_conn_del(qc->h3);
		qc->h3 = NULL;
	}
	if (qc->conn != NULL) {
		ngtcp2_conn_del(qc->conn);
		qc->conn = NULL;
	}
	if (qc->ssl != NULL)
		(void)SSL_set_app_data(qc->ssl, NULL);
	ngtcp2_crypto_ossl_ctx_del(qc->ossl_ctx);
	if (hp->tlsconn != NULL)
		vtc_tls_quic_free(hp);
	h3_free(qc);

	closefd(&qc->efd);
	PTOK(pthread_cond_destroy(&qc->cond));
	PTOK(pthread_mutex_destroy(&qc->mtx));
	hp->quic = NULL;
	FREE_OBJ(qc);
}

/**********************************************************************
 * Connection level commands
 */

static void
quic_need_started(const struct quic_conn *qc, const char *cmd,
    struct vtclog *vl)
{

	if (!qc->started)
		vtc_fatal(vl, "%s: no QUIC connection yet, use tls_handshake",
		    cmd);
}

/* SECTION: stream.spec.quic_close quic_close
 *
 * quic_close [-err CODE] [-app] [-reason STRING] (HTTP/3 only)
 *	Send CONNECTION_CLOSE. CODE is a transport error code, or with
 *	``-app`` an application (HTTP/3) error code; the default is
 *	NO_ERROR. CODE can be a number or a name like H3_NO_ERROR.
 */
static void
quic_cmd_close(struct quic_conn *qc, char * const *av, struct vtclog *vl)
{
	uint64_t err = 0;
	const char *reason = NULL;
	int app = 0, err_set = 0;

	quic_need_started(qc, av[0], vl);
	for (av++; *av != NULL; av++) {
		if (!strcmp(*av, "-app"))
			app = 1;
		else if (!strcmp(*av, "-err") && av[1] != NULL) {
			err = h3_err_parse(av[1], vl);
			err_set = 1;
			av++;
		} else if (!strcmp(*av, "-reason") && av[1] != NULL) {
			reason = av[1];
			av++;
		} else
			vtc_fatal(vl, "Unknown quic_close spec: %s", *av);
	}
	if (app && !err_set)
		err = NGHTTP3_H3_NO_ERROR;
	PTOK(pthread_mutex_lock(&qc->mtx));
	quic_close_locked(qc, app, err, reason);
	PTOK(pthread_mutex_unlock(&qc->mtx));
	quic_kick(qc);
}

/* SECTION: stream.spec.quic_rebind quic_rebind
 *
 * quic_rebind [-migrate] (HTTP/3 only)
 *	Move to a new local UDP port. Without ``-migrate`` the client
 *	behaves as if a NAT rebound its address (passive migration);
 *	with it the client migrates actively and validates the new path.
 */
static void
quic_cmd_rebind(struct quic_conn *qc, char * const *av, struct vtclog *vl)
{
	unsigned how = 1;
	int i = 0;

	quic_need_started(qc, av[0], vl);
	if (av[1] != NULL && !strcmp(av[1], "-migrate")) {
		how = 2;
		av++;
	}
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown quic_rebind spec: %s", av[1]);
	PTOK(pthread_mutex_lock(&qc->mtx));
	qc->rebind = how;
	quic_kick(qc);
	while (qc->rebind && !qc->stop && i != ETIMEDOUT)
		i = quic_cond_wait(&qc->cond, qc,
		    VTIM_real() + qc->hp->timeout);
	i = qc->rebind != 0;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (i)
		vtc_fatal(vl, "quic_rebind: timeout");
}

/* SECTION: stream.spec.quic_wait_handshake_confirmed
 *
 * quic_wait_handshake_confirmed (HTTP/3 only)
 *	Wait until the server confirmed the handshake (HANDSHAKE_DONE).
 */
static void
quic_cmd_confirmed(struct quic_conn *qc, char * const *av,
    struct vtclog *vl)
{
	double deadline;
	int i = 0;

	quic_need_started(qc, av[0], vl);
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown %s spec: %s", av[0], av[1]);
	deadline = VTIM_real() + qc->hp->timeout;
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (!qc->handshake_confirmed && qc->close_type == QUIC_OPEN &&
	    !qc->stop && i != ETIMEDOUT)
		i = quic_cond_wait(&qc->cond, qc, deadline);
	i = qc->handshake_confirmed;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (!i)
		vtc_fatal(vl, "Handshake not confirmed");
}

/* SECTION: stream.spec.rxgoaway_h3 rxgoaway (HTTP/3)
 *
 * In HTTP/3 mode ``rxgoaway`` waits for the server's next GOAWAY frame.
 * The stream or push id it carries is available as ``goaway.id``.
 *
 * SECTION: stream.spec.txgoaway_h3 txgoaway (HTTP/3)
 *
 * txgoaway [-final]
 *	In HTTP/3 mode, send a GOAWAY frame announcing a graceful
 *	shutdown. With ``-final`` nghttp3 sends the final GOAWAY and
 *	accepts no new pushes. The id is chosen by nghttp3.
 */
static void
quic_cmd_goaway(struct quic_conn *qc, char * const *av, struct vtclog *vl)
{
	double deadline;
	int i = 0, final = 0;

	quic_need_started(qc, av[0], vl);
	if (!strcmp(av[0], "rxgoaway")) {
		if (av[1] != NULL)
			vtc_fatal(vl, "Unknown rxgoaway spec: %s", av[1]);
		deadline = VTIM_real() + qc->hp->timeout;
		PTOK(pthread_mutex_lock(&qc->mtx));
		while (qc->goaway == qc->goaway_rx &&
		    qc->close_type == QUIC_OPEN && !qc->stop &&
		    i != ETIMEDOUT)
			i = quic_cond_wait(&qc->cond, qc, deadline);
		i = qc->goaway > qc->goaway_rx;
		if (i)
			qc->goaway_rx++;
		PTOK(pthread_mutex_unlock(&qc->mtx));
		if (!i)
			vtc_fatal(vl, "No GOAWAY received");
		return;
	}
	if (av[1] != NULL && !strcmp(av[1], "-final")) {
		final = 1;
		av++;
	}
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown txgoaway spec: %s", av[1]);
	PTOK(pthread_mutex_lock(&qc->mtx));
	if (qc->h3 == NULL)
		i = NGHTTP3_ERR_INVALID_STATE;
	else if (final)
		i = nghttp3_conn_shutdown(qc->h3);
	else
		i = nghttp3_conn_submit_shutdown_notice(qc->h3);
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (i != 0)
		vtc_fatal(vl, "txgoaway: %s", nghttp3_strerror(i));
	quic_kick(qc);
}

void
quic_conn_cmd(struct http *hp, char * const *av, struct vtclog *vl)
{
	struct quic_conn *qc;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	AN(av[0]);
	if (!strcmp(av[0], "quic_close"))
		quic_cmd_close(qc, av, vl);
	else if (!strcmp(av[0], "quic_rebind"))
		quic_cmd_rebind(qc, av, vl);
	else if (!strcmp(av[0], "quic_wait_handshake_confirmed"))
		quic_cmd_confirmed(qc, av, vl);
	else if (!strcmp(av[0], "rxgoaway") || !strcmp(av[0], "txgoaway"))
		quic_cmd_goaway(qc, av, vl);
	else
		WRONG(av[0]);
}

void
quic_not_available(const struct http *hp, char * const *av,
    struct vtclog *vl)
{

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	vtc_fatal(vl, "\"%s\" is not available over HTTP/3%s", av[0],
	    hp->quic != NULL ? " (use a stream)" : "");
}

/* SECTION: stream.spec.expect_close_h3 expect_close (HTTP/3)
 *
 * In HTTP/3 mode ``expect_close`` waits until the connection closes: the
 * server sent CONNECTION_CLOSE or a stateless reset, the idle timeout
 * expired, or the client closed it. ``quic.close.type`` tells which.
 */
void
quic_expect_close(struct http *hp, struct vtclog *vl)
{
	struct quic_conn *qc;
	double deadline;
	int i = 0;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	quic_need_started(qc, "expect_close", vl);
	vtc_log(vl, 4, "Expecting QUIC close");
	deadline = VTIM_real() + hp->timeout;
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (qc->close_type == QUIC_OPEN && !qc->stop && i != ETIMEDOUT)
		i = quic_cond_wait(&qc->cond, qc, deadline);
	i = qc->close_type;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (i == QUIC_OPEN)
		vtc_log(vl, hp->fatal, "Expected close: timeout");
	else
		vtc_log(vl, 4, "QUIC close (%s), as expected",
		    quic_close_types[i]);
}

/**********************************************************************
 * Expectations
 */

/* SECTION: client-server.spec.quic_vars HTTP/3 expectations
 *
 * A client started with ``-quic`` resolves these names in ``expect``,
 * at the top level of its specification and in streams:
 *
 * quic.handshake_done / quic.handshake_confirmed
 *	"true" or "false".
 *
 * quic.early_data
 *	"not_sent" (no 0-RTT attempted), "pending" (handshake not done),
 *	"accepted" or "rejected".
 *
 * quic.resumed
 *	"true" if the TLS session was resumed.
 *
 * quic.retry / quic.new_token
 *	"true" if a Retry packet / a NEW_TOKEN frame was received.
 *
 * quic.version
 *	The negotiated QUIC version, as a number.
 *
 * quic.close.type
 *	"open", or why the connection closed: "local", "transport",
 *	"application" (the server sent CONNECTION_CLOSE of that kind),
 *	"idle", "stateless_reset", "version_negotiation",
 *	"handshake_timeout".
 *
 * quic.close.err / quic.close.app / quic.close.reason
 *	The error code, "true" if it is an application error, and the
 *	reason phrase of the CONNECTION_CLOSE.
 *
 * quic.peer.NAME
 *	The server's transport parameter NAME: initial_max_data,
 *	initial_max_stream_data_bidi_local,
 *	initial_max_stream_data_bidi_remote, initial_max_stream_data_uni,
 *	max_streams_bidi, max_streams_uni, max_idle_timeout (seconds),
 *	max_udp_payload_size, active_connection_id_limit.
 *
 * quic.pkts_in / quic.pkts_out / quic.drops_in / quic.drops_out
 *	Datagram counters.
 *
 * goaway.id
 *	The id of the last GOAWAY received.
 *
 * The ``tls.*`` names work as for TLS connections. HTTP/3 error names
 * such as H3_NO_ERROR resolve to their numbers.
 */
static const char *
quic_var_peer(const struct quic_conn *qc, const char *n, char *buf,
    size_t len, int *unknown)
{
	static const ngtcp2_transport_params none;
	const ngtcp2_transport_params *p = NULL;
	uint64_t v;

	if (qc->conn != NULL)
		p = ngtcp2_conn_get_remote_transport_params2(qc->conn);
	if (p == NULL)
		p = &none;
	if (!strcmp(n, "initial_max_data"))
		v = p->initial_max_data;
	else if (!strcmp(n, "initial_max_stream_data_bidi_local"))
		v = p->initial_max_stream_data_bidi_local;
	else if (!strcmp(n, "initial_max_stream_data_bidi_remote"))
		v = p->initial_max_stream_data_bidi_remote;
	else if (!strcmp(n, "initial_max_stream_data_uni"))
		v = p->initial_max_stream_data_uni;
	else if (!strcmp(n, "max_streams_bidi"))
		v = p->initial_max_streams_bidi;
	else if (!strcmp(n, "max_streams_uni"))
		v = p->initial_max_streams_uni;
	else if (!strcmp(n, "max_idle_timeout"))
		v = p->max_idle_timeout / NGTCP2_SECONDS;
	else if (!strcmp(n, "max_udp_payload_size"))
		v = p->max_udp_payload_size;
	else if (!strcmp(n, "active_connection_id_limit"))
		v = p->active_connection_id_limit;
	else {
		*unknown = 1;
		return (NULL);
	}
	if (p == &none)
		return (NULL);
	(void)snprintf(buf, len, "%ju", (uintmax_t)v);
	return (buf);
}

/* vtc_tls_var_resolve() calls vtc_fatal() on unknown names */
static int
quic_tls_name_ok(const char *spec)
{
	static const char * const names[] = {
		"tls.version", "tls.cipher", "tls.servername", "tls.alpn",
		"tls.alert", "tls.failed", "tls.sess_reused",
		"tls.early_data_status", "tls.staple_requested",
		"tls.ocsp_cert_status", "tls.ocsp_resp_status",
		"tls.ocsp_verify", "tls.ocsp_this_update", NULL
	};
	const char * const *n;

	if (!strncmp(spec, "tls.cert", 8))
		return (1);
	for (n = names; *n != NULL; n++)
		if (!strcmp(spec, *n))
			return (1);
	return (0);
}

#define TF(x)	((x) ? "true" : "false")

static const char *
quic_var_locked(struct quic_conn *qc, const char *spec, char *buf,
    size_t len, int *unknown)
{

	if (!strncmp(spec, "tls.", 4))
		return (qc->hp->tlsconn != NULL ?
		    vtc_tls_var_resolve(qc->hp, spec) : spec);
	if (!strcmp(spec, "goaway.id")) {
		if (!qc->goaway)
			return (NULL);
		(void)snprintf(buf, len, "%jd", (intmax_t)qc->goaway_id);
		return (buf);
	}
	spec += 5;
	if (!strcmp(spec, "handshake_done"))
		return (TF(qc->handshake_done));
	if (!strcmp(spec, "handshake_confirmed"))
		return (TF(qc->handshake_confirmed));
	if (!strcmp(spec, "early_data")) {
		if (!qc->early_enabled)
			return ("not_sent");
		if (qc->early_rejected)
			return ("rejected");
		return (qc->handshake_done ? "accepted" : "pending");
	}
	if (!strcmp(spec, "resumed"))
		return (TF(qc->resumed));
	if (!strcmp(spec, "retry"))
		return (TF(qc->retry));
	if (!strcmp(spec, "new_token"))
		return (TF(qc->new_token));
	if (!strcmp(spec, "close.type"))
		return (quic_close_types[qc->close_type]);
	if (!strcmp(spec, "close.app"))
		return (TF(qc->close_app));
	if (!strcmp(spec, "close.reason"))
		return (qc->close_reason);
	if (!strcmp(spec, "close.err") || !strcmp(spec, "version") ||
	    !strcmp(spec, "pkts_in") || !strcmp(spec, "pkts_out") ||
	    !strcmp(spec, "drops_in") || !strcmp(spec, "drops_out")) {
		if (!strcmp(spec, "close.err"))
			(void)snprintf(buf, len, "%ju",
			    (uintmax_t)qc->close_err);
		else if (!strcmp(spec, "version"))
			(void)snprintf(buf, len, "%u", qc->conn == NULL ? 0 :
			    ngtcp2_conn_get_negotiated_version2(qc->conn));
		else if (!strcmp(spec, "pkts_in"))
			(void)snprintf(buf, len, "%lu", qc->pkts_in);
		else if (!strcmp(spec, "pkts_out"))
			(void)snprintf(buf, len, "%lu", qc->pkts_out);
		else if (!strcmp(spec, "drops_in"))
			(void)snprintf(buf, len, "%lu", qc->drops_in);
		else
			(void)snprintf(buf, len, "%lu", qc->drops_out);
		return (buf);
	}
	if (!strncmp(spec, "peer.", 5))
		return (quic_var_peer(qc, spec + 5, buf, len, unknown));
	*unknown = 1;
	return (NULL);
}

#undef TF

const char *
quic_var_resolve(struct http *hp, const char *spec, char *buf, size_t len)
{
	struct quic_conn *qc;
	const char *r;
	int unknown = 0;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	AN(spec);
	AN(buf);
	if (!strncmp(spec, "H3_", 3) || !strncmp(spec, "QPACK_", 6)) {
		(void)snprintf(buf, len, "%ju",
		    (uintmax_t)h3_err_parse(spec, hp->vl));
		return (buf);
	}
	if (!strncmp(spec, "tls.", 4) && !quic_tls_name_ok(spec))
		vtc_fatal(hp->vl, "Unknown TLS variable: %s", spec);
	PTOK(pthread_mutex_lock(&qc->mtx));
	r = quic_var_locked(qc, spec, buf, len, &unknown);
	/* Copy, the engine may change the source once we unlock */
	if (r != NULL && r != buf && r != spec) {
		(void)snprintf(buf, len, "%s", r);
		r = buf;
	}
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (unknown)
		vtc_fatal(hp->vl, "Unknown QUIC variable: %s", spec);
	return (r);
}

#endif /* VTEST_WITH_QUIC */
