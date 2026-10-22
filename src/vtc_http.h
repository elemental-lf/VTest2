/*-
 * Copyright (c) 2008-2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "vqueue.h"

#define MAX_HDR		64

/* Session operations for TLS abstraction */
typedef int	sess_poll_f(const struct http *, short *, vtim_real);
typedef ssize_t	sess_read_f(const struct http *, void *, size_t);
typedef ssize_t	sess_write_f(const struct http *, const void *, size_t);
typedef void	sess_close_f(struct http *);

struct sess_ops {
	sess_poll_f		*poll;
	sess_read_f		*read;
	sess_write_f		*write;
	sess_close_f		*close;
};

sess_poll_f http_fd_poll;

/* Forward declarations for TLS and QUIC types */
struct tlsctx;
struct tlsconn;
struct quic_cfg;
struct quic_conn;

struct vtc_sess {
	unsigned		magic;
#define VTC_SESS_MAGIC		0x932bd565
	struct vtclog		*vl;
	char			*name;
	int			repeat;
	int			keepalive;
	int			*fd;

	ssize_t			rcvbuf;

	/* client -quic options, NULL for TCP */
	const struct quic_cfg	*quic;
};

struct h2_window {
	uint64_t		init;
	int64_t			size;
};

struct http {
	unsigned		magic;
#define HTTP_MAGIC		0x2f02169c
	int			*sfd;
	struct vtc_sess		*sess;
	vtim_dur		timeout;
	struct vtclog		*vl;
	struct tlsctx		*tlsconf;
	struct tlsconn		*tlsconn;
	const struct sess_ops	*so;

	struct vsb		*vsb;

	int			rcvbuf;
	int			nrxbuf;
	char			*rx_b;
	char			*rx_p;
	char			*rx_e;
	char			*rem_ip;
	char			*rem_port;
	char			*rem_path;
	char			*body;
	long			bodyl;
	char			bodylen[20];
	char			chunklen[20];

	char			*req[MAX_HDR];
	char			*resp[MAX_HDR];

	int			gziplevel;
	int			gzipresidual;

	int			head_method;

	int			fatal;

	/* H/2 */
	unsigned		h2;
	int			wf;
	int			no_rfc7540_priorities;

	pthread_t		tp;
	VTAILQ_HEAD(, stream)   streams;
	unsigned		last_stream;
	pthread_mutex_t		mtx;
	pthread_cond_t          cond;
	struct hpk_ctx		*encctx;
	struct hpk_ctx		*decctx;
	struct h2_window	h2_win_self[1];
	struct h2_window	h2_win_peer[1];

	/* H/3, set for the whole session of a client -quic */
	struct quic_conn	*quic;
};

void http_process(struct vtclog *vl, struct vtc_sess *vsp, const char *spec,
    int *sock, int *sfd, const char *addr, int rcvbuf);
void http_set_cmds(const struct http *hp, struct vtclog *vl);

#ifdef VTEST_WITH_QUIC
/* vtc_quic.c */
struct quic_cfg *quic_cfg_new(void);
void quic_cfg_free(struct quic_cfg **);
int quic_cfg_opt(struct quic_cfg *, char * const **avp, struct vtclog *);
int quic_udp_connect(struct vtclog *, const char *addr, const char **errp);
void quic_http_init(struct http *, const struct quic_cfg *);
void quic_http_fini(struct http *);
void quic_handshake(struct http *, struct vtclog *);
void quic_expect_close(struct http *, struct vtclog *);
const char *quic_var_resolve(struct http *, const char *spec, char *buf,
    size_t len);
void quic_conn_cmd(struct http *, char * const *av, struct vtclog *);
void quic_not_available(const struct http *, char * const *av,
    struct vtclog *);

/* vtc_http3.c */
void h3_cmd_stream(CMD_ARGS);

/* vtc_tls.c */
struct ssl_st *vtc_tls_quic_new(struct http *, struct vtclog *, int *early);
void vtc_tls_quic_free(struct http *);
void vtc_tls_quic_failed(const struct http *);
const char *vtc_tls_quic_sess_in(const struct http *);
void vtc_tls_quic_set_tp(const struct http *, const void *, size_t);
int vtc_tls_quic_read_tp(const char *fn, unsigned char **tp, long *len);
#endif

