/*-
 * Copyright (c) 2008-2011 Varnish Software AS
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
 *
 */

#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif

#include "vdef.h"

#include "miniobj.h"
#include "vas.h"
#include "vsb.h"
#include "vqueue.h"

#include "vtest_api.h"

struct suckaddr;


int fail_out(void);

#define CMD_GLOBAL(n) cmd_f cmd_##n;
#define CMD_TOP(n) cmd_f cmd_##n;
#include "cmds.h"

extern int iflg;
extern int ign_unknown_macro;

void init_server(void);
void init_syslog(void);
void init_tunnel(void);

/* Sessions */
struct vtc_sess *Sess_New(struct vtclog *vl, const char *name);
void Sess_Destroy(struct vtc_sess **spp);
int Sess_GetOpt(struct vtc_sess *, char * const **);
void sess_process(struct vtclog *vl, struct vtc_sess *,
    const char *spec, int *sock, int *sfd, const char *addr);

typedef int sess_conn_f(void *priv, struct vtclog *);
typedef void sess_disc_f(void *priv, struct vtclog *, int *fd);
pthread_t
Sess_Start_Thread(
    void *priv,
    struct vtc_sess *vsp,
    sess_conn_f *conn,
    sess_disc_f *disc,
    const char *listen_addr,
    int *asocket,
    const char *spec
);

char * synth_body(const char *len, int rnd);

void cmd_server_gen_haproxy_conf(struct vsb *vsb);

void vtc_loginit(char *buf, unsigned buflen);
void vtc_hexdump(struct vtclog *, int , const char *, const void *, unsigned);

void vtc_proxy_tlv(struct vtclog *vl, struct vsb *vsb, const char *kva);
int vtc_send_proxy(int fd, int version, const struct suckaddr *sac,
    const struct suckaddr *sas, struct vsb *tlb);

void add_extension(const char *name);
struct cmds *find_cmd(const char *name);
int exec_file(const char *fn, const char *script, const char *tmpdir,
    char *logbuf, unsigned loglen);


struct http;
void cmd_stream(CMD_ARGS);
void start_h2(struct http *hp);
void stop_h2(struct http *hp);
void b64_settings(struct http *hp, const char *s);

/* vtc_tls.c */
void cmd_http_tls_config(CMD_ARGS);
void cmd_http_tls_handshake(CMD_ARGS);
void cmd_http_tls_shutdown(CMD_ARGS);
void tls_txreq_early_data(struct http *hp);
void vtc_tls_init(void);
const char *vtc_tls_var_resolve(const struct http *hp, const char *spec);

/* vtc_gzip.c */
void vtc_gunzip(struct http *, char *, long *);
int vtc_gzip_cmd(struct http *hp, char * const *argv, char **body, long *bodylen);

/* vtc_subr.c */
struct vsb *vtc_hex_to_bin(struct vtclog *vl, const char *arg);
void vtc_expect(struct vtclog *, const char *, const char *, const char *,
    const char *, const char *);
