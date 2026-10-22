/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HTTP/3 client: the HTTP/3 binding (nghttp3) and the stream commands.
 *
 * Library callbacks turn what nghttp3 and ngtcp2 report about a request
 * stream into events (HEADERS, TRAILERS, DATA, FIN, RESET) on the stream's
 * queue. The rx commands of the stream thread consume them in order and
 * publish headers and body for expect.
 */

#ifdef VTEST_WITH_QUIC

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#include "vtc.h"
#include "vtc_http.h"
#include "vtc_quic.h"

#include "vfil.h"
#include "vtim.h"

static const struct {
	const char	*name;
	uint64_t	code;
} h3_errs[] = {
#define H3_ERROR(n, v)	{ #n, v },
#include "tbl/h3_error.h"
	{ NULL, 0 }
};

static const char * const h3_ev_names[] = {
	[H3_EV_HEADERS] = "HEADERS",
	[H3_EV_TRAILERS] = "TRAILERS",
	[H3_EV_DATA] = "DATA",
	[H3_EV_FIN] = "FIN",
	[H3_EV_RESET] = "RESET_STREAM",
	[H3_EV_STOP] = "STOP_SENDING",
};

uint64_t
h3_err_parse(const char *s, struct vtclog *vl)
{
	unsigned u;
	uint64_t v;
	char *p;

	AN(s);
	for (u = 0; h3_errs[u].name != NULL; u++)
		if (!strcmp(s, h3_errs[u].name))
			return (h3_errs[u].code);
	v = strtoull(s, &p, 0);
	if (*s == '\0' || *p != '\0')
		vtc_fatal(vl, "Bad error code: %s", s);
	return (v);
}

static const char *
h3_err_name(uint64_t code)
{
	unsigned u;

	for (u = 0; h3_errs[u].name != NULL; u++)
		if (h3_errs[u].code == code)
			return (h3_errs[u].name);
	return ("unknown");
}

/**********************************************************************
 * Header blocks
 */

static struct h3_hdrs *
h3_hdrs_new(void)
{
	struct h3_hdrs *h;

	h = calloc(1, sizeof *h);
	AN(h);
	return (h);
}

static void
h3_hdrs_free(struct h3_hdrs **hp)
{
	struct h3_hdrs *h;
	unsigned u;

	AN(hp);
	h = *hp;
	*hp = NULL;
	if (h == NULL)
		return;
	for (u = 0; u < h->n; u++) {
		free(h->name[u]);
		free(h->value[u]);
	}
	free(h);
}

/* Returns -1 when the block is full */
static int
h3_hdrs_add(struct h3_hdrs *h, const char *n, size_t nl, const char *v,
    size_t vl)
{

	AN(h);
	if (h->n == MAX_HDR)
		return (-1);
	h->name[h->n] = strndup(n, nl);
	AN(h->name[h->n]);
	h->value[h->n] = strndup(v, vl);
	AN(h->value[h->n]);
	h->n++;
	return (0);
}

static const char *
h3_hdrs_find(const struct h3_hdrs *h, const char *n)
{
	unsigned u;

	if (h == NULL)
		return (NULL);
	for (u = 0; u < h->n; u++)
		if (!strcasecmp(h->name[u], n))
			return (h->value[u]);
	return (NULL);
}

static void
h3_hdrs_log(struct vtclog *vl, const char *pfx, const struct h3_hdrs *h)
{
	unsigned u;

	for (u = 0; u < h->n; u++)
		vtc_log(vl, 4, "%s[%2u]: %s: %s", pfx, u, h->name[u],
		    h->value[u]);
}

/**********************************************************************
 * Events
 */

static void
h3_ev_free(struct h3_event **evp)
{
	struct h3_event *ev;

	TAKE_OBJ_NOTNULL(ev, evp, H3_EVENT_MAGIC);
	h3_hdrs_free(&ev->hdrs);
	free(ev->data);
	FREE_OBJ(ev);
}

static struct h3_event *
h3_ev_push(struct h3_stream *s, enum h3_ev_type type)
{
	struct h3_event *ev;

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	ALLOC_OBJ(ev, H3_EVENT_MAGIC);
	AN(ev);
	ev->type = type;
	VTAILQ_INSERT_TAIL(&s->evq, ev, list);
	PTOK(pthread_cond_signal(&s->cond));
	return (ev);
}

/*
 * Wait for the next event. Without one, returns NULL with *why set, after
 * releasing qc->mtx.
 */
static struct h3_event *
h3_ev_next(struct h3_stream *s, const char **why)
{
	struct quic_conn *qc;
	struct h3_event *ev;
	double deadline;
	int i = 0;

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	qc = s->qc;
	deadline = VTIM_real() + qc->hp->timeout;
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (1) {
		ev = VTAILQ_FIRST(&s->evq);
		if (ev != NULL) {
			VTAILQ_REMOVE(&s->evq, ev, list);
			break;
		}
		if (qc->stop) {
			*why = "test is stopping";
			break;
		}
		if (s->closed) {
			*why = "stream closed";
			break;
		}
		if (qc->close_type != QUIC_OPEN) {
			*why = "connection closed";
			break;
		}
		if (i == ETIMEDOUT) {
			*why = "timeout";
			break;
		}
		i = quic_cond_wait(&s->cond, qc, deadline);
	}
	PTOK(pthread_mutex_unlock(&qc->mtx));
	return (ev);
}

/* Publish what the stream thread consumed */
static void
h3_ev_consume(struct h3_stream *s, struct h3_event *ev)
{

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	CHECK_OBJ_NOTNULL(ev, H3_EVENT_MAGIC);
	switch (ev->type) {
	case H3_EV_HEADERS:
		h3_hdrs_free(&s->resp);
		s->resp = ev->hdrs;
		ev->hdrs = NULL;
		break;
	case H3_EV_TRAILERS:
		h3_hdrs_free(&s->trailers);
		s->trailers = ev->hdrs;
		ev->hdrs = NULL;
		break;
	case H3_EV_DATA:
		s->body = realloc(s->body, s->bodylen + ev->len + 1);
		AN(s->body);
		memcpy(s->body + s->bodylen, ev->data, ev->len);
		s->bodylen += ev->len;
		s->body[s->bodylen] = '\0';
		break;
	case H3_EV_RESET:
		s->rst_seen = 1;
		s->rst_err = ev->err;
		break;
	default:
		break;
	}
}

static struct h3_event *
h3_ev_expect(struct h3_stream *s, enum h3_ev_type type, const char *cmd,
    unsigned n)
{
	struct h3_event *ev;
	const char *why = NULL;

	ev = h3_ev_next(s, &why);
	if (ev == NULL)
		vtc_fatal(s->vl, "%s: no %s (#%u): %s", cmd, h3_ev_names[type],
		    n, why);
	if (ev->type != type) {
		if (ev->type == H3_EV_RESET)
			vtc_fatal(s->vl, "%s: event #%u was RESET_STREAM "
			    "(%s, 0x%jx) instead of %s", cmd, n,
			    h3_err_name(ev->err), (uintmax_t)ev->err,
			    h3_ev_names[type]);
		vtc_fatal(s->vl, "%s: event #%u was %s instead of %s", cmd, n,
		    h3_ev_names[ev->type], h3_ev_names[type]);
	}
	h3_ev_consume(s, ev);
	return (ev);
}

/**********************************************************************
 * Submitting requests
 */

static nghttp3_ssize
h3_read_data_cb(nghttp3_conn *conn, int64_t sid, nghttp3_vec *vec,
    size_t veccnt, uint32_t *pflags, void *user_data, void *stream_user_data)
{
	struct h3_stream *s;
	size_t n = 0;

	(void)conn;
	(void)sid;
	(void)user_data;
	CAST_OBJ_NOTNULL(s, stream_user_data, H3_STREAM_MAGIC);
	while (s->txnext != NULL && n < veccnt) {
		CHECK_OBJ(s->txnext, H3_CHUNK_MAGIC);
		vec[n].base = (uint8_t *)s->txnext->data;
		vec[n].len = s->txnext->len;
		n++;
		s->txnext = VTAILQ_NEXT(s->txnext, list);
	}
	if (s->txnext == NULL && s->txeof) {
		*pflags |= NGHTTP3_DATA_FLAG_EOF;
		s->txfin = 1;
	} else if (n == 0)
		return (NGHTTP3_ERR_WOULDBLOCK);
	return ((nghttp3_ssize)n);
}

static const nghttp3_data_reader h3_data_reader = {
	.read_data = h3_read_data_cb,
};

/* Submit the requests of streams waiting for a QUIC stream id */
static int
h3_submit_pending(struct quic_conn *qc)
{
	struct h3_stream *s;
	nghttp3_nv nva[MAX_HDR];
	unsigned u;
	int i;

	if (qc->h3 == NULL || qc->close_type != QUIC_OPEN)
		return (0);
	VTAILQ_FOREACH(s, &qc->streams, list) {
		if (s->submitted || s->req == NULL)
			continue;
		if (!qc->handshake_done && !s->early)
			continue;
		i = ngtcp2_conn_open_bidi_stream(qc->conn, &s->id, s);
		if (i == NGTCP2_ERR_STREAM_ID_BLOCKED) {
			vtc_log(s->vl, 3, "Waiting for the server to allow "
			    "another stream");
			return (0);
		}
		if (i != 0) {
			vtc_log(s->vl, 3, "ngtcp2_conn_open_bidi_stream: %s",
			    ngtcp2_strerror(i));
			return (-1);
		}
		for (u = 0; u < s->req->n; u++) {
			nva[u].name = (uint8_t *)s->req->name[u];
			nva[u].namelen = strlen(s->req->name[u]);
			nva[u].value = (uint8_t *)s->req->value[u];
			nva[u].valuelen = strlen(s->req->value[u]);
			nva[u].flags = NGHTTP3_NV_FLAG_NONE;
		}
		s->txnext = VTAILQ_FIRST(&s->txq);
		s->txfin = 0;
		i = nghttp3_conn_submit_request(qc->h3, s->id, nva, s->req->n,
		    s->txnext == NULL && s->txeof ? NULL : &h3_data_reader,
		    s);
		if (i != 0) {
			quic_h3_error_locked(qc, i);
			return (-1);
		}
		s->submitted = 1;
		vtc_log(s->vl, 3, "tx: HEADERS on stream id %jd%s",
		    (intmax_t)s->id, qc->handshake_done ? "" : " (0-RTT)");
		PTOK(pthread_cond_signal(&s->cond));
	}
	return (0);
}

/**********************************************************************
 * nghttp3 callbacks
 */

static struct h3_stream *
h3_sud(void *stream_user_data)
{
	struct h3_stream *s;

	CAST_OBJ(s, stream_user_data, H3_STREAM_MAGIC);
	return (s);
}

static int
h3_begin_headers_cb(nghttp3_conn *conn, int64_t sid, void *user_data,
    void *stream_user_data)
{
	struct h3_stream *s;

	(void)conn;
	(void)sid;
	(void)user_data;
	s = h3_sud(stream_user_data);
	if (s == NULL)
		return (0);
	h3_hdrs_free(&s->rxhdrs);
	s->rxhdrs = h3_hdrs_new();
	return (0);
}

static int
h3_recv_header_cb(nghttp3_conn *conn, int64_t sid, int32_t token,
    nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
    void *user_data, void *stream_user_data)
{
	struct h3_stream *s;
	nghttp3_vec n, v;

	(void)conn;
	(void)sid;
	(void)token;
	(void)flags;
	(void)user_data;
	s = h3_sud(stream_user_data);
	if (s == NULL)
		return (0);
	AN(s->rxhdrs);
	n = nghttp3_rcbuf_get_buf(name);
	v = nghttp3_rcbuf_get_buf(value);
	if (h3_hdrs_add(s->rxhdrs, (const char *)n.base, n.len,
	    (const char *)v.base, v.len))
		vtc_log(s->vl, 3, "Too many header fields, dropped %.*s",
		    (int)n.len, n.base);
	return (0);
}

static int
h3_end_hdrs(void *stream_user_data, enum h3_ev_type type)
{
	struct h3_stream *s;
	struct h3_event *ev;

	s = h3_sud(stream_user_data);
	if (s == NULL)
		return (0);
	AN(s->rxhdrs);
	vtc_log(s->vl, 3, "rx: %s (%u fields)", h3_ev_names[type],
	    s->rxhdrs->n);
	h3_hdrs_log(s->vl, "header", s->rxhdrs);
	ev = h3_ev_push(s, type);
	ev->hdrs = s->rxhdrs;
	s->rxhdrs = NULL;
	return (0);
}

static int
h3_end_headers_cb(nghttp3_conn *conn, int64_t sid, int fin, void *user_data,
    void *stream_user_data)
{

	(void)conn;
	(void)sid;
	(void)fin;
	(void)user_data;
	return (h3_end_hdrs(stream_user_data, H3_EV_HEADERS));
}

static int
h3_end_trailers_cb(nghttp3_conn *conn, int64_t sid, int fin,
    void *user_data, void *stream_user_data)
{

	(void)conn;
	(void)sid;
	(void)fin;
	(void)user_data;
	return (h3_end_hdrs(stream_user_data, H3_EV_TRAILERS));
}

static void
h3_consume(struct quic_conn *qc, int64_t sid, size_t n)
{

	ngtcp2_conn_extend_max_stream_offset(qc->conn, sid, n);
	ngtcp2_conn_extend_max_offset(qc->conn, n);
}

static int
h3_recv_data_cb(nghttp3_conn *conn, int64_t sid, const uint8_t *data,
    size_t len, void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;
	struct h3_stream *s;
	struct h3_event *ev;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	h3_consume(qc, sid, len);
	s = h3_sud(stream_user_data);
	if (s == NULL)
		return (0);
	vtc_log(s->vl, 3, "rx: DATA (%zu bytes)", len);
	ev = h3_ev_push(s, H3_EV_DATA);
	ev->data = malloc(len + 1L);
	AN(ev->data);
	memcpy(ev->data, data, len);
	ev->data[len] = '\0';
	ev->len = len;
	return (0);
}

static int
h3_deferred_consume_cb(nghttp3_conn *conn, int64_t sid, size_t consumed,
    void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;

	(void)conn;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	h3_consume(qc, sid, consumed);
	return (0);
}

static int
h3_end_stream_cb(nghttp3_conn *conn, int64_t sid, void *user_data,
    void *stream_user_data)
{
	struct h3_stream *s;

	(void)conn;
	(void)sid;
	(void)user_data;
	s = h3_sud(stream_user_data);
	if (s == NULL)
		return (0);
	vtc_log(s->vl, 3, "rx: FIN");
	(void)h3_ev_push(s, H3_EV_FIN);
	return (0);
}

/* nghttp3 wants the peer to stop sending */
static int
h3_stop_sending_cb(nghttp3_conn *conn, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;

	(void)conn;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (ngtcp2_conn_shutdown_stream_read(qc->conn, 0, sid, err) != 0)
		return (NGHTTP3_ERR_CALLBACK_FAILURE);
	return (0);
}

/* nghttp3 wants the stream reset */
static int
h3_reset_stream_cb(nghttp3_conn *conn, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;

	(void)conn;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (ngtcp2_conn_shutdown_stream_write(qc->conn, 0, sid, err) != 0)
		return (NGHTTP3_ERR_CALLBACK_FAILURE);
	return (0);
}

/* GOAWAY received */
static int
h3_shutdown_cb(nghttp3_conn *conn, int64_t id, void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	vtc_log(qc->vl, 3, "rx: GOAWAY id %jd", (intmax_t)id);
	qc->goaway++;
	qc->goaway_id = id;
	PTOK(pthread_cond_broadcast(&qc->cond));
	return (0);
}

static int
h3_recv_settings_cb(nghttp3_conn *conn, const nghttp3_proto_settings *st,
    void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	vtc_log(qc->vl, 3, "rx: SETTINGS max_field_section_size=%ju "
	    "qpack_max_dtable_capacity=%zu qpack_blocked_streams=%zu",
	    (uintmax_t)st->max_field_section_size,
	    st->qpack_max_dtable_capacity, st->qpack_blocked_streams);
	return (0);
}

static void
h3_rand_cb(uint8_t *dest, size_t destlen)
{

	assert(RAND_bytes(dest, (int)destlen) == 1);
}

static const nghttp3_callbacks h3_callbacks = {
	.recv_data = h3_recv_data_cb,
	.deferred_consume = h3_deferred_consume_cb,
	.begin_headers = h3_begin_headers_cb,
	.recv_header = h3_recv_header_cb,
	.end_headers = h3_end_headers_cb,
	.begin_trailers = h3_begin_headers_cb,
	.recv_trailer = h3_recv_header_cb,
	.end_trailers = h3_end_trailers_cb,
	.stop_sending = h3_stop_sending_cb,
	.end_stream = h3_end_stream_cb,
	.reset_stream = h3_reset_stream_cb,
	.shutdown = h3_shutdown_cb,
	.rand = h3_rand_cb,
	.recv_settings2 = h3_recv_settings_cb,
};

/**********************************************************************
 * ngtcp2 callbacks, stream level
 */

int
h3_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t sid,
    uint64_t offset, const uint8_t *data, size_t len, void *user_data,
    void *stream_user_data)
{
	struct quic_conn *qc;
	nghttp3_ssize n;

	(void)offset;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 == NULL) {
		h3_consume(qc, sid, len);
		return (0);
	}
	n = nghttp3_conn_read_stream2(qc->h3, sid, data, len,
	    flags & NGTCP2_STREAM_DATA_FLAG_FIN,
	    ngtcp2_conn_get_timestamp(conn));
	if (n < 0) {
		quic_h3_error_locked(qc, (int)n);
		return (NGTCP2_ERR_CALLBACK_FAILURE);
	}
	h3_consume(qc, sid, (size_t)n);
	return (0);
}

int
h3_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t sid,
    uint64_t offset, uint64_t len, void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;
	int i;

	(void)conn;
	(void)offset;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 == NULL)
		return (0);
	i = nghttp3_conn_add_ack_offset(qc->h3, sid, len);
	if (i != 0) {
		quic_h3_error_locked(qc, i);
		return (NGTCP2_ERR_CALLBACK_FAILURE);
	}
	return (0);
}

int
h3_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t sid,
    uint64_t rx_err, uint64_t tx_err, void *user_data,
    void *stream_user_data)
{
	struct quic_conn *qc;
	struct h3_stream *s;
	uint32_t f = NGHTTP3_STREAM_CLOSE_FLAG_NONE;
	int i;

	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 != NULL) {
		if (flags & NGTCP2_STREAM_CLOSE2_FLAG_RX_APP_ERROR_CODE_SET)
			f |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
		if (flags & NGTCP2_STREAM_CLOSE2_FLAG_TX_APP_ERROR_CODE_SET)
			f |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
		i = nghttp3_conn_close_stream2(qc->h3, f, sid, rx_err, tx_err);
		if (i != 0 && i != NGHTTP3_ERR_STREAM_NOT_FOUND) {
			quic_h3_error_locked(qc, i);
			return (NGTCP2_ERR_CALLBACK_FAILURE);
		}
	}
	if (!ngtcp2_conn_is_local_stream2(conn, sid) &&
	    !ngtcp2_is_bidi_stream(sid))
		ngtcp2_conn_extend_max_streams_uni(conn, 1);
	s = h3_sud(stream_user_data);
	if (s != NULL) {
		vtc_log(s->vl, 3, "QUIC stream %jd closed", (intmax_t)sid);
		s->closed = 1;
		PTOK(pthread_cond_signal(&s->cond));
	}
	return (0);
}

/* The server reset the stream */
int
h3_stream_reset_cb(ngtcp2_conn *conn, int64_t sid, uint64_t final_size,
    uint64_t err, void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;
	struct h3_stream *s;
	int i;

	(void)conn;
	(void)final_size;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 != NULL) {
		i = nghttp3_conn_shutdown_stream_read(qc->h3, sid);
		if (i != 0) {
			quic_h3_error_locked(qc, i);
			return (NGTCP2_ERR_CALLBACK_FAILURE);
		}
	}
	s = h3_sud(stream_user_data);
	if (s != NULL) {
		vtc_log(s->vl, 3, "rx: RESET_STREAM %s (0x%jx)",
		    h3_err_name(err), (uintmax_t)err);
		h3_ev_push(s, H3_EV_RESET)->err = err;
	}
	return (0);
}

/* The server sent STOP_SENDING; ngtcp2 resets our sending side */
int
h3_recv_stop_sending_cb(ngtcp2_conn *conn, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data)
{
	struct h3_stream *s;

	(void)conn;
	(void)sid;
	(void)user_data;
	s = h3_sud(stream_user_data);
	if (s != NULL) {
		vtc_log(s->vl, 3, "rx: STOP_SENDING %s (0x%jx)",
		    h3_err_name(err), (uintmax_t)err);
		s->stop_seen = 1;
		s->stop_err = err;
		PTOK(pthread_cond_signal(&s->cond));
	}
	return (0);
}

/* We no longer read the stream */
int
h3_stream_stop_sending_cb(ngtcp2_conn *conn, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;
	int i;

	(void)conn;
	(void)err;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 == NULL)
		return (0);
	i = nghttp3_conn_shutdown_stream_read(qc->h3, sid);
	if (i != 0) {
		quic_h3_error_locked(qc, i);
		return (NGTCP2_ERR_CALLBACK_FAILURE);
	}
	return (0);
}

int
h3_extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t sid,
    uint64_t max_data, void *user_data, void *stream_user_data)
{
	struct quic_conn *qc;
	int i;

	(void)conn;
	(void)max_data;
	(void)stream_user_data;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	if (qc->h3 == NULL)
		return (0);
	i = nghttp3_conn_unblock_stream(qc->h3, sid);
	if (i != 0) {
		quic_h3_error_locked(qc, i);
		return (NGTCP2_ERR_CALLBACK_FAILURE);
	}
	return (0);
}

int
h3_extend_max_local_streams_bidi_cb(ngtcp2_conn *conn, uint64_t max_streams,
    void *user_data)
{
	struct quic_conn *qc;

	(void)conn;
	(void)max_streams;
	CAST_OBJ_NOTNULL(qc, user_data, QUIC_CONN_MAGIC);
	return (h3_submit_pending(qc) ? NGTCP2_ERR_CALLBACK_FAILURE : 0);
}

/**********************************************************************
 * Connection
 */

int
h3_setup(struct quic_conn *qc)
{
	nghttp3_settings settings;
	int64_t ctrl, qenc, qdec;
	int i;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	if (qc->h3 != NULL)
		return (0);
	if (ngtcp2_conn_get_streams_uni_left2(qc->conn) < 3) {
		vtc_log(qc->vl, 3,
		    "Server allows fewer than 3 unidirectional streams");
		return (-1);
	}
	nghttp3_settings_default(&settings);
	settings.qpack_max_dtable_capacity = 4096;
	settings.qpack_blocked_streams = 100;
	i = nghttp3_conn_client_new(&qc->h3, &h3_callbacks, &settings,
	    nghttp3_mem_default(), qc);
	if (i != 0) {
		vtc_log(qc->vl, 3, "nghttp3_conn_client_new: %s",
		    nghttp3_strerror(i));
		return (-1);
	}
	if (ngtcp2_conn_open_uni_stream(qc->conn, &ctrl, NULL) != 0 ||
	    ngtcp2_conn_open_uni_stream(qc->conn, &qenc, NULL) != 0 ||
	    ngtcp2_conn_open_uni_stream(qc->conn, &qdec, NULL) != 0) {
		vtc_log(qc->vl, 3, "Cannot open the HTTP/3 control streams");
		return (-1);
	}
	if (nghttp3_conn_bind_control_stream(qc->h3, ctrl) != 0 ||
	    nghttp3_conn_bind_qpack_streams(qc->h3, qenc, qdec) != 0) {
		vtc_log(qc->vl, 3, "Cannot bind the HTTP/3 control streams");
		return (-1);
	}
	vtc_log(qc->vl, 3, "HTTP/3 control stream %jd, QPACK streams %jd %jd",
	    (intmax_t)ctrl, (intmax_t)qenc, (intmax_t)qdec);
	return (h3_submit_pending(qc));
}

/* ngtcp2 discarded the 0-RTT streams: submit their requests again */
void
h3_early_rejected(struct quic_conn *qc)
{
	struct h3_stream *s;
	struct h3_event *ev, *ev2;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	if (qc->h3 != NULL) {
		nghttp3_conn_del(qc->h3);
		qc->h3 = NULL;
	}
	VTAILQ_FOREACH(s, &qc->streams, list) {
		if (!s->submitted)
			continue;
		vtc_log(s->vl, 3, "0-RTT request discarded, will retry");
		s->submitted = 0;
		s->id = -1;
		s->closed = 0;
		h3_hdrs_free(&s->rxhdrs);
		VTAILQ_FOREACH_SAFE(ev, &s->evq, list, ev2) {
			VTAILQ_REMOVE(&s->evq, ev, list);
			h3_ev_free(&ev);
		}
	}
}

void
h3_conn_closed(struct quic_conn *qc)
{
	struct h3_stream *s;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	VTAILQ_FOREACH(s, &qc->streams, list)
		PTOK(pthread_cond_signal(&s->cond));
}

/**********************************************************************
 * Stream commands
 */

#define H3_REQ_STREAM(s, av)						\
	do {								\
		if (!strcmp((s)->name, "0"))				\
			vtc_fatal((s)->vl, "\"%s\": stream 0 is the "	\
			    "connection, use another stream", (av)[0]);	\
	} while (0)

static struct h3_chunk *
h3_chunk_add(struct h3_stream *s, char *data, size_t len)
{
	struct h3_chunk *c;

	ALLOC_OBJ(c, H3_CHUNK_MAGIC);
	AN(c);
	c->data = data;
	c->len = len;
	VTAILQ_INSERT_TAIL(&s->txq, c, list);
	return (c);
}

/* SECTION: stream.spec.h3 HTTP/3 streams
 *
 * In a client started with ``-quic``, ``stream NAME { SPEC }`` runs SPEC
 * against one HTTP/3 request stream. NAME is only a label: the QUIC
 * stream id (0, 4, 8, ...) is allocated by the first ``txreq`` and is
 * available as ``stream.id``. ``stream 0`` is the connection: it takes the
 * connection level commands (``quic_close``, ``quic_rebind``,
 * ``rxgoaway``, ``txgoaway``, ``quic_wait_handshake_confirmed``,
 * ``expect_close``) and ``expect``. ``next`` as NAME picks a new label.
 *
 * These commands are available in HTTP/3 streams:
 *
 * txreq [-req|-method STRING] [-url STRING] [-scheme STRING] [-noadd]
 * [-hdr NAME VALUE]... [-body STRING | -bodyfrom FILE | -bodylen INT |
 * -gzipbody STRING | -gziplen INT] [-nostrend] [-early]
 *	Send a request. The pseudo-headers default to GET, ``/``,
 *	``https`` and an authority taken from the ``http_default_authority``
 *	macro, else the address the client connected to. They come first;
 *	``-noadd`` drops them.
 *	``-nostrend`` keeps the request body open for ``txdata``.
 *	``-early`` sends the request as 0-RTT data and needs a client
 *	started with ``-0rtt`` whose session allows early data; without
 *	it ``txreq`` waits for the handshake. If the server rejects the
 *	early data, the request is sent again after the handshake.
 *
 * txdata [-data STRING | -datalen INT] [-nostrend]
 *	Append to the request body. Unless ``-nostrend`` is given, this
 *	ends the request body.
 *
 * rxhdrs
 *	Receive a header block (HEADERS).
 *
 * rxdata [-all | -some INT]
 *	Receive one, INT, or with ``-all`` all DATA chunks up to the end
 *	of the stream. Chunk boundaries depend on the packets, so prefer
 *	``-all`` or ``rxresp``.
 *
 * rxresp [-no_obj]
 *	Receive a header block, then data and trailers up to the end of
 *	the stream. ``-no_obj`` is accepted for tests shared with HTTP/2
 *	and does nothing.
 *
 * txrst [-err CODE]
 *	Reset the request stream (RESET_STREAM). CODE defaults to
 *	H3_REQUEST_CANCELLED.
 *
 * txstop [-err CODE]
 *	Ask the server to stop sending (STOP_SENDING). CODE defaults to
 *	H3_REQUEST_CANCELLED.
 *
 * rxrst
 *	Wait for the server's RESET_STREAM. Headers and data received
 *	before it are consumed.
 *
 * rxstop
 *	Wait for the server's STOP_SENDING.
 *
 * expect, gunzip, write_body
 *	As in HTTP/2 streams. The names are ``resp.status``,
 *	``resp.http.NAME``, ``resp.trailer.NAME``, ``resp.body``,
 *	``resp.bodylen``, ``req.method``, ``req.url``, ``req.scheme``,
 *	``req.authority``, ``req.http.NAME``, ``stream.id``, ``rst.err``,
 *	``stop.err`` and the connection names (``quic.*``, ``tls.*``,
 *	``goaway.id``). HTTP/3 error names such as H3_NO_ERROR resolve to
 *	their numbers.
 *
 * The HTTP/2 frame level commands (txsettings, rxsettings, txping,
 * rxping, txwinup, rxwinup, txprio, rxprio, txpush, rxpush, txcont,
 * rxcont, sendhex, rxframe) are not available over HTTP/3.
 */

static void
h3_authority(const struct quic_conn *qc, struct vtclog *vl, char *buf,
    size_t len)
{
	struct vsb *vsb;

	if (!macro_isdef(NULL, "http_default_authority")) {
		(void)snprintf(buf, len, "%s", qc->authority);
		return;
	}
	vsb = macro_expand(vl, "${http_default_authority}");
	AN(vsb);
	(void)snprintf(buf, len, "%s", VSB_data(vsb));
	VSB_destroy(&vsb);
}

static void
cmd_h3_txreq(CMD_ARGS)
{
	struct h3_stream *s;
	struct quic_conn *qc;
	struct h3_hdrs *req;
	const char *method = "GET", *url = "/", *scheme = "https";
	const char *pseudo;
	char authority[256];
	char *body = NULL;
	long bodylen = 0;
	ssize_t len;
	int noadd = 0, nostrend = 0, early = 0, i;
	char * const *ap;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	qc = s->qc;
	H3_REQ_STREAM(s, av);
	if (s->req != NULL)
		vtc_fatal(vl, "txreq: stream %s already sent a request",
		    s->name);
	h3_authority(qc, vl, authority, sizeof authority);
	req = h3_hdrs_new();

	/* Pseudo-headers first (RFC 9114 4.3): look ahead for overrides */
	for (ap = av + 1; *ap != NULL; ap++) {
		if (!strcmp(*ap, "-noadd"))
			noadd = 1;
		else if ((!strcmp(*ap, "-req") || !strcmp(*ap, "-method")) &&
		    ap[1] != NULL)
			method = *++ap;
		else if (!strcmp(*ap, "-url") && ap[1] != NULL)
			url = *++ap;
		else if (!strcmp(*ap, "-scheme") && ap[1] != NULL)
			scheme = *++ap;
		else if (!strcmp(*ap, "-hdr") && ap[1] != NULL &&
		    ap[2] != NULL) {
			if (!strcasecmp(ap[1], ":authority") ||
			    !strcasecmp(ap[1], "host"))
				*authority = '\0';
			ap += 2;
		}
	}
	if (!noadd) {
		AZ(h3_hdrs_add(req, ":method", 7, method, strlen(method)));
		AZ(h3_hdrs_add(req, ":scheme", 7, scheme, strlen(scheme)));
		if (*authority != '\0')
			AZ(h3_hdrs_add(req, ":authority", 10, authority,
			    strlen(authority)));
		AZ(h3_hdrs_add(req, ":path", 5, url, strlen(url)));
	}

	for (av++; *av != NULL; av++) {
		if (!strcmp(*av, "-noadd"))
			continue;
		if (!strcmp(*av, "-req") || !strcmp(*av, "-method") ||
		    !strcmp(*av, "-url") || !strcmp(*av, "-scheme")) {
			if (av[1] == NULL)
				vtc_fatal(vl, "%s needs an argument", *av);
			/* With -noadd, in the order given */
			if (!strcmp(*av, "-url"))
				pseudo = ":path";
			else if (!strcmp(*av, "-scheme"))
				pseudo = ":scheme";
			else
				pseudo = ":method";
			if (noadd && h3_hdrs_add(req, pseudo, strlen(pseudo),
			    av[1], strlen(av[1])))
				vtc_fatal(vl, "Too many header fields");
			av++;
		} else if (!strcmp(*av, "-hdr")) {
			if (av[1] == NULL || av[2] == NULL)
				vtc_fatal(vl, "-hdr takes two arguments");
			if (h3_hdrs_add(req, av[1], strlen(av[1]), av[2],
			    strlen(av[2])))
				vtc_fatal(vl, "Too many header fields");
			av += 2;
		} else if (!strcmp(*av, "-body") && av[1] != NULL) {
			AZ(body);
			body = strdup(av[1]);
			AN(body);
			bodylen = strlen(body);
			av++;
		} else if (!strcmp(*av, "-bodyfrom") && av[1] != NULL) {
			AZ(body);
			body = VFIL_readfile(NULL, av[1], &len);
			if (body == NULL)
				vtc_fatal(vl, "Cannot read %s", av[1]);
			bodylen = len;
			av++;
		} else if (!strcmp(*av, "-bodylen") && av[1] != NULL) {
			AZ(body);
			body = synth_body(av[1], 0);
			bodylen = strlen(body);
			av++;
		} else if (!strncmp(*av, "-gzip", 5)) {
			i = vtc_gzip_cmd(qc->hp, av, &body, &bodylen);
			if (i == 0)
				break;
			av++;
			if (i > 1 && h3_hdrs_add(req, "content-encoding", 16,
			    "gzip", 4))
				vtc_fatal(vl, "Too many header fields");
		} else if (!strcmp(*av, "-nostrend"))
			nostrend = 1;
		else if (!strcmp(*av, "-early"))
			early = 1;
		else
			break;
	}
	if (*av != NULL)
		vtc_fatal(vl, "Unknown txreq spec: %s", *av);

	if (early) {
		PTOK(pthread_mutex_lock(&qc->mtx));
		i = qc->early_enabled && !qc->early_rejected &&
		    !qc->handshake_done && qc->h3 != NULL;
		PTOK(pthread_mutex_unlock(&qc->mtx));
		if (!i)
			vtc_fatal(vl, "txreq -early: no 0-RTT keys "
			    "(needs -0rtt, a session with early data, and "
			    "an unfinished handshake)");
	} else if (!quic_wait_handshake(qc, VTIM_real() + qc->hp->timeout))
		vtc_fatal(vl, "txreq: QUIC connection closed");

	vtc_log(vl, 4, "txreq: %u fields, body %ld bytes%s", req->n, bodylen,
	    nostrend ? ", open" : "");
	h3_hdrs_log(vl, "header", req);

	PTOK(pthread_mutex_lock(&qc->mtx));
	if (body != NULL && bodylen > 0)
		(void)h3_chunk_add(s, body, bodylen);
	else
		free(body);
	s->txeof = !nostrend;
	s->early = early;
	s->req = req;
	i = h3_submit_pending(qc);
	if (i)
		quic_close_locked(qc, 1, NGHTTP3_H3_INTERNAL_ERROR,
		    "cannot submit request");
	PTOK(pthread_mutex_unlock(&qc->mtx));
	quic_kick(qc);
	if (i)
		vtc_fatal(vl, "txreq: cannot submit the request");
}

static void
cmd_h3_txdata(CMD_ARGS)
{
	struct h3_stream *s;
	struct quic_conn *qc;
	char *data = NULL;
	int nostrend = 0, i = 0;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	qc = s->qc;
	H3_REQ_STREAM(s, av);
	for (av++; *av != NULL; av++) {
		if (!strcmp(*av, "-data") && av[1] != NULL) {
			AZ(data);
			data = strdup(av[1]);
			AN(data);
			av++;
		} else if (!strcmp(*av, "-datalen") && av[1] != NULL) {
			AZ(data);
			data = synth_body(av[1], 0);
			av++;
		} else if (!strcmp(*av, "-nostrend"))
			nostrend = 1;
		else
			break;
	}
	if (*av != NULL)
		vtc_fatal(vl, "Unknown txdata spec: %s", *av);
	if (s->req == NULL)
		vtc_fatal(vl, "txdata: no txreq on this stream yet");

	PTOK(pthread_mutex_lock(&qc->mtx));
	if (s->txeof)
		i = -1;
	else {
		if (data != NULL && *data != '\0') {
			vtc_log(vl, 3, "tx: DATA (%zu bytes)%s", strlen(data),
			    nostrend ? "" : " + FIN");
			if (s->txnext == NULL)
				s->txnext = h3_chunk_add(s, data,
				    strlen(data));
			else
				(void)h3_chunk_add(s, data, strlen(data));
			data = NULL;
		}
		s->txeof = !nostrend;
		if (s->submitted && qc->h3 != NULL)
			i = nghttp3_conn_resume_stream(qc->h3, s->id);
	}
	PTOK(pthread_mutex_unlock(&qc->mtx));
	free(data);
	if (i == -1)
		vtc_fatal(vl, "txdata: the request body has ended");
	if (i != 0)
		vtc_fatal(vl, "txdata: %s", nghttp3_strerror(i));
	quic_kick(qc);
}

static void
h3_shutdown_stream(struct h3_stream *s, char * const *av, struct vtclog *vl,
    int rst)
{
	struct quic_conn *qc;
	uint64_t err = NGHTTP3_H3_REQUEST_CANCELLED;
	int i = 0;

	qc = s->qc;
	H3_REQ_STREAM(s, av);
	if (av[1] != NULL && !strcmp(av[1], "-err") && av[2] != NULL) {
		err = h3_err_parse(av[2], vl);
		av += 2;
	}
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown %s spec: %s", av[0], av[1]);

	PTOK(pthread_mutex_lock(&qc->mtx));
	if (!s->submitted)
		i = NGTCP2_ERR_STREAM_NOT_FOUND;
	else if (rst) {
		if (qc->h3 != NULL)
			nghttp3_conn_shutdown_stream_write(qc->h3, s->id);
		i = ngtcp2_conn_shutdown_stream_write(qc->conn, 0, s->id, err);
	} else
		i = ngtcp2_conn_shutdown_stream_read(qc->conn, 0, s->id, err);
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (i != 0)
		vtc_fatal(vl, "%s: %s", av[0], ngtcp2_strerror(i));
	vtc_log(vl, 3, "tx: %s %s (0x%jx)", rst ? "RESET_STREAM" :
	    "STOP_SENDING", h3_err_name(err), (uintmax_t)err);
	quic_kick(qc);
}

static void
cmd_h3_txrst(CMD_ARGS)
{
	struct h3_stream *s;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	h3_shutdown_stream(s, av, vl, 1);
}

static void
cmd_h3_txstop(CMD_ARGS)
{
	struct h3_stream *s;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	h3_shutdown_stream(s, av, vl, 0);
}

static void
cmd_h3_rxhdrs(CMD_ARGS)
{
	struct h3_stream *s;
	struct h3_event *ev;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	H3_REQ_STREAM(s, av);
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown rxhdrs spec: %s", av[1]);
	ev = h3_ev_expect(s, H3_EV_HEADERS, av[0], 1);
	h3_ev_free(&ev);
}

static void
cmd_h3_rxdata(CMD_ARGS)
{
	struct h3_stream *s;
	struct h3_event *ev;
	const char *why = NULL;
	unsigned long times = 1, rcv = 0;
	int all = 0;
	char *p;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	H3_REQ_STREAM(s, av);
	for (av++; *av != NULL; av++) {
		if (!strcmp(*av, "-all"))
			all = 1;
		else if (!strcmp(*av, "-some") && av[1] != NULL) {
			times = strtoul(av[1], &p, 0);
			if (*p != '\0' || times == 0)
				vtc_fatal(vl, "-some takes a positive number");
			av++;
		} else
			vtc_fatal(vl, "Unknown rxdata spec: %s", *av);
	}
	while (all || rcv < times) {
		ev = h3_ev_next(s, &why);
		if (ev == NULL)
			vtc_fatal(vl, "rxdata: no DATA (#%lu): %s", rcv + 1,
			    why);
		if (all && (ev->type == H3_EV_FIN ||
		    ev->type == H3_EV_TRAILERS)) {
			h3_ev_consume(s, ev);
			if (ev->type == H3_EV_FIN) {
				h3_ev_free(&ev);
				break;
			}
			h3_ev_free(&ev);
			continue;
		}
		if (ev->type != H3_EV_DATA)
			vtc_fatal(vl, "rxdata: event #%lu was %s instead of "
			    "DATA", rcv + 1, h3_ev_names[ev->type]);
		h3_ev_consume(s, ev);
		h3_ev_free(&ev);
		rcv++;
	}
}

static void
cmd_h3_rxresp(CMD_ARGS)
{
	struct h3_stream *s;
	struct h3_event *ev;
	const char *why = NULL;
	unsigned n = 1;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	H3_REQ_STREAM(s, av);
	/* -no_obj, for tests shared with HTTP/1: the FIN ends the response */
	if (av[1] != NULL && !strcmp(av[1], "-no_obj"))
		av++;
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown rxresp spec: %s", av[1]);
	ev = h3_ev_expect(s, H3_EV_HEADERS, av[0], n);
	h3_ev_free(&ev);
	while (1) {
		n++;
		ev = h3_ev_next(s, &why);
		if (ev == NULL)
			vtc_fatal(vl, "rxresp: no end of stream: %s", why);
		h3_ev_consume(s, ev);
		if (ev->type == H3_EV_FIN) {
			h3_ev_free(&ev);
			break;
		}
		if (ev->type == H3_EV_RESET)
			vtc_fatal(vl, "rxresp: RESET_STREAM %s (0x%jx)",
			    h3_err_name(ev->err), (uintmax_t)ev->err);
		if (ev->type == H3_EV_HEADERS)
			vtc_fatal(vl, "rxresp: event #%u was HEADERS instead "
			    "of DATA", n);
		h3_ev_free(&ev);
	}
	vtc_log(vl, 3, "rxresp: status %s, %ld body bytes",
	    h3_hdrs_find(s->resp, ":status"), s->bodylen);
}

static void
cmd_h3_rxrst(CMD_ARGS)
{
	struct h3_stream *s;
	struct h3_event *ev;
	const char *why = NULL;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	H3_REQ_STREAM(s, av);
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown rxrst spec: %s", av[1]);
	while (1) {
		ev = h3_ev_next(s, &why);
		if (ev == NULL)
			vtc_fatal(vl, "rxrst: no RESET_STREAM: %s", why);
		h3_ev_consume(s, ev);
		if (ev->type == H3_EV_RESET) {
			h3_ev_free(&ev);
			return;
		}
		if (ev->type == H3_EV_FIN)
			vtc_fatal(vl, "rxrst: stream ended without "
			    "RESET_STREAM");
		h3_ev_free(&ev);
	}
}

static void
cmd_h3_rxstop(CMD_ARGS)
{
	struct h3_stream *s;
	struct quic_conn *qc;
	double deadline;
	int i = 0;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	qc = s->qc;
	H3_REQ_STREAM(s, av);
	if (av[1] != NULL)
		vtc_fatal(vl, "Unknown rxstop spec: %s", av[1]);
	deadline = VTIM_real() + qc->hp->timeout;
	PTOK(pthread_mutex_lock(&qc->mtx));
	while (!s->stop_seen && !s->closed && !qc->stop &&
	    qc->close_type == QUIC_OPEN && i != ETIMEDOUT)
		i = quic_cond_wait(&s->cond, qc, deadline);
	i = s->stop_seen;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	if (!i)
		vtc_fatal(vl, "rxstop: no STOP_SENDING");
}

static void
cmd_h3_gunzip(CMD_ARGS)
{
	struct h3_stream *s;
	struct vsb *vin, *vout;

	(void)av;
	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	if (s->body == NULL || s->bodylen < 2 ||
	    s->body[0] != (char)0x1f || s->body[1] != (char)0x8b) {
		vtc_log(vl, s->qc->hp->fatal,
		    "Gunzip error: body lacks gzip magic");
		return;
	}
	vin = VSB_new_auto();
	AN(vin);
	AZ(VSB_bcat(vin, s->body, s->bodylen));
	AZ(VSB_finish(vin));
	vout = vtc_gunzip_vsb(vl, s->qc->hp->fatal, vin);
	VSB_destroy(&vin);
	free(s->body);
	s->bodylen = VSB_len(vout);
	s->body = malloc(s->bodylen + 1L);
	AN(s->body);
	memcpy(s->body, VSB_data(vout), s->bodylen + 1L);
	VSB_destroy(&vout);
	vtc_log(vl, 3, "new bodylen %ld", s->bodylen);
	vtc_dump(vl, 4, "body", s->body, s->bodylen);
}

static void
cmd_h3_write_body(CMD_ARGS)
{
	struct h3_stream *s;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	AN(av[1]);
	AZ(av[2]);
	if (VFIL_writefile(NULL, av[1], s->body, s->bodylen) != 0)
		vtc_fatal(vl, "failed to write body: %s (%d)",
		    strerror(errno), errno);
}

/* Stream variables are only changed by the stream thread, except stop.* */
static const char *
h3_var_resolve(struct h3_stream *s, const char *spec, char *buf, size_t len)
{
	struct quic_conn *qc;
	const struct h3_hdrs *h;
	unsigned u;
	int i;

	qc = s->qc;
	if (!strncmp(spec, "quic.", 5) || !strncmp(spec, "tls.", 4) ||
	    !strncmp(spec, "goaway.", 7))
		return (quic_var_resolve(qc->hp, spec, buf, len));
	if (!strcmp(spec, "stream.id")) {
		PTOK(pthread_mutex_lock(&qc->mtx));
		i = s->submitted;
		(void)snprintf(buf, len, "%jd", (intmax_t)s->id);
		PTOK(pthread_mutex_unlock(&qc->mtx));
		return (i ? buf : NULL);
	}
	if (!strcmp(spec, "rst.err")) {
		if (!s->rst_seen)
			return (NULL);
		(void)snprintf(buf, len, "%ju", (uintmax_t)s->rst_err);
		return (buf);
	}
	if (!strcmp(spec, "stop.err")) {
		PTOK(pthread_mutex_lock(&qc->mtx));
		i = s->stop_seen;
		(void)snprintf(buf, len, "%ju", (uintmax_t)s->stop_err);
		PTOK(pthread_mutex_unlock(&qc->mtx));
		return (i ? buf : NULL);
	}
	if (!strncmp(spec, "resp.", 5)) {
		spec += 5;
		if (!strcmp(spec, "body"))
			return (s->body);
		if (!strcmp(spec, "bodylen")) {
			(void)snprintf(buf, len, "%ld", s->bodylen);
			return (buf);
		}
		if (!strcmp(spec, "status"))
			return (h3_hdrs_find(s->resp, ":status"));
		if (!strncmp(spec, "http.", 5))
			return (h3_hdrs_find(s->resp, spec + 5));
		if (!strncmp(spec, "trailer.", 8))
			return (h3_hdrs_find(s->trailers, spec + 8));
		return (NULL);
	}
	if (!strncmp(spec, "req.", 4)) {
		h = s->req;
		spec += 4;
		if (!strcmp(spec, "method"))
			return (h3_hdrs_find(h, ":method"));
		if (!strcmp(spec, "url"))
			return (h3_hdrs_find(h, ":path"));
		if (!strcmp(spec, "scheme"))
			return (h3_hdrs_find(h, ":scheme"));
		if (!strcmp(spec, "authority"))
			return (h3_hdrs_find(h, ":authority"));
		if (!strncmp(spec, "http.", 5))
			return (h3_hdrs_find(h, spec + 5));
		return (NULL);
	}
	for (u = 0; h3_errs[u].name != NULL; u++) {
		if (!strcmp(spec, h3_errs[u].name)) {
			(void)snprintf(buf, len, "%ju",
			    (uintmax_t)h3_errs[u].code);
			return (buf);
		}
	}
	return (spec);
}

static void
cmd_h3_expect(CMD_ARGS)
{
	struct h3_stream *s;
	char lbuf[256], rbuf[256];
	const char *lhs, *rhs;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	AN(av[1]);
	AN(av[2]);
	AN(av[3]);
	AZ(av[4]);
	lhs = h3_var_resolve(s, av[1], lbuf, sizeof lbuf);
	rhs = h3_var_resolve(s, av[3], rbuf, sizeof rbuf);
	vtc_expect(vl, av[1], lhs, av[2], av[3], rhs);
}

static void
cmd_h3_conn(CMD_ARGS)
{
	struct h3_stream *s;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	if (strcmp(s->name, "0"))
		vtc_fatal(vl, "\"%s\" is a connection command, use stream 0",
		    av[0]);
	if (!strcmp(av[0], "expect_close")) {
		AZ(av[1]);
		quic_expect_close(s->qc->hp, vl);
	} else
		quic_conn_cmd(s->qc->hp, av, vl);
}

static void
cmd_h3_na(CMD_ARGS)
{

	(void)priv;
	vtc_fatal(vl, "\"%s\" is not available over HTTP/3", av[0]);
}

static const struct cmds h3_stream_cmds[] = {
#define CMD_H3(n) { CMDS_MAGIC, #n, cmd_h3_##n },
#define CMD_CONN(n) { CMDS_MAGIC, #n, cmd_h3_conn },
#define CMD_NA(n) { CMDS_MAGIC, #n, cmd_h3_na },
	CMD_H3(expect)
	CMD_H3(gunzip)
	CMD_H3(write_body)
	CMD_H3(txreq)
	CMD_H3(txdata)
	CMD_H3(rxhdrs)
	CMD_H3(rxdata)
	CMD_H3(rxresp)
	CMD_H3(txrst)
	CMD_H3(txstop)
	CMD_H3(rxrst)
	CMD_H3(rxstop)

	CMD_CONN(expect_close)
	CMD_CONN(quic_close)
	CMD_CONN(quic_rebind)
	CMD_CONN(quic_wait_handshake_confirmed)
	CMD_CONN(rxgoaway)
	CMD_CONN(txgoaway)

	CMD_NA(txsettings)
	CMD_NA(rxsettings)
	CMD_NA(txping)
	CMD_NA(rxping)
	CMD_NA(txwinup)
	CMD_NA(rxwinup)
	CMD_NA(txprio)
	CMD_NA(rxprio)
	CMD_NA(txpush)
	CMD_NA(rxpush)
	CMD_NA(txcont)
	CMD_NA(rxcont)
	CMD_NA(sendhex)
	CMD_NA(rxframe)
	CMD_NA(txresp)
	CMD_NA(rxreq)
#undef CMD_NA
#undef CMD_CONN
#undef CMD_H3
	{ CMDS_MAGIC, NULL, NULL }
};

/**********************************************************************
 * Stream threads
 */

static void *
h3_stream_thread(void *priv)
{
	struct h3_stream *s;

	CAST_OBJ_NOTNULL(s, priv, H3_STREAM_MAGIC);
	parse_string(s->vl, s, s->spec);
	vtc_log(s->vl, 2, "Ending stream %s", s->name);
	return (NULL);
}

static struct h3_stream *
h3_stream_new(const char *name, struct quic_conn *qc)
{
	struct h3_stream *s;
	char buf[32];

	if (!strcmp(name, "next")) {
		bprintf(buf, "next%u", qc->nstreams + 1);
		name = buf;
	}
	ALLOC_OBJ(s, H3_STREAM_MAGIC);
	AN(s);
	REPLACE(s->name, name);
	s->qc = qc;
	s->id = -1;
	PTOK(pthread_cond_init(&s->cond, NULL));
	VTAILQ_INIT(&s->evq);
	VTAILQ_INIT(&s->txq);
	s->vl = vtc_logopen("%s.%s", qc->hp->sess->name, name);
	AN(s->vl);
	vtc_log_set_cmd(s->vl, h3_stream_cmds);
	PTOK(pthread_mutex_lock(&qc->mtx));
	VTAILQ_INSERT_TAIL(&qc->streams, s, list);
	qc->nstreams++;
	PTOK(pthread_mutex_unlock(&qc->mtx));
	return (s);
}

static void
h3_stream_delete(struct h3_stream *s)
{
	struct h3_event *ev, *ev2;
	struct h3_chunk *c, *c2;

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	AZ(s->running);
	VTAILQ_FOREACH_SAFE(ev, &s->evq, list, ev2) {
		VTAILQ_REMOVE(&s->evq, ev, list);
		h3_ev_free(&ev);
	}
	VTAILQ_FOREACH_SAFE(c, &s->txq, list, c2) {
		VTAILQ_REMOVE(&s->txq, c, list);
		free(c->data);
		FREE_OBJ(c);
	}
	h3_hdrs_free(&s->resp);
	h3_hdrs_free(&s->trailers);
	h3_hdrs_free(&s->rxhdrs);
	h3_hdrs_free(&s->req);
	PTOK(pthread_cond_destroy(&s->cond));
	vtc_logclose(s->vl);
	free(s->body);
	free(s->spec);
	free(s->name);
	FREE_OBJ(s);
}

static void
h3_stream_start(struct h3_stream *s)
{

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	vtc_log(s->qc->vl, 2, "Starting stream %s", s->name);
	PTOK(pthread_create(&s->tp, NULL, h3_stream_thread, s));
	s->running = 1;
}

static void
h3_stream_wait(struct h3_stream *s)
{
	void *res;

	CHECK_OBJ_NOTNULL(s, H3_STREAM_MAGIC);
	vtc_log(s->qc->vl, 2, "Waiting for stream %s", s->name);
	PTOK(pthread_join(s->tp, &res));
	s->running = 0;
	if (res != NULL)
		vtc_fatal(s->qc->vl, "Stream %s returned \"%s\"", s->name,
		    (char *)res);
}

void
h3_cmd_stream(CMD_ARGS)
{
	struct h3_stream *s;
	struct quic_conn *qc;
	struct http *hp;

	CAST_OBJ_NOTNULL(hp, priv, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	AZ(strcmp(av[0], "stream"));
	av++;
	AN(*av);

	/* The client thread owns the stream list */
	VTAILQ_FOREACH(s, &qc->streams, list)
		if (!strcmp(s->name, av[0]))
			break;
	if (s == NULL)
		s = h3_stream_new(av[0], qc);
	av++;

	for (; *av != NULL; av++) {
		if (vtc_error)
			break;
		if (!strcmp(*av, "-wait")) {
			if (!s->running)
				vtc_fatal(vl, "stream %s is not running",
				    s->name);
			h3_stream_wait(s);
			continue;
		}
		if (s->running)
			h3_stream_wait(s);
		if (!strcmp(*av, "-start") || !strcmp(*av, "-run")) {
			if (s->spec == NULL)
				vtc_fatal(vl, "stream %s has no spec",
				    s->name);
			quic_start(hp);
			h3_stream_start(s);
			if (!strcmp(*av, "-run"))
				h3_stream_wait(s);
			continue;
		}
		if (**av == '-')
			vtc_fatal(vl, "Unknown stream argument: %s", *av);
		REPLACE(s->spec, *av);
	}
}

/* Wait for the stream threads */
void
h3_stop(struct http *hp)
{
	struct quic_conn *qc;
	struct h3_stream *s;

	CHECK_OBJ_NOTNULL(hp, HTTP_MAGIC);
	CAST_OBJ_NOTNULL(qc, hp->quic, QUIC_CONN_MAGIC);
	VTAILQ_FOREACH(s, &qc->streams, list) {
		if (s->running) {
			PTOK(pthread_join(s->tp, NULL));
			s->running = 0;
		}
	}
}

/* Free the streams, once the libraries are gone */
void
h3_free(struct quic_conn *qc)
{
	struct h3_stream *s, *s2;

	CHECK_OBJ_NOTNULL(qc, QUIC_CONN_MAGIC);
	AZ(qc->h3);
	VTAILQ_FOREACH_SAFE(s, &qc->streams, list, s2) {
		VTAILQ_REMOVE(&qc->streams, s, list);
		h3_stream_delete(s);
	}
}

#endif /* VTEST_WITH_QUIC */
