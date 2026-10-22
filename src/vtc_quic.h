/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * HTTP/3 (QUIC) client internals, shared by vtc_quic.c and vtc_http3.c.
 *
 * Locking: qc->mtx serialises every ngtcp2 and nghttp3 call and protects
 * all state below, the streams' included. Library callbacks run with it
 * held, in whichever thread made the library call; they only record
 * state and signal condition variables, they never wait. Never call
 * vtc_fatal() with qc->mtx held: it exits the thread.
 */

#ifdef VTEST_WITH_QUIC

#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>
#include <nghttp3/nghttp3.h>

#include "vqueue.h"

/* Client options, set on the client line */
struct quic_drop {
	unsigned		magic;
#define QUIC_DROP_MAGIC		0x1d2e8b51
	VTAILQ_ENTRY(quic_drop)	list;
	unsigned		out;
	unsigned		every;
	unsigned long		n;
};

struct quic_cfg {
	unsigned		magic;
#define QUIC_CFG_MAGIC		0x5e1b3f0d
	unsigned		debug;
	unsigned		zero_rtt;
	char			*token_in;
	char			*token_out;
	ngtcp2_transport_params	params;
	double			handshake_timeout;
	size_t			max_udp_payload_size;
	VTAILQ_HEAD(, quic_drop) drops;
};

enum quic_close_type {
	QUIC_OPEN = 0,
#define QUIC_CLOSE_TYPE(U, l)	QUIC_CLOSE_##U,
#include "tbl/quic_close.h"
};

struct h3_hdrs {
	unsigned		n;
	char			*name[MAX_HDR];
	char			*value[MAX_HDR];
};

enum h3_ev_type {
	H3_EV_HEADERS,
	H3_EV_TRAILERS,
	H3_EV_DATA,
	H3_EV_FIN,
	H3_EV_RESET,
	H3_EV_STOP,
};

struct h3_event {
	unsigned		magic;
#define H3_EVENT_MAGIC		0x2a6c95e1
	enum h3_ev_type		type;
	VTAILQ_ENTRY(h3_event)	list;
	struct h3_hdrs		*hdrs;
	char			*data;
	size_t			len;
	uint64_t		err;
};

/* Request body, kept until the stream is deleted: nghttp3 references it */
struct h3_chunk {
	unsigned		magic;
#define H3_CHUNK_MAGIC		0x6f1e2c43
	VTAILQ_ENTRY(h3_chunk)	list;
	char			*data;
	size_t			len;
};

struct h3_stream {
	unsigned		magic;
#define H3_STREAM_MAGIC		0x3d81f6a7
	char			*name;
	char			*spec;
	struct vtclog		*vl;
	struct quic_conn	*qc;
	VTAILQ_ENTRY(h3_stream)	list;
	pthread_t		tp;
	unsigned		running;
	pthread_cond_t		cond;

	/* QUIC stream id, -1 until the request is submitted */
	int64_t			id;
	unsigned		submitted;
	unsigned		early;
	unsigned		closed;

	VTAILQ_HEAD(, h3_event)	evq;

	/* rx, published when an rx command consumes the event */
	struct h3_hdrs		*resp;
	struct h3_hdrs		*trailers;
	char			*body;
	long			bodylen;
	unsigned		rst_seen;
	uint64_t		rst_err;
	unsigned		stop_seen;
	uint64_t		stop_err;

	/* rx, header block being received */
	struct h3_hdrs		*rxhdrs;

	/* tx */
	struct h3_hdrs		*req;
	VTAILQ_HEAD(, h3_chunk)	txq;
	struct h3_chunk		*txnext;
	unsigned		txeof;
	unsigned		txfin;
};

struct quic_conn {
	unsigned		magic;
#define QUIC_CONN_MAGIC		0x7c0e4a19
	struct http		*hp;
	struct vtclog		*vl;
	const struct quic_cfg	*cfg;

	pthread_mutex_t		mtx;
	pthread_cond_t		cond;
	pthread_t		tp;
	unsigned		started;
	unsigned		stop;
	int			efd;

	ngtcp2_crypto_conn_ref	conn_ref;
	ngtcp2_conn		*conn;
	ngtcp2_crypto_ossl_ctx	*ossl_ctx;
	SSL			*ssl;
	nghttp3_conn		*h3;
	ngtcp2_ccerr		last_error;

	struct sockaddr_storage	local;
	socklen_t		locallen;
	struct sockaddr_storage	remote;
	socklen_t		remotelen;
	char			authority[128];
	unsigned		rebind;

	/* state, for expectations */
	unsigned		handshake_done;
	unsigned		handshake_confirmed;
	unsigned		early_enabled;
	unsigned		early_rejected;
	unsigned		resumed;
	unsigned		retry;
	unsigned		new_token;
	unsigned		stateless_reset;
	enum quic_close_type	close_type;
	uint64_t		close_err;
	unsigned		close_app;
	char			close_reason[256];
	unsigned		goaway;
	unsigned		goaway_rx;
	int64_t			goaway_id;
	unsigned long		pkts_in;
	unsigned long		pkts_out;
	unsigned long		drops_in;
	unsigned long		drops_out;

	VTAILQ_HEAD(, h3_stream) streams;
	unsigned		nstreams;
};

/* vtc_quic.c */
int quic_cond_wait(pthread_cond_t *, struct quic_conn *, double deadline);
void quic_kick(const struct quic_conn *);
void quic_start(struct http *);
int quic_wait_handshake(struct quic_conn *, double deadline);
void quic_close_locked(struct quic_conn *, int app, uint64_t err,
    const char *reason);
void quic_fail_locked(struct quic_conn *, int liberr);
void quic_h3_error_locked(struct quic_conn *, int liberr);

/* vtc_http3.c */
int h3_setup(struct quic_conn *);
void h3_early_rejected(struct quic_conn *);
void h3_conn_closed(struct quic_conn *);
void h3_stop(struct http *);
void h3_free(struct quic_conn *);
uint64_t h3_err_parse(const char *, struct vtclog *);

/* ngtcp2 stream level callbacks, in vtc_http3.c */
int h3_recv_stream_data_cb(ngtcp2_conn *, uint32_t flags, int64_t sid,
    uint64_t offset, const uint8_t *data, size_t len, void *user_data,
    void *stream_user_data);
int h3_acked_stream_data_offset_cb(ngtcp2_conn *, int64_t sid,
    uint64_t offset, uint64_t len, void *user_data, void *stream_user_data);
int h3_stream_close_cb(ngtcp2_conn *, uint32_t flags, int64_t sid,
    uint64_t rx_err, uint64_t tx_err, void *user_data,
    void *stream_user_data);
int h3_stream_reset_cb(ngtcp2_conn *, int64_t sid, uint64_t final_size,
    uint64_t err, void *user_data, void *stream_user_data);
int h3_recv_stop_sending_cb(ngtcp2_conn *, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data);
int h3_stream_stop_sending_cb(ngtcp2_conn *, int64_t sid, uint64_t err,
    void *user_data, void *stream_user_data);
int h3_extend_max_stream_data_cb(ngtcp2_conn *, int64_t sid,
    uint64_t max_data, void *user_data, void *stream_user_data);
int h3_extend_max_local_streams_bidi_cb(ngtcp2_conn *, uint64_t max_streams,
    void *user_data);

#endif /* VTEST_WITH_QUIC */
