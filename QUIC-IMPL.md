# QUIC and HTTP/3 Implementation in VTest2

## Overview

VTest2 has an HTTP/3 client. A test starts it with `client cNAME -quic`. The client speaks QUIC v1
through ngtcp2 and HTTP/3 through nghttp3. TLS comes from OpenSSL 3.5 or later, through
ngtcp2's `ngtcp2_crypto_ossl` backend. There is no HTTP/3 server.

The test language reuses the HTTP/2 `stream` model. A test that uses only request-level
commands can run over HTTP/2 and HTTP/3. QUIC-specific commands and variables let a test
examine 0-RTT, resumption, Retry, NEW_TOKEN, stream resets, flow control, connection close,
idle timeout, migration and packet loss.

The code is new and has little use yet. When a QUIC test fails, check the client as well as the
server. The section "Problem areas" lists the known weak points.

The command reference is in the `SECTION:` comments of `src/vtc_quic.c`, `src/vtc_http3.c` and
`src/vtc_http.c`.

Out of scope:

- An HTTP/3 server. The client tests HTTP/3 servers and proxies.
- Frame-level fuzzing of HTTP/3 and QPACK. nghttp3 is the codec, and it does not send
  malformed frames.
- QUIC versions other than v1.

## Design decisions

| Question | Decision | Reason |
|---|---|---|
| In the VTest2 source, or an extension (`libvtest_ext_*`)? | In the source (`src/vtc_quic.c`, `src/vtc_http3.c`), compiled only with `VTEST_WITH_QUIC` | The client needs `struct http`, `http_cmds`, `expect`, `tls_config` and the internals of `vtc_tls.c`. The extension API gives access to none of them. The compile flag isolates the code just as well. |
| Which ngtcp2 crypto backend? | `ngtcp2_crypto_ossl` | VTest2 already uses OpenSSL, and OpenSSL 3.5 has a QUIC TLS API. `tls_config` (certificates, ALPN, SNI, peer verification, session files) thus applies to QUIC without change. A GnuTLS backend would add a second TLS stack and a second configuration language. |
| Which test language? | The HTTP/2 `stream NAME { ... }` language, with an HTTP/3 command table | Request-level tests run on both protocols, and test authors learn nothing new. The HTTP/2 frame commands are fatal over HTTP/3, with a clear message. |
| How to share the libraries between threads? | One engine thread per connection owns the socket and the timer. One mutex serialises all library calls. | ngtcp2 and nghttp3 are not thread-safe. Unlike the HTTP/2 receive thread, the engine also sends. A message queue from the stream threads to the engine gives the same safety, but needs more code. |
| How does a test select QUIC? | `client cNAME -quic`. The QUIC handshake happens on `tls_handshake`. | The choice is explicit per client. `tls_config` comes before the handshake, as in TLS tests. |

### Tests for more than one protocol

A test suite can run one test over TCP, TLS and QUIC. The suite defines macros that carry the
differences:

- A macro on the client line holds `-quic` for QUIC and is empty for the other transports, for
  example `client c1 ${h_client} {`. The client skips empty arguments for this purpose.
- A macro at the start of the client specification holds the handshake. It is empty for TCP. It
  holds `tls_config` with the protocol's ALPN and `tls_handshake` for TLS and QUIC. A macro can
  hold more than one line.
- HTTP/3 has its own ALPN token, `h3`. Give it its own handshake macro. Do not reuse the HTTP/2
  macro for HTTP/3, because a test written for HTTP/2 must not become an HTTP/3 test by
  accident. A separate protocol-neutral macro (HTTP/2 on TLS, HTTP/3 on QUIC) is for tests that
  are valid for both protocols.

A test is portable when it uses only `txreq`, `txdata`, `rxhdrs`, `rxdata`, `rxresp` and
`expect resp.*` in its streams. Tests that use SETTINGS, WINDOW_UPDATE, PING or `rst.err`
values stay specific to one protocol. The error codes of HTTP/2 and HTTP/3 are different.

## Building

QUIC support is optional. `WITH_QUIC=1` adds `-DVTEST_WITH_QUIC` and links ngtcp2, its OpenSSL
crypto library and nghttp3:

```bash
make clean
make varnishtest WITH_QUIC=1 NGTCP2=/prefix/of/ngtcp2 NGHTTP3=/prefix/of/nghttp3
```

- `NGTCP2` and `NGHTTP3` are install prefixes with `include/` and `lib/`. The Makefile sets an
  rpath to both `lib/` directories.
- The code uses the API of ngtcp2 1.25.0 and nghttp3 1.18.0. It uses callbacks and
  functions that older versions do not have, for example `stream_close2` and
  `recv_stop_sending`.
- The Makefile does not track the defines. Run `make clean` when you change `WITH_QUIC`.
- Without `WITH_QUIC`, the QUIC files compile to nothing. `-quic` is then a fatal error, and
  `feature quic` skips the test.

## Files

| File | Content |
|---|---|
| `src/vtc_quic.h` | Internal structures and functions shared by the two QUIC files |
| `src/vtc_quic.c` | QUIC transport: client options, UDP socket, engine thread, ngtcp2 setup and callbacks, close handling, connection commands, `quic.*` variables |
| `src/vtc_http3.c` | HTTP/3 binding: nghttp3 setup and callbacks, stream-level ngtcp2 callbacks, stream threads, stream commands |
| `src/tbl/quic_close.h` | Values of `quic.close.type` |
| `src/tbl/h3_error.h` | HTTP/3 and QPACK error names and codes |
| `tests/quic/a30000.vtc` | Self-test without a server (handshake timeout, packet drops) |
| `tests/a00031.vtc` | Empty arguments on the client line |

The QUIC changes in existing files:

- `src/vtc_client.c`: the `-quic` options, the UDP connect, and the empty-argument fix.
- `src/vtc_http.c` and `src/vtc_http.h`: `hp->quic`, the client-level command table in QUIC
  mode, `http_set_cmds()`, and the routing of `quic.*`, `tls.*` and `goaway.*` in `expect`.
- `src/vtc_tls.c`: the hooks that `vtc_quic.c` uses (see "TLS integration").
- `src/vtc_http2.c`: the `http_default_authority` macro, the new name of
  `h2_default_authority`.
- `src/vtc_misc.c`: `feature quic`.
- `src/vtc_gzip.c` and `src/vtc.h`: `vtc_gunzip_vsb()` is no longer static.

## Architecture

### Data structures

- `struct quic_cfg` holds the client options from the client line. The client owns it. The
  sessions read it through `struct vtc_sess`.
- `struct quic_conn` is one QUIC connection. `hp->quic` points to it for the whole session of
  a `-quic` client. It holds the ngtcp2 and nghttp3 connections, the `SSL`, the addresses, the
  engine thread, and the state that the `quic.*` variables show.
- `struct h3_stream` is one `stream NAME` of the test. It holds the request, a queue of
  received events, the published response, and the request body.
- `struct h3_event` is one thing that happened on a request stream: `HEADERS`, `TRAILERS`,
  `DATA`, `FIN` or `RESET`.
- `struct h3_chunk` is one piece of request body.

### Threads and locking

Three kinds of threads touch a QUIC connection:

1. The client thread runs the client specification and starts the stream threads.
2. One stream thread per running `stream` runs that stream's specification.
3. One engine thread per connection owns the UDP socket, the eventfd and the timer.

The engine thread loops. It writes what ngtcp2 and nghttp3 have to send, computes the timeout
from `ngtcp2_conn_get_expiry2()`, and polls the socket and the eventfd. Then it reads all
datagrams and handles expiry.

One mutex, `qc->mtx`, serialises every ngtcp2 and nghttp3 call. These rules apply:

- Every ngtcp2 and nghttp3 call happens with `qc->mtx` held.
- `qc->mtx` also protects all state in `struct quic_conn` and in the streams. One exception: a
  stream thread reads its own published response without the lock.
- Library callbacks run with `qc->mtx` held, in the thread that made the library call. A
  callback only records state, adds events, and signals condition variables. A callback never
  waits.
- A stream thread that changes library state releases the lock and then calls `quic_kick()`.
  The kick writes to the eventfd, so the engine writes the new data and computes a new timeout.
- Never call `vtc_fatal()` with `qc->mtx` held. `vtc_fatal()` ends the thread, and the mutex
  stays locked. The cleanup handler of the client thread then locks the same mutex, and the
  test hangs until the global timeout.
- The engine never calls `vtc_fatal()`. It logs the error and closes the connection.

Waits use `pthread_cond_timedwait()` with a deadline of `hp->timeout`. `qc->cond` signals
connection events: handshake, close, GOAWAY, rebind. Each stream has its own condition
variable for its events.

### Connection life cycle

1. `client_connect()` opens a connected UDP socket with `quic_udp_connect()`. It sends nothing.
2. `http_process()` calls `quic_http_init()`. This creates `struct quic_conn` and selects the
   QUIC client command table.
3. `quic_start()` creates the `SSL`, the ngtcp2 connection and the engine thread. The first
   `tls_handshake` or the first `stream ... -start|-run` calls it. Only the client thread calls
   `quic_start()`, because it can parse an empty `tls_config` on the client's log.
4. `tls_handshake` waits for `handshake_completed` or a close. A failed handshake is not
   fatal, as for TLS. The test checks `quic.handshake_done` or `tls.failed`.
5. When the handshake gets 1-RTT keys, `recv_rx_key` calls `h3_setup()`. This creates the
   nghttp3 connection and opens the control stream and the two QPACK streams.
6. At the end of the specification, `quic_http_fini()` runs:
   1. If the test failed, it sets `qc->stop` and wakes all stream threads, so they stop.
   2. It joins the stream threads.
   3. It sends CONNECTION_CLOSE with `H3_NO_ERROR`, if the connection is still open.
   4. It stops and joins the engine thread.
   5. It deletes the nghttp3 connection, then the ngtcp2 connection, then the crypto context
      and the `SSL`.
   6. It frees the streams. Only now, because nghttp3 refers to their request body.

### Request life cycle

1. `txreq` builds the header list. The pseudo-headers come first: `:method`, `:scheme`,
   `:authority`, `:path`. Then it adds the body to the stream's chunk list.
2. Without `-early`, `txreq` waits for the handshake. With `-early`, it needs 0-RTT keys.
3. `h3_submit_pending()` opens a bidirectional QUIC stream and calls
   `nghttp3_conn_submit_request()`. If the server allows no more streams, the request waits.
   The `extend_max_local_streams_bidi` callback submits it later.
4. nghttp3 pulls the body through `h3_read_data_cb()`. `txdata` adds chunks and calls
   `nghttp3_conn_resume_stream()`.
5. The callbacks add events to the stream's queue. The rx commands consume them in order.

## Important implementation details

### Events and publication

The rx commands consume events in arrival order, as the HTTP/2 code consumes frames. A
consumed event becomes visible to `expect`: a `HEADERS` event replaces `resp`, a `DATA` event
extends `resp.body`. An event that is still in the queue is not visible. Thus
`expect resp.status` after `rxhdrs` shows the first header block, also when a second block
arrived meanwhile.

`STOP_SENDING` from the server is not an event. It sets `stop_seen` at once, because it can
arrive at any time. `rxstop` waits for this flag.

`rxrst` consumes and publishes `HEADERS` and `DATA` events until it finds `RESET`. A server can
send part of a response before it resets the stream.

### Flow control

The client gives stream and connection credit back when the data arrives, not when the test
consumes it. A small `initial_max_stream_data_bidi_local` thus makes the server stall and
resume many times. The client never blocks the server for longer than the network round trip.

### Request body memory

nghttp3 keeps pointers into the request body until the server acknowledges the data. The
client never moves or frees a chunk while the stream exists. `txdata` adds a new chunk. It
never uses `realloc()` on old data.

### Stream names and IDs

In HTTP/2 the stream name is the stream ID. In HTTP/3 the name is only a label. The first
`txreq` gets the QUIC stream ID (0, 4, 8, ...) and `stream.id` shows it. `stream 0` is the
connection. It accepts only the connection commands and `expect`. `stream next` makes a new
label `nextN`. A stream sends one request. A second `txreq` on the same stream is fatal.

### 0-RTT

1. `sess_out` writes the session file when a session ticket arrives. For a QUIC connection it
   adds a second PEM block, `QUIC TRANSPORT PARAMETERS`. It holds the 0-RTT transport
   parameters that `handshake_completed` stores with `vtc_tls_quic_set_tp()`.
2. A client with `-0rtt` and `sess_in` reads both blocks. It calls
   `ngtcp2_conn_decode_and_set_0rtt_transport_params()` and
   `SSL_set_quic_tls_early_data_enabled()`. Then it creates the nghttp3 connection at once.
3. OpenSSL reports a rejection only after the handshake. `quic_handshake_completed_cb()` then
   calls `ngtcp2_conn_tls_early_data_rejected()`. ngtcp2 discards the 0-RTT streams.
4. `h3_early_rejected()` deletes the nghttp3 connection and resets the streams. `h3_setup()`
   creates a new nghttp3 connection and submits the requests again in 1-RTT.

`quic.early_data` is `not_sent`, `pending`, `accepted` or `rejected`.

### Connection close

`quic_fail_locked()` maps library errors to `quic.close.type`:

| Event | `quic.close.type` |
|---|---|
| CONNECTION_CLOSE from the server (`NGTCP2_ERR_DRAINING`) | `transport` or `application` |
| Stateless reset (callback, then `NGTCP2_ERR_DRAINING`) | `stateless_reset` |
| Version Negotiation packet | `version_negotiation` |
| `NGTCP2_ERR_IDLE_CLOSE` | `idle` |
| `NGTCP2_ERR_HANDSHAKE_TIMEOUT` | `handshake_timeout` |
| Any other error, or `quic_close` | `local` |

For a `local` close, the client sends CONNECTION_CLOSE with `qc->last_error`. An nghttp3 error
first sets `qc->last_error` to the matching HTTP/3 error code. After any close, the engine
stops reading the socket, and all waiting threads wake up.

ngtcp2's handshake timeout defaults to the client timeout. `quic_wait_handshake()` waits one
second longer. Thus ngtcp2 closes the connection first, and the test sees
`handshake_timeout`. Without the extra second, the test failed with a fatal timeout.

### TLS integration

QUIC uses `tls_config` and the `tls.*` variables, but the `SSL` is not bound to the socket.
`hp->so` stays the plain file-descriptor operations.

- `vtc_tls_quic_new()` creates the `struct tlsconn` and the `SSL`. If `tls_config` sets no
  ALPN, it sets `h3`.
- `vtc_tls.c` keeps its `struct tlsconn` in a private SSL ex_data index. Index 0
  (`SSL_get_app_data()`) belongs to ngtcp2's `ngtcp2_crypto_conn_ref`. Before this change,
  both used index 0.
- `vtc_tls_quic_failed()` sets `tls.failed` when the handshake fails.
- If `SSLKEYLOGFILE` is set, TLS and QUIC connections write their secrets to that file.
- `quic_var_resolve()` reads `tls.*` under `qc->mtx`, because the engine uses the same `SSL`.
  It checks the name before it locks. `vtc_tls_var_resolve()` calls `vtc_fatal()` for an
  unknown name.

### Client commands in QUIC mode

In QUIC mode the client uses `http_quic_cmds`, not `http_cmds`. HTTP/1 commands such as
`txreq` and `rxresp` are fatal at the client level. They would read the UDP socket as a byte
stream. `tls_config` parses its block with its own table. `http_set_cmds()` then sets the
QUIC table again.

### Pseudo-headers and authority

`txreq` sets `:authority` from the `http_default_authority` macro. Without the macro it uses
the connected address, for example `127.0.0.1:43210`. A `-hdr` named `:authority` or `host`
replaces the default. The HTTP/2 code uses the same macro, but it adds no `:authority` when
the macro is not defined.

### Packet size and Retry

The OpenSSL 3.5 ClientHello includes an X25519MLKEM768 key share. It needs two Initial
packets. This has two effects:

- `-quic_drop out:2` drops the second half of the ClientHello.
- A server that sends Retry sends one Retry for each Initial. ngtcp2 uses the first and
  ignores the second.

### Logging

- Level 3: handshake, close, stream events (`rx: HEADERS`, `tx: RESET_STREAM`, ...).
- Level 4: each datagram with size, packet type and DCID, and each header field.
- `-quic_debug` adds ngtcp2's own log at level 4.

## Testing

### VTest2 self-tests

```bash
make test-varnishtest WITH_QUIC=1   # runs tests/*.vtc, tests/tls/*.vtc and tests/quic/*.vtc
```

VTest2 has no HTTP/3 server. `tests/quic/a30000.vtc` therefore tests only what works without
one: the handshake timeout, `quic.*` variables before a handshake, and packet drops.

### Tests against a server

Real HTTP/3 traffic needs an HTTP/3 server from outside VTest2. These tests cover the most
important paths:

1. The handshake, ALPN `h3`, and one request with a response body.
2. A large response through a small stream window (`-quic_param
   initial_max_stream_data_bidi_local=4096`).
3. A request body that is larger than the server's buffer, and a body sent in parts with
   `txdata`.
4. Concurrent streams with interleaved response bodies.
5. `txrst` during a response, and `txstop` before it. The connection must survive both.
6. Session resumption, then 0-RTT that the server accepts, and 0-RTT that it rejects.
7. NEW_TOKEN reuse with `-token_out` and `-token_in`, and the Retry path.
8. The idle timeout, a connection lifetime on the server, and a close by the client.
9. NAT rebinding and active migration with `quic_rebind`.
10. Packet loss with `-quic_drop`, and several connections at the same time.

### Debugging a failed test

1. Run with `-v` and read the client lines (`c1`, `c1.1`) next to the server log.
2. Check `quic.close.type`, `quic.close.err` and `quic.close.reason`.
3. Add `-quic_debug` for ngtcp2's log of frames and timers.
4. Set `SSLKEYLOGFILE` and capture the loopback traffic. Wireshark can then decrypt it.
5. Use `-quic_drop` to make loss reproducible. Do not use timing for it.

## Problem areas

### Problem areas in the client

- The code is new. It passed tests against one HTTP/3 server and a ThreadSanitizer run, but it
  has little use. A failure can come from the client.
- Deadlocks are the main risk of the mutex design. Look for a `vtc_fatal()` with `qc->mtx`
  held, and for a callback that waits.
- `rxdata` without `-all` consumes one `DATA` event. The packet boundaries set the size of an
  event, so a test that counts events is not reproducible. Use `rxdata -all` or `rxresp`.
- `rxgoaway` and `goaway.id` have no test against a server that sends an HTTP/3 GOAWAY.
- `txgoaway` cannot set the ID. nghttp3 chooses it.
- The stateless reset path and the version negotiation path have no tests.
- `quic_rebind` closes the old socket at once. Packets that the server sends to the old port
  are lost.
- A NAT rebinding followed by an active migration stalled against one server. Each one alone
  works. The cause is not known. It can be in the client, in ngtcp2 or in the server.
- The rx commands wait at most `hp->timeout` for each event. A long transfer is not limited,
  but a pause of the server longer than `hp->timeout` is fatal.
- Not available: an HTTP/3 server, `-keepalive`, `-proxy1`/`-proxy2`, QUIC v2, and raw HTTP/3
  frames. nghttp3 cannot send malformed frames.
- The Makefile does not rebuild objects when `WITH_QUIC` changes. Run `make clean`.

### Server problems that look like client problems

A server bug can show up as a strange client result. Read the server log before you change the
client. These cases occurred during the tests:

- The server ended the session on a failed TLS handshake, but sent no CONNECTION_CLOSE. The
  client then reports `handshake_timeout`, not `transport`.
- The server crashed after a Retry or after a close. The client then reports
  `connection closed` in a stream, or an `idle` close.
- The server sent no HTTP/3 GOAWAY. `rxgoaway` then fails with "No GOAWAY received".

### Possible extensions

- Frame-level tests: a command that writes raw bytes to a stream past nghttp3, for example
  `txraw -uni TYPE HEX`. This is simpler than a second HTTP/3 codec.
- `expect_close` options that fail when the close type differs, for example `-idle`.
- QUIC v2, and an HTTP/3 server.

### VTest2 problems seen during the work

These problems existed before the QUIC work:

- `tests/a02019.vtc` fails. Since 044eee8 the default `:path` comes before `-idxHdr 5`.
- After a stream thread fails, the cleanup of the session closes the socket. Then
  `client_disc()` calls `VTCP_close()` on -1 and the assert stops the process. A guard there
  makes failed HTTP/2 tests hang until the timeout, so the code keeps the assert.
- The HTTP/2 `gunzip` writes the result back into the body buffer. That buffer can be too
  small. The HTTP/3 `gunzip` uses `vtc_gunzip_vsb()` and a new buffer.
- `${string,repeat,0,x}` stops the process with an assert in `VSB_newbuf()`.
- `make vtest` does not link without `libvarnishapi` in `/usr/local/lib`.

## References

- RFC 9000 (QUIC), RFC 9001 (QUIC TLS), RFC 9114 (HTTP/3), RFC 9204 (QPACK).
- ngtcp2 examples: `simpleclient.c`, `client.cc`, `http3_client_proto_codec.cc`,
  `tls_client_session_ossl.cc`.
- `TLS-IMPL.md`: the TLS support that QUIC uses.
