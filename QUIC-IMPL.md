# QUIC and HTTP/3 Implementation in VTest2

## Overview

VTest2 has an HTTP/3 client. A test starts it with `client cNAME -quic`. The client speaks QUIC v1
through ngtcp2 and HTTP/3 through nghttp3. TLS comes from OpenSSL 3.5 or later, through
ngtcp2's `ngtcp2_crypto_ossl` backend. There is no HTTP/3 server.

The test language reuses the HTTP/2 `stream` model. A test that uses only request-level
commands can run over HTTP/2 and HTTP/3. QUIC-specific commands and variables let a test
examine 0-RTT, resumption, Retry, NEW_TOKEN, stream resets, flow control, connection close,
idle timeout, migration and packet loss. Packet filters drop packets by number or, at runtime,
by packet type.

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
| `tests/quic/a30000.vtc` | Self-test without a server (handshake timeout, packet drops, `quic_drop` and its errors) |
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
  engine thread, the state that the `quic.*` variables show, and the runtime packet filter
  of each direction (`struct quic_pkt_filter`).
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
connection events: handshake, close, GOAWAY, rebind, and a `quic_drop -count` that is used up.
Each stream has its own condition variable for its events.

The runtime packet filter is per connection, and `qc->mtx` protects it. `quic_drop` changes it
under the lock and returns. The engine holds the lock in `quic_read()` and `quic_send()`. The
new filter thus applies to every datagram that the engine reads after the command, including
the ones that already wait in the socket buffer.

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

### Packet filters

Two filters simulate loss. Both apply:

| | `-quic_drop SPEC` (client line) | `quic_drop` (command) |
|---|---|---|
| Set | Once, when the client starts | At runtime, in the client specification or in `stream 0` |
| Selects | Datagrams by number, per direction (`in:N`, `out:every:N`) | Packets by type, per direction |
| Drops | Whole datagrams | Single packets, cut out of their datagram |

The static filter runs first. A datagram that it drops never reaches the runtime filter.

Syntax:

```
quic_drop -in|-out -pkt [!]TYPE[,TYPE...] [-count N [-wait]]
quic_drop -in|-out -wait

TYPE: all, initial, 0rtt, handshake, retry, 1rtt, vn
```

- The types form a set, and `!` complements the whole set. `!all` is the empty set and turns
  the filter off. There is no "off" keyword.
- `-pkt` is required. A later `-frame` option (see "Possible extensions") would make a missing
  selector mean "any", and a bare `quic_drop -in` that drops everything would be a trap.
- Each command replaces the filter of its direction.
- The command works before `tls_handshake`. `quic_http_init()` creates `struct quic_conn` when
  the client connects, so a filter set before the handshake applies to the first Initial.

`-count N` drops the next N matching packets, then turns the filter of that direction off.
`-wait` waits until the count of that direction is used up, so a test knows that the loss
happened before it checks the recovery:

- With `-pkt` and `-count`, the command sets the filter and then waits. Alone, it waits for the
  count of an earlier command. The second form exists because a filter set before
  `tls_handshake` can only be waited for after it.
- It returns at once when the count is used up, also when the connection closed meanwhile.
- It is fatal when the filter has no `-count`, after `hp->timeout`, when the connection closes
  first, and before the connection started. The message names the packets still to drop.

`quic_pkt_split()` walks the packets of a datagram (RFC 9000, 17.2 and 17.3). A long header
packet of QUIC v1 ends after its Length field; an Initial also has a token. Version
Negotiation, Retry and short header (1-RTT) packets are the rest of the datagram. A packet of
an unknown version, or one whose length runs past the datagram, is the rest of the datagram as
well, of an unknown type: only `all` matches it. Trailing zero bytes are padding, not a
packet: no filter matches them, and they never use a count. A datagram that holds more than 16
packets has the rest as one unknown packet.

The filter cuts the matching packets and moves the others together (`quic_cut()`). It drops the
datagram only when no packet is left. The server's batching and coalescing thus do not change
what a test drops. Two consequences:

- A server discards a datagram with an Initial packet that is shorter than 1200 bytes (RFC
  9000, 14.1). When a cut leaves an Initial in an outgoing datagram of at least 1200 bytes,
  the client pads the datagram with zeros to its old length. ngtcp2 ignores zero bytes after
  the last packet (`should_buffer_1rtt_pkt()` during the handshake; after it, the zeros fail
  as a short header packet without harm).
- A stateless reset looks like a 1-RTT packet (RFC 9000, 10.3). `1rtt` and `all` thus match
  resets as well.

`quic_write_close()` sends through `quic_send()`. `quic_drop -out -pkt all` thus swallows the
client's own CONNECTION_CLOSE, and the client vanishes without a trace.

Counters and variables:

- `quic.drops_in` and `quic.drops_out` count datagrams that never reach ngtcp2 or the socket:
  the ones that `-quic_drop` dropped, and the ones that `quic_drop` cut empty.
- `quic.pkt_drops_in` and `quic.pkt_drops_out` count packets that `quic_drop` cut.
- `quic.drop.in` and `quic.drop.out` are the packets that the current `-count` still drops,
  0 when no count is active.
- `quic.initials_out` counts the Initial packets that `quic_send()` gets, before any filter.
  `quic.first_flight_initials` is the part of it before the first datagram arrived
  (`pkts_in == 0`): the Initial packets of the ClientHello, if the server answers before
  the first PTO. A test that depends on it sets `groups` in `tls_config`: OpenSSL 3.5 with
  `*X25519MLKEM768:*X25519` gives 2, `X25519` gives 1.

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
  `quic_drop -out -pkt initial -count 1` drops the first half, whatever the key share.
- A server that sends Retry sends one Retry for each Initial. ngtcp2 uses the first and
  ignores the second.

### Logging

- Level 3: handshake, close, stream events (`rx: HEADERS`, `tx: RESET_STREAM`, ...). Each
  `quic_drop` command with the resulting filter (`quic_drop: in pkt={handshake} count 1`), and
  each cut packet (`rx datagram #2: cut Handshake (2 of 3 packets)`).
- Level 4: each datagram with its size, every packet in it (type, and the size when there is
  more than one), the version and DCID of the first packet, and each header field.
- `-quic_debug` adds ngtcp2's own log at level 4.

## Testing

### VTest2 self-tests

```bash
make test-varnishtest WITH_QUIC=1   # runs tests/*.vtc, tests/tls/*.vtc and tests/quic/*.vtc
```

VTest2 has no HTTP/3 server. `tests/quic/a30000.vtc` therefore tests only what works without
one: the handshake timeout, `quic.*` variables before a handshake, and packet drops of
outgoing packets. It runs the fatal errors of `quic_drop` as nested tests that must fail.

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
10. Packet loss with `-quic_drop` and `quic_drop`, and several connections at the same time.
11. The stateless reset: `quic_drop -in -pkt all` until the server forgot the session, then
    `quic_drop -in -pkt !all` and a new request. `quic.close.type` is `stateless_reset`.

### Debugging a failed test

1. Run with `-v` and read the client lines (`c1`, `c1.1`) next to the server log.
2. Check `quic.close.type`, `quic.close.err` and `quic.close.reason`.
3. Add `-quic_debug` for ngtcp2's log of frames and timers.
4. Set `SSLKEYLOGFILE` and capture the loopback traffic. Wireshark can then decrypt it.
5. Use `-quic_drop` to make loss reproducible. Do not use timing for it. For the loss of one
   packet type, `quic_drop -count` is more exact: it does not depend on how the server
   batches its packets.

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
- The stateless reset path and the version negotiation path have no tests. `quic_drop` makes
  the reset testable (see "Tests against a server").
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
- Frame filters for `quic_drop`: `-frame [!]FRAME[,FRAME...]`, to lose one frame whatever
  packet type carries it (HANDSHAKE_DONE, NEW_TOKEN, PATH_RESPONSE, CONNECTION_CLOSE,
  RESET_STREAM, ...). `-frame` is reserved now and fatal with "not implemented". These rules
  are fixed, so that `-frame` does not change what an existing command means:
  - A frame filter selects packets to drop. It never removes single frames from a packet that
    still arrives: the peer acknowledges the rest of such a packet and never sends the frame
    again. That simulates a broken peer, not loss.
  - A packet matches if its type is in the `-pkt` set and it carries a frame of the `-frame`
    set. A missing selector matches any; at least one of the two is required.
  - `!` complements the frame set first, then "carries any frame of the set" applies.
    `-frame !ack` thus matches a packet with a frame other than ACK. PADDING never counts for
    a match, or nearly every Initial would match.
  - Frame names are the RFC 9000 and RFC 9114 names in lower case (`connection_close`,
    `handshake_done`, `new_token`, `path_response`, ...).
  - Version Negotiation, Retry and stateless resets carry no frames. A packet without keys
    yet can only be matched once ngtcp2 decrypts it.

  A sketch, checked against ngtcp2 1.25.0:
  - `ngtcp2_encrypt` and `ngtcp2_decrypt` have no user data. Both run with `qc->mtx` held, in
    the thread that made the ngtcp2 call. A thread-local "current connection", set by lock
    and unlock helpers for `qc->mtx`, gives the callbacks their filter.
  - ngtcp2 has no public frame decoder. The client needs its own parser for the RFC 9000
    frame types and DATAGRAM (RFC 9221). An unknown frame type ends the parse: the packet
    does not match, and the client logs that.
  - Out: `ngtcp2_ppe_final()` encrypts each packet in place, with `aad` at the packet start.
    The `encrypt` wrapper calls `ngtcp2_crypto_encrypt_cb()`, parses the plaintext, and on a
    match records the range from `aad` to the end of the ciphertext. `quic_send()` cuts the
    recorded ranges with `quic_cut()`'s code. ngtcp2 takes the packet as sent and recovers
    the loss.
  - In: the `decrypt` wrapper calls `ngtcp2_crypto_decrypt_cb()` and parses the plaintext.
    On a match it returns `NGTCP2_ERR_DECRYPT`. ngtcp2 then does not record the packet
    number, so the packet is never acknowledged: real loss. But `conn_recv_cpkt()` also
    discards the rest of the datagram. To keep the per-packet rule, the wrapper records where
    the packet ends (`ciphertext` points into the datagram buffer of `quic_read()`; `aad`
    does not), and `quic_read()` passes the rest of the datagram to
    `ngtcp2_conn_read_pkt()` again. Packets that ngtcp2 buffered for keys it did not have
    yet are replayed from its own buffer; there `ciphertext` is outside the datagram, and
    only that packet is lost.
  - A dropped packet of a new key phase only delays the key update: ngtcp2 picks the key by
    the key phase bit and does not retry with the other key.
  - These points depend on ngtcp2 internals. Assert them where the client can see them
    (`ciphertext` inside or outside the buffer, `aad` at the packet start on send), so a
    newer ngtcp2 fails loudly.
  - Alternative: derive the packet keys from the TLS secrets with
    `ngtcp2_crypto_derive_packet_protection_key()` and `ngtcp2_crypto_hp_mask()`, and
    decrypt a copy of each packet in `quic_read()`. No ngtcp2 internals, but the client then
    repeats header protection removal, packet number recovery and key updates.

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
