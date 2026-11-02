# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## Overview

VTest2 is a standalone HTTP testing program, originally derived from Varnish's varnishtest. It tests HTTP clients, servers, and proxies using a domain-specific scripting language (`.vtc` files).

### Where this fork sits

- **Upstream:** vinyl-cache's VTest2, `https://code.vinyl-cache.org/vtest/VTest2` (git remote usually named `vinylvtest`).
- **This repo:** `github.com/varnish/VTest2`, the Varnish Software fork. Its main addition is TLS support (`vtc_tls.c`, `tls_config`/`tls_handshake`, `tls.*` variables, `tls*` feature checks), plus some Varnish-specific adjustments.
- **Consumer:** the Varnish repo vendors this one as the git submodule `bin/vinyltest/vtest2`. Varnish-specific commands (`varnish`, `logexpect`, `vsm`, `vcache_builtwith`) do not live here. They are in that repo's `libvtest_ext_varnish` extension.

## Build Commands

```bash
make vtest          # Build vtest
make test           # Build and run tests/*.vtc
make clean          # Remove build artifacts
make install DESTDIR=/prefix  # Install vtest, vtest_api.h and vtest.pc (pkg-config)
```

### Generated Files
The build generates these files before compilation:
- `src/teken_state.h` - Generated from `src/sequences` using awk
- `src/vtc_h2_dectbl.h` - Generated from `src/tbl/vhp_huffman.h` using Python
- `version.h` - Generated from `git describe`. It is a phony target, so it is always regenerated.

## Porting from upstream

New upstream commits are cherry-picked from vinyl-cache's VTest2 onto a catch-up branch (e.g. `vinyl-catchup-YYYY-MM-DD`) and merged via a PR.

- One commit per upstream commit. Never squash, so bisecting and seeing which upstream commits were merged stays easy.
- Keep the upstream author and message. Drop any `(cherry picked from ...)` line and end with this two-line trailer:
  ```
  Upstream: https://code.vinyl-cache.org/vtest/VTest2/commit/<full-sha>
  Port: exact
  ```
  If the content differs from upstream in any way (including conflict resolutions around downstream code), use:
  ```
  Port: adjusted -- <terse one-line reason>
  ```
- When resolving conflicts, never take upstream's whole file (`git checkout --theirs`). This fork carries downstream changes in shared files, e.g. `vtc_tls_init()` in `vtc_main.c` or the TLS feature checks in `vtc_misc.c`. Edit the conflicting hunk only, then diff against `HEAD` to confirm nothing downstream was lost.
- `make update` (`tools/sync/`) imports `lib/` code from varnish-cache. This fork does not track upstream's vinyl-ized version of these scripts.
- Record user-visible changes in `CHANGES.md` (newest first).

## Code Architecture

### Directory Structure
- **lib/** - Shared utility library code synced from Varnish-Cache/vinyl-cache (vsb, vqueue, vtcp, etc.)
- **src/** - Core VTest implementation
  - `vtc_main.c` - Entry point, test execution orchestration, parallel test runner, `-i` mode
  - `vtc.c` - Core test execution, macro expansion, command dispatch, extension loading
  - `vtc_http.c/vtc_http.h` - HTTP/1.1 client/server implementation with session operations abstraction
  - `vtc_http2.c` - HTTP/2 support
  - `vtc_tls.c` - TLS/SSL support (OpenSSL-based, downstream-only)
  - `vtc_client.c` - Client command implementation
  - `vtc_server.c` - Server command implementation
  - `vtc_process.c` - Process spawning and management with terminal emulation
  - `vtc_barrier.c` - Synchronization primitives for tests
  - `vtc_haproxy.c` - HAProxy-specific testing
  - `vtc_misc.c` - Miscellaneous commands, including `feature`
  - `vtest_api.h` - Public API for extensions (installed)
  - `cmds.h` - X-macro command table
  - `builtin_cert.h` - Default self-signed certificate (CN=example.com)
  - `tbl/` - Table-driven code generation (H2 frames, settings, errors, TLS alerts/protocols)
- **tests/** - Test suite: `a[0-9]{5}.vtc` (run by `make test`) and `tests/tls/`
- **tools/sync/** - Scripts for syncing `lib/` code from Varnish-Cache
- **CHANGES.md** - Changelog, newest first
- **TLS-IMPL.md** - TLS implementation notes

### Command System
Commands are registered via `cmds.h` using X-macros:
- **CMD_GLOBAL**: Available everywhere (barrier, delay, shell, include)
- **CMD_TOP**: Top-level test commands (client, server, process, haproxy, etc.)

### Extensions
Product-specific commands come from shared-library extensions loaded with `-E extension_shlib`. Extensions are `dlopen()`ed at startup, in the main process, and register themselves from a `__attribute__((constructor))` function using the `vtest_api.h` API:
- `add_cmd(name, func, flags)` - Register a command
- `extmacro_def(name, func, fmt, ...)` - Define a global macro
- `i_mode_add(where, subdir, pfx, sfx)` - Add build-tree directories to `$PATH` for `-i` mode

The old `VTEST_WITH_VTC_*` compile-time switches are gone. A monolithic build links its extension in instead (e.g. Varnish links `libvtest_ext_varnish` with `--no-as-needed`).

### Core Concepts

**Test Execution Model:**
Tests are executed in forked child processes with their own temporary directories. The main process (`vtc_main.c`) orchestrates parallel execution (configurable via `-j`), manages timeouts, and collects results via pipes.

**Macro System:**
VTest has a powerful macro expansion system supporting:
- Static macros defined via `-D name=val`
- Dynamic macros defined in test scripts
- Function macros (e.g., `${date}`, `${string,repeat,N,text}`)
- Automatic macros for servers/clients (sNAME_addr, sNAME_port, sNAME_sock)

**Session Abstraction:**
HTTP clients and servers share common session handling code (`vtc_sess.c`, `sess_process()`) with pluggable connect/disconnect callbacks. This enables code reuse between client, server, and tunneling modes.

**Session Operations Pattern:**
VTest2 uses a session operations abstraction (`struct sess_ops` in `vtc_http.h`) that enables transparent switching between plain TCP and TLS connections. The `struct http` contains operation pointers (`poll`, `read`, `write`, `close`) that dispatch to either plain file descriptor operations (`http_fd_so`) or TLS operations (`tlsconn_so`). This allows all HTTP I/O code to remain unchanged whether using plain or encrypted connections. Upstream calls `read()`/`write()`/`poll()` on the fd directly, which is a frequent source of port conflicts.

**Terminal Emulation:**
Process commands include a full terminal emulator (`teken.c`) supporting VT220 escape sequences for testing interactive programs and screen output.

## Test File Format

Tests are `.vtc` files that must start with `vtest` or `varnishtest` followed by a description:
```vtc
vtest "Test description"

server s1 {
    rxreq
    txresp
} -start

client c1 -connect ${s1_sock} {
    txreq
    rxresp
    expect resp.status == 200
} -run
```

### TLS Test Example
```vtc
vtest "Basic TLS test"

server s1 {
    tls_config {
        cert = "/path/to/cert.pem"
        version = TLSv1.2 TLSv1.3
    }
    tls_handshake
    rxreq
    txresp -status 200
} -start

client c1 {
    tls_config {
        servername = "example.com"
        verify_peer = false
    }
    tls_handshake
    txreq -url "/"
    rxresp
    expect resp.status == 200
    expect tls.version == "TLSv1.3"
} -run
```

## Build Dependencies

### Linux
- libpcre2-dev
- zlib
- libssl-dev (OpenSSL 1.0.x or later, 1.1.0+ recommended)

### macOS
- Libraries typically available via Homebrew
- OpenSSL 3.x (via `brew install openssl@3`)

**Note:** Current Makefile uses hardcoded paths for macOS. For portability, consider using `pkg-config --cflags --libs libssl libcrypto`.

## Platform-Specific Notes

- **Linux**: Uses `dlopen()` by name for extensions. Primary development/testing platform.
- **macOS**: Bound but non-listening sockets timeout instead of refusing, so bad_backend_fd is closed. TLS implementation compiles successfully but may encounter VTest2 runtime issues unrelated to TLS (file descriptor management in `VSUB_closefrom()`). Recommend testing TLS features on Linux.
- **FreeBSD jails**: localhost/127.0.0.1 becomes the jail's IP

## TLS/SSL Support

VTest2 includes comprehensive TLS support ported from Varnish Cache Plus. See `TLS-IMPL.md` for detailed implementation documentation.

### Key TLS Features
- TLS 1.0 through TLS 1.3 support (OpenSSL version dependent)
- Certificate loading and validation
- ALPN (Application-Layer Protocol Negotiation)
- Session resumption
- OCSP stapling
- Client certificate verification
- SNI (Server Name Indication)

### TLS Commands
- **tls_config** - Configure TLS settings (certificate, versions, ciphers, ALPN, etc.)
- **tls_handshake** - Perform TLS handshake and switch to encrypted I/O

### TLS Configuration Options

**Common (client & server):**
- `cert = FILENAME` - Load certificate/key bundle (PEM format)
- `version = PROTO_MIN [PROTO_MAX]` - Set TLS version range (SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3)
- `cipher_list = CIPHER[:CIPHER...]` - Set cipher list for TLS ≤ 1.2
- `ciphersuites = CIPHER[:CIPHER...]` - Set cipher suites for TLS 1.3
- `groups = GROUP[:GROUP...]` - Set the key exchange groups (default: OpenSSL and its configuration)
- `alpn = PROTO [PROTO...]` - Set ALPN protocol list (e.g., "h2 http/1.1")

**Server-only:**
- `client_vfy = none|optional|required` - Client certificate verification mode
- `client_vfy_ca = FILENAME` - CA bundle for client certificate verification
- `staple = FILENAME` - Provide OCSP staple response

**Client-only:**
- `servername = HOST` - Set SNI hostname
- `verify_peer = true|false` - Enable/disable certificate verification
- `sess_out = filename` - Save TLS session for resumption
- `sess_in = filename` - Resume TLS session from file
- `cert_status = true|false` - Request OCSP staple from server

### TLS Variables for expect Commands

After `tls_handshake`, these variables are available:
- `tls.version` - Negotiated TLS version (e.g., "TLSv1.3")
- `tls.cipher` - Negotiated cipher suite
- `tls.servername` - SNI hostname (client)
- `tls.alpn` - Negotiated ALPN protocol
- `tls.alert` - Latest TLS alert message
- `tls.failed` - "true" if handshake/I/O failed
- `tls.cert[N].subject` - Certificate CN (N=0 is peer cert)
- `tls.cert[N].issuer` - Certificate issuer
- `tls.cert[N].subject_alt_names` - Subject Alternative Names
- `tls.sess_reused` - "true" if session was resumed
- `tls.staple_requested` - "true" if client requested OCSP
- `tls.ocsp_cert_status` - OCSP certificate status
- `tls.ocsp_resp_status` - OCSP response status
- `tls.ocsp_verify` - OCSP signature verification result

### TLS Architecture

The TLS implementation uses a **session operations abstraction** pattern that allows seamless switching between plain TCP and TLS connections:

1. `struct sess_ops` defines function pointers for `poll`, `read`, `write`, `close`
2. `struct http` contains operation pointers that default to plain FD operations
3. After `tls_handshake`, operations switch to TLS implementations
4. All HTTP I/O code remains unchanged - it transparently uses the correct operations

This design cleanly separates TLS concerns from HTTP protocol handling.

## Development Notes

- Code in `lib/` is synced from Varnish-Cache - don't modify directly
- Use `leave_temp` options (`-l`, `-L`) to preserve test directories for debugging
- The codebase uses Varnish's utility libraries: miniobj for object checking, vsb for string buffers, vqueue for linked lists
- TLS support requires OpenSSL; version detection happens at compile-time via `OPENSSL_VERSION_NUMBER`
- Default self-signed certificate (CN=example.com) is embedded in `builtin_cert.h` for testing without providing certificates
