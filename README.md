# VTest2

HTTP test program derived from Varnish's varnishtest. Tests HTTP clients, servers, and proxies using `.vtc` test
scripts.

Plug-in replacement for [vtest1](https://github.com/vtest/VTest).

## Building

```bash
make vtest                              # Build standalone
make varnishtest VARNISH_SRC=/path      # Build with Varnish support
make test                               # Build and run tests
```

### HTTP/3 (QUIC) client

> **Disclaimer: The HTTP/3 client was coded by Claude Code (Opus 5.5) with only
minimal supervision. A thorough review of this code is still outstanding.
The code should be mostly okay as it has been tested against another server
implementation, but you have been warned. See `QUIC-IMPL.md` for
implementation details.**

`WITH_QUIC=1` adds an HTTP/3 client (`client cNAME -quic`, see `feature quic`), built on
ngtcp2's OpenSSL backend and nghttp3:

```bash
make varnishtest WITH_QUIC=1 NGTCP2=/path/to/ngtcp2 NGHTTP3=/path/to/nghttp3
```

`NGTCP2` and `NGHTTP3` are install prefixes (with `include/` and `lib/`). It needs OpenSSL 3.5 or later.
Object files are not rebuilt when this changes: run `make clean` first.

### Dependencies

**Linux:** libpcre2-dev, zlib, libssl-dev
**macOS:** Same via Homebrew (OpenSSL via `brew install openssl@3`)

## Usage

```bash
./vtest tests/a00001.vtc                # Run single test
./vtest -j4 tests/*.vtc                 # Run tests in parallel
```

Test files start with `vtest` or `varnishtest` followed by a description. See `tests/` directory for examples.

## Syncing with Varnish-Cache

For maintainers: `make update` syncs shared code from Varnish-Cache. Set `VARNISHSRC` to use a local repo instead of
cloning.

See `CLAUDE.md` for architecture details, `TLS-IMPL.md` for TLS support documentation and `QUIC-IMPL.md` for
the QUIC and HTTP/3 client.
