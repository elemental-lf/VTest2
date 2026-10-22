#

PYTHON	?=	python3
PYTHON	?=	python

# Path to a built varnish-cache source tree, only needed for the
# varnishtest target. Must be set by the user.
VARNISH_SRC ?=

AWK	?=	awk

SRCS=	src/*.c \
	lib/*.c

OBJS=	src/*.o \
	lib/*.o

DEPS=	lib/*.h \
	src/*.h \
	src/tbl/*.h \
	src/teken_state.h \
	src/vtc_h2_dectbl.h

FLAGS=	-O2 -Wall -Werror

CFLAGS=  ${FLAGS}
LDFLAGS= ${FLAGS} -rdynamic
DEFINES=
VARNISH_INCS=

INCS=	-I. \
	-Isrc \
	-Ilib \
	-I/usr/local/include \
	-pthread

LIBS=	-L/usr/local/lib \
	-lm \
	-lpcre2-8 \
	-lz \
	-ldl \
	-lssl \
	-lcrypto

#######################################################################
# HTTP/3 (QUIC) client support, enabled with WITH_QUIC=1

WITH_QUIC ?= 0
NGTCP2	?= /home/lf/src/stf/tlsentinel/cmake-build-debug/ngtcp2
NGHTTP3	?= /home/lf/src/stf/tlsentinel/cmake-build-debug/nghttp3

QUIC_DEFINES_1 = -DVTEST_WITH_QUIC \
	-I${NGTCP2}/include \
	-I${NGHTTP3}/include
QUIC_LIBS_1 = -L${NGTCP2}/lib \
	-L${NGHTTP3}/lib \
	-Wl,--rpath,${NGTCP2}/lib \
	-Wl,--rpath,${NGHTTP3}/lib \
	-lngtcp2_crypto_ossl \
	-lngtcp2 \
	-lnghttp3

QUIC_DEFINES = ${QUIC_DEFINES_${WITH_QUIC}}
QUIC_LIBS = ${QUIC_LIBS_${WITH_QUIC}}

#######################################################################
# target for vtest without builtin varnish support

vtest: ${DEPS} ${SRCS}

	${MAKE} \
		 `for s in $(SRCS); do echo $${s%.c}.o;done`

	${CC} \
		${LDFLAGS} \
		-o vtest \
		${INCS} \
		${OBJS} \
		${QUIC_LIBS} \
		${LIBS}

test-vtest: vtest
	env PATH=`pwd`:${PATH} vtest tests/*.vtc tests/tls/*.vtc tests/quic/*.vtc

#######################################################################
# target for vtest with builtin varnish support (needs varnish source tree)

varnishtest:	${DEPS} ${SRCS}

	@[ -n "${VARNISH_SRC}" ] || \
		( echo "You must set VARNISH_SRC" 1>&2 ; exit 2)
	@[ -d "${VARNISH_SRC}" ] || \
		( echo "${VARNISH_SRC} directory missing" 1>&2 ; exit 2)

	${MAKE} \
		 VARNISH_INCS="-I${VARNISH_SRC}/include" \
		 DEFINES="-DVTEST_WITH_VTC_VARNISH -DVTEST_WITH_VTC_LOGEXPECT -DVTEST_WITH_VTC_VSM" \
		 `for s in $(SRCS); do echo $${s%.c}.o;done`

	${CC} \
		${LDFLAGS} \
		-o varnishtest \
		${OBJS} \
		${QUIC_LIBS} \
		${LIBS} \
		-L${VARNISH_SRC}/lib/libvarnishapi/.libs \
		-Wl,--rpath,${VARNISH_SRC}/lib/libvarnishapi/.libs \
		-lvarnishapi

#######################################################################
# Test target

test-varnishtest: varnishtest
	env PATH=`pwd`:${PATH} varnishtest tests/*.vtc tests/tls/*.vtc tests/quic/*.vtc

#######################################################################
# Install target.
# 1. You must set DESTDIR
# 2. DESTDIR must have 'include' and 'bin' subdirs.

install: vtest
	@[ ! -z "${DESTDIR}" ] || \
		( echo "You must set DESTDIR" 1>&2 ; exit 2)
	@[ -d "${DESTDIR}" ] || \
		( echo "${DESTDIR} directory missing" 1>&2 ; exit 2)
	@[ -d "${DESTDIR}/bin" ] || \
		( echo "${DESTDIR}/bin directory missing" 1>&2 ; exit 2)
	@[ -d "${DESTDIR}/include" ] || \
		( echo "${DESTDIR}/include directory missing" 1>&2 ; exit 2)

	rm -f ${DESTDIR}/bin/vtest
	cp vtest ${DESTDIR}/bin/vtest
	chmod 555 ${DESTDIR}/bin/vtest

	rm -f ${DESTDIR}/include/vtest_api.h
	cp src/vtest_api.h ${DESTDIR}/include/vtest_api.h
	chmod 444 ${DESTDIR}/include/vtest_api.h

#######################################################################
# Implicit rule used in a sub-process by the rules above, and makes use
# of ${DEFINES} for extra arguments :
.c.o:
	${CC} \
		${CFLAGS} \
		${DEFINES} \
		${QUIC_DEFINES} \
		${INCS} \
		${VARNISH_INCS} \
		-o $@ -c $<

#######################################################################

src/vtc_h2_dectbl.h:	src/huffman_gen.py src/tbl/vhp_huffman.h
	${PYTHON} -u src/huffman_gen.py src/tbl/vhp_huffman.h > $@ 

#######################################################################

src/teken_state.h:	src/gensequences src/sequences
	${AWK} -f src/gensequences src/sequences > src/teken_state.h

#######################################################################

clean:
	rm -rf */.deps */.dirstamp
	rm -f vtest varnishtest
	rm -f src/teken_state.h
	rm -f src/vtc_h2_dectbl.h
	rm -f ${OBJS}

#######################################################################
# Housekeeping
#
.PHONY: update

update:
	tools/sync/update-code-from-vc.sh
