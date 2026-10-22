#
#
# VERSION to use when not building from git.
# Update when tagging a new version
PACKAGE_VERSION =	VTest2-2.1-trunk-nogit

PYTHON	?=	python3
PYTHON	?=	python

VARNISH_SRC ?= /home/phk/Varnish/trunk/varnish-cache

AWK	?=	awk

SED	?=	sed

SRCS=	src/*.c \
	lib/*.c

OBJS=	src/*.o \
	lib/*.o

DEPS=	lib/*.h \
	src/*.h \
	src/tbl/*.h \
	src/teken_state.h \
	src/vtc_h2_dectbl.h \
	version.h

FLAGS=	-O2 -Wall -Werror

CFLAGS=  ${FLAGS}
LDFLAGS= ${FLAGS} -rdynamic
DEFINES=

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

.PHONY: version.h

version.h:
	@if git describe >$@.tt ; then \
	    (echo '#define VTEST_VERSION "'`cat $@.tt`'"' >$@.t) && \
	    diff $@ $@.t >/dev/null 2>&1 || mv -f $@.t $@ ; \
	else \
	    echo '#define VTEST_VERSION "$(PACKAGE_VERSION)"' >$@ ; \
	fi
	@rm -f $@.t $@.tt

src/vtc_main.o: version.h


#######################################################################
# Test target

test: vtest
	env PATH=`pwd`:${PATH} vtest tests/*.vtc tests/tls/*.vtc tests/quic/*.vtc

#######################################################################
# pkg-config
vtest.pc: vtest.pc.in
	${SED} <$< >$@.tmp "s:@DESTDIR@:$(DESTDIR):; s:@PACKAGE_VERSION@:$(PACKAGE_VERSION):;"
	mv $@.tmp $@

#######################################################################
# Install target.
# 1. You must set DESTDIR
# 2. DESTDIR must have 'include' and 'bin' subdirs.

install: vtest vtest.pc
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

	mkdir -p ${DESTDIR}/lib/pkgconfig
	rm -f ${DESTDIR}/lib/pkgconfig/vtest.pc
	cp vtest.pc ${DESTDIR}/lib/pkgconfig
	chmod 444 ${DESTDIR}/lib/pkgconfig/vtest.pc

#######################################################################
# Implicit rule used in a sub-process by the rules above, and makes use
# of ${DEFINES} for extra arguments :
.c.o:
	${CC} \
		${CFLAGS} \
		${DEFINES} \
		${QUIC_DEFINES} \
		${INCS} \
		-I${VARNISH_SRC}/include \
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
