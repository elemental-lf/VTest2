/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * QUIC connection close types, as reported by quic.close.type
 */

/*lint -save -e525 -e539 */

QUIC_CLOSE_TYPE(LOCAL,			local)
QUIC_CLOSE_TYPE(TRANSPORT,		transport)
QUIC_CLOSE_TYPE(APPLICATION,		application)
QUIC_CLOSE_TYPE(IDLE,			idle)
QUIC_CLOSE_TYPE(STATELESS_RESET,	stateless_reset)
QUIC_CLOSE_TYPE(VERSION_NEGOTIATION,	version_negotiation)
QUIC_CLOSE_TYPE(HANDSHAKE_TIMEOUT,	handshake_timeout)
#undef QUIC_CLOSE_TYPE

/*lint -restore */
