/*
 * vtc_tls commands
 *
 */

TLS_CMD(cert)
TLS_CMD(version)
TLS_CMD(cipher_list)
TLS_CMD(alpn)
#if defined(TLS1_3_VERSION) || OPENSSL_VERSION_NUMBER >= 0x10101000L
TLS_CMD(ciphersuites)
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
TLS_CMD(groups)
#endif

#ifdef TLS_CLIENT
TLS_CMD(servername)
TLS_CMD(verify_peer)
TLS_CMD(sess_out)
TLS_CMD(sess_in)
TLS_CMD(cert_status)
#  undef TLS_CLIENT
#endif

#ifdef TLS_SERVER
TLS_CMD(client_vfy)
TLS_CMD(client_vfy_ca)
TLS_CMD(staple)
#  undef TLS_SERVER
#endif

#undef TLS_CMD
