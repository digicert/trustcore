/*
 * ssl.h
 *
 * OpenSSL SSL interface for DIGICERT
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#ifndef __DISABLE_DIGICERT_OPENSSL__

#ifndef __OSSL_SSL_HEADER__
#define __OSSL_SSL_HEADER__

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * VxWorks7 has openssl .h files in different locations
 */
#ifdef __RTOS_VXWORKS__
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <openssl/comp.h>
#else
#include <comp.h>
#endif
#else
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include "include/openssl/comp.h"
#else
#include "crypto/comp/comp.h"
#endif
#endif

/* DTLS ctrl options */
#define DTLS_CTRL_GET_TIMEOUT           73
#define DTLS_CTRL_HANDLE_TIMEOUT        74
#define DTLS_CTRL_LISTEN                75
#define SSL_CTRL_CHECK_PROTO_VERSION    119
#define DTLS_CTRL_SET_LINK_MTU          120
#define DTLS_CTRL_GET_LINK_MIN_MTU      121
#define SSL_CTRL_SET_MTU                17

#define DTLSV1_VERSION		0xFEFF

#define SSL_OP_ALL			0xFF
/* DTLS options */
# define SSL_OP_NO_QUERY_MTU                 0x00001000L
/* Turn on Cookie Exchange (on relevant for servers) */
# define SSL_OP_COOKIE_EXCHANGE              0x00002000L
/* Don't use RFC4507 ticket extension */
# define SSL_OP_NO_TICKET                    0x00004000L
/* Use Cisco's "speshul" version of DTLS_BAD_VER (as client)  */
# define SSL_OP_CISCO_ANYCONNECT             0x00008000L

/* As server, disallow session resumption on renegotiation */
# define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION   0x00010000L
/* Don't use compression even if supported */
# define SSL_OP_NO_COMPRESSION                           0x00020000L
/* Permit unsafe legacy renegotiation */
# define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION        0x00040000L
/* If set, always create a new key when using tmp_ecdh parameters */
# define SSL_OP_SINGLE_ECDH_USE                          0x00080000L
/* Does nothing: retained for compatibility */
# define SSL_OP_SINGLE_DH_USE                            0x00100000L
/* Does nothing: retained for compatibiity */
# define SSL_OP_EPHEMERAL_RSA                            0x0
/*
 * Set on servers to choose the cipher according to the server's preferences
 */
# define SSL_OP_CIPHER_SERVER_PREFERENCE                 0x00400000L
/*
 * If set, a server will allow a client to issue a SSLv3.0 version number as
 * latest version supported in the premaster secret, even when TLSv1.0
 * (version 3.1) was announced in the client hello. Normally this is
 * forbidden to prevent version rollback attacks.
 */
#define SSL_OP_TLS_ROLLBACK_BUG                         0x00800000L
/* Disallowed Protocol Options */
#define SSL_OP_NO_SSLv2                 0x01000000L
#define SSL_OP_NO_SSLv3                 0x02000000L
#define SSL_OP_NO_TLSv1                 0x04000000L
#define SSL_OP_NO_TLSv1_2               0x08000000L
#define SSL_OP_NO_TLSv1_1               0x10000000L
#define SSL_OP_NO_TLSv1_3               0x20000000U
#define SSL_OP_NO_DTLSv1               0x04000000L
#define SSL_OP_NO_DTLSv1_2             0x08000000L

# define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv3|\
        SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2|SSL_OP_NO_TLSv1_3)

/* No support for NPN*/
# define MOCANA_NPN_UNSUPPORTED 0
# define MOCANA_NPN_NEGOTIATED  1
# define MOCANA_NPN_NO_OVERLAP  2

/* Handshake Status*/
#define SSL_CB_HANDSHAKE_START          0x10
#define SSL_CB_HANDSHAKE_DONE           0x20

#define SSL_ST_CONNECT 0x1000
#define SSL_ST_BEFORE 0x4000

# define SSL3_AD_CLOSE_NOTIFY             0
# define SSL3_AD_UNEXPECTED_MESSAGE      10/* fatal */
# define SSL3_AD_BAD_RECORD_MAC          20/* fatal */
# define SSL3_AD_DECOMPRESSION_FAILURE   30/* fatal */
# define SSL3_AD_HANDSHAKE_FAILURE       40/* fatal */
# define SSL3_AD_NO_CERTIFICATE          41
# define SSL3_AD_BAD_CERTIFICATE         42
# define SSL3_AD_UNSUPPORTED_CERTIFICATE 43
# define SSL3_AD_CERTIFICATE_REVOKED     44
# define SSL3_AD_CERTIFICATE_EXPIRED     45
# define SSL3_AD_CERTIFICATE_UNKNOWN     46
# define SSL3_AD_ILLEGAL_PARAMETER       47/* fatal */

# define TLS1_AD_DECRYPTION_FAILED       21
# define TLS1_AD_RECORD_OVERFLOW         22
# define TLS1_AD_UNKNOWN_CA              48/* fatal */
# define TLS1_AD_ACCESS_DENIED           49/* fatal */
# define TLS1_AD_DECODE_ERROR            50/* fatal */
# define TLS1_AD_DECRYPT_ERROR           51
# define TLS1_AD_EXPORT_RESTRICTION      60/* fatal */
# define TLS1_AD_PROTOCOL_VERSION        70/* fatal */
# define TLS1_AD_INSUFFICIENT_SECURITY   71/* fatal */
# define TLS1_AD_INTERNAL_ERROR          80/* fatal */
# define TLS1_AD_INAPPROPRIATE_FALLBACK  86/* fatal */
# define TLS1_AD_USER_CANCELLED          90
# define TLS1_AD_NO_RENEGOTIATION        100
/* codes 110-114 are from RFC3546 */
# define TLS1_AD_UNSUPPORTED_EXTENSION   110
# define TLS1_AD_CERTIFICATE_UNOBTAINABLE 111
# define TLS1_AD_UNRECOGNIZED_NAME       112
# define TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE 113
# define TLS1_AD_BAD_CERTIFICATE_HASH_VALUE 114
# define TLS1_AD_UNKNOWN_PSK_IDENTITY    115/* fatal */
# define TLS1_AD_NO_APPLICATION_PROTOCOL 120 /* fatal */

/* Flags returned by SSL_check_chain */
/* Certificate can be used with this session */
# define CERT_PKEY_VALID         0x1

# define SSL_VERIFY_NONE                 0x00
# define SSL_VERIFY_PEER                 0x01
# define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
# define SSL_VERIFY_CLIENT_ONCE          0x04
# define SSL_VERIFY_POST_HANDSHAKE       0x08

enum
{
  SSL_CTRL_EXTRA_CHAIN_CERT          = 14,
  SSL_CTRL_GET_EXTRA_CHAIN_CERTS     = 82,
  SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS   = 83,
  SSL_CTRL_SET_CURVES                = 91,
  SSL_CTRL_SET_CURVES_LIST           = 92,
  SSL_CTRL_SET_GROUPS_LIST           = 93,
  SSL_CTRL_SET_ECDH_AUTO             = 94,
  SSL_CTRL_MODE                      = 33,
  SSL_CTRL_OPTIONS                   = 32,
  SSL_CTRL_GET_READ_AHEAD            = 40,
  SSL_CTRL_SET_READ_AHEAD            = 41,
  SSL_CTRL_SET_SESS_CACHE_MODE       = 44,
  SSL_CTRL_GET_SESS_CACHE_MODE       = 45,
  SSL_CTRL_SET_TMP_DH                = 3,
  SSL_CTRL_SET_TMP_ECDH              = 4,
  SSL_CTRL_SET_TMP_RSA_CB            = 5,
  SSL_CTRL_SET_TMP_DH_CB             = 6,
  SSL_CTRL_SET_TMP_ECDH_CB           = 7,
  SSL_CTRL_GET_SESSION_REUSED        = 8,
  SSL_CTRL_SET_MSG_CALLBACK          = 15,
  SSL_CTRL_SET_MSG_CALLBACK_ARG      = 16,
  SSL_CTRL_SET_TLSEXT_HOSTNAME       = 55,
  SSL_CTRL_SET_TLSEXT_SERVERNAME_CB  = 53,
  SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG = 54,
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB  = 63,
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG    = 64,
  SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE      = 65,
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP = 70,
  SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB  = 72,
  SSL_CTRL_GET_RI_SUPPORT            = 76,
  SSL_CTRL_CLEAR_OPTIONS             = 77,
  SSL_CTRL_CHAIN_CERT                = 89,
  SSL_CTRL_SET_SIGALGS               = 97,
  SSL_CTRL_SET_SIGALGS_LIST          = 98,
  SSL_CTRL_SET_VERIFY_CERT_STORE     = 106,
  SSL_CTRL_GET_SERVER_TMP_KEY        = 109,
  SSL_CTRL_SET_CURRENT_CERT          = 117,
  SSL_CTRL_SET_MIN_PROTO_VERSION     = 123,
  SSL_CTRL_SET_MAX_PROTO_VERSION     = 124,
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE   = 127,
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB     = 128,
  SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG = 129,
  SSL_CTRL_GET_MIN_PROTO_VERSION     = 130,
  SSL_CTRL_GET_MAX_PROTO_VERSION     = 131,
  SSL_CTRL_GET_VERIFY_CERT_STORE     = 137,
};

#define SSL_F_REQUEST_CERTIFICATE                113
#define SSL_F_SSL2_SET_CERTIFICATE               126
#define SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM      130
#define SSL_F_SSL3_CTX_CTRL                      133
#define SSL_F_SSL3_GET_CERTIFICATE_REQUEST       135
#define SSL_F_SSL3_GET_CERT_STATUS               289
#define SSL_F_SSL3_GET_CERT_VERIFY               136
#define SSL_F_SSL3_GET_CLIENT_CERTIFICATE        137
#define SSL_F_SSL3_ACCEPT                        128
#define SSL_F_SSL3_GET_CLIENT_HELLO              138
#define SSL_F_SSL3_GET_KEY_EXCHANGE              141
#define SSL_F_SSL3_GET_RECORD                    143
#define SSL_F_SSL3_GET_SERVER_CERTIFICATE        144
#define SSL_F_SSL3_WRITE_BYTES                   158
#define SSL_F_SSL3_WRITE_PENDING                 159
#define SSL_F_SSL3_HANDSHAKE_MAC                 285
#define SSL_F_SSL3_CTRL                          213
#define SSL_F_SSL3_CLIENT_HELLO                  131
#define SSL_F_SSL3_CONNECT                       132
#define SSL_F_SSL3_PEEK                          235
#define SSL_R_LIBRARY_HAS_NO_CIPHERS             161
#define SSL_F_SSL_CHECK_PRIVATE_KEY              163
#define SSL_F_SSL_CONF_CMD                       334
#define SSL_F_SSL_CLEAR                          164
#define SSL_F_SSL_CTX_CHECK_PRIVATE_KEY          168
#define SSL_F_SSL_CTX_NEW                        169
#define SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE     290
#define SSL_F_SSL_CTX_SET_SSL_VERSION            170
#define SSL_F_SSL_CTX_USE_CERTIFICATE            171
#define SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1       172
#define SSL_F_SSL_CTX_USE_CERTIFICATE_FILE       173
#define SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1        175
#define SSL_F_SSL_CTX_USE_PRIVATEKEY_FILE        176
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY          177
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1     178
#define SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_FILE     179
#define SSL_F_SSL_DO_HANDSHAKE                   180
#define SSL_F_SSL_LOAD_CLIENT_CA_FILE            185
#define SSL_F_SSL_NEW                            186
#define SSL_F_SSL_SESSION_PRINT_FP               190
#define SSL_F_SSL_SET_CERT                       191
#define SSL_F_SSL_SET_FD                         192
#define SSL_F_SSL_SET_RFD                        194
#define SSL_F_SSL_SESSION_NEW                    189
#define SSL_F_SSL_SESSION_SET1_ID_CONTEXT        312
#define SSL_F_SSL_SET_SESSION_ID_CONTEXT         218
#define SSL_F_SSL_SET_SESSION_TICKET_EXT         294
#define SSL_F_SSL_SET_WFD                        196
#define SSL_F_SSL_SRP_CTX_INIT                   313
#define SSL_F_SSL_UNDEFINED_FUNCTION             197
#define SSL_F_SSL_USE_CERTIFICATE                198
#define SSL_F_SSL_USE_CERTIFICATE_ASN1           199
#define SSL_F_SSL_USE_CERTIFICATE_FILE           200
#define SSL_F_SSL_USE_PRIVATEKEY                 201
#define SSL_F_SSL_USE_PRIVATEKEY_ASN1            202
#define SSL_F_SSL_USE_RSAPRIVATEKEY              204
#define SSL_F_SSL_USE_PRIVATEKEY_FILE            203
#define SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1         205
#define SSL_F_SSL_USE_RSAPRIVATEKEY_FILE         206
#define SSL_F_SSL_VERIFY_CERT_CHAIN              207
#define SSL_F_SSL_WRITE                          208
#define SSL_F_SSL_ADD_DIR_CERT_SUBJECTS_TO_STACK 215
#define SSL_F_SSL_ADD_FILE_CERT_SUBJECTS_TO_STACK 216
#define SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT     219
#define SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE 220
#define SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT      272
#define SSL_F_SSL_CTX_USE_SERVERINFO             336
#define SSL_F_SSL_CTX_USE_SERVERINFO_FILE        337
#define SSL_F_SSL_BUILD_CERT_CHAIN               332
#define SSL_F_SSL_CERT_INST                      222
#define SSL_F_SSL_READ                           223
#define SSL_F_SSL_PEEK                           270
#define SSL_F_SSL_CTX_MAKE_PROFILES              309
#define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST   353
#define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES   362
#define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE    364
#define SSL_F_TLS_PROCESS_SERVER_DONE            368

# define SSL_F_DTLS1_ACCEPT                               246
# define SSL_F_DTLS1_CONNECT                              249
# define SSL_F_DTLS1_READ_FAILED                          259

#define SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE           616
#define SSL_F_SSL_CIPHER_DESCRIPTION                     626
#define SSL_R_STILL_IN_INIT                              121
#define SSL_R_CERTIFICATE_VERIFY_FAILED                  134
#define SSL_R_NOT_SERVER                                 284
#define SSL_R_WRONG_SSL_VERSION                          266
#define SSL_F_SSL_READ_EARLY_DATA                        529
#define SSL_R_BAD_LENGTH                                 271
#define SSL_F_SSL_KEY_UPDATE                             515
#define SSL_R_INVALID_KEY_UPDATE_TYPE                    120
#define SSL_READ_EARLY_DATA_ERROR                          0
#define SSL_READ_EARLY_DATA_SUCCESS                        1
#define SSL_READ_EARLY_DATA_FINISH                         2

#define SSL_R_INVALID_CONFIGURATION_NAME                 113
#define SSL_R_BAD_SIGNATURE                              123
#define SSL_R_BAD_WRITE_RETRY                            127
#define SSL_R_UNKNOWN_COMMAND                            139
#define SSL_R_LENGTH_MISMATCH                            159
#define SSL_R_NO_CIPHERS_AVAILABLE                       181
#define SSL_R_NO_SHARED_CIPHER                           193
#define SSL_R_WRONG_CIPHER_RETURNED                      261
#define SSL_R_WRONG_NUMBER_OF_KEY_BITS                   263
#define SSL_R_WRONG_VERSION_NUMBER                       267
#define SSL_R_PATH_TOO_LONG                              270
#define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC        281
#define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE                 315
#define SSL_R_NO_REQUIRED_DIGEST                         324
#define SSL_R_INVALID_STATUS_RESPONSE                    328
#define SSL_R_SIGNATURE_ALGORITHMS_ERROR                 360

#if defined(__ENABLE_DIGICERT_OSSL_LOG_REDIRECT_STDERR__)
#define PRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define PRINT(...) printf( __VA_ARGS__)
#endif

/*
 * Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written):
 */
#ifdef __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__
# define SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001U
#else
# define SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001L
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

/* Maximum plaintext length: defined by SSL/TLS standards */
# define SSL3_RT_MAX_PLAIN_LENGTH                16384

/*
 * Make it possible to retry SSL_write() with changed buffer location (buffer
 * contents must stay the same!); this is not the default to avoid the
 * misconception that non-blocking SSL_write() behaves like non-blocking
 * write():
 */
# define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L


#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#define SSL_F_OPENSSL_INIT_SSL                   342
#endif

#define SSL_R_BAD_SSL_FILETYPE                   124
#define SSL_R_BAD_VALUE                          384
#define SSL_R_INVALID_NULL_CMD_NAME              385
#define SSL_R_NO_CERTIFICATE_ASSIGNED            177
#define SSL_R_NO_CIPHER_MATCH                    185
#define SSL_R_NO_METHOD_SPECIFIED                188
#define SSL_R_NO_PRIVATE_KEY_ASSIGNED            190
#define SSL_R_NULL_SSL_CTX                       195
#define SSL_R_UNINITIALIZED                      276
#define SSL_R_NO_RENEGOTIATION                   339
#define SSL_R_NULL_SSL_METHOD_PASSED             196
#define SSL_R_UNKNOWN_CERTIFICATE_TYPE           247
#define SSL_R_X509_LIB                           268
#define SSL_F_SSL_CTX_SET_CIPHER_LIST            269
#define SSL_F_SSL_SET_CIPHER_LIST                271
#define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG    273
#define SSL_R_SSL3_EXT_INVALID_SERVERNAME        319
#define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE   320
#define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE  199
#define SSL_R_PROTOCOL_IS_SHUTDOWN               207
#define SSL_R_UNKNOWN_CMD_NAME                   386

#define SSL_ERROR_NONE                           0
#define SSL_ERROR_SSL                            1
#define SSL_ERROR_WANT_READ                      2
#define SSL_ERROR_WANT_WRITE                     3
#define SSL_ERROR_WANT_X509_LOOKUP               4
#define SSL_ERROR_SYSCALL                        5 /* look at error stack/return */
#define SSL_ERROR_ZERO_RETURN                    6
#define SSL_ERROR_WANT_CONNECT                   7
#define SSL_ERROR_WANT_ACCEPT                    8
#define SSL_ERROR_WANT_CLIENT_HELLO_CB          11

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
#define SSL_SENT_SHUTDOWN     1
#define SSL_RECEIVED_SHUTDOWN 2

/* RGK_LATER: Copied from openssl/ssl.h. Fix this to NOT be a copy. It should
 * refer to the defns. in openssl/ssl.h
 */
#define SSL_ST_OK      0x03
#define SSL_ST_CONNECT 0x1000
#define SSL_ST_ACCEPT  0x2000
#define SSL_ST_INIT        (SSL_ST_CONNECT|SSL_ST_ACCEPT)
#define SSL_ST_RENEGOTIATE (0x04|SSL_ST_INIT)
#define SSL_ST_ACCEPT_NEGOTIATING 0x8000

# define SSL_NOTHING     1
# define SSL_WRITING     2
# define SSL_READING     3
# define SSL_CLIENT_HELLO_CB 7

/* Used by SSL_CONF API
 */
#define SSL_CONF_FLAG_CMDLINE           0x1
#define SSL_CONF_FLAG_FILE              0x2
#define SSL_CONF_FLAG_CLIENT            0x4
#define SSL_CONF_FLAG_SERVER            0x8
#define SSL_CONF_FLAG_SHOW_ERRORS       0x10
#define SSL_CONF_FLAG_CERTIFICATE       0x20
#define SSL_CONF_FLAG_REQUIRE_PRIVATE   0x40

#define SSL_CONF_TYPE_UNKNOWN           0x0
#define SSL_CONF_TYPE_STRING            0x1
#define SSL_CONF_TYPE_FILE              0x2
#define SSL_CONF_TYPE_DIR               0x3
#define SSL_CONF_TYPE_NONE              0x4

# define SSL2_CF_8_BYTE_ENC                      0x02

/*-
 * Macros to check the export status and cipher strength for export ciphers.
 * Even though the macros for EXPORT and EXPORT40/56 have similar names,
 * their meaning is different:
 * *_EXPORT macros check the 'exportable' status.
 * *_EXPORT40/56 macros are used to check whether a certain cipher strength
 *          is given.
 * Since the SSL_IS_EXPORT* and SSL_EXPORT* macros depend on the correct
 * algorithm structure element to be passed (algorithms, algo_strength) and no
 * typechecking can be done as they are all of type unsigned long, their
 * direct usage is discouraged.
 * Use the SSL_C_* macros instead.
 */
# define SSL_IS_EXPORT(a)        ((a)&SSL_EXPORT)
# define SSL_IS_EXPORT56(a)      ((a)&SSL_EXP56)
# define SSL_IS_EXPORT40(a)      ((a)&SSL_EXP40)
# define SSL_C_IS_EXPORT(c)      SSL_IS_EXPORT((c)->algo_strength)
# define SSL_C_IS_EXPORT56(c)    SSL_IS_EXPORT56((c)->algo_strength)
# define SSL_C_IS_EXPORT40(c)    SSL_IS_EXPORT40((c)->algo_strength)

# define SSL_EXPORT_KEYLENGTH(a,s)       (SSL_IS_EXPORT40(s) ? 5 : \
                                 (a) == SSL_DES ? 8 : 7)
# define SSL_EXPORT_PKEYLENGTH(a) (SSL_IS_EXPORT40(a) ? 512 : 1024)
# define SSL_C_EXPORT_KEYLENGTH(c)       SSL_EXPORT_KEYLENGTH((c)->algorithm_enc, \
                                (c)->algo_strength)
# define SSL_C_EXPORT_PKEYLENGTH(c)      SSL_EXPORT_PKEYLENGTH((c)->algo_strength)

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
/* TLSv1.3 KeyUpdate message types */
/* -1 used so that this is an invalid value for the on-the-wire protocol */
#define SSL_KEY_UPDATE_NONE             -1
/* Values as defined for the on-the-wire protocol */
#define SSL_KEY_UPDATE_NOT_REQUESTED     0
#define SSL_KEY_UPDATE_REQUESTED         1

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
/*
 * The valid handshake states (one for each type message sent and one for each
 * type of message received). There are also two "special" states:
 * TLS = TLS or DTLS state
 * DTLS = DTLS specific state
 * CR/SR = Client Read/Server Read
 * CW/SW = Client Write/Server Write
 *
 * The "special" states are:
 * TLS_ST_BEFORE = No handshake has been initiated yet
 * TLS_ST_OK = A handshake has been successfully completed
 */
typedef enum {
    TLS_ST_BEFORE,
    TLS_ST_OK,
    DTLS_ST_CR_HELLO_VERIFY_REQUEST,
    TLS_ST_CR_SRVR_HELLO,
    TLS_ST_CR_CERT,
    TLS_ST_CR_CERT_STATUS,
    TLS_ST_CR_KEY_EXCH,
    TLS_ST_CR_CERT_REQ,
    TLS_ST_CR_SRVR_DONE,
    TLS_ST_CR_SESSION_TICKET,
    TLS_ST_CR_CHANGE,
    TLS_ST_CR_FINISHED,
    TLS_ST_CW_CLNT_HELLO,
    TLS_ST_CW_CERT,
    TLS_ST_CW_KEY_EXCH,
    TLS_ST_CW_CERT_VRFY,
    TLS_ST_CW_CHANGE,
    TLS_ST_CW_NEXT_PROTO,
    TLS_ST_CW_FINISHED,
    TLS_ST_SW_HELLO_REQ,
    TLS_ST_SR_CLNT_HELLO,
    DTLS_ST_SW_HELLO_VERIFY_REQUEST,
    TLS_ST_SW_SRVR_HELLO,
    TLS_ST_SW_CERT,
    TLS_ST_SW_KEY_EXCH,
    TLS_ST_SW_CERT_REQ,
    TLS_ST_SW_SRVR_DONE,
    TLS_ST_SR_CERT,
    TLS_ST_SR_KEY_EXCH,
    TLS_ST_SR_CERT_VRFY,
    TLS_ST_SR_NEXT_PROTO,
    TLS_ST_SR_CHANGE,
    TLS_ST_SR_FINISHED,
    TLS_ST_SW_SESSION_TICKET,
    TLS_ST_SW_CERT_STATUS,
    TLS_ST_SW_CHANGE,
    TLS_ST_SW_FINISHED,
    TLS_ST_SW_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_ENCRYPTED_EXTENSIONS,
    TLS_ST_CR_CERT_VRFY,
    TLS_ST_SW_CERT_VRFY,
    TLS_ST_CR_HELLO_REQ,
    TLS_ST_SW_KEY_UPDATE,
    TLS_ST_CW_KEY_UPDATE,
    TLS_ST_SR_KEY_UPDATE,
    TLS_ST_CR_KEY_UPDATE,
    TLS_ST_EARLY_DATA,
    TLS_ST_PENDING_EARLY_DATA_END,
    TLS_ST_CW_END_OF_EARLY_DATA,
    TLS_ST_SR_END_OF_EARLY_DATA
} OSSL_HANDSHAKE_STATE;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* These states are a copy from sslsock_priv.h; These are needed for SSL_get_state */
/* SSL Handshake Record type also used as a Handshake state identifier */
#define SSL_BEGIN                           (-1)
#define SSL_HELLO_REQUEST                   (0)
#define SSL_CLIENT_HELLO                    (1)
#define SSL_SERVER_HELLO                    (2)
#define SSL_SERVER_HELLO_VERIFY_REQUEST     (3)
#define SSL_NEW_SESSION_TICKET              (4)
#define SSL_CLIENT_END_OF_EARLY_DATA        (5)
#define SSL_HELLO_RETRY_REQUEST             (6)
#define SSL_ENCRYPTED_EXTENSIONS            (8)
#define SSL_CERTIFICATE                     (11)
#define SSL_SERVER_KEY_EXCHANGE             (12)
#define SSL_CERTIFICATE_REQUEST             (13)
#define SSL_SERVER_HELLO_DONE               (14)
#define SSL_CLIENT_CERTIFICATE_VERIFY       (15)
#define SSL_CLIENT_KEY_EXCHANGE             (16)
#define SSL_EXPECTING_FINISHED              (19) /* not a valid record type -> only a state */
#define SSL_FINISHED                        (20)
#define SSL_CERTIFICATE_STATUS              (22)
#define SSL_KEY_UPDATE                      (24)
#define SSL_MESSAGE_HASH                    (254)

#endif

MOC_EXTERN void	SSL_free(SSL *ssl);
MOC_EXTERN int	SSL_connect(SSL *ssl);
MOC_EXTERN int	SSL_accept(SSL *ssl);
MOC_EXTERN X509 *SSL_get_certificate(const SSL *ssl);
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
MOC_EXTERN X509 *SSL_get0_peer_certificate(const SSL *s);
MOC_EXTERN X509 *SSL_get1_peer_certificate(const SSL *s);
#define SSL_get_peer_certificate SSL_get1_peer_certificate
#else
MOC_EXTERN X509 *SSL_get_peer_certificate(SSL *s);
#endif
MOC_EXTERN EVP_PKEY* SSL_get_privatekey(SSL *ssl);
MOC_EXTERN int	SSL_get_error(const SSL *s, int ret_code);
MOC_EXTERN long SSL_get_verify_result(const SSL *ssl);
MOC_EXTERN void	SSL_load_error_strings(void );
MOC_EXTERN SSL *SSL_new(SSL_CTX *ctx);
MOC_EXTERN int 	SSL_peek(SSL *ssl, void *buf, int num);
MOC_EXTERN int	SSL_pending(const SSL *s);
MOC_EXTERN int 	SSL_read(SSL *ssl, void *buf, int num);
MOC_EXTERN void SSL_set_connect_state(SSL *s);
MOC_EXTERN int	SSL_set_fd(SSL *s, int fd);
MOC_EXTERN void SSL_set_read_ahead(SSL *ssl, int yes);
MOC_EXTERN int	SSL_set_session(SSL *to, SSL_SESSION *session);
MOC_EXTERN int 	SSL_write(SSL *ssl, const void *buf, int num);

/* SSL_get_cipher(s) -> SSL_CIPHER_get_name(SSL_get_current_cipher(s)) */
int SSL_set_cipher_list(SSL *s, const char *str);
MOC_EXTERN const char* SSL_get_cipher(SSL* ssl);

MOC_EXTERN STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s);

MOC_EXTERN SSL_SESSION *SSL_get1_session(SSL *ssl);
MOC_EXTERN SSL_SESSION *SSL_get_session(const SSL *ssl);
MOC_EXTERN void	SSL_SESSION_free(SSL_SESSION *ses);
MOC_EXTERN void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,unsigned *len);
MOC_EXTERN const COMP_METHOD *SSL_get_current_compression(SSL *s);
MOC_EXTERN void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,unsigned *len);
MOC_EXTERN size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);
MOC_EXTERN size_t SSL_get_finished(const SSL *s, void *buf, size_t count);
MOC_EXTERN int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,unsigned protos_len);
MOC_EXTERN int SSL_select_next_proto(unsigned char **out, unsigned char 			*outlen,const unsigned char *server,
                          unsigned int server_len,
                          const unsigned char *client,
                          unsigned int client_len);
MOC_EXTERN void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx,
                                      int (*cb) (SSL *s, unsigned char **out,
                                                 unsigned char *outlen,
                                                 const unsigned char *in,
                                                 unsigned int inlen,
                                                 void *arg), void *arg);
MOC_EXTERN void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *ctx,
                                           int (*cb) (SSL *ssl,
                                                      const unsigned char
                                                      **out,
                                                      unsigned int *outlen,
                                                      void *arg), void *arg);

MOC_EXTERN SSL_SESSION* SSL_SESSION_reference(SSL_SESSION*);

  /* SSL CTX Functions */
MOC_EXTERN int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x);
MOC_EXTERN int SSL_CTX_check_private_key(const SSL_CTX *ctx);
MOC_EXTERN int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
MOC_EXTERN void SSL_CTX_free(SSL_CTX *);
MOC_EXTERN X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
MOC_EXTERN int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
					     const char *CApath);
MOC_EXTERN SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
MOC_EXTERN int SSL_CTX_set_cipher_list(SSL_CTX *, const char *str);
MOC_EXTERN void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
MOC_EXTERN void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
MOC_EXTERN pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx);
MOC_EXTERN void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx);
#endif
MOC_EXTERN void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
			int (*callback)(int, X509_STORE_CTX *));
MOC_EXTERN int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
MOC_EXTERN int	SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
MOC_EXTERN int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file); /* PEM type */
MOC_EXTERN int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
MOC_EXTERN int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);

MOC_EXTERN long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
MOC_EXTERN long SSL_CTX_set_timeout(SSL_CTX *s, long t);
MOC_EXTERN long SSL_CTX_get_timeout(const SSL_CTX *s);
# define SSL_CTX_set_msg_callback_arg(ctx, arg) SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
# define SSL_set_msg_callback_arg(ssl, arg) SSL_ctrl((ssl), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
#define SSL_CTX_add_extra_chain_cert(ctx,x509) \
     SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
#define SSL_CTX_clear_extra_chain_certs(ctx) \
     SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op);
MOC_EXTERN int SSL_set1_host(SSL *pSsl, const char *pHostname);
MOC_EXTERN int SSL_add1_host(SSL *pSsl, const char *pHostname);
MOC_EXTERN void SSL_set_hostflags(SSL *pSsl, unsigned int flags);
MOC_EXTERN const char *SSL_get0_peername(SSL *pSsl);
#else
#define SSL_CTX_set_options(ctx,op) \
     SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL)
#endif
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
unsigned long SSL_CTX_get_options(const SSL_CTX *ctx);
unsigned long SSL_clear_options(SSL *s, unsigned long op);

# define SSL_CTX_set1_groups_list(ctx, s) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))
# define SSL_set1_groups_list(ctx, s) \
        SSL_ctrl(ctx,SSL_CTRL_SET_GROUPS_LIST,0,(char *)(s))
#else
#define SSL_CTX_get_options(ctx)			\
        SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,0,NULL)
#define SSL_clear_options(ssl, op) \
        SSL_ctrl((ssl),SSL_CTRL_CLEAR_OPTIONS,(op),NULL)
#endif
#define SSL_CTX_set_session_cache_mode(ctx,m) \
     SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb) \
     SSL_CTX_callback_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,(void (*)(void))cb)
#define SSL_CTX_set_tlsext_servername_arg(ctx, arg) \
     SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, (void *)arg)
#define SSL_CTX_set_tmp_dh(ctx,dh) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
# define SSL_CTX_set_current_cert(ctx, op) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURRENT_CERT, op, NULL)
# define SSL_get_secure_renegotiation_support(ssl) \
        SSL_ctrl((ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)

# define SSL_CTX_get_default_read_ahead(ctx) SSL_CTX_get_read_ahead(ctx)
# define SSL_CTX_set_default_read_ahead(ctx,m) SSL_CTX_set_read_ahead(ctx,m)
# define SSL_CTX_get_read_ahead(ctx) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,NULL)
# define SSL_CTX_set_read_ahead(ctx,m) \
        SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,NULL)

#define SSL_add0_chain_cert(ssl, x509) \
        SSL_ctrl(ssl, SSL_CTRL_CHAIN_CERT, 0, (char *)x509)
#define SSL_add1_chain_cert(ssl, x509) \
        SSL_ctrl(ssl, SSL_CTRL_CHAIN_CERT, 1, (char *)x509)
#define SSL_CTX_add0_chain_cert(ctx, x509) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 0, (char *)x509)
#define SSL_CTX_add1_chain_cert(ctx,x509) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_CHAIN_CERT, 1, (char *)x509)

#define SSL_CTX_set1_sigalgs(ctx, slist, slistlen) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, (int *)(slist))
#define SSL_CTX_set1_sigalgs_list(ctx, s) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, (char *)(s))
#define SSL_set1_sigalgs(ctx, slist, slistlen) \
        SSL_ctrl(ctx, SSL_CTRL_SET_SIGALGS, slistlen, (int *)(slist))
#define SSL_set1_sigalgs_list(ctx, s) \
        SSL_ctrl(ctx, SSL_CTRL_SET_SIGALGS_LIST, 0, (char *)(s))

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
unsigned long SSL_set_options(SSL *s, unsigned long op);
#else
# define SSL_set_options(ssl,op) \
        SSL_ctrl((ssl),SSL_CTRL_OPTIONS,(op),NULL)
#endif

#define SSL_set_app_data(s,arg)         (SSL_set_ex_data(s,0,(char *)arg))
#define SSL_get_app_data(s)             (SSL_get_ex_data(s,0))
#define SSL_set_max_send_fragment(ssl,m) \
        SSL_ctrl(ssl,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

extern int SSL_CTX_use_PrivateKey_file_ex(SSL_CTX *ctx, const char *file, int type);

/* SSL/TLS Methods */
MOC_EXTERN const SSL_METHOD *SSLv23_client_method(void);
MOC_EXTERN const SSL_METHOD *TLSv1_client_method(void);
MOC_EXTERN const SSL_METHOD *SSLv3_client_method(void);
MOC_EXTERN const SSL_METHOD *SSLv3_method(void);
MOC_EXTERN const SSL_METHOD *SSLv23_method(void);
MOC_EXTERN const SSL_METHOD *TLSv1_method(void);

/* RU: BEGIN SKELETON FUNCTION DECLARATIONS */

/* Typedefs for handling custom extensions */
typedef int (*custom_ext_add_cb) (SSL *s, unsigned int ext_type,
                                  const unsigned char **out,
                                  size_t *outlen, int *al, void *add_arg);

typedef void (*custom_ext_free_cb) (SSL *s, unsigned int ext_type,
                                    const unsigned char *out, void *add_arg);

typedef int (*custom_ext_parse_cb) (SSL *s, unsigned int ext_type,
                                    const unsigned char *in,
                                    size_t inlen, int *al, void *parse_arg);

typedef struct X509_VERIFY_PARAM_ID_st X509_VERIFY_PARAM_ID_MOC;
#define X509_VERIFY_PARAM_ID X509_VERIFY_PARAM_ID_MOC

typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM_MOC;
#define X509_VERIFY_PARAM X509_VERIFY_PARAM_MOC

typedef int (*tls_session_ticket_ext_cb_fn) (SSL *s,
                                             const unsigned char *data,
                                             int len, void *arg);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef sbyte4 (*pskFindSessionCallbackFuncPtr)(sbyte4 connectionInstance, ubyte *pIdentityPSK,
                                                 ubyte4 identityLengthPSK, ubyte **ppPsk, ubyte4 *pPskLen,
                                                 intBoolean *pFreeMemory);

typedef sbyte4 (*pskUseSessionCallbackFuncPtr)(sbyte4 connectionInstance,
                                                sbyte* ServerInfo, ubyte4 serverInfoLen,
                                                void *userData, void **ppPSKs,
                                                ubyte2 *pNumPSKs,ubyte* selectedIndex,
                                                intBoolean *pFreeMemory);

typedef sbyte4 (*pskSaveSessionCallbackFuncPtr)(sbyte4 connectionInstance,
                                                 sbyte* ServerInfo, ubyte4 serverInfoLen,
                                                 void *userData, ubyte* pPskData, ubyte4 pskLen);

typedef sbyte4 (*serverPskSaveSessionCallbackFuncPtr)(sbyte4 connectionInstance, ubyte *pServerName,
                                                      ubyte4 serverNameLen, ubyte *pIdentityPSK,
                                                      ubyte4 identityLengthPSK, ubyte *pPskData,
                                                      ubyte4 pskDataLen);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

typedef struct ssl_conf_ctx_st SSL_CONF_CTX;

#ifndef __DISABLE_DIGICERT_UNSUPPORTED_OPENSSL_FN__

MOC_EXTERN void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio);
MOC_EXTERN BIO *SSL_get_rbio(const SSL *s);
MOC_EXTERN int SSL_do_handshake(SSL *s);
MOC_EXTERN void SSL_set_accept_state(SSL *s_ssl);
MOC_EXTERN SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
MOC_EXTERN const char *SSL_get_version(const SSL *s);
MOC_EXTERN int SSL_set_min_proto_version(SSL *s,int version);
MOC_EXTERN int SSL_get_min_proto_version(SSL *s);
MOC_EXTERN int SSL_set_max_proto_version(SSL *s,int version);
MOC_EXTERN int SSL_get_max_proto_version(SSL *s);
MOC_EXTERN const char *SSL_CIPHER_get_name(const SSL_CIPHER *c);
MOC_EXTERN void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                                 int (*cb) (X509_STORE_CTX *, void *),
                                                 void *arg);
MOC_EXTERN int SSL_CTX_set_session_id_context(SSL_CTX *ctx,
                                              const unsigned char *sid_ctx,
                                              unsigned int sid_ctx_len);
MOC_EXTERN void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                           int (*cb) (SSL *ssl,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg), void *arg);
MOC_EXTERN long SSL_ctrl(SSL *s, int cmd, long larg, void *parg);
MOC_EXTERN int SSL_shutdown(SSL *s);
MOC_EXTERN int SSL_renegotiate(SSL *s);
MOC_EXTERN long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void));
MOC_EXTERN char *SSL_CIPHER_get_version(const SSL_CIPHER *c);
MOC_EXTERN int SSL_library_init(void);
MOC_EXTERN const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);
MOC_EXTERN const char *SSL_state_string_long(const SSL *s);
MOC_EXTERN int SSL_state(const SSL *ssl);
MOC_EXTERN int SSL_SRP_CTX_init(SSL *s);
MOC_EXTERN int SSL_CTX_SRP_CTX_init(SSL_CTX *ctx);
MOC_EXTERN int SSL_SRP_CTX_free(SSL *ctx);
MOC_EXTERN int SSL_CTX_SRP_CTX_free(SSL_CTX *ctx);
MOC_EXTERN int SSL_srp_server_param_with_username(SSL *s, int *ad);
MOC_EXTERN int SRP_generate_server_master_secret(SSL *s, unsigned char *master_key);
MOC_EXTERN int SRP_Calc_A_param(SSL *s);
MOC_EXTERN int SRP_generate_client_master_secret(SSL *s, unsigned char *master_key);
MOC_EXTERN int SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e);
MOC_EXTERN void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx,
                        int (*app_gen_cookie_cb) (SSL *ssl,
                                                  unsigned char
                                                  *cookie,
                                                  unsigned int
                                                  *cookie_len));
MOC_EXTERN void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx,
                        int (*app_verify_cookie_cb) (SSL *ssl,
                        unsigned char
                        *cookie,
                        unsigned int
                        cookie_len));
MOC_EXTERN void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx,
                        unsigned int (*psk_client_callback) (SSL
                                                             *ssl,
                                                             const
                                                             char
                                                             *hint,
                                                             char
                                                             *identity,
                                                             unsigned
                                                             int
                                                             max_identity_len,
                                                             unsigned
                                                             char
                                                             *psk,
                                                             unsigned
                                                             int
                                                             max_psk_len));
MOC_EXTERN void SSL_set_psk_client_callback(SSL *ssl,
                        unsigned int (*psk_client_callback) (SSL
                                                             *ssl,
                                                             const
                                                             char
                                                             *hint,
                                                             char
                                                             *identity,
                                                             unsigned
                                                             int
                                                             max_identity_len,
                                                             unsigned
                                                             char
                                                             *psk,
                                                             unsigned
                                                             int
                                                             max_psk_len));
MOC_EXTERN void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx,
                        unsigned int (*psk_server_callback) (SSL
                                                             *ssl,
                                                             const
                                                             char
                                                             *identity,
                                                             unsigned
                                                             char
                                                             *psk,
                                                             unsigned
                                                             int
                                                             max_psk_len));
MOC_EXTERN void SSL_set_psk_server_callback(SSL *ssl,
                        unsigned int (*psk_server_callback) (SSL
                                                             *ssl,
                                                             const
                                                             char
                                                             *identity,
                                                             unsigned
                                                             char
                                                             *psk,
                                                             unsigned
                                                             int
                                                             max_psk_len));
MOC_EXTERN int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint);
MOC_EXTERN int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);
MOC_EXTERN const char *SSL_get_psk_identity_hint(const SSL *s);
MOC_EXTERN const char *SSL_get_psk_identity(const SSL *s);
MOC_EXTERN int SSL_CTX_add_client_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  custom_ext_add_cb add_cb,
                                  custom_ext_free_cb free_cb,
                                  void *add_arg,
                                  custom_ext_parse_cb parse_cb,
                                  void *parse_arg);
MOC_EXTERN int SSL_CTX_add_server_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                                  custom_ext_add_cb add_cb,
                                  custom_ext_free_cb free_cb,
                                  void *add_arg,
                                  custom_ext_parse_cb parse_cb,
                                  void *parse_arg);
MOC_EXTERN int SSL_extension_supported(unsigned int ext_type);
MOC_EXTERN void SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *);
MOC_EXTERN int SSL_want(const SSL *s);
MOC_EXTERN int SSL_clear(SSL *s);
MOC_EXTERN void SSL_CTX_flush_sessions(SSL_CTX *ctx, long tm);
MOC_EXTERN int SSL_get_fd(const SSL *s);
MOC_EXTERN int SSL_get_rfd(const SSL *s);
MOC_EXTERN int SSL_get_wfd(const SSL *s);
MOC_EXTERN const char *SSL_get_cipher_list(const SSL *s, int n);
MOC_EXTERN char *SSL_get_shared_ciphers(const SSL *s, char *buf, int len);
MOC_EXTERN int SSL_get_read_ahead(const SSL *s);
MOC_EXTERN int (*SSL_get_verify_callback(const SSL *s)) (int, X509_STORE_CTX *);
MOC_EXTERN void SSL_set_verify_depth(SSL *s, int depth);
MOC_EXTERN void SSL_set_cert_cb(SSL *s, int (*cb) (SSL *ssl, void *arg), void *arg);
MOC_EXTERN int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);
MOC_EXTERN int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
MOC_EXTERN int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
MOC_EXTERN int SSL_use_PrivateKey_ASN1(int pk, SSL *ssl, const unsigned char *d, long len);
MOC_EXTERN int SSL_use_certificate(SSL *ssl, X509 *x);
MOC_EXTERN int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len);
MOC_EXTERN int SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
                           size_t serverinfo_length);
MOC_EXTERN int SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file);
MOC_EXTERN int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
MOC_EXTERN int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
MOC_EXTERN int SSL_use_certificate_file(SSL *ssl, const char *file, int type);
MOC_EXTERN int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs, const char *file);
MOC_EXTERN int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs, const char *dir);
MOC_EXTERN const char *SSL_rstate_string(const SSL *s);
MOC_EXTERN const char *SSL_rstate_string_long(const SSL *s);
MOC_EXTERN long SSL_SESSION_set_time(SSL_SESSION *s, long t);
MOC_EXTERN long SSL_SESSION_get_timeout(const SSL_SESSION *s);
MOC_EXTERN void SSL_copy_session_id(SSL *to, const SSL *from);
MOC_EXTERN X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
MOC_EXTERN int SSL_SESSION_set1_id_context(SSL_SESSION *s, const unsigned char *sid_ctx,
                                unsigned int sid_ctx_len);
MOC_EXTERN SSL_SESSION *SSL_SESSION_new(void);
MOC_EXTERN int SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *ses);
MOC_EXTERN int SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
MOC_EXTERN int SSL_CTX_remove_session(SSL_CTX *, SSL_SESSION *c);
MOC_EXTERN int SSL_CTX_set_generate_session_id(SSL_CTX *, GEN_SESSION_CB);
MOC_EXTERN int SSL_set_generate_session_id(SSL *, GEN_SESSION_CB);
MOC_EXTERN int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id,
                                unsigned int id_len);
MOC_EXTERN int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);
MOC_EXTERN void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
MOC_EXTERN void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb) (SSL *ssl, void *arg),
                                void *arg);
MOC_EXTERN int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d,
                                long len);
MOC_EXTERN int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx,
                                const unsigned char *d, long len);
MOC_EXTERN int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len,
                                const unsigned char *d);
MOC_EXTERN int SSL_CTX_check_private_key(const SSL_CTX *ctx);
MOC_EXTERN int SSL_CTX_set_purpose(SSL_CTX *s, int purpose);
MOC_EXTERN int SSL_set_purpose(SSL *s, int purpose);
MOC_EXTERN int SSL_CTX_set_trust(SSL_CTX *s, int trust);
MOC_EXTERN int SSL_set_trust(SSL *s, int trust);
MOC_EXTERN int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm);
MOC_EXTERN int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm);
MOC_EXTERN X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx);
MOC_EXTERN X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl);
MOC_EXTERN int SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name);
MOC_EXTERN int SSL_CTX_set_srp_password(SSL_CTX *ctx, char *password);
MOC_EXTERN int SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength);
MOC_EXTERN int SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx, char *(*cb) (SSL *, void *));
MOC_EXTERN int SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx, int (*cb) (SSL *, void *));
MOC_EXTERN int SSL_set_srp_server_param_pw(SSL *s, const char *user, const char *pass, const char *grp);
MOC_EXTERN BIGNUM *SSL_get_srp_g(SSL *s);
MOC_EXTERN BIGNUM *SSL_get_srp_N(SSL *s);
MOC_EXTERN void SSL_certs_clear(SSL *s);
MOC_EXTERN long SSL_callback_ctrl(SSL *, int, void (*)(void));
MOC_EXTERN int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);
MOC_EXTERN const SSL_METHOD *SSLv2_method(void);
MOC_EXTERN const SSL_METHOD *SSLv2_server_method(void);
MOC_EXTERN const SSL_METHOD *SSLv2_client_method(void);
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
MOC_EXTERN const SSL_METHOD *DTLSv1_method(void); /* DTLSv1.0 */
MOC_EXTERN const SSL_METHOD *DTLSv1_server_method(void); /* DTLSv1.0 */
MOC_EXTERN const SSL_METHOD *DTLSv1_client_method(void); /* DTLSv1.0 */
MOC_EXTERN const SSL_METHOD *DTLSv1_2_method(void); /* DTLSv1.2 */
MOC_EXTERN const SSL_METHOD *DTLSv1_2_server_method(void); /* DTLSv1.2 */
MOC_EXTERN const SSL_METHOD *DTLSv1_2_client_method(void); /* DTLSv1.2 */
MOC_EXTERN const SSL_METHOD *DTLS_method(void); /* DTLS 1.0 and 1.2 */
MOC_EXTERN const SSL_METHOD *DTLS_server_method(void); /* DTLS 1.0 and 1.2 */
MOC_EXTERN const SSL_METHOD *DTLS_client_method(void); /* DTLS 1.0 and 1.2 */
#endif
MOC_EXTERN int SSL_renegotiate_abbreviated(SSL *s);
MOC_EXTERN int SSL_renegotiate_pending(SSL *s);
MOC_EXTERN const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx);
MOC_EXTERN const SSL_METHOD *SSL_get_ssl_method(SSL *s);
MOC_EXTERN int SSL_set_ssl_method(SSL *s, const SSL_METHOD *method);
MOC_EXTERN const char *SSL_alert_desc_string(int value);
MOC_EXTERN int SSL_add_client_CA(SSL *ssl, X509 *x);
MOC_EXTERN long SSL_get_default_timeout(const SSL *s);
MOC_EXTERN char *SSL_CIPHER_description(const SSL_CIPHER *, char *buf, int size);
MOC_EXTERN STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk);
MOC_EXTERN SSL *SSL_dup(SSL *ssl);
MOC_EXTERN EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx);
MOC_EXTERN void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode);
MOC_EXTERN int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx);
MOC_EXTERN void SSL_set_quiet_shutdown(SSL *ssl, int mode);
MOC_EXTERN int SSL_get_quiet_shutdown(const SSL *ssl);
MOC_EXTERN int SSL_version(const SSL *ssl);
MOC_EXTERN void SSL_set_info_callback(SSL *ssl,
                                void (*cb) (const SSL *ssl, int type, int val));
MOC_EXTERN void (*SSL_get_info_callback(const SSL *ssl)) (const SSL *ssl, int type, int val);
MOC_EXTERN void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                                 void (*cb) (const SSL *ssl, int type,
                                             int val));
MOC_EXTERN void (*SSL_CTX_get_info_callback(SSL_CTX *ctx)) (const SSL *ssl, int type,
                                                   int val);
MOC_EXTERN int SSL_SESSION_set_ex_data(SSL_SESSION *ss, int idx, void *data);
MOC_EXTERN void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx);
MOC_EXTERN int SSL_SESSION_get_ex_new_index(long argl, void *argp,
                                CRYPTO_EX_new *new_func,
                                CRYPTO_EX_dup *dup_func,
                                CRYPTO_EX_free *free_func);
MOC_EXTERN int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                                CRYPTO_EX_dup *dup_func,
                                CRYPTO_EX_free *free_func);
MOC_EXTERN void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
                                RSA *(*cb) (SSL *ssl, int is_export, int keylength));
MOC_EXTERN void SSL_set_tmp_rsa_callback(SSL *ssl,
                                RSA *(*cb) (SSL *ssl, int is_export, int keylength));
MOC_EXTERN void SSL_set_tmp_dh_callback(SSL *ssl,
                                DH *(*dh) (SSL *ssl, int is_export, int keylength));
#if (defined (__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
MOC_EXTERN void SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
                                EC_KEY *(*ecdh) (SSL *ssl, int is_export, int keylength));
MOC_EXTERN void SSL_set_tmp_ecdh_callback(SSL *ssl,
                                EC_KEY *(*ecdh) (SSL *ssl, int is_export, int keylength));
#endif
MOC_EXTERN const COMP_METHOD *SSL_get_current_expansion(SSL *s);
MOC_EXTERN const char *SSL_COMP_get_name(const COMP_METHOD *comp);
MOC_EXTERN STACK_OF(SSL_COMP) *SSL_COMP_get_compression_methods(void);
MOC_EXTERN STACK_OF(SSL_COMP) *SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP) *meths);
MOC_EXTERN void SSL_COMP_free_compression_methods(void);
MOC_EXTERN int SSL_COMP_add_compression_method(int id, COMP_METHOD *cm);
MOC_EXTERN const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr);
MOC_EXTERN int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);
MOC_EXTERN int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb, void *arg);
MOC_EXTERN int SSL_set_session_secret_cb(SSL *s,
                              tls_session_secret_cb_fn tls_session_secret_cb,
                              void *arg);
MOC_EXTERN void SSL_set_debug(SSL *s, int debug);
MOC_EXTERN int SSL_cache_hit(SSL *s);
MOC_EXTERN int SSL_is_server(SSL *s);
MOC_EXTERN SSL_CONF_CTX *SSL_CONF_CTX_new(void);
MOC_EXTERN int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx);
MOC_EXTERN void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx);
MOC_EXTERN unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags);
MOC_EXTERN unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags);
MOC_EXTERN int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre);

MOC_EXTERN void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl);
MOC_EXTERN void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx);

MOC_EXTERN int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value);
MOC_EXTERN int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv);
MOC_EXTERN int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd);

MOC_EXTERN void SSL_trace(int write_p, int version, int content_type,
               const void *buf, size_t len, SSL *ssl, void *arg);
MOC_EXTERN const char *SSL_CIPHER_standard_name(const SSL_CIPHER *c);
MOC_EXTERN const struct openssl_ssl_test_functions *SSL_test_functions(void);

MOC_EXTERN void ERR_load_SSL_strings(void);
MOC_EXTERN void *SSL_CTX_get_ex_data(const SSL_CTX *ssl, int idx);
MOC_EXTERN int SSL_CTX_set_ex_data(SSL_CTX *ssl, int idx, void *data);

# define SSL_SESSION_set_app_data(s,a)   (SSL_SESSION_set_ex_data(s,0,(char *)a))
# define SSL_SESSION_get_app_data(s)     (SSL_SESSION_get_ex_data(s,0))
# define SSL_CTX_get_app_data(ctx)       (SSL_CTX_get_ex_data(ctx,0))
# define SSL_CTX_set_app_data(ctx,arg)   (SSL_CTX_set_ex_data(ctx,0,(char *)arg))

# define SSL_set_mode(ssl,op)             SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)
# define SSL_CTX_set_mode(ctx,op)         SSL_CTX_ctrl((ctx), SSL_CTRL_MODE, (op), NULL)
# define SSL_set_tlsext_host_name(s,name) \
SSL_ctrl(s,SSL_CTRL_SET_TLSEXT_HOSTNAME,TLSEXT_NAMETYPE_host_name,(char *)name)
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
int SSL_session_reused(SSL *s);
#else
# define SSL_session_reused(ssl) \
SSL_ctrl((ssl),SSL_CTRL_GET_SESSION_REUSED,0,NULL)
#endif

#if (defined (__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
#define SSL_CTX_set_ecdh_auto(ctx, onoff) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)
#define SSL_set_ecdh_auto(s, onoff) \
        SSL_ctrl(s, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)
#endif

# define SSL_CTX_set1_curves(ctx, clist, clistlen) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURVES, clistlen, (char *)clist)
# define SSL_CTX_set1_curves_list(ctx, s) \
        SSL_CTX_ctrl(ctx, SSL_CTRL_SET_CURVES_LIST, 0, (char *)s)
# define SSL_set1_curves(s, clist, clistlen) \
        SSL_ctrl(s, SSL_CTRL_SET_CURVES, clistlen, (char *)clist)
# define SSL_set1_curves_list(s, list) \
        SSL_ctrl(s, SSL_CTRL_SET_CURVES_LIST, 0, (char *)list)

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
unsigned long SSL_CTX_clear_options(SSL_CTX *ctx, unsigned long op);
#else
# define SSL_CTX_clear_options(ctx,op) \
SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_OPTIONS,(op),NULL)
#endif

#define SSL_CTX_set_tlsext_status_cb(ssl, cb) \
        SSL_CTX_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB, (void (*)(void))cb)
#define SSL_CTX_set_tlsext_status_arg(ssl, arg) \
        SSL_CTX_ctrl(ssl, SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG, 0, (void *)arg)

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define SSL_CTX_get_tlsext_status_cb(ssl, cb) \
        SSL_CTX_ctrl(ssl, SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB, 0, (void (**)(void))cb)
#define SSL_CTX_get_tlsext_status_arg(ssl, arg) \
        SSL_CTX_ctrl(ssl, SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG, 0, (void *)arg)
#endif

#endif /* __DISABLE_DIGICERT_UNSUPPORTED_OPENSSL_FN__ */

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
#define DTLSv1_listen(ssl, peer) \
SSL_ctrl(ssl,DTLS_CTRL_LISTEN,0, (void *)peer)
#endif
#endif
/* RU: END SKELETON FUNCTION DECLARATIONS */

typedef struct cipher_order_st {
      SSL_CIPHER *cipher;
      int active;
      int dead;
      struct cipher_order_st *next, *prev;
} CIPHER_ORDER;

/* Internal use only */
int register_pem_bio_handler();
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

size_t SSL_client_hello_get0_random(SSL *pSsl, const unsigned char **pRandomNumber);
size_t SSL_client_hello_get0_ciphers(SSL *pSsl, const unsigned char **pCiphers);
size_t SSL_client_hello_get0_compression_methods(SSL *pSsl, const unsigned char **pCompMethods);
size_t SSL_client_hello_get0_session_id(SSL *pSsl, const unsigned char **pSessionId);
int SSL_client_hello_get0_ext(SSL *pSsl, unsigned int extensionsType, const unsigned char **pExtensions,
                              size_t *pExtensionsLen);
unsigned int SSL_client_hello_get0_legacy_version(SSL *pSsl);
int SSL_client_hello_get1_extensions_present(SSL *s, int **pExtensions, size_t *pExtensionsLen);
int SSL_client_hello_isv2(SSL *pSsl);

int SSL_SESSION_set_protocol_version(SSL_SESSION *s, int version);
int SSL_SESSION_get_protocol_version(const SSL_SESSION *pSession);
int SSL_SESSION_set_max_early_data(SSL_SESSION *s, uint32_t max_early_data);
int SSL_SESSION_set_cipher(SSL_SESSION *s, const SSL_CIPHER *cipher);
int SSL_SESSION_set1_ticket_appdata(SSL_SESSION *ss, const void *data, size_t len);
int SSL_SESSION_set1_master_key(SSL_SESSION *sess, const unsigned char *in, size_t len);
int SSL_SESSION_set1_hostname(SSL_SESSION *s, const char *hostname);
int SSL_SESSION_set1_alpn_selected(SSL_SESSION *s,
                                         const unsigned char *alpn,
                                          size_t len);

int SSL_SESSION_is_resumable(const SSL_SESSION *s);
uint8_t SSL_SESSION_get_max_fragment_length(const SSL_SESSION *sess);
uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *s);
void SSL_SESSION_get0_ticket(const SSL_SESSION *s, const unsigned char **tick,
                             size_t *len);
int SSL_SESSION_get0_ticket_appdata(SSL_SESSION *ss, void **data, size_t *len);
void SSL_SESSION_get0_alpn_selected(const SSL_SESSION *s,
                                    const unsigned char **alpn,
                                    size_t *len);

SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *src);
int SSL_get_early_data_status(const SSL *s);
int SSL_get_key_update_type(const SSL *s);
uint32_t SSL_get_max_early_data(const SSL *s);
int SSL_set_max_early_data(SSL *s, uint32_t max_early_data);
int SSL_CTX_set_max_early_data(SSL_CTX *ctx, uint32_t max_early_data);
uint32_t SSL_CTX_get_max_early_data(const SSL_CTX *ctx);

int SSL_set_num_tickets(SSL *s, size_t num_tickets);
size_t SSL_get_num_tickets(const SSL *s);
int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t num_tickets);
size_t SSL_CTX_get_num_tickets(const SSL_CTX *ctx);

int SSL_CTX_set_recv_max_early_data(SSL_CTX *ctx, uint32_t recv_max_early_data);
uint32_t SSL_CTX_get_recv_max_early_data(const SSL_CTX *ctx);
int SSL_set_recv_max_early_data(SSL *s, uint32_t recv_max_early_data);
uint32_t SSL_get_recv_max_early_data(const SSL *s);

int SSL_verify_client_post_handshake(SSL *s);
void SSL_set_post_handshake_auth(SSL *s, int postHandshakeAuth);


void SSL_set_psk_find_session_callback(SSL *s, SSL_psk_find_session_cb_func cb);
void SSL_CTX_set_psk_find_session_callback(SSL_CTX *ctx,
                                           SSL_psk_find_session_cb_func cb);
void SSL_set_psk_use_session_callback(SSL *s, SSL_psk_use_session_cb_func cb);
void SSL_CTX_set_psk_use_session_callback(SSL_CTX *ctx,
                                          SSL_psk_use_session_cb_func cb);


int SSL_CTX_set_block_padding(SSL_CTX *ctx, size_t block_size);
int SSL_set_block_padding(SSL *ssl, size_t block_size);

/*
 * SSL_CTX_set_keylog_callback configures a callback to log key material. This
 * is intended for debugging use with tools like Wireshark. The cb function
 * should log line followed by a newline.
 */
void SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb);

/*
 * SSL_CTX_get_keylog_callback returns the callback configured by
 * SSL_CTX_set_keylog_callback.
 */
SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX *ctx);



void SSL_CTX_set_allow_early_data_cb(SSL_CTX *ctx,
                                     SSL_allow_early_data_cb_fn cb,
                                     void *arg);

void SSL_set_allow_early_data_cb(SSL *s,
                                 SSL_allow_early_data_cb_fn cb,
                                 void *arg);

int SSL_CTX_set_session_ticket_cb(SSL_CTX *ctx,
                                  SSL_CTX_generate_session_ticket_fn gen_cb,
                                  SSL_CTX_decrypt_session_ticket_fn dec_cb,
                                  void *arg);

void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *);

/* SSL_CTX_set_client_hello_cb() sets the callback function, which is automatically
called during the early stages of ClientHello processing on the server.
The argument supplied when setting the callback is passed back to the
callback at runtime.  */
void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb,
                                 void *arg);

const SSL_CIPHER *SSL_get_pending_cipher(const SSL *s);
int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int SSL_read_early_data(SSL *s, void *buf, size_t num, size_t *readbytes);
int SSL_peek_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_write_early_data(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_verify_client_post_handshake(SSL *s);
int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
                                STACK_OF(X509) *chain, int override);
int SSL_stateless(SSL *s);
int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *ctx, uint8_t mode);
int SSL_set_ciphersuites(SSL *s, const char *str);
int SSL_key_update(SSL *s, int updatetype);
int SSL_get_peer_signature_type_nid(const SSL *s, int *pnid);
int SSL_free_buffers(SSL *ssl);
int SSL_alloc_buffers(SSL *ssl);

/*
 * SSL_export_keying_material_early exports a value derived from the
 * early exporter master secret, as specified in
 * https://tools.ietf.org/html/draft-ietf-tls-tls13-23. It writes
 * |olen| bytes to |out| given a label and optional context. It
 * returns 1 on success and 0 otherwise.
 */
int SSL_export_keying_material_early(SSL *s, unsigned char *out,
                                            size_t olen, const char *label,
                                            size_t llen,
                                            const unsigned char *context,
                                            size_t contextlen);

int SSL_bytes_to_cipher_list(SSL *s, const unsigned char *bytes, size_t len,
                             int isv2format, STACK_OF(SSL_CIPHER) **sk,
                             STACK_OF(SSL_CIPHER) **scsvs);

int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
                                     const unsigned char *serverinfo,
                                     size_t serverinfo_length);

int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                                    STACK_OF(X509) *chain, int override);

void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb) (SSL *ssl,
                                       const unsigned char *cookie,
                                       size_t cookie_len));

void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*gen_stateless_cookie_cb) (SSL *ssl,
                                    unsigned char *cookie,
                                    size_t *cookie_len));

int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);

typedef int (*SSL_custom_ext_add_cb_ex)(SSL *s, unsigned int ext_type,
                                        unsigned int context,
                                        const unsigned char **out,
                                        size_t *outlen, X509 *x,
                                        size_t chainidx,
                                        int *al, void *add_arg);

typedef void (*SSL_custom_ext_free_cb_ex)(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *out,
                                          void *add_arg);

typedef int (*SSL_custom_ext_parse_cb_ex)(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx,
                                          int *al, void *parse_arg);

int SSL_CTX_add_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                           unsigned int context,
                           SSL_custom_ext_add_cb_ex add_cb,
                           SSL_custom_ext_free_cb_ex free_cb,
                           void *add_arg,
                           SSL_custom_ext_parse_cb_ex parse_cb,
                           void *parse_arg);

const EVP_MD *SSL_CIPHER_get_handshake_digest(const SSL_CIPHER *c);
uint16_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *c);
const char *OPENSSL_cipher_name(const char *rfc_name);
size_t DTLS_get_data_mtu(const SSL *s);
#define OSSL_ASYNC_FD       int

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

#define OSSL_BAD_ASYNC_FD   -1
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);

SKM_DEFINE_STACK_OF_INTERNAL(SSL_CIPHER, const SSL_CIPHER, SSL_CIPHER)
OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk,
                                            OPENSSL_sk_compfunc cmp);

#define sk_SSL_CIPHER_delete(sk, i) ((const SSL_CIPHER *)OPENSSL_sk_delete(ossl_check_SSL_CIPHER_sk_type(sk), (i)))
#define sk_SSL_CIPHER_dup(sk) ((STACK_OF(SSL_CIPHER) *)OPENSSL_sk_dup(ossl_check_const_SSL_CIPHER_sk_type(sk)))
#define sk_SSL_CIPHER_free(sk) OPENSSL_sk_free(ossl_check_SSL_CIPHER_sk_type(sk))
#define sk_SSL_CIPHER_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_SSL_CIPHER_sk_type(sk), ossl_check_SSL_CIPHER_type(ptr), (idx))
#define sk_SSL_CIPHER_new_null() ((STACK_OF(SSL_CIPHER) *)OPENSSL_sk_new_null())
#define sk_SSL_CIPHER_num(sk) OPENSSL_sk_num(ossl_check_const_SSL_CIPHER_sk_type(sk))
#define sk_SSL_CIPHER_push(sk, ptr) OPENSSL_sk_push(ossl_check_SSL_CIPHER_sk_type(sk), ossl_check_SSL_CIPHER_type(ptr))
#define sk_SSL_CIPHER_set_cmp_func(sk, cmp) ((sk_SSL_CIPHER_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_SSL_CIPHER_sk_type(sk), ossl_check_SSL_CIPHER_compfunc_type(cmp)))
#define sk_SSL_CIPHER_sort(sk) OPENSSL_sk_sort(ossl_check_SSL_CIPHER_sk_type(sk))
#define sk_SSL_CIPHER_value(sk, idx) ((const SSL_CIPHER *)OPENSSL_sk_value(ossl_check_const_SSL_CIPHER_sk_type(sk), (idx)))
#endif

#ifdef  __cplusplus
}
#endif

#endif /* __OSSL_SSL_HEADER__ */
#endif /* __DISABLE_DIGICERT_OPENSSL__ */
