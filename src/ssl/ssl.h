/*
 * ssl.h
 *
 * SSL Developer API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
@file       ssl.h
@brief      NanoSSL and NanoDTLS developer API header.
@details    This header file contains definitions, enumerations, and function
            declarations used by NanoSSL and NanoDTLS servers and clients.

@since 1.41
@version 4.2 and later

@todo_version   (post-6.4 revision to SSL_setOcspResponderUrl() signature,
                commit [35a726e], March 30, 2016. Added
                SSL_setApplicationLayerProtocol() and
                SSL_getSelectedApplicationProtocol(), commit [e6173b4], March
                21, 2016). Added TLS13_MINORVERSION #define, commit [61e569b],
                April 8. 

@flags
Whether the following flags are defined determines which function declarations
and callbacks are enabled:
+ \c \__ENABLE_DIGICERT_EAP_FAST__
+ \c \__ENABLE_DIGICERT_EXTRACT_CERT_BLOB__
+ \c \__ENABLE_DIGICERT_INNER_APP__
+ \c \__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_DUAL_MODE_API__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__
+ \c \__ENABLE_DIGICERT_SSL_KEY_EXPANSION__
+ \c \__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_NEW_HANDSHAKE__
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_CUSTOM_RNG__

@filedoc    ssl.h
*/


/*------------------------------------------------------------------*/

#ifndef __SSL_HEADER__
#define __SSL_HEADER__

#include "../crypto/hw_accel.h"
#include "../common/moc_net.h"
#include "../common/vlong.h"
#include "../common/mtcp.h"

#include "../common/sizedbuffer.h"
#ifdef __ENABLE_DIGICERT_OPENSSL_SHIM__
#include "../openssl_wrapper/openssl_shim.h"
#endif

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_chain.h"
#endif

#ifdef __ENABLE_DIGICERT_MBEDTLS_SHIM__
#include "../mbedtls_wrapper/mbedtls_shim.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* NOTE: copyed over from ike_utils.h */
#ifndef __ENABLE_DIGICERT_IPV6__

#define ZERO_MOC_IPADDR(a)      a = 0
#define ISZERO_MOC_IPADDR(a)    (0 == a)
#define SAME_MOC_IPADDR(a, b)   (a == b)
#define COPY_MOC_IPADDR(d, s)   d = s
#define REF_MOC_IPADDR(a)       a
#define GET_MOC_IPADDR4(a)      a
#define SET_MOC_IPADDR4(a, v)   a = v;
#define LT_MOC_IPADDR4(a, b)    (a < b)
#define LT_MOC_IPADDR           LT_MOC_IPADDR4
#define TEST_MOC_IPADDR6(a, _c)

#else

#ifndef AF_INET
#define AF_INET     2   /* Internet IP Protocol */
#endif

#ifndef AF_INET6        /* IP version 6 */
#if defined(__LINUX_RTOS__)
#define AF_INET6    10
#elif defined (__WIN32_RTOS__)
#define AF_INET6    23
#else
#error Must define AF_INET6
#endif
#endif

#define ZERO_MOC_IPADDR(s)      (s).family = 0;\
                                (s).uin.addr6[0] = (s).uin.addr6[1] =\
                                (s).uin.addr6[2] = (s).uin.addr6[3] = 0
#define ISZERO_MOC_IPADDR(s)    (0 == (s).family)
#define SAME_MOC_IPADDR(a, s)   ((a) && ((a)->family == (s).family) &&\
                                 (((AF_INET == (a)->family) &&\
                                   ((a)->uin.addr == (s).uin.addr))\
                                  ||\
                                  ((AF_INET6 == (a)->family) &&\
                                   ((a)->uin.addr6[0] == (s).uin.addr6[0]) &&\
                                   ((a)->uin.addr6[1] == (s).uin.addr6[1]) &&\
                                   ((a)->uin.addr6[2] == (s).uin.addr6[2]) &&\
                                   ((a)->uin.addr6[3] == (s).uin.addr6[3]))\
                                  ))
#define COPY_MOC_IPADDR(s, a)   s = *(a)
#define REF_MOC_IPADDR(s)       &(s)
#define GET_MOC_IPADDR4(a)      (a)->uin.addr
#define SET_MOC_IPADDR4(s, v)   (s).family = AF_INET; (s).uin.addr = v
#define LT_MOC_IPADDR4(x, y)    ((x).uin.addr < (y).uin.addr)

#define TEST_MOC_IPADDR6(a, _c) if (AF_INET6 == (a)->family) _c else

#define GET_MOC_IPADDR6(a)      (ubyte *) (a)->uin.addr6
#define SET_MOC_IPADDR6(s, v)   (s).family = AF_INET6;\
                                DIGI_MEMCPY((ubyte *) (s).uin.addr6, (ubyte *)(v), 16)
#define LT_MOC_IPADDR6(x, y)    ((GET_NTOHL((x).uin.addr6[0]) < GET_NTOHL((y).uin.addr6[0])) ||\
                                 (((x).uin.addr6[0] == (y).uin.addr6[0]) &&\
                                  ((GET_NTOHL((x).uin.addr6[1]) < GET_NTOHL((y).uin.addr6[1])) ||\
                                   (((x).uin.addr6[1] == (y).uin.addr6[1]) &&\
                                    ((GET_NTOHL((x).uin.addr6[2]) < GET_NTOHL((y).uin.addr6[2])) ||\
                                     (((x).uin.addr6[2] == (y).uin.addr6[2]) &&\
                                      (GET_NTOHL((x).uin.addr6[3]) < GET_NTOHL((y).uin.addr6[3]))))))))
#define LT_MOC_IPADDR(p, q)     (((p).family != (q).family) ||\
                                 ((AF_INET == (p).family) ? LT_MOC_IPADDR4(p, q) : LT_MOC_IPADDR6(p, q)))

#endif /* __ENABLE_DIGICERT_IPV6__ */

#if defined(__ENABLE_DIGICERT_TAP_OSSL_REMOTE__) || defined(__ENABLE_DIGICERT_SSL_SSLCONNECT_RENAME__)
#define SSL_connect MOC_SSL_connect
#endif

#if !defined( __ENABLE_DIGICERT_SSL_CLIENT__ ) && defined( __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__ )
#define __ENABLE_DIGICERT_SSL_CLIENT__
#endif

#if !defined( __ENABLE_DIGICERT_SSL_SERVER__ ) && defined( __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__ )
#define __ENABLE_DIGICERT_SSL_SERVER__
#endif

/* check for possible build configuration errors */
#ifndef __ENABLE_DIGICERT_SSL_DUAL_MODE_API__
#if defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) && defined(__ENABLE_DIGICERT_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)
#error SSL build configuration error.  Mixing async client w/ sync server prohibited.
#endif

#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
#error SSL build configuration error.  Mixing async server w/ sync client prohibited.
#endif
#endif /* __ENABLE_DIGICERT_SSL_DUAL_MODE_API__ */

#if defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)

#ifdef _DEBUG
#define TIMEOUT_SSL_RECV                    (0)
#define TIMEOUT_SSL_HELLO                   (0)
#else
/* timeouts in milliseconds  0 means for ever */
#define TIMEOUT_SSL_RECV                    (15000)
#define TIMEOUT_SSL_HELLO                   (15000)
#endif

#define TIMEOUT_DTLS_CONNECT_TIMED_WAIT     (2*60*1000)

#ifndef SSL_WRITE_FAIL_RETRY_TIME
#define SSL_WRITE_FAIL_RETRY_TIME           (5)
#endif

/* for reference */
#define SSL_DEFAULT_TCPIP_PORT              (443)

/* sizes */
#define SSL_SHA512_FINGER_PRINT_SIZE        (64)
#define SSL_SHA_FINGER_PRINT_SIZE           (20)
#define SSL_MD5_FINGER_PRINT_SIZE           (16)
#ifdef __UCOS_DIRECT_RTOS__
#define SSL_SYNC_BUFFER_SIZE                (512)
#else
#define SSL_SYNC_BUFFER_SIZE                (2048)
#endif /* __UCOS_DIRECT_RTOS__ */
#define SSL_MAXSESSIONIDSIZE                (32)

#ifndef SSL_MASTERSECRETSIZE
#define SSL_MASTERSECRETSIZE                (48)
#endif

#define SSL_ALPN_MAX_SIZE                   (64)

#define SSL_PSK_SERVER_IDENTITY_LENGTH      (128)  /* also max for SRP salt size */
#define SSL_PSK_MAX_LENGTH                  (64)
#define SSL_PSK_TLS13_MAX_LENGTH            (64)

#define SSL_PSK_IDENTITY_TLS13_MAX_LENGTH   (32)
#define SSL_SESSION_TICKET_NONCE_SIZE       (64)
#define SSL_PSK_TLS13_MIN_BINDER_LENGTH     (32)
#define SSL_PSK_TLS13_MAX_BINDER_LENGTH     (255)
#define SSL_TLS13_RECV_EARLY_DATA_SIZE      (16384)
#define SSL_MAX_NUM_CIPHERS                 (150)


/* SSL runtime flags */
#define SSL_FLAG_REQUIRE_MUTUAL_AUTH         (0x00000001L)
#define SSL_FLAG_NO_MUTUAL_AUTH_REQUEST      (0x00000002L)       /* for server */
#define SSL_FLAG_NO_MUTUAL_AUTH_REPLY        (0x00000002L)       /* for client */
#define SSL_FLAG_ENABLE_SEND_EMPTY_FRAME     (0x00000004L)
#define SSL_FLAG_ENABLE_SEND_BUFFER          (0x00000008L)
#define SSL_FLAG_ENABLE_RECV_BUFFER          (0x00000010L)
#define SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH  (0x00000020L)
#define SSL_FLAG_ALLOW_INSECURE_REHANDSHAKE  (0x00000080L)       /* permit legacy renegotiation */

/* DTLS runtime flags */
#define DTLS_FLAG_ENABLE_SRTP_DATA_SEND     (0x00001000L)

/* SSL runtime flags: upper 2 octect for internal use only */
#define SSL_FLAG_INTERNAL_USE                   (0xFF000000L)
#define SSL_FLAG_VERSION_SET                    (0x80000000L)
#define SSL_FLAG_MINIMUM_FALLBACK_VERSION_SET   (0x40000000L)
#define SSL_FLAG_SCSV_FALLBACK_VERSION_SET      (0x20000000L)
#define SSL_PSK_EXCHANGE_MODE_FLAG_SET          (0x10000000L)

/*TLS 1.2 SUITE B minimum level of security */
#define SSL_TLS12_MINLOS_128                 (1)
#define SSL_TLS12_MINLOS_192                 (2)

/* SSL ioctl settings */
#define SSL_SET_VERSION                         (1)
#define SSL_SET_MINIMUM_VERSION                 (2)
#define SSL_SET_SCSV_VERSION                    (3)
#define SSL_SET_RECV_TIMEOUT                    (4)
#define SSL_GET_CLIENT_RANDOM                   (5)
#define SSL_GET_SERVER_RANDOM                   (6)

/* SSL_Settings_Ioctl */
#define SSL_SETTINGS_MAX_BYTE_COUNT             (1)
#define SSL_SETTINGS_MAX_TIMER_COUNT            (2)
#define SSL_SETTINGS_GET_RECV_MAX_EARLY_DATA    (3)
#define SSL_SETTINGS_SET_RECV_MAX_EARLY_DATA    (4)

/* DTLS ioctl settings */
#define DTLS_SET_HANDSHAKE_RETRANSMISSION_TIMER (10)
#define DTLS_SET_PMTU                           (11)
#define DTLS_USE_SRTP                           (12)
#define DTLS_SET_HELLO_VERIFIED                 (13)

/* TLS v1.3 Ioctl settings */
#define SSL_REQUEST_SESSION_TICKET              (21)
#define SSL_PSK_KEY_EXCHANGE_MODE               (22)

#define SSL_GET_EARLY_DATA_STATUS               (23)
#define SSL_GET_KEY_UPDATE_DATA_TYPE            (24)

#define SSL_GET_MAX_EARLY_DATA                  (25)
#define SSL_SET_MAX_EARLY_DATA                  (26)

#define SSL_SET_NUM_TICKETS                     (27)
#define SSL_GET_NUM_TICKETS                     (28)
#define SSL_SET_SEND_EARLY_DATA                 (29)

#define SSL_SET_USE_EXTENDED_MASTERSECRET       (30)

/* TLS v1.3 Ioctl setting */
#define SSL_ENABLE_TLS13_SESSION_TICKETS        (31)

#if 0
#define SSL_SET_BLOCK_PADDING                   (32)
#define SSL_SET_MAX_FRAGMENT_LENGTH             (33)
#define SSL_GET_MAX_FRAGMENT_LENGTH             (34)
#endif

/* TLS v1.3 Ioctl setting */
#define SSL_SET_SESSION_TICKET_NONCE_LEN        (35)

/* SSL Record Header type */
#define SSL_CHANGE_CIPHER_SPEC              (20)
#define SSL_ALERT                           (21)
#define SSL_HANDSHAKE                       (22)
#define SSL_APPLICATION_DATA                (23)
#define SSL_INNER_APPLICATION               (24)
/* Enumeration for SSL_INNER_APPLICATION and SSL_HEARTBEAT is same */
#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
#define SSL_HEARTBEAT                       (24)
#endif
#define SSL_ACK                             (26)

/* SSL Alert level */
#define SSLALERTLEVEL_WARNING               (1)
#define SSLALERTLEVEL_FATAL                 (2)

/* SSL Alert description */
#define SSL_ALERT_CLOSE_NOTIFY                      (0)
#define SSL_ALERT_UNEXPECTED_MESSAGE                (10)
#define SSL_ALERT_BAD_RECORD_MAC                    (20)
#define SSL_ALERT_DECRYPTION_FAILED                 (21)
#define SSL_ALERT_RECORD_OVERFLOW                   (22)
#define SSL_ALERT_DECOMPRESSION_FAILURE             (30)
#define SSL_ALERT_HANDSHAKE_FAILURE                 (40)
#define SSL_ALERT_NO_CERTIFICATE                    (41)
#define SSL_ALERT_BAD_CERTIFICATE                   (42)
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE           (43)
#define SSL_ALERT_CERTIFICATE_REVOKED               (44)
#define SSL_ALERT_CERTIFICATE_EXPIRED               (45)
#define SSL_ALERT_CERTIFICATE_UNKNOWN               (46)
#define SSL_ALERT_ILLEGAL_PARAMETER                 (47)
#define SSL_ALERT_UNKNOWN_CA                        (48)
#define SSL_ALERT_ACCESS_DENIED                     (49)
#define SSL_ALERT_DECODE_ERROR                      (50)
#define SSL_ALERT_DECRYPT_ERROR                     (51)
#define SSL_ALERT_EXPORT_RESTRICTION                (60)
#define SSL_ALERT_PROTOCOL_VERSION                  (70)
#define SSL_ALERT_INSUFFICIENT_SECURITY             (71)
#define SSL_ALERT_INTERNAL_ERROR                    (80)
#define SSL_ALERT_INAPPROPRIATE_FALLBACK            (86)
#define SSL_ALERT_USER_CANCELED                     (90)
#define SSL_ALERT_NO_RENEGOTIATION                  (100)
#define SSL_ALERT_MISSING_EXTENSION                 (109)
#define SSL_ALERT_UNSUPPORTED_EXTENSION             (110)
#define SSL_ALERT_CERTIFICATE_UNOBTAINABLE          (111)
#define SSL_ALERT_UNRECOGNIZED_NAME                 (112)
#define SSL_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE   (113)
#define SSL_ALERT_BAD_CERTIFICATE_HASH_VALUE        (114)
#define SSL_ALERT_UNKNOWN_PSK_IDENTITY              (115)
#define SSL_ALERT_CERTIFICATE_REQUIRED              (116)
#define SSL_ALERT_NO_APPLICATION_PROTOCOL           (120)
#define SSL_ALERT_INNER_APPLICATION_FAILURE         (208)
#define SSL_ALERT_INNER_APPLICATION_VERIFICATION    (209)

#define SSL_ALERT_DIRECTION_BIT             (0x40000000)

#define SSL_CONNECTION_RENEGOTIATE          (4)
#define SSL_CONNECTION_OPEN                 (3)
#define SSL_CONNECTION_NEGOTIATE            (2)

#ifndef MIN_SSL_RSA_SIZE
#define MIN_SSL_RSA_SIZE                (2048)
#endif

#ifndef MIN_SSL_DH_SIZE
#define MIN_SSL_DH_SIZE                 (1024)
#endif

#ifndef MAX_SSL_DH_SIZE
#define MAX_SSL_DH_SIZE                 (8192)
#endif

    /* default DH group size is 2048: the values allowed are defined in
     crypto/dh.h */
#ifndef SSL_DEFAULT_DH_GROUP
#define SSL_DEFAULT_DH_GROUP            DH_GROUP_14
#endif

#define SSL3_MAJORVERSION               (3)
#define SSL3_MINORVERSION               (0)
#define TLS10_MINORVERSION              (1)
#define TLS11_MINORVERSION              (2)
#define TLS12_MINORVERSION              (3)
#define TLS13_MINORVERSION              (4)

    /* define max and min version if not specified
     disable SSLv3 by default */
#ifndef MIN_SSL_MINORVERSION
#define MIN_SSL_MINORVERSION  (TLS12_MINORVERSION)
#endif

#ifndef MAX_SSL_MINORVERSION
#ifdef __ENABLE_DIGICERT_TLS13__
#define MAX_SSL_MINORVERSION (TLS13_MINORVERSION)
#else
#define MAX_SSL_MINORVERSION (TLS12_MINORVERSION)
#endif
#endif

#define VERSION_MASK_1  (0x01)
#define VERSION_MASK_2  (0x02)
#define VERSION_MASK_3  (0x03)

#define VALID_SSL_VERSION( major, minor) (( SSL3_MAJORVERSION == major) && (MIN_SSL_MINORVERSION <= minor) && (minor <= MAX_SSL_MINORVERSION))

    /* DTLS: we should use a signed quantity for minor version and use negative numbers
     that would prevent minimum being bigger than maximum ! */
#define DTLS1_MAJORVERSION              (254)
#define DTLS10_MINORVERSION             (255)
#define DTLS12_MINORVERSION             (253)
#define DTLS13_MINORVERSION             (252)

#ifndef MIN_DTLS_MINORVERSION
#define MIN_DTLS_MINORVERSION  (DTLS12_MINORVERSION)
#endif

#ifndef MAX_DTLS_MINORVERSION
#if defined(__ENABLE_DIGICERT_TLS13__) && !defined(__ENABLE_DIGICERT_OPENSSL_SHIM__)
#define MAX_DTLS_MINORVERSION (DTLS13_MINORVERSION)
#else
#define MAX_DTLS_MINORVERSION (DTLS12_MINORVERSION)
#endif
#endif

    /* careful here since MAX_DTLS_MINORVERSION <= MIN_DTLS_MINORVERSION */
#if MIN_DTLS_MINORVERSION == (255)
#define VALID_DTLS_VERSION( major, minor) (( DTLS1_MAJORVERSION == major) && (minor >= MAX_DTLS_MINORVERSION))
#else
#define VALID_DTLS_VERSION( major, minor) (( DTLS1_MAJORVERSION == major) && ( MIN_DTLS_MINORVERSION >= minor) && (minor >= MAX_DTLS_MINORVERSION))
#endif

#define MAX_PASSWORD_SIZE   (128)

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
typedef enum
{
    noHeartbeatMessages = 0,
    peerAllowedToSend,
    peerNotAllowedToSend
} E_HeartbeatExtension;
#endif

struct AsymmetricKey;
struct certStore;

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
enum tlsExtensionTypes
{
    tlsExt_server_name = 0,
    tlsExt_max_fragment_length = 1,
    tlsExt_client_certificate_url = 2,
    tlsExt_trusted_ca_keys = 3,
    tlsExt_truncated_hmac = 4,
    tlsExt_status_request = 5,
    /* In TLS 1.2 and less tlsExt_supportedEllipticCurves = 10, */
    tlsExt_supportedGroups = 10,
    tlsExt_ECPointFormat = 11,
    tlsExt_SRP = 12,
    tlsExt_supportedSignatureAlgorithms = 13,
    dtlsExt_use_srtp = 14, /* RFC 5764 */
    tlsExt_heartbeat = 15,
    tlsExt_applicationLayerProtocolNegotiation = 16,
    tlsExt_signed_certificate_timestamp = 18,
#ifdef __ENABLE_DIGICERT_TLS13__
    tlsExt_certificate_type = 19,
    tlsExt_server_certificate_type = 20,
#endif
    tlsExt_encrypt_then_mac = 22,
    tlsExt_extendedMasterSecret = 23,
    tlsExt_ticket = 35,
#ifdef __ENABLE_DIGICERT_TLS13__
    tlsExt_pre_shared_key = 41,
    tlsExt_early_data   = 42,
    tlsExt_supported_versions = 43,
    tlsExt_cookie = 44,
    tlsExt_psk_key_exchange_modes = 45,
    tlsExt_certificateAuthorities = 47,
    tlsExt_oidFilters = 48,
    tlsExt_postHandshakeAuth    = 49,
    tlsExt_signatureAlgorithmCerts  = 50,
    tlsExt_key_share = 51,
#endif
    tlsExt_nextProtocolNegotiation = 13172,
    tlsExt_innerApplication = 37703,
    tlsExt_renegotiated_connection = 0xff01
};

#ifdef __ENABLE_DIGICERT_TLS13__
enum keyUpdateRequest
{
    keyUpdateRequest_not_requested = 0,
    keyUpdateRequest_requested = 1,
    keyUpdate_none = 255
};
#endif

#define TLS_EXT_NAMED_CURVES_ECDHE  (0x0000)
#define TLS_EXT_NAMED_CURVES_DHE    (0x0100)
#define TLS_EXT_NAMED_CURVES_PQC    (0x1100)
#define TLS_EXT_NAMED_CURVES_MASK   (0xFF00)

#define TLS_EXT_NAMED_CURVE_IS_PQC(_curve)  ((_curve & TLS_EXT_NAMED_CURVES_MASK) == TLS_EXT_NAMED_CURVES_PQC)

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
enum tlsExtNamedCurves
{
    /* Elliptic Curve Groups (ECDHE) */
    tlsExtNamedCurves_secp192r1 = TLS_EXT_NAMED_CURVES_ECDHE | 0x0013,
    tlsExtNamedCurves_secp224r1 = TLS_EXT_NAMED_CURVES_ECDHE | 0x0015,
    tlsExtNamedCurves_secp256r1 = TLS_EXT_NAMED_CURVES_ECDHE | 0x0017,
    tlsExtNamedCurves_secp384r1 = TLS_EXT_NAMED_CURVES_ECDHE | 0x0018,
    tlsExtNamedCurves_secp521r1 = TLS_EXT_NAMED_CURVES_ECDHE | 0x0019,
    tlsExtNamedCurves_x25519    = TLS_EXT_NAMED_CURVES_ECDHE | 0x001D,
    tlsExtNamedCurves_x448      = TLS_EXT_NAMED_CURVES_ECDHE | 0x001E,

    /* Finite Field Groups (DHE) */
    tlsExtNamedCurves_ffdhe2048 = TLS_EXT_NAMED_CURVES_DHE | 0x0000,
    tlsExtNamedCurves_ffdhe3072 = TLS_EXT_NAMED_CURVES_DHE | 0x0001,
    tlsExtNamedCurves_ffdhe4096 = TLS_EXT_NAMED_CURVES_DHE | 0x0002,
    tlsExtNamedCurves_ffdhe6144 = TLS_EXT_NAMED_CURVES_DHE | 0x0003,
    tlsExtNamedCurves_ffdhe8192 = TLS_EXT_NAMED_CURVES_DHE | 0x0004,
    
    tlsExtHybrid_SecP256r1MLKEM768     = TLS_EXT_NAMED_CURVES_PQC | 0x00eb,
    tlsExtHybrid_X25519MLKEM768        = TLS_EXT_NAMED_CURVES_PQC | 0x00ec,
};

#ifdef __ENABLE_DIGICERT_INNER_APP__
/**
 * @dont_show
 * @internal
 */
typedef enum innerAppType
{
    SSL_INNER_APPLICATION_DATA =0,
    SSL_INNER_INTER_FINISHED   =1,
    SSL_INNER_FINAL_FINISHED   =2,
} InnerAppType;
#endif

/**
 * @dont_show
 * @internal
 */
typedef enum nameTypeSNI
{
    nameTypeHostName = 0
    /* currently only one is supported */

} NameTypeSNI;

/* used by OCSP */
/**
 * @dont_show
 * @internal
 */
typedef enum certificateStatusType
{
    certStatusType_ocsp = 1
    /* currently only one is supported */
} CertificateStatusType;

/* New for TLS1.2: signature algorithms definitions */
typedef enum TLS_HashAlgorithm
{
    TLS_NONE        = 0,
    TLS_MD5         = 1,
    TLS_SHA1        = 2,
    TLS_SHA224      = 3,
    TLS_SHA256      = 4,
    TLS_SHA384      = 5,
    TLS_SHA512      = 6,
    TLS_INTRINSIC   = 8,
    TLS_QS          = 9,
    TLS_PRIVATE     = 254,
    TLS_HASH_MAX    = 255
} TLS_HashAlgorithm;

typedef struct sessionTicketStruct
{
    ubyte2   cipherId;
    ubyte    masterSecret[SSL_MASTERSECRETSIZE];
    ubyte4   lifeTimeHintInSec;
    TimeDate startTime;
    ubyte4   ticketLen;
    ubyte    *pTicket; /* Session ticket sent by the server */
} sessionTicket;

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This enum is for Mocana internal code use only, and
 * should not be included in the API documentation.
 *
 * Inform the server about the mode of PSK being sent.
 * The values can range from 1 to 255.
 * First 2 values are defined in TLS v1.3 draft 20.
 */
enum tlsExtPskKeyExchangeMode
{
    psk_ke = 0,/* PSK Key establishment */
    psk_dhe_ke = 1 /* PSK with (EC)DHE Key establishment  */
};

/**
 * @dont_show
 * @internal
 *
 * Enum to map hash value to be used
 */
typedef enum hashType
{
    sha1 = 0,
    sha224,
    sha256,
    sha384,
    sha512,
    md5,
    intrinsic = 8 /* for eddsa */
} hashType;


/* Below structure is based on mentioned RFC section.
 * TLS 1.3 RFC- 4.6.1.  New Session Ticket Message.
 */

typedef struct tls13PskIdentities
{
    ubyte4 pskIdentityLength;
    sbyte *pskIdentity;
    ubyte4 ticketAge;
} tls13PskIdentities;

typedef struct tls13PSK
{
    ubyte               isExternal;
    ubyte               isPSKavailable;
    ubyte4              pskTLS13LifetimeHint;
    ubyte4              pskTLS13AgeAdd;
    ubyte               ticketNonce[SSL_SESSION_TICKET_NONCE_SIZE];
    ubyte               pskTLS13[SSL_PSK_TLS13_MAX_LENGTH]; /* Max PSK length is (2^16 - 1) */
    ubyte2              pskTLS13Length;
    ubyte*              pskTLS13Identity;
    ubyte4              pskTLS13IdentityLength;
    ubyte4              obfuscatedTicketAge;
    TLS_HashAlgorithm   hashAlgo;
    TimeDate            startTime;
    ubyte4              maxEarlyDataSize;
    ubyte2              pSelectedTlsVersion;
    ubyte               selectedALPN[SSL_ALPN_MAX_SIZE];
    ubyte2              selectedCipherSuiteId;
} tls13PSK;

typedef struct tls13PSKList
{
    tls13PSK             *pPSK;
    struct tls13PSKList  *pNextPSK;
    ubyte                *pPskData;
    ubyte4                pskDataLen;
}tls13PSKList;

typedef enum
{
    earlySecret = 0,
    binderKey,
    clientEarlyTrafficSecret,
    earlyExporterMasterSecret,
    handshakeSecret,
    clientHandshakeTrafficSecret,
    serverHandshakeTrafficSecret,
    masterSecret,
    clientApplicationTrafficSecret0,
    serverApplicationTrafficSecret0,
    exporterMasterSecret,
    resumptionMasterSecret
} tls13KDFKeyType;

/*
 * The following enums indicate the state in which stack Rx/Tx application data
 * clientEarlyData indicates the early_data sent by client as part of 0-RTT
 * serverHandshakeData indicates data sent by Server following Server Finished
 * clientHandshakeData indicates data sent by Client following Client Finished
 */
typedef enum
{
    clientEarlyData = 0,
    serverHandshakeData,
    clientHandshakeData
} dataState;

/**
 * @dont_show
 * @internal
 */
typedef struct responderID
{
    ubyte responderIDlen;
    void* pResponderID;
} ResponderID;


#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)   || \
        defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)|| \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
ubyte2 SSL_getNamedCurveOfCurveId( ubyte4 curveId);
ubyte4 SSL_getCurveIdOfNamedCurve( ubyte2 namedCurve);
#endif

/* definition needed by DTLS. however the common interfaces need this definition */
/**
 * @dont_show
 * @internal
 */
typedef struct peerDescr
{
    void *pUdpDescr;
    ubyte2 srcPort;
    MOC_IP_ADDRESS_S srcAddr;
    ubyte2 peerPort;
    MOC_IP_ADDRESS_S peerAddr;
} peerDescr;

/**
@coming_soon
*/
typedef struct SrtpProfileInfo
{
    ubyte2                  profileId;                  /* profile identification */
    ubyte                   supported;                  /* support by this implementation */
    sbyte                   keySize;                    /* size of key */
    sbyte                   saltSize;                   /* size of salt */
} SrtpProfileInfo;

typedef MSTATUS (*funcPtrPasswordCallback)(
    void *pCallbackInfo,
    ubyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pOutLen
    );

/**
 * @dont_show
 * @internal
 *
 * @brief      This structure will contain the callback information required for
 *             a PKCS#8 encrypted PEM.
 *
 * @details    This structure will contain a callback and any information the
 *             callback may need. The callback information will be stored as
 *             a void pointer.
 */
typedef struct
{
  funcPtrPasswordCallback pCallback;
  void *pCallbackInfo;
} pemPasswordInfo;

/*
 * TAP_keyHandle is ubyte8
 * TAP_tokenHandle is ubyte8
 * These datatypes should be updated if TAP_keyHandle or TAP_tokenHandle change
 */
typedef struct tapKeyHandle
{
    ubyte8              keyHandle;
    ubyte8              tokenHandle;
    ubyte               certSubjectHashValue[32];
    struct tapKeyHandle *pNextHandle;
} tapKeyHandle;

/**
@brief      Configuration settings and callback function pointers for NanoSSL
            SSL/TLS clients and NanoDTLS DTLS clients.

@details    This structure is used for NanoSSL and NanoDTLS %client
            configuration.

Which products and features you've included (by defining the appropriate 
flags in moptions.h) determine which data fields and callback functions are 
present in this structure. Each included callback function should be 
customized for your application and then registered by assigning it to the 
appropriate structure function pointer(s).

@since 1.41
@version 5.8 and later

@flags
To use this structure, at least one of the following flags must be defined in moptions.h:
- \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

*/
typedef struct sslSettings
{
    ubyte                   isFIPSEnabled;

    /** @brief      Port number for the connection context.
        @details    Port number for the connection context.
        @flags
        This field is defined only if the \c \__ENABLE_DIGICERT_SSL_SERVER__ flag
        is defined in moptions.h.
    */
    ubyte4    sslListenPort;
    /** Internal use only.
    Internal use only.
    */
#ifdef __ENABLE_DIGICERT_TLS13__
    ubyte                   helloCookieSecret[2][SSL_SHA512_FINGER_PRINT_SIZE];
#else
    ubyte                   helloCookieSecret[2][SSL_SHA_FINGER_PRINT_SIZE];
#endif
    /** Internal use only.
    Internal use only.
    */
    ubyte4                  helloCookieSecretLen[2];
    /** Internal use only.
    Internal use only.
    */
    ubyte4                  helloCookieSecretLastGenTime;
    /** Internal use only.
    Internal use only.
    */
    /* indicate the helloCookieSecret version currently in use.
     * it alternates between 0 and 1 */
    ubyte                   helloCookieVersion;
    /** Internal use only.
    Internal use only.
    */
    hwAccelDescr            hwAccelCookie;          /* hardware accelerator cookie */
    /** @brief      Number of seconds to wait for connection timeout.
        @details    Number of seconds to wait for connection timeout.
        @flags
        This field is defined only if the \c \__ENABLE_DIGICERT_SSL_SERVER__ and
        \c \__ENABLE_DIGICERT_DTLS_SERVER__ flags are defined in moptions.h.
    */
    ubyte4                  sslTimeOutConnectTimedWait;

    SizedBuffer             *pClientCANameList;
    ubyte4                  numClientCANames;
    ubyte4                  recvEarlyDataSize; /* The max Early data Size, a server can receive in its lifetime;
                                                * This value should always be greater than or equal to maxEarlyDataSize
                                                * for current and all the previous sessions (since clients may have
                                                * valid session ticket with that maxEarlyDatSize)
                                                */

/** @brief      Number of seconds to wait for a \c Receive message.
    @details    Number of seconds to wait for a \c Receive message.
*/
    ubyte4    sslTimeOutReceive;
/** @brief      Number of seconds to wait for a \c Hello message.
    @details    Number of seconds to wait for a \c Hello message.
*/
    ubyte4    sslTimeOutHello;

/** @brief      Minimum RSA Key Size allowed
    @details    Minimum RSA Key Size allowed
*/
    ubyte4      minRSAKeySize;

/** @brief      Minimum DH Key Size allowed
    @details    Minimum DH Key Size allowed
*/
    ubyte4      minDHKeySize;

/** @brief      Enable or disable SHA-1 for TLS 1.2 signature algorithms.
    @details    Enable or disable SHA-1 for TLS 1.2 signature algorithms.
*/
    intBoolean  allowSha1SigAlg;

/** @brief      Enable or disable DSA signature algorithms.
    @details    Enable or disable DSA signature algorithms.
*/
    intBoolean  allowDSASigAlg;

/** @brief      Max number of bytes sent.
    @details    Max number of bytes sent.
*/
    sbyte4    maxByteCount;

/** @brief      Max timer count for rehandshake.
    @details    Max timer count for rehandshake.
*/
    sbyte4    maxTimerCountForRehandShake;

/**
@brief      Indicate time for SSL-rehandshake; applicable to clients and servers.

@details    This callback indicates that the timer or bytes sent count has
            exceeded the maximum set count, and therefore it is time for an
            SSL-rehandshake.

@remark     This callback function is applicable to synchronous clients and
            servers (even though the name includes, "Client").

@ingroup   cb_ssl_sync

@since 5.8
@version 5.8 and later

@param connectionInstance   Connection instance returned from
                            SSL_acceptConnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.
            
@callbackdoc ssl.h
*/
    sbyte4(*funcPtrClientRehandshakeRequest)(sbyte4 connectionInstance);

/**
@brief      Application defined function pointer called to update the keys.

@details    This callback indicates that the timer or bytes sent count has
            exceeded the maximum set count, and therefore it is time
            to update the application traffic secret.

@remark     This callback function is applicable to synchronous clients and
            servers.

@ingroup   cb_ssl_sync

@since 5.8
@version 5.8 and later

@param connectionInstance   Connection instance returned from
                            SSL_acceptConnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssl.h
*/
    sbyte4(*funcPtrKeyUpdateRequest)(sbyte4 connectionInstance);

/**
@brief      Indicate successful asynchronous session establishment.

@details    This callback indicates that a secure asynchronous session has been
            (re)established between peers (%client and %server). This function
            is called when an SSL-rehandshake has completed.

@ingroup    cb_ssl_async_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                            SSL_ASYNC_acceptConnection().
@param isRehandshake        True (1) indicates a rehandshake notice.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.
            
@callbackdoc ssl.h
*/
    sbyte4(*funcPtrOpenStateUpcall)(sbyte4 connectionInstance, sbyte4 isRehandshake);

/**
@brief      Decrypt and return data received through a connection context.

@details    This callback decrypts and returns data received through a
            connection context.

@ingroup    cb_ssl_async_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                            SSL_ASYNC_acceptConnection().
@param pMesg                Pointer to decrypted message.
@param mesgLen              Number of bytes in received message (\p pMesg).

@return None.
            
@callbackdoc ssl.h
*/
    void(*funcPtrReceiveUpcall)  (sbyte4 connectionInstance,
                                  ubyte *pMesg,
                                  ubyte4 mesgLen);

/**
@brief      Start a timer to use for timeout notifications.

@details    This callback starts a timer to use for timeout notifications.

@ingroup    cb_ssl_async_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from
                            SSL_ASYNC_acceptConnection().
@param msTimerExpire        Number of milliseconds until timer expires.
@param future               (Reserved for future use.)

@return None.
            
@callbackdoc ssl.h
*/
    void(*funcPtrStartTimer)     (sbyte4 connectionInstance,
                                  ubyte4 msTimerExpire,
                                  sbyte4 future);

/**
@brief      Handle the SSL timeout
@details    This callback incerease the timeout for SSL timer

@param connectionInstance   Connection instance returned from
                            SSL_ASYNC_acceptConnection().
@param msTime               Pointer to adjusted timeout value.

@return     \c OK (0) if successful; otherwise a negative number
            error code definition from merrors.h. To retrieve a string
            containing an English text error identifier corresponding to the
            function's returned error status, use the \c DISPLAY_ERROR macro.

@remark     msAdjustedTime > 0; restart the timer with msAdjustedTimeout
            msAdjustedTime = 0; Continue with the timeout

@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrSSLHandleTimeout)    (sbyte4 connectionInstance,
                                          ubyte4 *msAdjustedTime);

/**
@brief      Indicate that a secure asynchronous session has been established
            between peers.

@details    This callback indicates that a secure asynchronous session has been
            (re)established between peers (%client and %server). This function
            is called when an SSL-rehandshake has completed.

@ingroup    cb_ssl_async_client

@note       Your application should not attempt to send data through the given
            connection context until the successful session establishment
            indicated by this upcall is achieved.

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param isRehandshake        True(One) indicates a rehandshake notice.

@return     \c OK (0) if successful; otherwise a negative number
            error code definition from merrors.h. To retrieve a string
            containing an English text error identifier corresponding to the
            function's returned error status, use the \c DISPLAY_ERROR macro.
            
@callbackdoc ssl.h
*/
    sbyte4(*funcPtrClientOpenStateUpcall)(sbyte4 connectionInstance, sbyte4 isRehandshake);

/**
@brief      Retrieve data received from a server.
@details    This callback retrieves data received from a server through the
            given connection context. The data is returned through the \p pMesg
            parameter as decrypted text.

@ingroup    cb_ssl_async_client

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param pMesg                Pointer to the received decrypted message.
@param mesgLen              Number of bytes in the received message (\p pMesg).

@return None.

@callbackdoc ssl.h
*/
    void(*funcPtrClientReceiveUpcall)  (sbyte4 connectionInstance,
                                        ubyte *pMesg,
                                        ubyte4 mesgLen);

/**
@brief      Start a timer for timeout notifications.

@details    This callback starts a timer for timeout notifications.

@ingroup    cb_ssl_async_client

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param msTimerExpire        Number of milliseconds until timer expires.
@param future               (Reserved for future use.)

@return None.
            
@callbackdoc ssl.h
*/
    void(*funcPtrClientStartTimer)     (sbyte4 connectionInstance,
                                        ubyte4 msTimerExpire,
                                        sbyte4 future);

/**
@brief      Compute the signature for a certificate verify message sent for
            %client authentication.

@details    This callback function is used by an %ssl %client when it needs to
            compute the content of a certificate verify message for mutual
            authentication.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_core_client

@since 3.2
@version 3.2 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@param connectionInstance   Pointer to the SSL/TLS %client instance.
@param hash                 Pointer to hash byte string.
@param hashLen              Number of bytes in the hash byte string (\c hash).
@param result               Pointer to the signature.
@param resultLength         Number of bytes in the signature buffer (\c result).

@return     0 or a positive number if successful; for ECDSA signatures, the
            return value is the size of the signature (a DER encoded \c SEQUENCE);
            for RSA signatures, the return value has no additional significance.
            Otherwise a negative number error code definition from merrors.h.
            To retrieve a string containing an English text error identifier
            corresponding to the function's returned error status, use the \c
            DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured to use mutual authentication and
            the private key used for mutual authentication is not accessible
            (that is, it's provided by external hardware such as a smart card).
            Your implementation of this function must place the signature of
            the hash (of length \c hashLength) into this result buffer.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrMutualAuthCertificateVerify) (sbyte4 connectionInstance, const ubyte* hash,
                                    ubyte4 hashLen, ubyte* result, ubyte4 resultLength);


/**
@brief      Retrieve a server's preferred PSK.

@details    This callback function returns a hint through the \p hintPSK
            parameter indicating the server's preferred PSK. To abort the
            session, the function should return an error code (a negative value) instead of \c DISPLAY_ERROR (0).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@note   If this function isn't defined, no hint can be returned to the %client.

@ingroup    cb_ssl_core_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param hintPSK              On return, the server's preferred PSK.
@param pRetHintLength       On return, pointer to number of bytes (excluding
                            any terminating \c NULL) in \p hintPSK.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrGetHintPSK)(sbyte4 connectionInstance, ubyte hintPSK[SSL_PSK_SERVER_IDENTITY_LENGTH], ubyte4 *pRetHintLength);

/**
@brief      Save server's preferred PSK.

@details    This callback function saves associated paramter with psk 
            server's preferred PSK. To abort the session, 
            the function should return an error code (a negative value) instead of \c DISPLAY_ERROR (0).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@note   If this function isn't defined, no hint can be returned to the %client.

@ingroup    cb_ssl_core_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pServerName          Name of the server.
@param serverNameLen        Length of the server name.
@param pIdentityPSK         Pointer to buffer containing the PSK identity to
                            look up.
@param identityLengthPSK    Number of bytes in PSK identity (\p pIdentityPSK).
@param pPsk                 Serialized tls13PSk structure.
@param pskLen               Length of PSK.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrServerSavePSK)(sbyte4 connectionInstance, ubyte *pServerName, ubyte4 serverNameLen, ubyte *pIdentityPSK, ubyte4 identityLengthPSK, ubyte *pPsk, ubyte4 pskLen);

/**
@brief      Save server's preferred PSK.

@details    This callback function updates the existing psk 
            To abort the session, the function should return 
            an error code (a negative value) instead of \c DISPLAY_ERROR (0).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@note   If this function isn't defined, no hint can be returned to the %client.

@ingroup    cb_ssl_core_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pServerName          Name of the server.
@param serverNameLen        Length of the server name.
@param pIdentityPSK         Pointer to buffer containing the PSK identity to
                            look up.
@param identityLengthPSK    Number of bytes in PSK identity (\p pIdentityPSK).
@param pPskParams           Serialized tls13PSk structure.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrServerDeletePSK)(sbyte4 connectionInstance, sbyte *pServerName, ubyte4 serverNameLen, ubyte *pIdentityPSK, ubyte4 identityLengthPSK, ubyte *pPskParams);


/**
@brief      Retrieve a (based on the provided PSK's name/identity) the
            preferred PSK.

@details    This callback function looks up the specified identity (the PSK's
            name) and returns its preferred PSK&mdash;the secret used to
            encrypt data&mdash;through the \p retPSK parameter. To abort the
            session, the function should return an error code (a negative value) instead of \c DISPLAY_ERROR (0).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_core_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pIdentityPSK         Pointer to buffer containing the PSK identity to
                            look up.
@param identityLengthPSK    Number of bytes in PSK identity (\p pIdentityPSK).
@param retPSK               On return, buffer containing the identity's PSK.
@param pRetLengthPSK        On return, pointer to number of bytes in identity's
                            PSK (\p retPSK).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrLookupPSK)(sbyte4 connectionInstance, ubyte *pIdentityPSK, ubyte4 identityLengthPSK, ubyte retPSK[SSL_PSK_MAX_LENGTH], ubyte4 *pRetLengthPSK);

/**
@brief      Retrieve a (based on the provided PSK's name/identity) the
            preferred PSK params.

@details    This callback function looks up the specified identity (the PSK's
            name) and returns its preferred PSK&mdash;the secret used to
            encrypt data&mdash;through the \p retPSK parameter. To abort the
            session, the function should return an error code (a negative value) instead of \c DISPLAY_ERROR (0).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_core_server

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pIdentityPSK         Pointer to buffer containing the PSK identity to
                            look up.
@param identityLengthPSK    Number of bytes in PSK identity (\p pIdentityPSK).
@param pPsk        On return, Pointer to serialized tls13PSK structure.
@param pFreeMemory          Should stack free the memory of PSK. Application sets this value
                            when the callback is invoked. If set to true, stack frees the memory.
                            If set to FALSE, it is application's responsibility to free the memory.


@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrLookupPSKParams)(sbyte4 connectionInstance, ubyte *pIdentityPSK,
                                     ubyte4 identityLengthPSK, ubyte **pPsk,
                                     ubyte4 *pPskLen, intBoolean *pFreeMemory);

    /* Stack received Application Data; This callback is used to pass the Data to the application.
     * The parameters are connectionInstance, Data received and length of data and an additional state */
    sbyte4 (*funcPtrSSLReceiveApplicationDataCallback)(sbyte4 connectoinInstance,
                                                       ubyte *pData, ubyte4 dataLen,
                                                       dataState state);


/**
@brief      Retrieve (based on the provided hint) the chosen PSK, its
            identifying name, and their lengths.

@details    This callback function retrieves (based on the provided hint) the
            chosen PSK and its identifying name, as well as their lengths. A
            negative return status indicates that the session should be aborted.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@note   If this function isn't defined, no hint can be returned to the %client.

@ingroup    cb_ssl_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_PSK_SUPPORT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pHintPSK             Pointer to buffer containing the PSK hint&mdash;a
                            previously agreed on identifier which %client and
                            %server use to look up the PSK.
@param hintLength           Number of bytes (excluding any terminating \c NULL)
                            in \p pHintPSK.
@param retPskIdentity       On return, buffer containing the chosen PSK.
@param pRetPskIdentity      On return, pointer to number of bytes in chosen PSK
                            (\p retPskIdentity).
@param retPSK               On return, buffer containing the chosen PSK's name.
@param pRetLengthPSK        On return, pointer to number of bytes in chosen PSK's name (\p retPSK).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured for PSK support.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrChoosePSK)(sbyte4 connectionInstance, ubyte *pHintPSK, ubyte4 hintLength, ubyte retPskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH], ubyte4 *pRetPskIdentity, ubyte retPSK[SSL_PSK_MAX_LENGTH], ubyte4 *pRetLengthPSK);

/**
@brief      Do application-specific work required when the alert is received.

@details    This callback function does any application-specific work required
            when the alert is received.

            For example, a typical response upon receiving an \c
            SSL_ALERT_ACCESS_DENIED error would be to notify the %client
            application that this error has occurred.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param alertId              SSL alert code (see \ref ssl_alert_codes).
@param alertClass           Alert class (\c SSLALERTLEVEL_WARNING or \c
                            SSLALERTLEVEL_FATAL).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function for your
            application if SSL is configured to use alerts.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrAlertCallback)(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass);

/**
@brief      Determine whether to grant or ignore a %client or server
            rehandshake request.

@details    This callback function determines whether to grant or ignore a
            %client or server rehandshake rehandshake request. For example,
            this callback could count the number of rehandshake requests
            received, and choose to ignore the request after an excessive
            number of attempts (which could indicate a DoS attack).

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_core

@since 2.45
@version 2.45 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_NEW_HANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance       Pointer to the SSL/TLS Client instance.
@param pRetDoRehandshake        On return, pointer to \c TRUE if request should
                                be granted; otherwise, pointer to \c FALSE.
@param pRetDoSessionResumption  On return, pointer to \c TRUE if request should
                                be granted; otherwise, pointer to \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     You should define and customize this hookup function if the server
            should respond in some fashion to a client's rehandshake request.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrNewHandshakeCallback)(sbyte4 connectionInstance, sbyte4 *pRetDoRehandshake, sbyte4 *pRetDoSessionResumption);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
    sbyte4 (*funcPtrExtensionRequestCallback)(sbyte4 connectionInstance, ubyte4 extensionType, ubyte *pExtension, ubyte4 extensionLength);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
    sbyte4 (*funcPtrPACOpaqueCallback)(sbyte4 connectionInstance, ubyte* pPACOpaque, ubyte4 pacOpaqueLen, ubyte pacKey[/*PACKEY_SIZE*/]);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
    sbyte4 (*funcPtrInnerAppCallback)(sbyte4 connectionInstance, ubyte* data, ubyte4 dataLen);

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
    sbyte4 (*funcPtrExtensionApprovedCallback)(sbyte4 connectionInstance, ubyte4 extensionType, ubyte *pApproveExt, ubyte4 approveExtLength);


/**
@brief      Initialize SRTP cryptographic context.

@details    This callback function is called at the end of a DTLS handshake to
            initialize SRTP cryptographic context for given connectionInstance.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_srtp

@since 4.2
@version 4.2 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_SRTP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pChannelDescr        Pointer peer descriptor.
@param profileId            Profile Id.
@param keyMaterials         Opaque value that contains the SRTP key materials.
                            Its components can be retrieved from the key
                            material by using the following macro functions
                            (defined in dtls_srtp.h):
                                + \c clientMasterKey
                                + \c serverMasterKey
                                + \c clientMasterSalt
                                + \c serverMasterSalt
@param mki                  Pointer to MKI (master key identifier) value, a
                            variable length value defined with TLS syntax.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrSrtpInitCallback)(sbyte4 connectionInstance, peerDescr *pChannelDescr, const SrtpProfileInfo* pProfile, void* keyMaterials, ubyte* mki);

/**
@brief      Apply SRTP profile to an RTP packet.

@details    This callback function is called by the DTLS stack at data send to
            apply the SRTP profile to an RTP packet. Using this callback is
            optional; the SRTP stack can take over the data communication
            using the DTLS-SRTP negotiated security profile.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@ingroup    cb_ssl_srtp

@since 4.2
@version 4.2 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_SRTP__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__

@param connectionInstance   Pointer to the SSL/TLS Client instance.
@param pChannelDescr        Pointer peer descriptor.
@param pData                At call, the RTP packet. On return, pointer to
                            enlarged SRTP packet.
@param pDataLength          At call, number of bytes in RTP packet (\p pData).
                            On return, pointer to number of bytes in enlarged
                            SRTP packet (\p pData).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     Be sure that the data pData buffer is large enough to accomodate the
            added bytes of the SRTP profile.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrSrtpEncodeCallback)(sbyte4 connectionInstance, peerDescr *pChannelDescr,
                                        const sbyte* pData, ubyte4 pDataLength,
                                        ubyte** encodedData, ubyte4* encodedLength);

/**
@brief      Specify the curve to use for this ECDHE or ECDH_ANON cipher suite.

@details    This callback lets you specify the curve to use for this ECDHE or
            ECDH_ANON cipher suite. Using this callback is optional. If it's
            not specified, the curve will be  selected according to the global
            array \c gSupportedNamedGroup.

            Callback registration happens at session creation and
            initialization by assigning your custom callback function (which
            can have any name) to this callback pointer.

@todo_eng_review (is this for sync and/or async, client and/or server?)
 
@ingroup   cb_ssl_ungrouped
 
@since 5.5
@version 5.5 and later

@flags
To enable this callback, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__

@param connectionInstance       Pointer to the SSL/TLS Client instance.
@param cipherSuiteID            Identifier for the cipher suite.\n
                                Values are as specified per RFC 4346 for the TLS
                                Cipher Suite Registry; refer to the following
                                Web page:
                                http://www.iana.org/assignments/tls-parameters .
@param pECCCurvesList           List of ECC curves that can be possibly
                                selected.\n This is the intersection of curves
                                supported by both the client and the server.
@param eccCurvesListLength      Number of entries in PSK identity (\p
                                pIdentityPSK).
@param selectedCurveIndex       On return, the curve to use for the key
                                exchange.\n

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     Your implementation can return an error if the pECCCurvesList does
            not contain any appropriate curve. This could occur if the client
            does not support the minimum level of security you require for
            that cipher suite.
            
@callbackdoc ssl.h
*/
    sbyte4 (*funcPtrChooseECCCurve)(sbyte4 connectionInstance, ubyte2 cipherSuiteID,
                                    const enum tlsExtNamedCurves* pECCCurvesList,
                                    ubyte4 eccCurvesListLength,
                                    enum tlsExtNamedCurves* selectedCurve);

    /**
    @coming_soon
    @ingroup   cb_ssl_ungrouped

    @brief      OCSP callback for TLS 1.2 to check for OCSP status extension.

    @details    This callback is invoked by TLS 1.2 Client. The callback alerts the
                application of whether or not the server has sent the OCSP
                extension.

    @param connectionInstance       Pointer to the SSL/TLS Client instance.
    @param certStatus               \c TRUE is the server has provided an OCSP
                                    extension, otherwise \c FALSE.

    @return     \c OK (0) if the application wants to proceed with the connection;
                otherwise a negative number error code definition from merrors.h can
                be returned to terminate the connection.

    */
    sbyte4 (*funcPtrCertStatusCallback)(sbyte4 connectionInstance, intBoolean certStatus);
    /**
    @coming_soon
    @ingroup    cb_ssl_ungrouped

    @brief      OCSP callback invoked during OCSP message processing.

    @details    This callback is invoked by the client or server after an OCSP
                message is processed. The application may decide to proceed or
                terminate the connection based on the provided certificate,
                OCSP message, and OCSP status.

    @param connectionInstance       Pointer to the SSL/TLS Client instance.
    @param pCert                    Pointer to the certificate for which the
                                    OCSP message is intended for.
    @param certLen                  Length of the certificate.
    @param pOcspResp                Pointer to the OCSP message provided by the
                                    peer.
    @param ocspRespLen              Length of the OCSP message.
    @param ocspStatus               Status returned by NanoSSL when validating
                                    the OCSP message. \c OK (0) if
                                    successful; otherwise a negative number
                                    error code definition from merrors.h.

    @return     \c OK (0) if the application wants to proceed with the connection;
                otherwise a negative number error code definition from merrors.h can
                be returned to terminate the connection.

    */
    sbyte4 (*funcPtrSingleCertStatusCallback)(sbyte4 connectionInstance, const ubyte *pCert, ubyte4 certLen,
                                              ubyte* pOcspResp, ubyte4 ocspRespLen, sbyte4 ocspStatus);

    /**
     @brief      Specify the SRP parameters for the given identity

     @details    This callback lets you specify the SRP salt and verifier for the
     specified identity.

     @todo_eng_review : async/sync, server only

     @ingroup   cb_ssl_ungrouped

     @since 6.5
     @version 6.5 and later

     @flags
     To enable this callback, the following flags must be defined in moptions.h:
     + \c \__ENABLE_DIGICERT_SSL_SERVER__
     + \c \__ENABLE_DIGICERT_SSL_SRP__

     @param connectionInstance       Pointer to the SSL/TLS Client instance.
     @param identity                 Pointer to the identity
     @param identityLength           Length in bytes of identity
     @param numBits                  number of bits for the SRP operation\n
     Your function should return a number from the set 1024, 1536, 2048, 3172,
     4096, 6144, 8192. Some of these values might be invalid based on the value
     of the compile time defined flag __DIGICERT_MIN_SRP_BITS__ Consult RFC 5054 
     for further information about these values.
     @param salt                     Salt used when computing the verifier.
     @param saltLength               Length in bytes of salt.
     @param verifier                 Verifier for the identity.
     @param verifierLength           Length in bytes of verifier.

     @return     \c OK (0) if successful; A non zero value may be returned
     to indicate an error.

     @remark     Your implementation of this function should return the number
     of bits, the salt and the verifier for a given identity. If the identity 
     is not know, the TLS server will generate random values for this to prevent
     leaking information about the valid user names. The buffer verifier
     should be allocated with MALLOC by your implementation of this function.
     This buffers will be FREE'ed by the SSL stack.

     @callbackdoc ssl.h
     */

    sbyte4 (*funcPtrSRPCallback)(sbyte4 connectionInstance, const ubyte* identity,
                                 ubyte4 identityLength, sbyte4* numBits,
                                 ubyte salt[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                 ubyte4* saltLength,
                                 ubyte** verifier, ubyte4* verifierLength);

    ubyte  *pDHP;
    ubyte4  pLen;
    ubyte  *pDHG;
    ubyte4  gLen;
    ubyte4 lengthY;

    ubyte4 sslMinProtoVersion;
    ubyte4 sslMaxProtoVersion;

} sslSettings;

typedef sbyte4 (*SSLTransportSend)(sbyte4 sslId, sbyte *pBuffer, ubyte4 bufferLen, ubyte4 *pRetNumBytesSent);
typedef sbyte4 (*SSLTransportRecv)(sbyte4 sslId, sbyte *pRetBuffer, ubyte4 bufferSize, ubyte4 *pNumBytesReceived, ubyte4 timeout);

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
/**
@brief      Enable FIPS at runtime.

@details    This function enables FIPS mode at runtime. When FIPS is enabled,
            only a subset of ciphers, keysizes, hash algorithms and symmetric algorithms
            are supported.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_FIPS__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_setFIPSEnabled(ubyte isFIPSEnabled);

/**
@brief      Check if FIPS library is loaded correctly.

@details    This function checks if FIPS library is loaded correctly.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_FIPS__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_checkFIPS();
#endif /* __ENABLE_DIGICERT_SSL_FIPS__ */

/*------------------------------------------------------------------*/

/**
@brief      Clean up memory and mutexes and shut down the SSL stack.

@details    This function performs memory and mutex cleanup and shuts down the
            SSL stack. In rare instances, for example changing the port number
            to which an embedded device listens, you may need to completely
            stop the SSL/TLS Client/Server and all its resources. However, in
            most circumstances this is unnecessary because the NanoSSL
            %client/server is threadless.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 status = 0;

status = SSL_shutdownStack();
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_shutdownStack(void);

/**
@brief      Release memory used by internal SSL/TLS memory tables.

@details    This function releases the SSL/TLS Client's or Server's internal
            memory tables. It should only be called after a call to
            SSL_shutdownStack(). To resume communication with a device after
            calling this function, you must create a new connection and
            register encryption keys and an X.509 certificate.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 status;

status = SSL_releaseTables();
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_releaseTables(void);

/**
 *
 * @brief       Set the minimum RSA Key Size
 *
 * @details     This function dynamically sets the minimum RSA Key size,
 *              that can be used in a SSL?TLS connection.
 *
 * @ingroup     func_ssl_core
 *
 * @param keySize Indicates the keySize to be set as minimum RSA Key Size.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @remark     This function is applicable to synchronous and asynchronous
 *             clients and servers.
*/
MOC_EXTERN sbyte4 SSL_setMinRSAKeySize(ubyte4 keySize);

#if defined(__ENABLE_DIGICERT_TLS12_UNSECURE_HASH__)

/**
 *
 * @brief       Dynamically set support for SHA-1 signature algorithms,
 *
 * @details     This function dynamically enables or disables the use of the
 *              SHA-1 algorithm for signature algorithms.
 *
 * @ingroup     func_ssl_core
 *
 * @param setting Pass in TRUE to enable SHA-1 or FALSE to disable SHA-1.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @remark     This function is applicable to synchronous and asynchronous
 *             clients and servers.
*/
MOC_EXTERN sbyte4 SSL_setSha1SigAlg(intBoolean setting);
#endif

#if ((!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)) || \
     defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__))
/**
@brief      Get a socket's connection instance.

@details    This function returns a connection instance for the specified
            socket identifier. The connection instance can be used as a
            parameter in subsequent calls to NanoSSL %client and server
            functions. This function is not applicable to ASYNC mode of operation
        where the socket descriptor is not managed by (or known) to the SSL layer

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param socket   TCP/IP socket for which you want to retrieve a connection instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
sbyte4 connectionInstance;
TCP_SOCKET socketClient;

connectionInstance = SSL_getInstanceFromSocket(socketClient);
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getInstanceFromSocket(TCP_SOCKET socket);
#endif

/**
@brief      Get custom information for a connection instance.

@details    This function retrieves custom information stored in the
            connection instance's context. Your application should not call
            this function until after calls to SSL_setCookie().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCookie              On return, pointer to the cookie containing the
                              context's custom information.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
mySessionInfo *myCookie = NULL;

SSL_getCookie(connectionInstance, (int *)(&myCookie));
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getCookie(sbyte4 connectionInstance, void** pCookie);

/*
@brief      Get the TLS unique value for a connection instance.

@details    This function will return the TLS unique value to the caller. This
            function will allocate the buffer and the caller is responsible for
            freeing the buffer.

@ingroup    func_ssl_core

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pTlsUniqueLen        On return, the length in bytes of the TLS unique
                              buffer.
@param ppTlsUnique          On return, a buffer which contains the TLS unique
                              value. The caller must free this buffer.
 */
MOC_EXTERN sbyte4  SSL_getTlsUnique(sbyte4 connectionInstance,
                                    ubyte4 *pTlsUniqueLen,
                                    ubyte **ppTlsUnique);

/**
@brief      Store custom information for a connection instance.

@details    This function stores information about the context connection.
            Your application should not call this function until after calling
            SSL_connect().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param cookie               Custom information (cookie data) to store.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@code
mySessionInfo *mySession = malloc(sizeof(mySessionInfo));

SSL_setCookie(connectionInstance, (int)(&mySession));
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_setCookie(sbyte4 connectionInstance, void* cookie);

/**
@brief      Get a pointer to current context's configuration settings.

@details    This function returns a pointer to NanoSSL %client/server settings
            that can be dynamically adjusted during initialization or runtime.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@return     Pointer to NanoSSL %client/server settings that can be
            dynamically adjusted during initialization or runtime.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sslSettings* SSL_sslSettings(void);

#ifndef __DISABLE_SSL_GET_SOCKET_API__
/**
@brief      Get a connection's socket identifier.

@details    This function returns the socket identifier for the specified
            connection instance.

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flags must \b not be defined:
+ \c \__DISABLE_SSL_GET_SOCKET_API__
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetSocket           On return, pointer to the socket corresponding to
                              the connection instance.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getSocketId(sbyte4 connectionInstance, TCP_SOCKET *pRetSocket);
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_getPeerDescr(sbyte4 connectionInstance, const peerDescr **ppRetPeerDescr);
#endif /* (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) */

/**
@brief      Determine whether a connection instance represents an SSL/TLS
            %server, an SSL/TLS %client, or an unrecognized connection (for
            example, SSH).

@details    This function determines whether a given connection instance
            represents an SSL/TLS %server, an SSL/TLS %client, or an
            unrecognized connection (for example, SSH). The returned value
            will be one of the following:
            + 0&mdash;Indicates an SSL/TLS %server connection
            + 1&mdash;Indicates an SSL/TLS %client connection
            + Negative number&mdash;Indicates an unknown connection type

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_IS_SESSION_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().

@return     0 if the connection instance is an SSL/TLS %server; 1 if an
            SSL/TLS %client; negative number if an unrecognized connection.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_isSessionSSL(sbyte4 connectionInstance);
#endif /* __DISABLE_SSL_IS_SESSION_API__ */

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
/**
@brief      Determine whether a connection instance represents a DTLS
            %server, a DTLS %client, or an unrecognized connection (for
            example, SSH).

@details    This function determines whether a given connection instance
            represents a DTLS %server, a DTLS %client, or an
            unrecognized connection (for example, SSH). The returned value
            will be one of the following:
            + 0&mdash;Indicates an DTLS %server connection
            + 1&mdash;Indicates an DTLS %client connection
            + Negative number&mdash;Indicates an unknown connection type

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from DTLS_connect().

@return     0 if the connection instance is a DTLS %server; 1 if an
            DTLS %client; negative number if an unrecognized connection.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_isSessionDTLS(sbyte4 connectionInstance);


#if defined(__ENABLE_DIGICERT_DTLS_EXT_API__)
/**
@brief      Get the time remaing until DTLS timeout

@details    This function returns the time remaining to timeout
            in the format of struct timeval.

@ingroup    func_ssl_core

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__
+ \c \__ENABLE_DIGICERT_DTLS_EXT_API__
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from DTLS_connect().
@param pTime                A pointer to the structure timeval.
                            This structure is populated with the time remaining.

@return     0 if successful, negative number for errors

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_DTLS_getTimeout(sbyte4 connectionInstance, void *pTime);

/**
@brief      Check if DTLS timer has expired.

@details    This function checks if the current DTLS timer has expired.

@ingroup    func_ssl_core

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_DTLS_SERVER__
+ \c \__ENABLE_DIGICERT_DTLS_CLIENT__
+ \c \__ENABLE_DIGICERT_DTLS_EXT_API__
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from DTLS_connect().

@return     0 if timer has NOT expired/there is no timer.
           -1 if timer has expired.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 DTLS_isTimerExpired(sbyte4 connectionInstance);
#endif /*__ENABLE_DIGICERT_DTLS_EXT_API__ */

#endif /* (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) */

#ifndef __DISABLE_SSL_SESSION_FLAGS_API__
/**
@brief      Get a connection's context (its flags).

@details    This function returns a connection's context&mdash;its flags. Your
            application can call this function any time after it calls
            SSL_connect().

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_SESSION_FLAGS_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetFlagsSSL         Pointer to the connection's flags, which have been
                              set by SSL_setSessionFlags.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getSessionFlags(sbyte4 connectionInstance, ubyte4 *pRetFlagsSSL);
#endif /* __DISABLE_SSL_SESSION_FLAGS_API__ */

/**
@brief      Get a connection's status.

@details    This function returns a connection's status: \c
            SSL_CONNECTION_OPEN or \c SSL_CONNECTION_NEGOTIATE.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h
@param connectionInstance   Connection instance returned from SSL_connect().
@param pRetStatusSSL        On successful return, session's current status: \c
                              SSL_CONNECTION_OPEN or \c SSL_CONNECTION_NEGOTIATE.


@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getSessionStatus(sbyte4 connectionInstance, ubyte4 *pRetStatusSSL);

#ifndef __DISABLE_SSL_SESSION_FLAGS_API__
/**
@brief      Store a connection's context (its flags).

@details    This function stores a connection's context&mdash;its flags. Your
            application can call this function any time after it calls
            SSL_connect().

The context flags are specified by OR-ing the desired bitmask flag
definitions, defined in ssl.h:
+ \c SSL_FLAG_ACCEPT_SERVER_NAME_LIST
+ \c SSL_FLAG_ENABLE_RECV_BUFFER
+ \c SSL_FLAG_ENABLE_SEND_BUFFER
+ \c SSL_FLAG_ENABLE_SEND_EMPTY_FRAME
+ \c SSL_FLAG_NO_MUTUAL_AUTH_REQ
+ \c SSL_FLAG_REQUIRE_MUTUAL_AUTH

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_SESSION_FLAGS_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param flagsSSL             Bitmask of flags to set for the given connection's
                              context. They can be retrieved by calling
                              SSL_getSessionFlags().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       To avoid clearing any flags that are already set, you should first
            call SSL_getSessionFlags(), then OR the returned value with the
            desired new flag, and only then call %SSL_setSessionFlags().

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_setSessionFlags(sbyte4 connectionInstance, ubyte4 flagsSSL);
#endif /* __DISABLE_SSL_SESSION_FLAGS_API__ */

#ifndef __DISABLE_SSL_IOCTL_API__
/**
@brief      Enable dynamic management of a connection's features.

@details    This function enables dynamic management (enabling and disabling)
            of selected features.

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_IOCTL_API__

@inc_file ssl.h

@param setting              SSL feature flag to dynamically alter; see SSL
                              runtime flag definitions (\c SSL_SETTINGS_*) in ssl.h.
@param value                Value to assign to the \p setting flag.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_Settings_Ioctl(ubyte4 setting, void *value);

/**
@brief      Enable dynamic management of a connection's features.

@details    This function enables dynamic management (enabling and disabling)
            of selected features for a specific SSL session's connection
            instance. (The initial value for these settings is defined in ssl.h.)

You can dynamically alter whether SSLv3, TLS 1.0, or TLS 1.1 is used by
calling this function for the \c SSL_SET_VERSION feature flag setting with
any of the following values:
- 0&mdash;Use SSLv3
- 1&mdash;Use TLS 1.0
- 2&mdash;Use TLS 1.1
- 3&mdash;Use TLS 1.2

@ingroup    func_ssl_core

@since 1.41
@version 3.06 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must \b not be defined:
+ \c \__DISABLE_SSL_IOCTL_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param setting              SSL feature flag to dynamically alter; see SSL
                              runtime flag definitions (\c SSL_FLAG_*) in ssl.h.
@param value                Value to assign to the \p setting flag.
                            Pass the value as a variable (eg : (void*)1) for the following settings:
                                setting : SSL_SET_VERSION
                                setting : SSL_SET_MINIMUM_VERSION
                                setting : SSL_SET_SCSV_VERSION
                                setting : DTLS_SET_HANDSHAKE_RETRANSMISSION_TIMER
                                setting : DTLS_SET_PMTU
                                setting : DTLS_SET_HELLO_VERIFIED
                            Pass the pointer to a variable for the following settings (eg : (void*)&value):
                                setting : DTLS_USE_SRTP

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_ioctl(sbyte4 connectionInstance, ubyte4 setting, void *value);
#endif /* __DISABLE_SSL_IOCTL_API__ */

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
/**
@brief      Get the SSL alert code for a Mocana error.

@details    This function returns the SSL alert code for the specified Mocana
            error (from merrors.h), as well as the alert class (\c
            SSLALERTLEVEL_WARNING or \c SSLALERTLEVEL_FATAL). See @ref
            ssl_alert_codes for the list of alert definitions.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param lookupError          Mocana error value to look up.
@param pRetAlertId          On return, pointer to SSL alert code.
@param pAlertClass          On return, pointer to alert class definition value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.
        
@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_lookupAlert(sbyte4 connectionInstance, sbyte4 lookupError, sbyte4 *pRetAlertId, sbyte4 *pAlertClass);

/**
@brief      Send an SSL alert message to an SSL peer.

@details    This function sends an SSL alert message to an SSL peer. Typical
            usage is to look up an error code using SSL_lookupAlert(), and
            then send the alert message using this SSL_sendAlert() function.

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
    
@inc_file ssl.h 

@param connectionInstance   Connection instance returned from SSL_connect().
@param alertId              SSL alert code.
@param alertClass           SSL alert class definition value.
        
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
        
@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_sendAlert(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass);
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */

#ifdef __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
/**
@brief      Enable specified ciphers.

@details    This function dynamically enables just those ciphers that are
            specified in the function call. If none of the specified ciphers
            match those supported by NanoSSL %client/server and enabled in
            your implementation, an error is returned.

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCipherSuiteList     Pointer to value (or array of values) representing
                            the desired cipher ID(s).\n
                            Values are as specified per RFC 4346 for the TLS
                            Cipher Suite Registry; refer to the following Web
                            page:
                            http://www.iana.org/assignments/tls-parameters .
@param listLength           Number of entries in \p pCipherSuiteList.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_enableCiphers(sbyte4 connectionInstance, const ubyte2 *pCipherSuiteList, ubyte4 listLength);

/**
@brief      Get the enabled ciphers.

@details    This functions returns the list of CipherIds enabled
            for the corresponding connection.

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param ppCipherIdList       Pointer to an empty array which will be filled by the API
                            which contains the cipherIds of the enabled ciphers.
                            Memory is allocated by the API, memory should be freed
                            by the application.
@param pCount               Number of entries in \p ppCipherIdList.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4  SSL_getCipherList(sbyte4 connectionInstance, ubyte2 **ppCipherIdList, ubyte4 *pCount);
#if defined(__ENABLE_DIGICERT_TLS13__)
/**
@brief      Set cipher, supported Groups and signature algorithm.

@details    This function sets either cipher or supported groups or
            signature algorithm for a given connection. It is
            supported in TLS 1.3 only

@ingroup    func_ssl_core

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
@flags
And the following flags have to be enabled
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pList                List of algorithms corresponding to the listType.
                            Please refer to the supported listTypes below.
@param listLength           Number of entities in the list
@param listType             Type of the list.
                                0 - Ciphers
                                1 - Supported Groups
                                2 - Signatuer Algotrithm

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN MSTATUS
SSL_setCipherAlgorithm(sbyte4 connectionInstance, ubyte2 *pList, ubyte4 listLength, ubyte4 listType);
#endif

/**
@brief      Enforces PQC algorithms for a given connection.

@details    This function sets PQC algorithms for key exchange and
            signature algorithm for a given connection. It is
            supported in TLS 1.3 only

@ingroup    func_ssl_core

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
@flags
And the following flags have to be enabled
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__
+ \c \__ENABLE_DIGICERT_PQC__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN MSTATUS
SSL_enforcePQCAlgorithm(sbyte4 connectionInstace);

/**
@brief      Disable ciphers using the specified hash algorithm (and lower).

@details    This function dynamically disables cipher algorithms with
            the specified digest or lower. This function should be invoked
            after SSL_enableCiphers(). This will ensure that weak or disabled
            digest(s) based ciphers do not get reenabled.

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param hashId               Hash enumeration available in crypto.h.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_disableCipherHashAlgorithm(sbyte4 connectionInstance, TLS_HashAlgorithm hashId);

#if defined(__ENABLE_DIGICERT_SSL_DSA_SUPPORT__)
/**
@brief      Enable/disable DSA ciphers.

@details    This function dynamically enables/disables ciphers.
            This function should be invoked after SSL_setDSACiphers().

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).


@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_SSL_DSA_SUPPORT__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param enableDSACiphers     1 - Enables DSA ciphers
                            0 - Disables DSA ciphers

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_setDSACiphers(sbyte4 connectionInstance, ubyte enableDSACiphers);
#endif

#if (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__)   || \
        defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__)|| \
        defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__) )
/**
@brief      Enable ECC curves.

@details    This function dynamically enables ECC curves that are
            specified in the function call. If none of the specified curves
            match those supported by NanoSSL %client/server and enabled in
            your implementation, an error is returned.

The function must not be called before a connection is established (see
SSL_connect() for synchronous clients, SSL_ASYNC_connect() for asynchronous
clients), but must be called before SSL_negotiateConnection() (for either
synchronous or asynchronous clients).

@ingroup    func_ssl_core

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pECCCurvesList       Pointer to value (or array of values) representing
                              the desired ECC curves.
@param listLength           Number of entries in \p pECCCurvesList.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_enableECCCurves(sbyte4 connectionInstance,
                                       enum tlsExtNamedCurves* pECCCurvesList,
                                       ubyte4 listLength);
#endif /* __ENABLE_DIGICERT_SSL_CIPHER_SUITES_SELECT__ */
#endif /* (defined( __ENABLE_DIGICERT_SSL_ECDH_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDHE_SUPPORT__) || defined(__ENABLE_DIGICERT_SSL_ECDH_ANON_SUPPORT__)) */

/**
@brief      Get a connection's ciphers and ecCurves.

@details    This function retrieves the specified connection's cipher and
            ecCurves.

@ingroup    func_ssl_core

@since 2.02
@version 2.02 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pCipherId            On return, pointer to the connection's cipher value.
@param pPeerEcCurves        On return, pointer to the connection's supported
                              ecCurves values (as a bit field built by OR-ing
                              together shift-left combinations of bits shifted
                              by the value of \c tlsExtNamedCurves enumerations).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getCipherInfo( sbyte4 connectionInstance, ubyte2* pCipherId, ubyte4* pPeerEcCurves);

/**
@brief      Get a connection's SSL/TLS version

@details    This function retrieves the specified connection's SSL/TLS version.

@todo_eng_review (is this for sync and/or async, client and/or server?)

@ingroup    func_ssl_ungrouped

@since 2.02
@version 2.02 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pVersion             On return, pointer to the connection's SSL version.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.


@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getSSLTLSVersion( sbyte4 connectionInstance, ubyte4* pVersion);

/**
@brief      Set the Application Layer Protocol Negotiation information.

@details    This function sets (defines) the application layer protocols to
            use during connection negotiations.

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@todo_eng_review    Please review the function and param descriptions to
                    ensure that the Tech Pubs edits are ok.

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param  connectionInstance  Connection instance returned from SSL_connect().
@param  numNextProtocols    Number of elements in the \p nextProtocols array
                              of protocols to use.
@param  nextProtocols       Array of protocols to use, in order of preference.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_setApplicationLayerProtocol(sbyte4 connectionInstance,
                                                   sbyte4 numNextProtocols,
                                                   const char** nextProtocols);

#if defined(__ENABLE_DIGICERT_SSL_HEARTBEAT_RFC_6520__)
MOC_EXTERN MSTATUS SSL_sendHeartbeatMessage(sbyte4 connectionInstance);

MOC_EXTERN MSTATUS SSL_enableHeartbeatSupport(sbyte4 connectionInstance, E_HeartbeatExtension value,
                                              sbyte4 (*funcPtrHeatbeatMessageCallback)(sbyte4 connectionInstance,
                                                                                       sbyte4 status, ubyte heartbeatType));
#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
/**
@brief      Set the CA list that will be sent as part of Certificate Request message.

@details    This function sets CA list sent as part of Certificate Request message
            during connection negotiations. Client should send a certificate
            who issuer is one in the CA list

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version


@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param  pClientCAList       List of CA Names. This is a SizedBuffer list,
                            where data of each element contains the CA X509 Name
                            and length contains the length of X509 Name
@param  numClientCANames    Number of CA Names in the list.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            servers.

@funcdoc ssl.c
*/

MOC_EXTERN MSTATUS SSL_setClientCAList(SizedBuffer *pClientCAList, ubyte4 numClientCANames);
#endif

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
MOC_EXTERN sbyte4 SSL_setCertifcateStatusRequestExtensions(sbyte4 connectionInstance,
                                                           char** ppTrustedResponderCertPath,
                                                           ubyte4 trustedResponderCertCount,
                                                           extensions* pExts,
                                                           ubyte4 extCount);
MOC_EXTERN MSTATUS
SSL_setOCSPCallback(sbyte4 (*funcPtrSingleCertStatusCallback)(sbyte4 connectionInstance,
                                                              const ubyte *pCert, ubyte4 certLen,
                                                              ubyte* pOcspResp, ubyte4 oscpRespLen,
                                                              sbyte4 ocspStatus));
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)) && defined(__ENABLE_DIGICERT_DTLS_SRTP__) && defined(__ENABLE_DIGICERT_SRTP_PROFILES_SELECT__)
MOC_EXTERN sbyte4 SSL_setSrtpInitCallback(sbyte4(*cb)(sbyte4 connectionInstance, peerDescr *pChannelDescr,
                                                      const SrtpProfileInfo* pProfile, void* keyMaterials, ubyte* mki));
MOC_EXTERN sbyte4 SSL_setSrtpEncodeCallback(sbyte4(*cb)(sbyte4 connectionInstance, peerDescr *pChannelDescr,
                                                        const sbyte* pData, ubyte4 pDataLength,
                                                        ubyte** encodedData, ubyte4* encodedLength));
MOC_EXTERN sbyte4 SSL_enableSrtpProfiles(sbyte4 connectionInstance, ubyte2 *pSrtpProfileList, ubyte4 listLength);
#endif

#if defined(__ENABLE_DIGICERT_TLS13__)

MOC_EXTERN MSTATUS SSL_sendKeyUpdateRequest(sbyte4 connectionInstance, ubyte updateRequest);

#if (defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)) || \
     defined(__ENABLE_DIGICERT_SSL_SERVER__)
MOC_EXTERN MSTATUS SSL_getSignatureAlgo(sbyte4 connectionInstance, ubyte2 *pSigAlg);
#endif

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__) && defined(__ENABLE_DIGICERT_SSL_SERVER__)
MOC_EXTERN MSTATUS SSL_sendPosthandshakeAuthCertificateRequest(sbyte4 connectionInstance);
#endif

#if (defined(__ENABLE_DIGICERT_TLS13_PSK__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))

/**
@brief      Set the recv early data size.

@details    This function sets the recv early data size for the server.
            Server can recieve early Data of size less than or equal to
            this value. MaxEarlyDataSize per session should be less than
            or equal to this value

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flags must be defined:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__
+ \c \__ENABLE_DIGICERT_TLS13_0RTT__

@inc_file ssl.h

@param  connectionInstance  Connection instance returned from SSL_connect().
@param  earlyDataSize       recv early data size to set.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_setRecvEarlyDataSize(sbyte4 connectionInstance,
                                           sbyte4 recvEarlyDataSize);

/**
@brief      Set the max early data size.

@details    This function sets (defines) the max early data size
            use during connection negotiations.

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@todo_eng_review    Please review the function and param descriptions to
                    ensure that the Tech Pubs edits are ok.

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flags must be defined:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__
+ \c \__ENABLE_DIGICERT_TLS13_0RTT__

@inc_file ssl.h

@param  connectionInstance  Connection instance returned from SSL_connect().
@param  earlyDataSize       max early data size to set.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_setMaxEarlyDataSize(sbyte4 connectionInstance,
                                          sbyte4 earlyDataSize);

/**
@brief      Set the max early data.

@details    This function sets the early data which should be sent if 0-RTT is being used.
            The early data is not copied. It is a shallow copy.
            Application owns the memory.

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__
+ \c \__ENABLE_DIGICERT_TLS13_0RTT__

@inc_file ssl.h

@param  connectionInstance  Connection instance returned from SSL_connect().
@param  pEarlyData          Early data to set.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_setEarlyData(sbyte4 connectionInstance,
                                          ubyte* pEarlyData, ubyte4 earlyDataSize);

#endif
#endif /* __ENABLE_DIGICERT_TLS13__ */

/**
@brief      Retrieve the selected Application Layer Protocol.

@details    This function retrieves the index of the selected application
            layer protocol, and returns it in the \p .

@ingroup    func_ssl_ungrouped

@since 6.5  (added in commit [e6173b4], March 21, 2016)
@version 6.5 and later
@todo_version

@todo_eng_review    Please review the function and param descriptions to
                    ensure that the Tech Pubs edits are ok.

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param  connectionInstance              Connection instance returned from
                                          SSL_connect().
@param  selectedApplicationProtocol     On input, application protocol to
                                          search for. On return, pointer to
                                          matching socket.
@param  selectedApplicationProtocolLen  On input, length (number of bytes) in
                                          the string representing the selected
                                          application protocol (\p selected
                                          ApplicationProtocol). On return,
                                          pointer to length of string
                                          representing the mathcing socket.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous
            clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getSelectedApplicationProtocol( sbyte4 connectionInstance,
                                                      const ubyte** selectedApplicationProtocol,
                                                      ubyte4* selectedApplicationProtocolLen);

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
/**
@brief      Renegotiate an SSL/TLS session.

@details    This function renegotiates a %client or server SSL session.
            Renegotiation can be necessary in a variety of circumstances,
            including:
+ Reducing attack vulnerability after a connection has been active for a long
    time
+ Enhancing security by using stronger encryption
+ Performing mutual authentication

The peer can ignore the rehandshake request or send back an
\c SSL_ALERT_NO_RENEGOTIATION alert.

@ingroup    func_ssl_core

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_REHANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_initiateRehandshake(sbyte4 connectionInstance);

/**
@brief      Check if the rehandshake is allowed for the connection.

@details    Check if the rehandshake is allowed for the connection.

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_REHANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@param connectionInstance   Connection instance returned from SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN sbyte4 SSL_isRehandshakeAllowed(sbyte4 connectionInstance, intBoolean *pRehandshake);

/**
@brief      Timer check for rehandshaking.

@details    This function checks whether a rehandshaking request for the server
            SSL session has timed out, and if so, calls the callback
            function. If timeout occurs, it will call the callback
            function to initiate the rehandshake.

@ingroup    func_ssl_sync

@since 5.8
@version 5.8 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_REHANDSHAKE__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_checkRehandshakeTimer(sbyte4 connectionInstance);
#endif /* __ENABLE_DIGICERT_SSL_REHANDSHAKE__ */

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_getSessionInfo(sbyte4 connectionInstance, ubyte* sessionIdLen, ubyte sessionId[SSL_MAXSESSIONIDSIZE], ubyte masterSecret[SSL_MASTERSECRETSIZE]);

#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_generateExpansionKey(sbyte4 connectionInstance, ubyte *pKey,ubyte2 keyLen, ubyte *keyPhrase, ubyte2 keyPhraseLen);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_generateTLSExpansionKey(sbyte4 connectionInstance, ubyte *pKey,ubyte2 keyLen, ubyte *keyPhrase, ubyte2 keyPhraseLen);
#endif

#ifdef __ENABLE_DIGICERT_SSL_INTERNAL_STRUCT_ACCESS__
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN void*   SSL_returnPtrToSSLSocket(sbyte4 connectionInstance);
#endif

/* common client */
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/**
@brief      Get connection instance's identifying information.

@details    This function retrieves identifying information for the connection
            instance's context. This information can be saved for SSL session
            reuse, allowing subsequent connections to be made much more
            quickly than the initial connection.

@ingroup    func_ssl_core_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect
@param sessionIdLen         Pointer to number of bytes in \p sessionId.
@param sessionId            Buffer for returned session ID.
@param masterSecret         Buffer for returned master secret.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous and asynchronous clients.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_getClientSessionInfo(sbyte4 connectionInstance,
                                            ubyte* sessionIdLen,
                                            ubyte sessionId[SSL_MAXSESSIONIDSIZE],
                                            ubyte masterSecret[SSL_MASTERSECRETSIZE]);


#if defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__)
/**
@brief      Specify a list of DNS names acceptable to the %client.

@details    This function specifies a list of DNS names that when matched to
            the certificate subject name will enable a connection.

@ingroup    func_ssl_core_client

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param cnMatchInfos         Pointer to CNMatchInfo structure (defined in
                              ca_mgmt.h) containing acceptable DNS names. The \p
                              flags field is a bit combination of \p matchFlag
                              enumerations (see ca_mgmt.h). The length of the
                              array is indicated by setting the \p name field of
                              the array's final element to \c NULL.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@code
MatchInfo myMatchInfo[] = {  { 0, "yael.AMT.com"}, {1, ".intel.com"}, {0, NULL} };
SSL_setDNSNames( myConnection, myMatchInfo);
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_setDNSNames( sbyte4 connectionInstance,
                                   const CNMatchInfo* cnMatchInfo);
#endif /* __ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__ */

MOC_EXTERN sbyte4 SSL_setServerNameIndication(sbyte4 connectionInstance,
                                              const char *serverName);

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
MOC_EXTERN sbyte4 SSL_setClientSRPIdentity(sbyte4 connectionInstance,
                                           ubyte* userName,
                                           ubyte userNameLen,
                                           ubyte* password,
                                           ubyte4 passwordLen);
#endif

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#if defined(__ENABLE_DIGICERT_EAP_FAST__) && defined(__ENABLE_DIGICERT_SSL_CLIENT__)
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_setEAPFASTParams(sbyte4 connectionInstance, ubyte* pPacOpaque, ubyte4 pacOpaqueLen, ubyte pPacKey[/*PACKEY_SIZE*/]);
#endif
#if defined(__ENABLE_DIGICERT_EAP_FAST__)
MOC_EXTERN sbyte4 SSL_getEAPFAST_CHAPChallenge(sbyte4 connectionInstance, ubyte *challenge , ubyte4 challengeLen);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_getEAPFAST_IntermediateCompoundKey(sbyte4 connectionInstance, ubyte *s_imk, ubyte *msk, ubyte mskLen, ubyte *imk);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4  SSL_generateEAPFASTSessionKeys(sbyte4 connectionInstance, ubyte* S_IMCK, sbyte4 s_imckLen, ubyte* MSK, sbyte4 mskLen, ubyte* EMSK, sbyte4 emskLen);
#endif

#if (defined(__ENABLE_DIGICERT_INNER_APP__))
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 SSL_setInnerApplicationExt(sbyte4 connectionInstance, ubyte4 innerAppValue);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 SSL_sendInnerApp(sbyte4 connectionInstance, InnerAppType innerApp, ubyte* pMsg, ubyte4 msgLen,ubyte4 *retMsgLen);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 SSL_updateInnerAppSecret(sbyte4 connectionInstance, ubyte* session_key, ubyte4 sessionKeyLen);
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code (EAP stack) use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN sbyte4 SSL_verifyInnerAppVerifyData(sbyte4 connectionInstance,ubyte *data,InnerAppType appType);
#endif

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)
MOC_EXTERN sbyte4 SSL_setOcspResponderUrl(sbyte4 connectionInstance, const char* pUrl);
#endif

/* common server */
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)

#if defined(__ENABLE_DIGICERT_SSL_SRP__)
MOC_EXTERN sbyte4 SSL_getClientSRPIdentity(sbyte4 connectionInstance,
                                           const ubyte** identity,
                                           ubyte4* identityLength);

MOC_EXTERN MSTATUS SSL_setFuncPtrSRPCallback(sbyte4(*funcPtrSRPCallback)
                                             (sbyte4 connectionInstance, const ubyte* identity,
                                              ubyte4 identityLength, sbyte4* numBits,
                                              ubyte salt[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                              ubyte4* saltLength,
                                              ubyte** verifier, ubyte4* verifierLength));
#endif /* __ENABLE_DIGICERT_SSL_SRP__ */

#endif

/* common synchronous client/server */
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__))) || ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)))
/**
@brief      Initialize NanoSSL %client or server internal structures.

@details    This function initializes NanoSSL %client/server internal
            structures. Your application should call this function before
            starting the HTTPS and application servers.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param numServerConnections     Maximum number of SSL/TLS %server connections to
                                  allow. (Each connection requires only a few
                                  bytes of memory.)
@param numClientConnections     Maximum number of SSL/TLS %client connections to
                                  allow.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_init(sbyte4 numServerConnections, sbyte4 numClientConnections);

#if defined(__ENABLE_DIGICERT_SSL_CUSTOM_RNG__)
MOC_EXTERN sbyte4  SSL_initEx(sbyte4 numServerConnections, sbyte4 numClientConnections, RNGFun rngFun, void* rngArg);
#endif

/**
@brief      Establish a secure SSL client-server connection.

@details    This function performs SSL handshaking, establishing a secure
            connection between a %client and %server. Before calling this
            function, you must first create a connection context (instance) by
            calling SSL_connect().

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
sbyte4 connectionInstance;
int mySocket;

// connect to server
connect(mySocket, (struct sockaddr *)&server, sizeof(server))

// register connect, get connectionInstance
connectionInstance = SSL_connect(mySocket, 0, NULL, NULL, "mocana.com");

// set a cookie
SSL_setCookie(connectionInstance, (int)&someFutureContext);

// negotiate SSL secure connection
if (0 > SSL_negotiateConnection(connectionInstance))
    goto error;
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_negotiateConnection(sbyte4 connectionInstance);

/**
@brief      Send data to a connected server/client.

@details    This function sends data to a connected server/client. It should
            not be called until a secure SSL connection is established between
            the %client and %server. A negative return value indicates that an
            error has occurred. A return value >= 0 indicates the number of
            bytes transmitted.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pBuffer              Pointer to buffer containing the data to send.
@param bufferSize           Number of bytes in \p pBuffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
char reply[1024];
sbyte4 status;
status = SSL_send(connectionInstance, reply, strlen(reply));
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_send(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize);

/**
@brief      Get data from a connected server/client.

@details    This function retrieves data from a connected server/client. It
            should not be called until an SSL connection is established
            between the %client and %server.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pRetBuffer           Pointer to the buffer in which to write the
                              received data.
@param bufferSize           Number of bytes in receive data buffer.
@param pNumBytesReceived    On return, pointer to the number of bytes received.
@param timeout              Number of milliseconds the client/server will wait
                              to receive the message. To specify no timeout (an
                              infinite wait), set this parameter to 0.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@code
static int GetSecurePageAux(int connectionInstance, const char* pageName)
{
    char            buffer[1025];
    unsigned int    bytesSent;
    int             result = 0;

    sprintf(buffer, "GET /%s HTTP/1.0\r\n\r\n", pageName);
    bytesSent = SSL_send(connectionInstance,
                         buffer, strlen(buffer));
    if (bytesSent == strlen(buffer)) {
        int bytesReceived;

        // how to receive
        while (0 <= result) {
            memset(buffer, 0x00, 1025);
            result = SSL_recv(connectionInstance,
                              buffer, 1024, &bytesReceived, 0);
            printf("%s", buffer);
        }
        return 0;
    }

    return -1;
}
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_recv(sbyte4 connectionInstance, sbyte *pRetBuffer, sbyte4 bufferSize, sbyte4 *pNumBytesReceived, ubyte4 timeout);

/**
@brief      Determines whether there is data in a connection instance's SSL
            send buffer.

@details    This function determines whether there is data in a connection
            instance's SSL send buffer. If the send buffer is empty, zero
            (0) is returned through the \p pNumBytesPending parameter. If
            send data is pending, an attempt is made to send the data, and
            the subsequent number of bytes remaining to be sent is returned
            through the \p pNumBytesPending parameter. (A function return
            value of zero (0) indicates that the send was successful and
            that no data remains in the send buffer.)

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pNumBytesPending     On return, the number of bytes remaining in the SSL
send buffer.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_sendPending(sbyte4 connectionInstance, sbyte4 *pNumBytesPending);

/**
@brief      Test if a connection instance's SSL receive buffer contains data.

@details    This function determines whether there is data in a connection
            instance's SSL receive buffer, and returns either \c TRUE or \c
            FALSE accordingly.

@ingroup    func_ssl_sync

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().
@param pRetBooleanIsPending On return, contains \c TRUE if there is data to be
                              received, or \c FALSE if no data is pending
                              receipt.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_recvPending(sbyte4 connectionInstance, sbyte4 *pRetBooleanIsPending);

/**
@brief      Close an SSL session and release resources.

@details    This function closes a synchronous SSL session and releases all
            the resources that are managed by the NanoSSL %client/server.

@ingroup    func_ssl_sync

@since 1.41
@version 3.06 and later

@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_acceptconnection() or SSL_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4  SSL_closeConnection(sbyte4 connectionInstance);
#endif

/* common asynchronous client/server */
#if defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__)
/**
@brief      Initialize NanoSSL %client or %server internal structures.

@details    This function initializes NanoSSL %client/server internal
            structures. Your application should call this function before
            starting the HTTPS and application servers.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param numServerConnections     Maximum number of SSL/TLS %server connections to
                                  allow. (Each connection requires only a few
                                  bytes of memory.) If operating in
                                  dual mode, this is the sum of the synchronous
                                  and asynchronous %server connections.
@param numClientConnections     Maximum number of SSL/TLS %client connections to
                                  allow. If operating in dual mode, this is the
                                  sum of the synchronous and asynchronous
                                  %client connections.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_init(sbyte4 numServerConnections, sbyte4 numClientConnections);

#if defined(__ENABLE_DIGICERT_SSL_CUSTOM_RNG__)
MOC_EXTERN sbyte4 SSL_ASYNC_initEx(sbyte4 numServerConnections, sbyte4 numClientConnections, RNGFun rngFun, void* rngArg);
#endif

/**
@brief      Get a copy of data received from a connected server/client.

@details    This function retrieves data from a connected server/client and
            copies it into a new buffer. It should be called from your
            TCP/IP receive upcall handler, or from your application after
            reading a packet of data. The engine decrypts and processes the
            packet, and then calls NanoSSL server's upcall function, \p
            funcPtrReceiveUpcall, to hand off the decrypted data.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect.
@param pBytesReceived       On return, pointer to the packet or message
                              received from the TCP/IP stack.
@param numBytesReceived     On return, number of bytes in \p pBytesReceived.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function is provided for backward compatibility with earlier
            Embedded SSL/TLS implementations. New NanoSSL implementations
            should use SSL_ASYNC_recvMessage2(). The SSL_ASYNC_recvMessage2()
            function returns a pointer to the full data buffer, eliminating
            the need to consider maximum buffer sizes and manage multiple read
            calls.

@todo_techpubs (revise the note that refers to "earlier Embedded SSL/TLS
            implementations", which is quite old relative to the DSF/SoTP
            usage)

@remark     This function is applicable to asynchronous clients and servers.

@code
while ((OK == status) && (TRUE != mBreakServer))
{
    if (OK <= (status = TCP_READ_AVL(socketClient,
                                     pInBuffer,
                                     SSH_SYNC_BUFFER_SIZE,
                                     &numBytesRead,
                                     20000)))
    {
        if (0 != numBytesRead)
            status = SSL_ASYNC_recvMessage(connInstance,
                                           pInBuffer,
                                           numBytesRead);
    }

    if (ERR_TCP_READ_TIMEOUT == status)
        status = OK;
}
@endcode
@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_recvMessage(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived);

/**
@brief      Get a pointer to the connection's most recently receiveed message.

@details    This function returns a pointer (through the \p pBytesReceived
            parameter) to the specified connection's most recently received
            message. Typically, you'll call this function and then, if the
            returned number of bytes of application data is greater than 0,
            call SSL_ASYNC_getRecvBuffer() to get the pointer to the
            decrypted data.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_API_EXTENSIONS__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance       Connection instance returned from
                                  SSL_ASYNC_connect().
@param pBytesReceived           On return, pointer to the packet or message
                                  received from the TCP/IP stack.
@param numBytesReceived         On return, number of bytes in \p pBytesReceived.
@param ppRetBytesReceived       On return, pointer to buffer containing number
                                  of bytes remaining to be read.
@param pRetNumRxBytesRemaining  On return, pointer to number of bytes in \p
                                  ppRetBytesReceived.

@return     Value >= 0 is the number of bytes of application data available when
            the \c SSL_FLAG_ENABLE_RECV_BUFFER is set; otherwise a negative
            number error code definition from merrors.h. To retrieve a string
            containing an English text error identifier corresponding to the
            function's returned error %status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_recvMessage2(sbyte4 connectionInstance, ubyte *pBytesReceived, ubyte4 numBytesReceived, ubyte **ppRetBytesReceived, ubyte4 *pRetNumRxBytesRemaining);

/**
@brief      Send data to a connected server/client.

@details    This function sends data to a connected server/client. It should
            not be called until a secure SSL connection is established between
            the %client and %server.

@ingroup    func_ssl_async

@since 1.41
@version 6.4 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect.
@param pBuffer              Pointer to buffer containing the data to send.
@param bufferSize           Number of bytes in \p pBuffer.
@param pBytesSent           On return, pointer to number of bytes successfully sent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function should not be called until after a \p
            funcPtrOpenStateUpcall upcall event.

@remark     This function is applicable to asynchronous clients and servers.

@code
static void SSL_EXAMPLE_helloWorld(int connectionInstance)
{
    sbyte4 bytesSent = 0;
    sbyte4 status;

    status = SSL_ASYNC_sendMessage(connInstance,
                                   "hello world!", 12,
                                   &bytesSent);
}
@endcode

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_sendMessage(sbyte4 connectionInstance, sbyte *pBuffer, sbyte4 bufferSize, sbyte4 *pBytesSent);

/**
@brief      Determines whether there is data in a connection instance's SSL
            send buffer.

@details    This function determines whether there is data in a connection
            instance's SSL send buffer. If the send buffer is empty, the
            function returns zero (0) as its status. If send data is pending,
            an attempt is made to send the data, and the subsequent number of
            bytes remaining to be sent is returned as the function status. (A
            function return value of zero (0) indicates that the send was
            successful and that no data remains in the send buffer.)

@ingroup    func_ssl_async

@since 1.41
@version 3.06 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if the send buffer is empty or if this function
            successfully sent all remaining buffer data; otherwise the number
            of bytes remaining to be sent.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_sendMessagePending(sbyte4 connectionInstance);

/**
@brief      Close an SSL session and release resources.

@details    This function closes an asynchronous SSL session and releases all
            the resources that are managed by the NanoSSL %client/server.

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function does not close sockets or TCBs (transmission control
            blocks). Your integration code should explicitly close all TCP/IP
            sockets and TCBs.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_closeConnection(sbyte4 connectionInstance);

/**
@brief      Get a copy of the connection's send data buffer.

@details    This function returns a copy (through the \p data parameter) of the
            specified connection's most recently sent data buffer.

@ingroup    func_ssl_async

@since 1.41
@version 6.4 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param data                 On return, pointer to the buffer containing the data
                              in the connection's send buffer.
@param len                  On return pointer to number of bytes in \p data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_getSendBuffer(sbyte4 connectionInstance, ubyte *data, ubyte4 *len);

/**
@brief      Get a pointer to the connection's receive data buffer (the socket
            buffer itself).

@details    This function returns a pointer (through the \p data parameter) to
            the specified connection's most recently received data buffer (the
            socket buffer itself).

@ingroup    func_ssl_async

@since 1.41
@version 1.41 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().
@param data                 On return, pointer to the address of the
                              connection's receive buffer.
@param len                  On return pointer to number of bytes in \p data.
@param pRetProtocol         On return, the SSL protocol type for \p data
                              (usually 23 == SSL Application Data)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_getRecvBuffer(sbyte4 connectionInstance, ubyte **data, ubyte4 *len, ubyte4 *pRetProtocol);

/**
@brief      Get number of bytes to read.

@details    This function returns the the number of bytes needed to be read.

@ingroup    func_ssl_async

@since 1.41
@version 7.0 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect() or
                              SSL_ASYNC_accept().
@param len                  Pass in a pointer to a sbyte4. On return this contains the
                              number of bytes to be read

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_ASYNC_getRecvPending(sbyte4 connectionInstance, sbyte4 *len);

/**
@brief      Get a pointer reference to the connection's send data buffer.

@details    This function returns the pointer (through the \p data parameter) of the
            specified connection's most recently sent data buffer. It is suitable for
        Zero-Copy implementations. After the caller gets the pointer and transmits
        all (or some) of the data, it must call SSL_ASYNC_freeSendBufferZeroCopy()
        to indicate how much of data still remains to be transmitted before it
        makes another call to SSL_ASYNC_getSendBuffer() to send fresh data.

@ingroup    func_ssl_async

@since 1.41
@version 7.0 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect() or
                              SSL_ASYNC_accept().
@param data                 On return, contains the address of the buffer containing
                              the data in the connection's send buffer. i.e \p *data
                              has the pointer to the connection's send buffer)
@param len                  Pass in a pointer to a ubyte4. On return this contains the
                              number of bytes in the connection's send buffer (i.e \p data)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_getSendBufferZeroCopy(sbyte4 connectionInstance, ubyte **data, ubyte4 *len);

/**
@brief      Get a pointer reference to the connection's send data buffer.

@details    This function is used to indicate how many bytes of the most recently produced
            send data buffer was consumed by the caller. This call typically follows
            the call to SSL_ASYNC_getSendBufferZeroCopy() that returns the pointer to
            the send data buffer that is waiting to be transmitted. If \p numUnusedBytes
            is 0, then the send data buffer is freed. If it is not zero, then that much
            data is retained and the next call to SSL_ASYNC_getSendBufferZeroCopy() will
            return the saved data. This call is suitable for Zero-Copy implementations.

@ingroup    func_ssl_async

@since 1.41
@version 7.0 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect() or
                              SSL_ASYNC_accept().
@param numUnusedBytes       A ubyte4 value that indicates how many bytes is left over
                              from the data buffer obtained from a previous call to
                              SSL_ASYNC_getSendBufferZeroCopy().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_freeSendBufferZeroCopy(sbyte4 connectionInstance, ubyte4 numUnusedBytes);

#if (defined(__ENABLE_DIGICERT_MBEDTLS_SHIM__))
/**
@brief      Binds NanoSSL functions to be used by NanoSSL Shim layer.

@details    This function is used to bind NanoSSL functions to be used
            as callback functions in an internal data structure so that
            NanoSSL functions are used under the hood of the Shim layer.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_MBEDTLS_SHIM__

@inc_file ssl.h

@param pMeth               Pointer to data structure that stores the NanoSSL
                             functions.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_bindMbedtlsShimMethods(mssl_methods_t *pMeth);
#endif

#if (defined(__ENABLE_DIGICERT_OPENSSL_SHIM__))
/**
@brief      Binds NanoSSL functions to be used by NanoSSL Shim layer.

@details    This function is used to bind NanoSSL functions to be used
            as callback functions in an internal data structure so that
            NanoSSL functions are used under the hood of the Shim layer.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param pMeth               Pointer to data structure that stores the NanoSSL
                             functions.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_bindShimMethods(nssl_methods_t *pMeth);

/**
@brief      Convert RSA private key into Mocana's internal KeyBlob format.

@details    This function is called by the NanoSSL Shim layer to create
            an RSA private key and use the RSA parameters given to
            convert it into Mocana's internal KeyBlob format.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param pR                  Pointer to the RSA parameters.
@param ppKeyBlob           On return, pointer to the converted KeyBlob.
@param pBlobLen            On return, pointer to the length of the KeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_OSSL_RSAParamsToKeyBlob(OSSL_RSAParams *pR, void **ppKeyBlob, unsigned int *pBlobLen);
MOC_EXTERN sbyte4 SSL_getSessionStatusEx(sbyte4 connectionInstance, ubyte4 *pRetStatusSSL);
MOC_EXTERN MSTATUS SSL_decryptPKCS8PemKey(ubyte *pContent, ubyte4 contentLength, AsymmetricKey** pKey,
                                          void *pPwInfo, intBoolean base64);
MOC_EXTERN sbyte4 SSL_InitAsymmetricKey(AsymmetricKey* pAsymKey);
MOC_EXTERN sbyte4 SSL_UninitAsymmetricKey(AsymmetricKey* pAsymKey);
MOC_EXTERN sbyte4 SSL_initializeVersion();
#if defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
MOC_EXTERN sbyte4 SSL_DTLS_start(sbyte4 connectionInstance);
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
/**
@brief      Convert DSA private key into Mocana's internal KeyBlob format.

@details    This function is called by the NanoSSL Shim layer to create
            an DSA private key and use the RSA parameters given to
            convert it into Mocana's internal KeyBlob format.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__
+ \c \__ENABLE_DIGICERT_DSA__

@inc_file ssl.h

@param pD                  Pointer to the DSA parameters.
@param ppKeyBlob           On return, pointer to the converted KeyBlob.
@param pBlobLen            On return, pointer to the length of the KeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_OSSL_DSAParamsToKeyBlob(OSSL_DSAParams *pD, void **ppKeyBlob, unsigned int *pBlobLen);
#endif /* __ENABLE_DIGICERT_DSA__ */
#if (defined(__ENABLE_DIGICERT_ECC__))
/**
@brief      Convert ECC private key into Mocana's internal KeyBlob format.

@details    This function is called by the NanoSSL Shim layer to create
            an DSA private key and use the EC parameters given to
            convert it into Mocana's internal KeyBlob format.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__
+ \c \__ENABLE_DIGICERT_ECC__

@inc_file ssl.h

@param pEParams            Pointer to the ECC parameters.
@param ppKeyBlob           On return, pointer to the converted KeyBlob.
@param pBlobLen            On return, pointer to the length of the KeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_OSSL_ECCParamsToKeyBlob(OSSL_ECCParams *pEParams, void *ppKeyBlob, unsigned int *pBlobLen);
#endif /* __ENABLE_DIGICERT_ECC__ */

/**
@brief      Add a trust point to a Mocana SoT Platform certificate store.

@details    This function adds a trust point to a Mocana SoT Platform
            certificate store.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param pCertStore          Pointer to the SoT Platform certificate store
                             to which to add the trust point.
@param pDerBuf             Pointer to the trust point to add.
@param derLen              Number of bytes in the trust point.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_OSSL_AddTrustPoint(void *pCertStore, u_int8_t *pDerBuf, int derLen);

/**
@brief      Add an x509v3 certificate identity to the Mocana SoT Platform
            certificate store.

@details    This function allocates space to the Mocana SoT Platform
            certificate store and adds a valid x509v3 certificate to
            it. The certificate is verified with its private key and
            is also indexed based on key type.

            certificate store

@ingroup    func_ssl_async

@since 6.5 
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
n
Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param pCertStore          Pointer to the SoT Platform certificate store
                             that contains the SSL connection's certificates.
@param certs               Pointer to the buffer that holds certificate data.
@param numCerts            Number of certificates in SoT Platform
                             certificate store.
@param ppKeyBlob           On return, pointer to the converted KeyBlob.
@param pBlobLen            On return, pointer to the length of the KeyBlob.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_OSSL_AddIdenCertChain(void *pCertStore, OSSL_SizedBuffer *certs, unsigned numCerts,
					    const u_int8_t *pKeyBlob, unsigned keyBlobLength, ubyte *pAlias, ubyte4 aliasLen);

MOC_EXTERN sbyte4 SSL_OSSL_AddIdenCertChainExtData(void *pCertStore, OSSL_SizedBuffer *certs, unsigned numCerts,
                        const u_int8_t *pKeyBlob, unsigned keyBlobLength, ubyte *pAlias, ubyte4 aliasLen,
                        ExtendedDataCallback extDataFunc, sbyte4 extDataIdentifier);

/**
@brief      Wrapper function to register a secure asynchronous SSL/TLS connection.

@details    This function is used by the NanoSSL Shim layer to register a secure
            asynchronous SSL/TLS connection.

@ingroup    func_ssl_async_server

@since 6.5 
@version 6.5 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param tempSocket          Socket or TCP identifier returned by a call to accept().
@param pCertStore          Pointer to the SoT Platform certificate store
                             that contains the SSL connection's certificates.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_ASYNC_acceptConnectionAlt(TCP_SOCKET tempSocket, void* pCertStore);

/**
@brief      Wrapper function to create an asynchronous %client connection context.

@details    This function is used by the NanoSSL Shim layer to create a connection
            context for a secure SSL/TLS asynchronous connection with a remote
            server.

@ingroup    func_ssl_async_client

@since 6.5 
@version 6.5 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file ssl.h

@param tempSocket       Socket or TCP identifier returned by a call to connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                         terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's certificate.
@param certStore        Pointer to SoT Platform certificate store that
                         contains the SSL connection's certificate (as a
                         trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_ASYNC_connectAlt(TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte * sessionId, ubyte * masterSecret,
		     const sbyte* dnsName, void *certStore);

/**
@brief      Wrapper function to create and initialize a Mocana SoT Platform
            certificate store.

@details    This function is used by the NanoSSL Shim layer to create and
            initialize a Mocana SoT Platform certificate store container
            instance. (Multiple instances are allowed.)

@ingroup    cert_store_functions

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file cert_store.h

@param ppNewStore   Pointer to \c certStorePtr, which on return, contains the
                      newly allocated and initialized certificate store
                      container.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
MOC_EXTERN sbyte4 CERT_STORE_createStoreAlt(void **ppNewStore);

/**
@brief      Wrapper function to release (free) memory used by a
            Mocana SoT Platform certificate store.

@details    This function is used by NanoSSL Shim layer to release (free)
            memory used by a Mocana SoT Platform certificate store,
            including all its component structures.

@ingroup    cert_store_functions

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

Additionally, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OPENSSL_SHIM__

@inc_file cert_store.h

@param ppReleaseStore   Pointer to Mocana SoT Platform certificate store to
                          release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
MOC_EXTERN MSTATUS CERT_STORE_releaseStoreAlt(void **ppReleaseStore);
#endif /* __ENABLE_DIGICERT_OPENSSL_SHIM__  || __ENABLE_DIGICERT_MBEDTLS_SHIM__*/
#endif /* defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__) */
/**
@brief      Checks if a secure connection has been established.

@details    This function is needed to get Apache MOD_SSL to work
            over NanoSSL instead of OpenSSL. The function checks
            whether the connection instance is a secure connection.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise, returns 1 (not successful).

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_isSecureConnectionEstablished(sbyte4 connectionInstance);

/**
@brief      Returns the last message sent.

@details    This function returns the last message sent by the stack.

@param connectionInstance   Pointer to the SSL/TLS instance.
@param pState               On return, pointer to the local state, one of the following values
                            SSL_BEGIN                           (-1)
                            SSL_HELLO_RETRY_REQUEST             (6)
                            SSL_FINISHED                        (20)

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN sbyte4 SSL_getLocalState(sbyte4 connectionInstance, sbyte4 *pState);

/**
@brief      Return the last handshake message recived by the stack.

@details    This function returns the last handshake message/expected handshake message
            received by the stack.

@param connectionInstance   Pointer to the SSL/TLS instance.
@param pState               On return, pointer to the state, one of the following values
                            SSL_BEGIN                           (-1)
                            SSL_HELLO_REQUEST                   (0)
                            SSL_CLIENT_HELLO                    (1)
                            SSL_SERVER_HELLO                    (2)
                            SSL_SERVER_HELLO_VERIFY_REQUEST     (3)
                            SSL_NEW_SESSION_TICKET              (4)
                            SSL_CLIENT_END_OF_EARLY_DATA        (5)
                            SSL_HELLO_RETRY_REQUEST             (6)
                            SSL_ENCRYPTED_EXTENSIONS            (8)
                            SSL_CERTIFICATE                     (11)
                            SSL_SERVER_KEY_EXCHANGE             (12)
                            SSL_CERTIFICATE_REQUEST             (13)
                            SSL_SERVER_HELLO_DONE               (14)
                            SSL_CLIENT_CERTIFICATE_VERIFY       (15)
                            SSL_CLIENT_KEY_EXCHANGE             (16)
                            SSL_EXPECTING_FINISHED              (19)
                            SSL_FINISHED                        (20)
                            SSL_CERTIFICATE_STATUS              (22)
                            SSL_KEY_UPDATE                      (24)
                            SSL_MESSAGE_HASH                    (254)

@return     0 or a positive number if successful; 1 means connection is already established.
            Otherwise a negative number error code definition from merrors.h.
            To retrieve a string containing an English text error identifier
            corresponding to the function's returned error status, use the \c
            DISPLAY_ERROR macro.

*/

MOC_EXTERN sbyte4 SSL_getState(sbyte4 connectionInstance, sbyte4 *pState);

/**
@brief      Checks if the connection instance can be connected to.

@details    This function is needed to get Apache MOD_SSL to work
            over NanoSSL instead of OpenSSL. The function checks
            if the connection instance is open to allow clients
            to connect to it.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise, returns 1 (not successful).

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_in_connect_init_moc(sbyte4 connectionInstance);

/**
@brief      Checks if server accepts a secure connection.

@details    This function is needed to get Apache MOD_SSL to work
            over NanoSSL instead of OpenSSL. The function checks
            if the connection instance can accept a secure
            connection from clients.

@ingroup    func_ssl_async

@since 6.5
@version 6.5 and later

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

Additionally, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise, returns 1 (not successful).

@remark     This function is applicable to asynchronous clients and servers.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_in_accept_init_moc(sbyte4 connectionInstance);

/**
@brief      Retrieve size and length of the peer's certificate.

@details    This function retrieves the peer's certificate and
            provides the certificate's data size in terms of
            bytes and the length of the certificate.

@ingroup    cert_store_functions

@since 6.5
@version 6.5 and later

@flags
To enable this function, no flags need to be defined in moptions.h

@inc_file cert_chain.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param ppCertBytes          On return, pointer to number of bytes in
                              the certificate.
@param pCertLen             On return, pointer to the length of the
                              certificate.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cert_store.c
*/
MOC_EXTERN MSTATUS SSL_SOCK_getPeerCertificateBytes(sbyte4 connectionInstance, ubyte **ppCertBytes, ubyte4 *pCertLen);

/* sync server */
#if defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || ((defined(__ENABLE_DIGICERT_SSL_SERVER__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)))
/**
@brief      Create a synchronous server connection context.

@details    This function performs SSL handshaking, establishing a secure
            connection between a %server and %client.

@ingroup    func_ssl_sync_server

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to accept().
@param pCertStore       Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@note       This function must be called from within the HTTPS daemon context.
            If you are using multiple HTTPS daemons,  you must use a semaphore
            (mutex) around this function call. @note If your web %server and
            application %server run as separate tasks, you should protect the
            call to SSL_acceptConnection with a semaphore to prevent race
            conditions.

@remark     This function is applicable to synchronous servers only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_acceptConnection(TCP_SOCKET tempSocket,
                                        struct certStore* pCertStore);
#endif

/* sync client */
#if (!defined(__ENABLE_DIGICERT_OPENSSL_SHIM__) || defined(ENABLE_DIGICERT_TAP_OSSL_REMOTE__)) && (defined(__ENABLE_DIGICERT_SSL_DUAL_MODE_API__) || ((defined(__ENABLE_DIGICERT_SSL_CLIENT__)) && (!defined(__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__))))
/**
@brief      Create a synchronous %client connection context.

@details    This function creates a connection context for a secure SSL/TLS
            synchronous connection with a remote %server.

@ingroup    func_ssl_sync_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

@inc_file ssl.h

@param tempSocket       Socket or TCP identifier returned by a call to
                          connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's
                          certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_connect(TCP_SOCKET tempSocket,
                               ubyte sessionIdLen, ubyte * sessionId,
                               ubyte * masterSecret, const sbyte* dnsName,
                               struct certStore* certStore);

/**
@brief      Create a synchronous %client connection context with transport handlers for
            creating a connection through an existing proxy server connection.

@details    This function creates a connection context for a secure SSL/TLS
            synchronous connection with a remote %server. Transport handlers can
            be defined for connecting through an existing SSL connection to a proxy server.

@ingroup    func_ssl_sync_client

@since 1.41
@version 1.41 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to
                          connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's
                          certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to synchronous clients only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4
SSL_PROXY_connect(TCP_SOCKET sslSocket, sbyte4 sslId, SSLTransportSend transportSend, SSLTransportRecv transportRecv, 
                  TCP_SOCKET tempSocket, ubyte sessionIdLen, ubyte* sessionId, ubyte* masterSecret,
                  const sbyte* dnsName, struct certStore* certStore);

#endif

/* async server */
#ifdef __ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__
/**
@brief      Register a secure asynchronous SSL/TLS connection.

@details    This function registers a secure asynchronous SSL/TLS connection.

@ingroup    func_ssl_async_server

@since 1.41
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__

@inc_file ssl.h

@param tempSocket       Socket or TCP identifier returned by a call to accept().
@param pCertStore       Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous servers only.

@note       This function must be called from within the HTTPS daemon context.
            If you are using multiple HTTPS daemons,  you must use a semaphore
            (mutex) around this function call. @note If your web %server and
            application %server run as separate tasks, you should protect the
            call to SSL_ASYNC_acceptConnection() with a semaphore to prevent
            race conditions.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_ASYNC_acceptConnection(TCP_SOCKET tempSocket,
                                              struct certStore* pCertStore);
#endif

/* async client */
#ifdef __ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__
/**
@brief      Create an asynchronous %client connection context.

@details    This function creates a connection context for a secure SSL/TLS
            asynchronous connection with a remote %server.

@ingroup    func_ssl_async_client

@since 1.41
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param tempSocket       Socket or TCB identifier returned by a call to connect().
@param sessionIdLen     Number of bytes in \p sessionId, excluding the \c NULL
                          terminator.
@param sessionId        Pointer to session ID.
@param masterSecret     Pointer to master secret for the session.
@param dnsName          Pointer to expected DNS name of the server's certificate.
@param certStore        Pointer to SoT Platform certificate store that
                          contains the SSL connection's certificate (as a
                          trust point or identity).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients only.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4  SSL_ASYNC_connect(TCP_SOCKET tempSocket, ubyte sessionIdLen,
                                     ubyte * sessionId, ubyte * masterSecret,
                                     const sbyte* dnsName,
                                     struct certStore* pCertStore);
/**
@brief      Start establishing a secure client-server connection.

@details    This function begins the process of establishing a secure
            connection between a %client and %server by sending an SSL \c
            Hello message to a %server.

@ingroup    func_ssl_async_client

@since 1.41
@version 1.41 and later

@todo_version

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ASYNC_CLIENT_API__

@inc_file ssl.h

@param connectionInstance   Connection instance returned from
                              SSL_ASYNC_connect().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This function is applicable to asynchronous clients only.
*/
MOC_EXTERN sbyte4  SSL_ASYNC_start(sbyte4 connectionInstance);
#endif

#ifndef __DISABLE_DIGICERT_ALPN_CALLBACK__
/**  
@brief      Register an Application Layer Protocol Negotiation callback

@details    This function lets you register an application-defined callback 
             
@ingroup   cb_ssl_ungrouped

@since 6.5
@version 6.5 and later

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_SERVER__
+ \c \__ENABLE_DIGICERT_SSL_CLIENT__

Additionally, the following flag must not be defined in moptions.h:
+ \c \__DISABLE_DIGICERT_ALPN_CALLBACK__

@param connectionInstance       Connection instance returned from SSL_connect().
@param funcPtrAlpnCallback      Function pointer to a valid ALPN callback function.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to asynchronous and
            synchronous clients and servers.
*/
MOC_EXTERN MSTATUS SSL_setAlpnCallback(sbyte4 connectionInstance,
                                      sbyte4 (*funcPtrAlpnCallback) (sbyte4 connectionInstance,
                                                                     ubyte** out[],
                                                                     sbyte4* outlen,
                                                                     ubyte* in,
                                                                     sbyte4 inlen));



#endif /* __DISABLE_DIGICERT_ALPN_CALLBACK__ */

#if defined( __ENABLE_DIGICERT_SSL_ALERTS__ )

/**
@brief      Register an alert msg callback function

@details    This function lets you register an application-defined alert msg callback

@ingroup   cb_ssl_ungrouped

@flags
To enable this callback, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_ALERTS__

@param connectionInstance       Connection instance returned from SSL_connect().
@param funcPtrAlerCallback      Function pointer to a valid Alert callback function.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to asynchronous and
            synchronous clients and servers.
*/

MOC_EXTERN MSTATUS SSL_setAlertCallback(sbyte4 connectionInstance,
                                      sbyte4 (*funcPtrAlertCallback) (sbyte4 connectionInstance,
                                                                       sbyte4 alertId,
                                                                       sbyte4 alertClass));
#endif

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__

/**
@brief     Provide Certificate and its validation status from the SSL stack

@details    This function lets you register an application-defined function,
            which provides the application with the certificate used and
            its validation status. Application can perform additional checks
            on the certificate and can override the SSL stack's
            validation.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.
To disable, define tthe following flag in moptions.h
+\c \__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__

@param connectionInstance               Connection instance returned from 
                                        SSL_connect().
@param funcPtrGetCertAndStatusCallback  Function pointer to a valid 
                                        function which handles further
                                        certificate processing.
@param validationstatus                 Status returned by the SSL Stack's
                                        certificate validation steps.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to synchronous and asynchronous
            clients and servers. The function pointer passed as an argument
            provides the application with the certificate used and
            the SSL stack's validation status. The application can then perform
            additional checks on the certificate and optionally override the
            SSL stack's validation. The implementation of this function should
            return OK, to indicate that the certificate is valid irrespective
            of the SSL stack's status. The application can choose to accept the
            status proposed by the SSL stack.
            If application needs to store/modify the certificate, it should
            make a copy of the certificate.

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS
SSL_setCertAndStatusCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrGetCertAndStatusCallback) (sbyte4 connectionInstance,
                                                struct certChain* pCertChain,
                                                MSTATUS validationstatus));

/**
@brief     Provide full certificate chain from the SSL record received

@details    This function lets you register an application-defined function,
            which provides the application with the full certificate chain.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.
To disable, define tthe following flag in moptions.h
+\c \__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__

@param connectionInstance               Connection instance returned from 
                                        SSL_connect().
@param funcPtrGetOriginalCertChainCallback  Function pointer to 
                                            certificate chain.

@remark     This callback function is applicable to synchronous and asynchronous
            clients and servers. The function pointer passed as an argument
            provides the application with the full certificate chain received in
            SSL record.

            If application needs to make a copy of the certificate chain if intended
            to use after callback returns.

@callbackdoc ssl.h
*/
MOC_EXTERN MSTATUS
SSL_setFullCertChainCallback(sbyte4 connectionInstance,
    void (*funcPtrGetOriginalCertChainCallback) (sbyte4 connectionInstance,
                                                struct certChain* pCertChain));

/**
@brief     Provide certificate authorities to SSL stack for client

@details    This function lets you register an application-defined function,
            which provides the application with the certificate authorities
            provided in a certificate request message.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.
To disable, define tthe following flag in moptions.h
+\c \__DISABLE_DIGICERT_SSL_CLIENT__
+\c \__DISABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__
+\c \__DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__

@param connectionInstance               Connection instance returned from
                                        SSL_connect().
@param funcPtrClientCertAuthorityCallback     Function pointer to a valid
                                        function which handles the certificate
                                        authorities extension.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to synchronous and asynchronous
            clients and servers. The function pointer passed as an argument
            provides the application with a SizedBuffer of certificate
            authorities.

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS
SSL_setClientCertAuthorityCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrClientCertAuthorityCallback) (sbyte4 connectionInstance,
                                             SizedBuffer *pCertAuthorities,
                                             ubyte4 certAuthorityCount));

#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */

/**
@brief     Set Callback to request cert and key from the Application.

@details    This function lets you register an application-defined function,
            which provides the certificate and key to be used for a connection.
            This operation is performed during the handshake if ther certstore
            is not initialized or a suitable certificate is not found in
            the certstore. This API can only be used by Client Application.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.
To disable, define tthe following flag in moptions.h
+\c \__DISABLE_DIGICERT_SSL_CLIENT__
+\c \__DISABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

@param connectionInstance           Connection instance returned from SSL_connect().
@param funcPtrClientCertCallback    Function pointer to a valid
                                    function which provides certificate and key.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to synchronous and asynchronous
            clients. The function pointer passed as an argument
            provides a mechianish for the application to provide a cert and key
            for a given connection during the handshake.
            The implementation of this function should
            return OK and populate Cert and Key to be used by the SSL stack.
            The memory fo the cert and key is freed by the SSL stack.

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS
SSL_setClientCertCallback(sbyte4 connInstance,
        MSTATUS (*funcPtrClientCertCallback)(sbyte4 connInstance,
                                            SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                                            ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                                            ubyte **ppRetCACert, ubyte4 *pRetNumCACerts));
/**
@brief      API to set the callback to compute signature for certificate verify message
            for %client authentication.

@details    This API sets the application defined callback function which
            is used by an %ssl %client when it needs to
            compute the content of a certificate verify message for mutual
            authentication.

@param cb Application defined funcPtrMutualAuthCertificateVerify Callback

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

*/
MOC_EXTERN MSTATUS
SSL_setCertVerifySignCallback(sbyte4 (*funcPtrMutualAuthCertificateVerify)
                                     (sbyte4 connectionInstance,
                                      const ubyte* pHash, ubyte4 hashLen,
                                      ubyte* pResult, ubyte4 resultLength));


/**
@brief      Function to populate the mutual auth cert store.

@details    This function lets you populate the Mutual Auth Cert Store
            with the give Certificate, Key and CA.
            This internal cert store is used by client in mutual auth case,
            if it is not able to select a certificate from the global cert store.
            This mutual auth cert store is per session, and valid as long as
            the session is alive.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.
To disable, define tthe following flag in moptions.h
+\c \__DISABLE_DIGICERT_SSL_CLIENT__
+\c \__DISABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

@param connectionInstance Connection instance returned from SSL_connect().
@param pCerts             Certificate to add to cert store (in der format).
@param numCerts           Number of certificates in the buffer.
@param pKey               Corresponding key.
@param keyLen             Length of the key.
@param pCACerts           Buffer of CA Certs
@param caCertLength       Length of the CA Cert Buffer

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS SSL_populateMutualAuthCertStore(sbyte4 connectionInstance,
                                                   const SizedBuffer *pCerts, ubyte4 numCerts,
                                                   ubyte *pKey, ubyte4 keyLen,
                                                   const ubyte *pCACert, ubyte4 caCertLength);

#ifdef __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__
/**
@brief      Provide status to application when stack receives empty certificate.

@details    This function lets you register an application-defined function,
            which provides the application option to accept an empty
            certificate sent by the client in reponse to certificate request
            message from the server.

@ingroup   cb_ssl_ungrouped

@since
@version

@flags
To enable define the following fla in moptions.h
+\c \__ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__

@param connectionInstance               Connection instance returned from
                                        SSL_connect().
@param funcPtrInvalidCertCallback       Function pointer to a valid
                                        function which handles further
                                        invalid certificate processing.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to synchronous and asynchronous
            clients and servers. The application can choose whether to accept
            and optionally override the SSL stack's status.
            The implementation of this function should return OK, to indicate
            that the empty certificate is valid irrespective of the SSL stack's status.
            The application can choose to accept the status given by the SSL stack
            and throw out an error.
            return status >= 0; Ignore Invalid Certificate Error
            return status < 0; Process the error

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS
SSL_setInvalidCertCallback(sbyte4 connectionInstance,
    MSTATUS (*funcPtrInvalidCertCallback) (sbyte4 connectionInstance,
                                           MSTATUS validationstatus));


#endif /* __ENABLE_DIGICERT_SSL_INVALID_CERTIFICATE_CALLBACK__ */

/**
@brief     Register a version callback to record the server version and client
           version.

@details   This function allows the caller register a version callback which
           will be called during the SSL handshake process. The version callback
           will be called on the server side during the processing of the client
           hello message. The client will call the callback during the
           processing of the server hello message. Note that the return value of
           the callback does not affect how the client/server negotiates the
           version to use during a SSL handshake. This callback is primarily for
           logging the server version and client version during a SSL handshake.

@ingroup cb_ssl_ungrouped

@since
@version

@flags
Enabled by default.

@param connectionInstance           Connection instance returned from 
                                    SSL_connect().
@param funcPtrVersionCallback       Function pointer to a version callback.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@callbackdoc ssl.h
*/
MOC_EXTERN MSTATUS
SSL_setVersionCallback(
    sbyte4 connectionInstance,
    MSTATUS (*funcPtrVersionCallback)(ubyte4 serverVersion,
                                      ubyte4 clientVersion,
                                      MSTATUS sslStatus));

/**
@brief      Set the DH parameters to use during the SSL connection.

@details    This function will allow the caller to set the DH prime and
            generator values used during a SSL connection. Additionally, the
            secret value size must be provided as well. If the DH parameters are
            not specified through this function then the default DH parameters
            will be used.

@ingroup    func_ssl_core

@since
@version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_DHE_SUPPORT__
+ \c \__ENABLE_DIGICERT_SSL_DH_ANON_SUPPORT__

@inc_file ssl.h

@param pP       The DH group value. This will be a prime number.
@param pLen     Length of pP buffer.
@param pG       The DH generator value. This value will be used to generate a
                secret during the server/client connection.
@param gLen     Length of pG buffer.
@param lengthY  This value will be the size of the secret to generate in bytes.
                This value should be less then the amount of bytes in the prime
                value.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
MOC_EXTERN sbyte4 SSL_setDHParameters(ubyte *pP, ubyte4 pLen, ubyte *pG, ubyte4 gLen, ubyte4 lengthY);

MOC_EXTERN sbyte4 SSL_setMinProtoVersion(ubyte4 version);
MOC_EXTERN ubyte4 SSL_getMinProtoVersion();
MOC_EXTERN sbyte4 SSL_setMaxProtoVersion(ubyte4 version);
MOC_EXTERN ubyte4 SSL_getMaxProtoVersion();
MOC_EXTERN sbyte4 SSL_getProtoVersion(sbyte4 connectionInstance);


#ifdef __ENABLE_DIGICERT_SSL_KEY_EXPANSION__
/**
@brief      Generate the export key material with the given label and context for a connection.

@details    This function will allow the caller to generate and get a
            export key. User can specify the label and context (otional)
            to be used to generate this export key.

@ingroup    func_ssl_core

@since
@version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SSL_KEY_EXPANSION__
@inc_file ssl.h

@param connectionInstance    Connection instance returned from SSL_connect().
@param pKey                  Export key returned.
@param keyLen                Key lenght.
@param pKeyPhrase            label to be used.
@param keyPhraseLen          label length.
@param pContext              Context to be used when generating the key.
@param contextLen            Length of context.
@param useContext            If this flag is set to 1, 0 length context is
                             appended even if context length is 0 and pContext is NULL
@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4 SSL_generateExportKeyMaterial(sbyte4 connectionInstance, ubyte *pKey, ubyte2 keyLen,
                                                ubyte *pKeyphrase, ubyte2 keyPhrase,
                                                ubyte *pContext, ubyte2 contextLen, int useContext);

/**
@brief      Generate export keying material based on the early exporter master
            secret, label, and context. The label and optional context are
            provided by the caller.

@details    This function will allow the caller to generate key material based
            on the early exporter master secret. The caller must pass in a label
            and an optional context. Applications will typically use this API
            to get their own keying material when performing 0-RTT. If 0-RTT is
            not being performed then it is recommended to get keying material
            from SSL_generateExportKeyMaterial. Refer to RFC 8446 and RFC 5705
            on how to properly use exporters. This function is only available
            for TLS 1.3.

@ingroup    func_ssl_core

@since
@version

@flags
To enable this function, at least one of the following flags must be defined in
moption.h:
+ \c \__ENABLE_DIGICERT_SSL_KEY_EXPANSION__
@inc_file ssl.h

@param connectionInstance   Connection instance returned from SSL_connect().
@param pKey                 Buffer where key material is returned.
@param keyLen               Length in bytes of how much key material to
                            generate.
@param pLabel               Label string. This string cannot be NULL terminated.
@param labelLen             The length of the label string.
@param pContext             Optional context.
@param contextLen           Length of the context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
 */
MOC_EXTERN sbyte4 SSL_generateEarlyExportKeyMaterial(sbyte4 connectionInstance,
                                                     ubyte *pKey, ubyte2 keyLen,
                                                     ubyte *pLabel, ubyte2 labelLen,
                                                     ubyte *pContext, ubyte4 contextLen);
#endif /* __ENABLE_DIGICERT_SSL_KEY_EXPANSION__ */

#if (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__))
/**
@brief      Function to set the callback to pass data
            to the application received during the SSL handshake.

@details    This function sets the callback function, which is invoked
            by the stack when it receives Application Data
            during the handshake is in progress. TLS 1.3 provides such a provision.

@since
@version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_0RTT__

@inc_file ssl.h

@param connectionInstance                    Connection instance returned from
                                             SSL_connect()/SSL_acceptConnection().

@param funcPtrTLS13ApplicationDataCallback   Function pointer to a valid function,
                                             which handles the data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/

MOC_EXTERN sbyte4
SSL_setReceiveApplicationDataCallback(sbyte4 (*funcPtrTLS13ApplicationDataCallback)(sbyte4 connectionInstance,
                                                                                   ubyte *pData, ubyte4 dataLen,
                                                                                   dataState state));

#endif /* (defined(__ENABLE_DIGICERT_TLS13__) && defined(__ENABLE_DIGICERT_TLS13_0RTT__)) */

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__))
/**
@brief      Set the alias of the certificate-key pair to be used for mutual auth.

@details    This function lets you set the alias and alias length;
            This alias will be used to lookup the certificate-key pair when responding
            to CertificateRequest message from the server.
            This API should be called prior to SSL_negotiateConnection() and after SSL_connect()

@since
@version

@flags
To enable define the following fla in moptions.h
+\c \__ENABLE_DIGICERT_SSL_CLIENT__
+\c \__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__

@param pAlias         Alias byte string; Alias will be used to search the
                      corresponding certificate
@param aliasLen       Length of the alias byte string

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English test error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This callback function is applicable to synchronous and asynchronous
            clients and servers.

@callbackdoc ssl.h
*/

MOC_EXTERN MSTATUS
SSL_setMutualAuthCertificateAlias(sbyte4 connectionInstance, ubyte *pAlias, ubyte4 aliasLen);
#endif

#endif /* (defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)) */

#ifdef __cplusplus
}
#endif

MOC_EXTERN MSTATUS SSL_setMaxTimerCountForRehandshake(ubyte4 timerCount);
MOC_EXTERN MSTATUS SSL_setmaxByteCount(ubyte4 byteCount);

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
MOC_EXTERN MSTATUS SSL_setFuncPtrClientRehandshakeRequest(sbyte4(*funcPtrClientRehandshakeRequest)
                                                                (sbyte4 connectionInstance));
#endif

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
MOC_EXTERN MSTATUS SSL_setFuncPtrAlertCallback(sbyte4 (*funcPtrAlertCallback)
                                                      (sbyte4 connectionInstance,
                                                       sbyte4 alertId, sbyte4 alertClass));
#endif

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
MOC_EXTERN MSTATUS
SSL_setClientSaveTicketCallback(sbyte4 connectionInstance,
                                sbyte4 (*cb)(sbyte4 connectionInstance,
                                             sbyte *serverInfo, ubyte4 serverInfoLen,
                                             void *userData, ubyte *pTicket, ubyte4 ticketLen));

MOC_EXTERN MSTATUS
SSL_setClientRetrieveTicketCallback(sbyte4 connectionInstance,
                                    sbyte4 (*cb)(sbyte4 connectionInstance,
                                                 sbyte *serverInfo, ubyte4 serverInfoLen,
                                                 void *userData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                                 intBoolean *pFreememory));
#endif

#if (defined(__ENABLE_DIGICERT_SSL_PSK_SUPPORT__) || defined(__ENABLE_DIGICERT_TLS13_PSK__))
MOC_EXTERN MSTATUS SSL_setFuncPtrLookupPSK(sbyte4 (*funcPtrLookupPSK)
                                                  (sbyte4, ubyte*, ubyte4,
                                                   ubyte[SSL_PSK_MAX_LENGTH],
                                                   ubyte4*));

MOC_EXTERN MSTATUS SSL_setFuncPtrGetHintPSK(sbyte4 (*funcPtrGetHintPSK)
                                                   (sbyte4, ubyte hintPSK[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                                    ubyte4 *));

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)

/**
@brief      Deserialize TLS 1.3 PSK.

@details    This function takes in a serialized ASN.1 TLS 1.3 PSK encoding and
            converts it into a NanoSSL TLS 1.3 PSK object. The allocated PSK
            object must be freed by the caller.

            The PSK ASN.1 encoding is required to be

                SEQUENCE
                  INTEGER      version
                  INTEGER      isExternal
                  INTEGER      isPSKavailable
                  INTEGER      pskTLS13LifetimeHint
                  INTEGER      pskTLS13AgeAdd
                  OCTETSTRING  ticketNonce
                  OCTETSTRING  pskTLS13
                  INTEGER      obfuscatedTicketAge
                  INTEGER      hashAlgo
                  UTCTIME      startTime
                  INTEGER      maxEarlyDataSize
                  INTEGER      pSelectedTlsVersion
                  OCTETSTRING  selectedALPN
                  INTEGER      selectedCipherSuiteId

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__

@inc_file ssl.h

@param  pPsk        Pointer to the PSK to deserialize.
@param  pskLen      Length of the PSK to deserialize.
@param  ppRetPsk    Location at which the new PSK object will be stored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
MOC_EXTERN MSTATUS SSL_deserializePSK(ubyte *pPsk, ubyte4 pskLen, tls13PSK **ppRetPsk);

/**
@brief      Serialize TLS 1.3 PSK.

@details    This function takes in a NanoSSL TLS 1.3 PSK object and serializes
            the data into an ASN.1 encoded byte array. The allocated array must
            be freed by the caller.

            The PSK ASN.1 encoding will be output as follows

                SEQUENCE
                  INTEGER      version
                  INTEGER      isExternal
                  INTEGER      isPSKavailable
                  INTEGER      pskTLS13LifetimeHint
                  INTEGER      pskTLS13AgeAdd
                  OCTETSTRING  ticketNonce
                  OCTETSTRING  pskTLS13
                  INTEGER      obfuscatedTicketAge
                  INTEGER      hashAlgo
                  UTCTIME      startTime
                  INTEGER      maxEarlyDataSize
                  INTEGER      pSelectedTlsVersion
                  OCTETSTRING  selectedALPN
                  INTEGER      selectedCipherSuiteId

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__

@inc_file ssl.h

@param  pPsk        PSK object to serialize.
@param  ppPsk       Location at which the new serialized PSK pointer will be
                      stored.
@param  pPskLen     Location at which the length of the serialized PSK will be
                      stored.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
MOC_EXTERN MSTATUS SSL_serializePSK(tls13PSK *pPsk, ubyte **ppPsk, ubyte4 *pPskLen);

/**
@brief      Free TLS 1.3 PSK.

@details    This function free a TLS 1.3 PSK structure.

@ingroup    func_ssl_ungrouped

@since 6.5
@version 6.5 and later
@todo_version

@flags
To enable this function, at least one of the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_TLS13__
+ \c \__ENABLE_DIGICERT_TLS13_PSK__

@inc_file ssl.h

@param  ppPsk       Location at which the serialized PSK pointer is
                      freed.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc ssl.c
*/
MOC_EXTERN MSTATUS SSL_freePSK(tls13PSK **ppPsk);

#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
MOC_EXTERN MSTATUS SSL_setFuncPtrChoosePSK(sbyte4 (*funcPtrChoosePSK)
                                                  (sbyte4, ubyte *, ubyte4,
                                                   ubyte retPskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH],
                                                   ubyte4 *, ubyte retPSK[SSL_PSK_MAX_LENGTH], ubyte4 *));

#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
MOC_EXTERN MSTATUS
SSL_setClientSavePSKCallback(sbyte4 connectionInstance,
                             sbyte4 (*cb)(sbyte4 connectionInstance,
                                          sbyte* ServerInfo, ubyte4 serverInfoLen,
                                          void *userData, ubyte *pPsk, ubyte4 pskLen));

MOC_EXTERN MSTATUS
SSL_CLIENT_setRetrievePSKCallback(sbyte4 connectionInstance,
                                  sbyte4 (*cb)(sbyte4 connectionInstance,
                                       sbyte* ServerInfo, ubyte4 serverInfoLen,
                                       void *userData, void **ppPSKs,
                                       ubyte2 *pNumPSKs,ubyte* selectedIndex,
                                       intBoolean *pFreeMemory));
#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /*__ENABLE_DIGICERT_SSL_CLIENT__ */
#endif /* __ENABLE_DIGICERT_SSL_PSK_SUPPORT__  || __ENABLE_DIGICERT_TLS13_PSK__ */

#if defined(__ENABLE_DIGICERT_TLS13__)

MOC_EXTERN MSTATUS SSL_setFuncPtrKeyUpdateRequest(sbyte4 (*funcPtrKeyUpdate)
                                                         (sbyte4 connectionInstance));
#if defined(__ENABLE_DIGICERT_TLS13_PSK__)
#if defined(__ENABLE_DIGICERT_SSL_SERVER__)
MOC_EXTERN MSTATUS
SSL_setServerSavePSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                          ubyte* ServerInfo, ubyte4 serverInfoLen,
                                          ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                          ubyte* pPsk, ubyte4 pskLen));

MOC_EXTERN MSTATUS
SSL_setServerLookupPSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                            ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                            ubyte** ppPsk, ubyte4 *pPskLen, intBoolean *pFreeMemory));

MOC_EXTERN MSTATUS
SSL_setServerDeletePSKCallback(sbyte4 (*cb)(sbyte4 connectionInstance,
                                          sbyte* ServerInfo, ubyte4 serverInfoLen,
                                          ubyte* pIdentityPSK, ubyte4 identityLengthPSK,
                                          ubyte* pPsk));
#endif /* __ENABLE_DIGICERT_SSL_SERVER__ */

#endif /* __ENABLE_DIGICERT_TLS13_PSK__ */
#endif /* __ENABLE_DIGICERT_TLS13__ */

#if (defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__))
MOC_EXTERN MSTATUS
SSL_setClientSaveTicketCallback(sbyte4 connectionInstance,
                                sbyte4 (*cb)(sbyte4 connectionInstance,
                                             sbyte *serverInfo, ubyte4 serverInfoLen,
                                             void *userData, ubyte *pTicket, ubyte4 ticketLen));

MOC_EXTERN MSTATUS
SSL_setClientRetrieveTicketCallback(sbyte4 connectionInstance,
                                    sbyte4 (*cb)(sbyte4 connectionInstance,
                                                 sbyte *serverInfo, ubyte4 serverInfoLen,
                                                 void *userData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                                 intBoolean *pFreememory));
#endif

MOC_EXTERN MSTATUS SSL_getSharedSignatureAlgorithm(sbyte4 connectionInstance, ubyte4 algoListIndex,
                                                   ubyte2 *pSigAlgo, ubyte isPeer);
MOC_EXTERN MSTATUS SSL_INTERNAL_setConnectionState(sbyte4 connectionInstance, sbyte4 connectionState);

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__)
/**
@brief      Unload the TAP keys in deferred mode, when the application is shutting down.

@details    This function unloads the TAP keys in deferred mode.

@flags
To enable this function, the following flags must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_TAP__
+ \c \__ENABLE_DIGICERT_TAP_DEFER_UNLOADKEY__

@inc_file ssl.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN MSTATUS SSL_TAP_clearKeyAndToken();
#endif
#endif /* __SSL_HEADER__ */
