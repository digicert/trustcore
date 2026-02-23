/*
 * ossl_ssl.c
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

/*
 * VxWorks7 & VxWorks6.9 have openssl .h files in different locations
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#ifdef __RTOS_WIN32__
#include <Winsock2.h>
#include <ws2tcpip.h>
#endif

#include <openssl/opensslconf.h>

#ifdef __RTOS_VXWORKS__
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <bio/bio_lcl.h>
#include <openssl/x509.h>
#include <internal/evp_int.h>
#include <comp/comp_lcl.h>
#include <x509/x509_lcl.h>
#include <internal/x509_int.h>
#include <dh/dh_locl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#else /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <openssl/x509.h>
#include <err.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <openssl/evp.h>
#include <arpa/inet.h>

#ifdef IPSSL
#include <ipcom_err.h>
#include <ipcom_os.h>
#endif  /* IPSSL */

#else   /* !__RTOS_VXWORKS__ */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <crypto/bio/bio_lcl.h>
#else
#include <crypto/bio/bio_local.h>
#endif
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <crypto/include/internal/evp_int.h>
#else
#include <include/crypto/evp.h>
#endif
#include <openssl/err.h>
#include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER < 0x010101060
#include <crypto/comp/comp_lcl.h>
#include <crypto/x509/x509_lcl.h>
#include <crypto/include/internal/x509_int.h>
#include <crypto/dh/dh_locl.h>
#else
#include <crypto/comp/comp_local.h>
#include <crypto/x509/x509_local.h>
#include <crypto/dh/dh_local.h>
#include <include/crypto/x509.h>
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <internal/sslconf.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#include <include/openssl/conf.h>
#include <openssl/engine.h>
/*#include <openssl/async.h>*/
#else
#include "crypto/x509/x509.h"
#include <crypto/err/err.h>
#include <crypto/evp/evp.h>
#endif
#endif  /* __RTOS_VXWORKS__ */

#include <openssl/crypto.h>
#include <openssl/conf.h>
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <openssl/bio.h>
#endif
#include <stdio.h>     /* for strcmp/snprintf */
#include <e_os.h> /* clear_sys_error() */
#include <stdlib.h>    /* for getenv() */
#ifndef __RTOS_WIN32__
#include <dirent.h>    /* for opendir/readdir */
#endif
#include <string.h>    /* for strchr() */
#ifndef __RTOS_WIN32__
#include <strings.h>   /* for strncasecmp() */
#endif
#include <ctype.h>
#ifndef __RTOS_WIN32__
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#endif

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/hash_table.h"
#include "../common/mrtos.h"
#include "../common/sizedbuffer.h"
#ifdef __RTOS_WIN32__
#include "../common/moc_win_utils.h"
#endif

#include "ossl_types.h"
#include "ossl_cert_convert.h"

#include "ossl_ssl.h"
/* .. then openssl/ssl.h.  This is due to overloading of SSL_connect() and
 *    SSL_shutdown
 */
#include "../openssl_wrapper/ssl.h"

#include "cipherdesc.h"

#include "openssl_shim.h"
#include "../ssl/ssl.h"
#include "../ssl/ssl_priv.h"

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
MSTATUS OSSL_sessionReleaseMutex(SSL *s);
#endif

#define MAX_HANDSHAKE_ATTEMPT (2)

#ifndef OSSL_DEFAULT_READ_AHEAD
#define OSSL_DEFAULT_READ_AHEAD 1
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900

#define snprintf c99_snprintf
#define vsnprintf c99_vsnprintf

__inline int c99_vsnprintf(char *outBuf, size_t size, const char *format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(outBuf, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

__inline int c99_snprintf(char *outBuf, size_t size, const char *format, ...)
{
    int count;
    va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(outBuf, size, format, ap);
    va_end(ap);

    return count;
}

#endif

#if defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__)

#undef SSL_connect
#undef SSL_shutdown

#define OPENSSL_NPN_UNSUPPORTED 0
#define OPENSSL_NPN_NEGOTIATED  1
#define OPENSSL_NPN_NO_OVERLAP  2
/*
typedef void* RTOS_MUTEX;
*/
#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
static BIO *pLogBio = NULL;
#endif

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
static intBoolean g_FIPSInitialized = 0;
#endif
static ubyte2 g_initialized    = 0;
static ubyte2 gConnectionCount = 1;
static RTOS_MUTEX m_connectionCountMutex = NULL;
static RTOS_MUTEX m_hashTableMutex       = NULL;
static intBoolean setTlsPfsCiphersOnly   = FALSE;
static int update_cipher_list_with_pfs_ciphers_only(SSL_CTX *pCtx);

#ifdef __RTOS_VXWORKS__
static int ssl_library_init(void);
#define SSL_LIB_INIT (void) ssl_library_init();
#else
#define SSL_LIB_INIT
#endif
int gNsslMethodsValid = 0;
nssl_methods_t gNsslMethods;
static hashTableOfPtrs *m_ssl_table = NULL;
void* pHashCookie = NULL;

#ifndef OSSL_MAX_SSL_MSG_SZ
#define OSSL_MAX_SSL_MSG_SZ          16896
#endif

#ifndef OSSL_MAX_SSL_RX_MSG_SZ
#define OSSL_MAX_SSL_RX_MSG_SZ       OSSL_MAX_SSL_MSG_SZ
#endif

#define MOC_SSL_CONN_INSTANCE_UNASSIGNED    -1

#define CIPHER_ADD      1
#define CIPHER_KILL     2
#define CIPHER_DEL      3
#define CIPHER_ORD      4
#define CIPHER_SPECIAL  5
/*
 * Bump the ciphers to the top of the list.
 * This rule isn't currently supported by the public cipherstring API.
 */
#define CIPHER_BUMP     6

#define CHARSET_EBCDIC 1

#define NUM_ALIAS (sizeof(cipher_aliases) / sizeof(SSL_CIPHER))
#define NUM_CIPHERS (sizeof(gCipherDescs) / sizeof(CipherDesc))

#define ITEM_SEP(a) \
          (((a) == ':') || ((a) == ' ') || ((a) == ';') || ((a) == ','))

#define MAX_FILE_NAME_SIZE 255

#ifdef __RTOS_WIN32__
#define STR_N_CASE_CMP(STR1, STR2, LEN) strnicmp(STR1, STR2, LEN)
#define STR_CASE_CMP(STR1, STR2) stricmp(STR1, STR2)
#define OSSL_UINT_PTR UINT_PTR
#else
#define STR_N_CASE_CMP(STR1, STR2, LEN) strncasecmp(STR1, STR2, LEN)
#define STR_CASE_CMP(STR1, STR2) strcasecmp(STR1, STR2)
#define OSSL_UINT_PTR uintptr
#endif

/*------------------------------------------------------------------*/

/* Sense of name is inverted e.g. "TLSv1" will clear SSL_OP_NO_TLSv1 */
#define SSL_TFLAG_INV   0x1
/* Flags refers to cert_flags not options */
#define SSL_TFLAG_CERT  0x2
/* Option can only be used for clients */
#define SSL_TFLAG_CLIENT SSL_CONF_FLAG_CLIENT
/* Option can only be used for servers */
#define SSL_TFLAG_SERVER SSL_CONF_FLAG_SERVER
#define SSL_TFLAG_BOTH (SSL_TFLAG_CLIENT|SSL_TFLAG_SERVER)

#define SSL_FLAG_TBL_INV(str, flag) \
        {str, (int)(sizeof(str) - 1), SSL_TFLAG_INV|SSL_TFLAG_BOTH, flag}

/* Original structure from OpenSSL.
 */
typedef struct
{
    int (*cmd) (SSL_CONF_CTX *cctx, const char *value);
    const char *str_file;
    const char *str_cmdline;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    unsigned short flags;
#endif
    unsigned int value_type;
} ssl_conf_cmd_tbl;

enum OSSL_TLS_SignatureAlgorithm
{
    OSSL_TLS_ANONYMOUS       = 0,
    OSSL_TLS_RSA             = 1,
    OSSL_TLS_DSA             = 2,
    OSSL_TLS_ECDSA           = 3,
    OSSL_TLS_EDDSA25519      = 7,
    OSSL_TLS_EDDSA448        = 8,
    OSSL_TLS_SIGNATURE_MAX   = 255
};

enum OSSL_TLS13_SignatureAlgorithm
{
    OSSL_TLS_13_RSA_PSS_RSAE_SHA256 = 0x04,
    OSSL_TLS_13_RSA_PSS_RSAE_SHA384 = 0x05,
    OSSL_TLS_13_RSA_PSS_RSAE_SHA512 = 0x06,
    OSSL_TLS_13_RSA_PSS_PSS_SHA256  = 0x09,
    OSSL_TLS_13_RSA_PSS_PSS_SHA384  = 0x0A,
    OSSL_TLS_13_RSA_PSS_PSS_SHA512  = 0x0B
};
/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int cmd_emptyStub(SSL_CONF_CTX *pCtx, const char *pValue);

#define SSL_CONF_CMD(name, cmdopt, flags, type) \
        {cmd_##name, #name, cmdopt, flags, type}

#define SSL_CONF_CMD2(name, cmdopt, flags, type) \
        {cmd_emptyStub, #name, cmdopt, flags, type}

#define SSL_CONF_CMD_STRING(name, cmdopt, flags) \
        SSL_CONF_CMD(name, cmdopt, flags, SSL_CONF_TYPE_STRING)

#define SSL_CONF_CMD_SWITCH(name, flags) \
        {0, NULL, name, flags, SSL_CONF_TYPE_NONE}

#else /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
#define SSL_CONF_CMD(name, cmdopt, type) \
        {cmd_##name, #name, cmdopt, type}

#define SSL_CONF_CMD_STRING(name, cmdopt) \
        SSL_CONF_CMD(name, cmdopt, SSL_CONF_TYPE_STRING)
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

static int cmd_CipherString(SSL_CONF_CTX *cctx, const char *value);
static int cmd_Protocol(SSL_CONF_CTX *cctx, const char *value);

#ifndef OPENSSL_NO_DH
static int
cmd_DHParameters(SSL_CONF_CTX *pConfCtx, const char *pValue);

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int cmd_MinProtocol(SSL_CONF_CTX *pCtx, const char *pValue);
static int cmd_MaxProtocol(SSL_CONF_CTX *pCtx, const char *pValue);
static int cmd_Groups(SSL_CONF_CTX *pConfCtx, const char *pValue);
#endif

/* Array of commands available through the SSL_CONF API.
 */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static const ssl_conf_cmd_tbl ssl_conf_cmds[] = {
    SSL_CONF_CMD_STRING(CipherString, "cipher", 0),
    SSL_CONF_CMD_STRING(Protocol, NULL, 0),
#ifndef OPENSSL_NO_DH
    SSL_CONF_CMD(DHParameters, "dhparam",
                 SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
#endif
    SSL_CONF_CMD_STRING(MinProtocol, "min_protocol", 0),
    SSL_CONF_CMD_STRING(MaxProtocol, "max_protocol", 0),
    SSL_CONF_CMD_SWITCH("no_ssl3", 0),
    SSL_CONF_CMD_SWITCH("no_tls1", 0),
    SSL_CONF_CMD_SWITCH("no_tls1_1", 0),
    SSL_CONF_CMD_SWITCH("no_tls1_2", 0),
    SSL_CONF_CMD_SWITCH("no_tls1_3", 0),
    SSL_CONF_CMD_SWITCH("bugs", 0),
    SSL_CONF_CMD_SWITCH("no_comp", 0),
    SSL_CONF_CMD_SWITCH("comp", 0),
    SSL_CONF_CMD_SWITCH("ecdh_single", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("no_ticket", 0),
    SSL_CONF_CMD_SWITCH("serverpref", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("legacy_renegotiation", 0),
    SSL_CONF_CMD_SWITCH("legacy_server_connect", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("no_renegotiation", 0),
    SSL_CONF_CMD_SWITCH("no_resumption_on_reneg", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("no_legacy_server_connect", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("allow_no_dhe_kex", 0),
    SSL_CONF_CMD_SWITCH("prioritize_chacha", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("strict", 0),
    SSL_CONF_CMD_SWITCH("no_middlebox", 0),
    SSL_CONF_CMD_SWITCH("anti_replay", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD_SWITCH("no_anti_replay", SSL_CONF_FLAG_SERVER),
    SSL_CONF_CMD2(SignatureAlgorithms, "sigalgs", 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(ClientSignatureAlgorithms, "client_sigalgs", 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(Curves, "curves", 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD_STRING(Groups, "groups", 0),
#ifndef OPENSSL_NO_EC
    SSL_CONF_CMD2(ECDHParameters, "named_curve", SSL_CONF_FLAG_SERVER, SSL_CONF_TYPE_STRING),
#endif
    SSL_CONF_CMD2(CipherSuites, "ciphersuites", 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(Options, NULL, 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(VerifyMode, NULL, 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(Certificate, "cert", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(PrivateKey, "key", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(ServerInfoFile, NULL,
                 SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(ChainCAPath, "chainCApath", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_DIR),
    SSL_CONF_CMD2(ChainCAFile, "chainCAfile", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(VerifyCAPath, "verifyCApath", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_DIR),
    SSL_CONF_CMD2(VerifyCAFile, "verifyCAfile", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(RequestCAFile, "requestCAFile", SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(ClientCAFile, NULL,
                 SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_FILE),
    SSL_CONF_CMD2(RequestCAPath, NULL, SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_DIR),
    SSL_CONF_CMD2(ClientCAPath, NULL,
                 SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CERTIFICATE,
                 SSL_CONF_TYPE_DIR),
    SSL_CONF_CMD2(RecordPadding, "record_padding", 0, SSL_CONF_TYPE_STRING),
    SSL_CONF_CMD2(NumTickets, "num_tickets", SSL_CONF_FLAG_SERVER, SSL_CONF_TYPE_STRING),
};
#else
static const ssl_conf_cmd_tbl ssl_conf_cmds[] = {
    SSL_CONF_CMD_STRING(CipherString, "cipher"),
    SSL_CONF_CMD_STRING(Protocol, NULL),
#ifndef OPENSSL_NO_DH
    SSL_CONF_CMD(DHParameters, "dhparam", SSL_CONF_TYPE_FILE)
#endif
};
#endif
/*------------------------------------------------------------------*/

extern int rsaExAppDataIndex;
extern int eccExAppDataIndex;

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

# define SSL2_NUM_CIPHERS (sizeof(ssl2_ciphers)/sizeof(SSL_CIPHER))

/* list of available SSLv2 ciphers (sorted by id) */
OPENSSL_GLOBAL const SSL_CIPHER ssl2_ciphers[] = {
# if 0
/* NULL_WITH_MD5 v3 */
    {
     1,
     SSL2_TXT_NULL_WITH_MD5,
     SSL2_CK_NULL_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL_SSLV2,
     SSL_EXPORT | SSL_EXP40 | SSL_STRONG_NONE,
     0,
     0,
     0,
     },
# endif

/* RC4_128_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_128_WITH_MD5,
     SSL2_CK_RC4_128_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },

# if 0
/* RC4_128_EXPORT40_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_128_EXPORT40_WITH_MD5,
     SSL2_CK_RC4_128_EXPORT40_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL2_CF_5_BYTE_ENC,
     40,
     128,
     },
# endif

/* RC2_128_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC2_128_CBC_WITH_MD5,
     SSL2_CK_RC2_128_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },

# if 0
/* RC2_128_CBC_EXPORT40_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5,
     SSL2_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL2_CF_5_BYTE_ENC,
     40,
     128,
     },
# endif

# ifndef OPENSSL_NO_IDEA
/* IDEA_128_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_IDEA_128_CBC_WITH_MD5,
     SSL2_CK_IDEA_128_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     0,
     128,
     128,
     },
# endif

# if 0
/* DES_64_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_DES_64_CBC_WITH_MD5,
     SSL2_CK_DES_64_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     0,
     56,
     56,
     },
# endif

/* DES_192_EDE3_CBC_WITH_MD5 */
    {
     1,
     SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5,
     SSL2_CK_DES_192_EDE3_CBC_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH,
     0,
     112,
     168,
     },

# if 0
/* RC4_64_WITH_MD5 */
    {
     1,
     SSL2_TXT_RC4_64_WITH_MD5,
     SSL2_CK_RC4_64_WITH_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL2_CF_8_BYTE_ENC,
     64,
     64,
     },
# endif

# if 0
/* NULL SSLeay (testing) */
    {
     0,
     SSL2_TXT_NULL,
     SSL2_CK_NULL,
     0,
     0,
     0,
     0,
     SSL_SSLV2,
     SSL_STRONG_NONE,
     0,
     0,
     0,
     },
# endif

/* end of list :-) */
};

#endif

#define SSL3_NUM_CIPHERS        (sizeof(ssl3_ciphers)/sizeof(SSL_CIPHER))

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
/* list of available SSLv3 ciphers (sorted by id) */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static SSL_CIPHER ssl3_ciphers[] = {
    {
     1,
     SSL3_TXT_RSA_NULL_MD5,
     SSL3_RFC_RSA_NULL_MD5,
     SSL3_CK_RSA_NULL_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     SSL3_TXT_RSA_NULL_SHA,
     SSL3_RFC_RSA_NULL_SHA,
     SSL3_CK_RSA_NULL_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_192_CBC3_SHA,
     SSL3_RFC_RSA_DES_192_CBC3_SHA,
     SSL3_CK_RSA_DES_192_CBC3_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA,
     SSL3_RFC_DHE_DSS_DES_192_CBC3_SHA,
     SSL3_CK_DHE_DSS_DES_192_CBC3_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA,
     SSL3_RFC_DHE_RSA_DES_192_CBC3_SHA,
     SSL3_CK_DHE_RSA_DES_192_CBC3_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_ADH_DES_192_CBC_SHA,
     SSL3_RFC_ADH_DES_192_CBC_SHA,
     SSL3_CK_ADH_DES_192_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#endif
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA,
     TLS1_RFC_RSA_WITH_AES_128_SHA,
     TLS1_CK_RSA_WITH_AES_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
     TLS1_RFC_DHE_DSS_WITH_AES_128_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
     TLS1_RFC_DHE_RSA_WITH_AES_128_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA,
     TLS1_RFC_ADH_WITH_AES_128_SHA,
     TLS1_CK_ADH_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA,
     TLS1_RFC_RSA_WITH_AES_256_SHA,
     TLS1_CK_RSA_WITH_AES_256_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
     TLS1_RFC_DHE_DSS_WITH_AES_256_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
     TLS1_RFC_DHE_RSA_WITH_AES_256_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA,
     TLS1_RFC_ADH_WITH_AES_256_SHA,
     TLS1_CK_ADH_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_NULL_SHA256,
     TLS1_RFC_RSA_WITH_NULL_SHA256,
     TLS1_CK_RSA_WITH_NULL_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_RSA_WITH_AES_128_SHA256,
     TLS1_CK_RSA_WITH_AES_128_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA256,
     TLS1_RFC_RSA_WITH_AES_256_SHA256,
     TLS1_CK_RSA_WITH_AES_256_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA256,
     TLS1_RFC_ADH_WITH_AES_128_SHA256,
     TLS1_CK_ADH_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA256,
     TLS1_RFC_ADH_WITH_AES_256_SHA256,
     TLS1_CK_ADH_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM,
     TLS1_RFC_RSA_WITH_AES_128_CCM,
     TLS1_CK_RSA_WITH_AES_128_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM,
     TLS1_RFC_RSA_WITH_AES_256_CCM,
     TLS1_CK_RSA_WITH_AES_256_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM_8,
     TLS1_RFC_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_RSA_WITH_AES_128_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM_8,
     TLS1_RFC_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_RSA_WITH_AES_256_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM,
     TLS1_RFC_PSK_WITH_AES_128_CCM,
     TLS1_CK_PSK_WITH_AES_128_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM,
     TLS1_RFC_PSK_WITH_AES_256_CCM,
     TLS1_CK_PSK_WITH_AES_256_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM_8,
     TLS1_RFC_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_PSK_WITH_AES_128_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM_8,
     TLS1_RFC_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_PSK_WITH_AES_256_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
     TLS1_RFC_ECDH_anon_WITH_NULL_SHA,
     TLS1_CK_ECDH_anon_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_RFC_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA,
     TLS1_RFC_PSK_WITH_NULL_SHA,
     TLS1_CK_PSK_WITH_NULL_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_DHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_DHE_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_RFC_RSA_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_RFC_RSA_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA256,
     TLS1_RFC_PSK_WITH_NULL_SHA256,
     TLS1_CK_PSK_WITH_NULL_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA384,
     TLS1_RFC_PSK_WITH_NULL_SHA384,
     TLS1_CK_PSK_WITH_NULL_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA256,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA384,
     TLS1_RFC_DHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_RSA_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_RSA_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA256,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA256,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA384,
     TLS1_RFC_RSA_PSK_WITH_NULL_SHA384,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
#  ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#  endif
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },

# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_RFC_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_PSK_WITH_CHACHA20_POLY1305,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_RFC_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
#endif                          /* !defined(OPENSSL_NO_CHACHA) &&
                                 * !defined(OPENSSL_NO_POLY1305) */

#ifndef OPENSSL_NO_CAMELLIA
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_RFC_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_RFC_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_RFC_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_CAMELLIA */

#ifndef OPENSSL_NO_GOST
    {
     1,
     "GOST2001-GOST89-GOST89",
     "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
     0x3000081,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2001-NULL-GOST94",
     "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
     0x3000083,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST94,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0,
     },
    {
     1,
     "GOST2012-GOST8912-GOST8912",
     NULL,
     0x0300ff85,
     SSL_kGOST,
     SSL_aGOST12 | SSL_aGOST01,
     SSL_eGOST2814789CNT12,
     SSL_GOST89MAC12,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2012-NULL-GOST12",
     NULL,
     0x0300ff87,
     SSL_kGOST,
     SSL_aGOST12 | SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST12_256,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     0,
     0,
     },
#endif                          /* OPENSSL_NO_GOST */

#ifndef OPENSSL_NO_IDEA
    {
     1,
     SSL3_TXT_RSA_IDEA_128_SHA,
     SSL3_RFC_RSA_IDEA_128_SHA,
     SSL3_CK_RSA_IDEA_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_SHA1,
     SSL3_VERSION, TLS1_1_VERSION,
     DTLS1_BAD_VER, DTLS1_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

#ifndef OPENSSL_NO_SEED
    {
     1,
     TLS1_TXT_RSA_WITH_SEED_SHA,
     TLS1_RFC_RSA_WITH_SEED_SHA,
     TLS1_CK_RSA_WITH_SEED_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
     TLS1_RFC_DHE_DSS_WITH_SEED_SHA,
     TLS1_CK_DHE_DSS_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
     TLS1_RFC_DHE_RSA_WITH_SEED_SHA,
     TLS1_CK_DHE_RSA_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_SEED_SHA,
     TLS1_RFC_ADH_WITH_SEED_SHA,
     TLS1_CK_ADH_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENSSL_NO_SEED */

#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC4_128_MD5,
     SSL3_RFC_RSA_RC4_128_MD5,
     SSL3_CK_RSA_RC4_128_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     SSL3_TXT_RSA_RC4_128_SHA,
     SSL3_RFC_RSA_RC4_128_SHA,
     SSL3_CK_RSA_RC4_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     SSL3_TXT_ADH_RC4_128_MD5,
     SSL3_RFC_ADH_RC4_128_MD5,
     SSL3_CK_ADH_RC4_128_MD5,
     SSL_kDHE,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_RFC_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_RFC_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_PSK_WITH_RC4_128_SHA,
     TLS1_CK_PSK_WITH_RC4_128_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_RSA_PSK_WITH_RC4_128_SHA,
     TLS1_CK_RSA_PSK_WITH_RC4_128_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA,
     TLS1_RFC_DHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_DHE_PSK_WITH_RC4_128_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENSSL_NO_WEAK_SSL_CIPHERS */

#ifndef OPENSSL_NO_ARIA
    {
     1,
     TLS1_TXT_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_ARIA_128_GCM_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_ARIA_256_GCM_SHA384,
     SSL_kRSA,
     SSL_aRSA,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aRSA,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aDSS,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_PSK_WITH_ARIA_128_GCM_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_PSK_WITH_ARIA_256_GCM_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_RFC_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     TLS1_CK_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_ARIA128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_RFC_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     TLS1_CK_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_ARIA256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#endif /* OPENSSL_NO_ARIA */
    {
        1,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_CK_AES_128_GCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128GCM,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }, {
        1,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_CK_AES_256_GCM_SHA384,
        SSL_kANY,
        SSL_aANY,
        SSL_AES256GCM,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA384,
        256,
        256,
    },
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    {
        1,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_CHACHA20POLY1305,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        256,
        256,
    },
#endif
    {
        1,
        TLS1_3_RFC_AES_128_CCM_SHA256,
        TLS1_3_RFC_AES_128_CCM_SHA256,
        TLS1_3_CK_AES_128_CCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }, {
        1,
        TLS1_3_RFC_AES_128_CCM_8_SHA256,
        TLS1_3_RFC_AES_128_CCM_8_SHA256,
        TLS1_3_CK_AES_128_CCM_8_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM8,
        SSL_AEAD,
        TLS1_3_VERSION, TLS1_3_VERSION,
        0, 0,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    }
};
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
static SSL_CIPHER ssl3_ciphers[] = {
    {
     1,
     SSL3_TXT_RSA_NULL_MD5,
     SSL3_CK_RSA_NULL_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     SSL3_TXT_RSA_NULL_SHA,
     SSL3_CK_RSA_NULL_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_192_CBC3_SHA,
     SSL3_CK_RSA_DES_192_CBC3_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_DHE_DSS_DES_192_CBC3_SHA,
     SSL3_CK_DHE_DSS_DES_192_CBC3_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_DHE_RSA_DES_192_CBC3_SHA,
     SSL3_CK_DHE_RSA_DES_192_CBC3_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     SSL3_TXT_ADH_DES_192_CBC_SHA,
     SSL3_CK_ADH_DES_192_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#endif
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA,
     TLS1_CK_RSA_WITH_AES_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA,
     TLS1_CK_ADH_WITH_AES_128_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA,
     TLS1_CK_RSA_WITH_AES_256_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA,
     TLS1_CK_ADH_WITH_AES_256_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_NULL_SHA256,
     TLS1_CK_RSA_WITH_NULL_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA256,
     TLS1_CK_RSA_WITH_AES_128_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA256,
     TLS1_CK_RSA_WITH_AES_256_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA256,
     TLS1_CK_ADH_WITH_AES_128_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA256,
     TLS1_CK_ADH_WITH_AES_256_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aDSS,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
     SSL_kDHE,
     SSL_aNULL,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM,
     TLS1_CK_RSA_WITH_AES_128_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM,
     TLS1_CK_RSA_WITH_AES_256_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_RSA_WITH_AES_128_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_RSA_WITH_AES_256_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM,
     TLS1_CK_PSK_WITH_AES_128_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM,
     TLS1_CK_PSK_WITH_AES_256_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_PSK_WITH_AES_128_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_PSK_WITH_AES_256_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },

#ifndef OPENSSL_NO_EC
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
     TLS1_CK_ECDH_anon_WITH_NULL_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_EC */

#ifndef OPENSSL_NO_PSK
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA,
     TLS1_CK_PSK_WITH_NULL_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_GCM_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_GCM_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA256,
     TLS1_CK_PSK_WITH_NULL_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_NULL_SHA384,
     TLS1_CK_PSK_WITH_NULL_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_DHE_PSK_WITH_NULL_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA256,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_NULL_SHA384,
     TLS1_CK_RSA_PSK_WITH_NULL_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
# ifndef OPENSSL_NO_EC
#  ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
#  endif
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_NULL_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_NULL_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_eNULL,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     0,
     0,
     },
# endif                         /* OPENSSL_NO_EC */
#endif                          /* OPENSSL_NO_PSK */

#ifndef OPENSSL_NO_SRP
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },
# endif
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_SRP */

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
# ifndef OPENSSL_NO_RSA
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
# endif                         /* OPENSSL_NO_RSA */

# ifndef OPENSSL_NO_EC
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
# endif                         /* OPENSSL_NO_EC */

# ifndef OPENSSL_NO_PSK
    {
     1,
     TLS1_TXT_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_PSK_WITH_CHACHA20_POLY1305,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
# endif                         /* OPENSSL_NO_PSK */
#endif                          /* !defined(OPENSSL_NO_CHACHA) &&
                                 * !defined(OPENSSL_NO_POLY1305) */

#ifndef OPENSSL_NO_CAMELLIA
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

# ifndef OPENSSL_NO_EC
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_2_VERSION, TLS1_2_VERSION,
     DTLS1_2_VERSION, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
# endif                         /* OPENSSL_NO_EC */

# ifndef OPENSSL_NO_PSK
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA128,
     SSL_SHA256,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     TLS1_CK_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CAMELLIA256,
     SSL_SHA384,
     TLS1_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
# endif                         /* OPENSSL_NO_PSK */

#endif                          /* OPENSSL_NO_CAMELLIA */

#ifndef OPENSSL_NO_GOST
    {
     1,
     "GOST2001-GOST89-GOST89",
     0x3000081,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2001-NULL-GOST94",
     0x3000083,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST94,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0,
     },
    {
     1,
     "GOST2012-GOST8912-GOST8912",
     0x0300ff85,
     SSL_kGOST,
     SSL_aGOST12 | SSL_aGOST01,
     SSL_eGOST2814789CNT12,
     SSL_GOST89MAC12,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     256,
     256,
     },
    {
     1,
     "GOST2012-NULL-GOST12",
     0x0300ff87,
     SSL_kGOST,
     SSL_aGOST12 | SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST12_256,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST12_256 | TLS1_PRF_GOST12_256 | TLS1_STREAM_MAC,
     0,
     0,
     },
#endif                          /* OPENSSL_NO_GOST */

#ifndef OPENSSL_NO_IDEA
    {
     1,
     SSL3_TXT_RSA_IDEA_128_SHA,
     SSL3_CK_RSA_IDEA_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_SHA1,
     SSL3_VERSION, TLS1_1_VERSION,
     DTLS1_BAD_VER, DTLS1_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

#ifndef OPENSSL_NO_SEED
    {
     1,
     TLS1_TXT_RSA_WITH_SEED_SHA,
     TLS1_CK_RSA_WITH_SEED_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
     TLS1_CK_DHE_DSS_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aDSS,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
     TLS1_CK_DHE_RSA_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ADH_WITH_SEED_SHA,
     TLS1_CK_ADH_WITH_SEED_SHA,
     SSL_kDHE,
     SSL_aNULL,
     SSL_SEED,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     DTLS1_BAD_VER, DTLS1_2_VERSION,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENSSL_NO_SEED */

#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC4_128_MD5,
     SSL3_CK_RSA_RC4_128_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     SSL3_TXT_RSA_RC4_128_SHA,
     SSL3_CK_RSA_RC4_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     SSL3_TXT_ADH_RC4_128_MD5,
     SSL3_CK_ADH_RC4_128_MD5,
     SSL_kDHE,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

# ifndef OPENSSL_NO_EC
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_PSK_WITH_RC4_128_SHA,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aNULL,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     TLS1_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
# endif                         /* OPENSSL_NO_EC */

# ifndef OPENSSL_NO_PSK
    {
     1,
     TLS1_TXT_PSK_WITH_RC4_128_SHA,
     TLS1_CK_PSK_WITH_RC4_128_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_RC4_128_SHA,
     TLS1_CK_RSA_PSK_WITH_RC4_128_SHA,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_RC4_128_SHA,
     TLS1_CK_DHE_PSK_WITH_RC4_128_SHA,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL3_VERSION, TLS1_2_VERSION,
     0, 0,
     SSL_NOT_DEFAULT | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
# endif                         /* OPENSSL_NO_PSK */

#endif                          /* OPENSSL_NO_WEAK_SSL_CIPHERS */

};
#else
OPENSSL_GLOBAL SSL_CIPHER ssl3_ciphers[] = {
/* The RSA ciphers */
/* Cipher 01 */
    {
     1,
     SSL3_TXT_RSA_NULL_MD5,
     SSL3_CK_RSA_NULL_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 02 */
    {
     1,
     SSL3_TXT_RSA_NULL_SHA,
     SSL3_CK_RSA_NULL_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 03 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC4_40_MD5,
     SSL3_CK_RSA_RC4_40_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 04 */
    {
     1,
     SSL3_TXT_RSA_RC4_128_MD5,
     SSL3_CK_RSA_RC4_128_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 05 */
    {
     1,
     SSL3_TXT_RSA_RC4_128_SHA,
     SSL3_CK_RSA_RC4_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 06 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_RC2_40_MD5,
     SSL3_CK_RSA_RC2_40_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 07 */
#ifndef OPENSSL_NO_IDEA
    {
     1,
     SSL3_TXT_RSA_IDEA_128_SHA,
     SSL3_CK_RSA_IDEA_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_IDEA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

/* Cipher 08 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_40_CBC_SHA,
     SSL3_CK_RSA_DES_40_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 09 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_RSA_DES_64_CBC_SHA,
     SSL3_CK_RSA_DES_64_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 0A */
    {
     1,
     SSL3_TXT_RSA_DES_192_CBC3_SHA,
     SSL3_CK_RSA_DES_192_CBC3_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* The DH ciphers */
/* Cipher 0B */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     0,
     SSL3_TXT_DH_DSS_DES_40_CBC_SHA,
     SSL3_CK_DH_DSS_DES_40_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 0C */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_DH_DSS_DES_64_CBC_SHA,
     SSL3_CK_DH_DSS_DES_64_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 0D */
    {
     1,
     SSL3_TXT_DH_DSS_DES_192_CBC3_SHA,
     SSL3_CK_DH_DSS_DES_192_CBC3_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 0E */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     0,
     SSL3_TXT_DH_RSA_DES_40_CBC_SHA,
     SSL3_CK_DH_RSA_DES_40_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 0F */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_DH_RSA_DES_64_CBC_SHA,
     SSL3_CK_DH_RSA_DES_64_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 10 */
    {
     1,
     SSL3_TXT_DH_RSA_DES_192_CBC3_SHA,
     SSL3_CK_DH_RSA_DES_192_CBC3_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* The Ephemeral DH ciphers */
/* Cipher 11 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_DSS_DES_40_CBC_SHA,
     SSL3_CK_EDH_DSS_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 12 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_DSS_DES_64_CBC_SHA,
     SSL3_CK_EDH_DSS_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 13 */
    {
     1,
     SSL3_TXT_EDH_DSS_DES_192_CBC3_SHA,
     SSL3_CK_EDH_DSS_DES_192_CBC3_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 14 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_RSA_DES_40_CBC_SHA,
     SSL3_CK_EDH_RSA_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
#endif

/* Cipher 15 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_EDH_RSA_DES_64_CBC_SHA,
     SSL3_CK_EDH_RSA_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 16 */
    {
     1,
     SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA,
     SSL3_CK_EDH_RSA_DES_192_CBC3_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 17 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_RC4_40_MD5,
     SSL3_CK_ADH_RC4_40_MD5,
     SSL_kEDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 18 */
    {
     1,
     SSL3_TXT_ADH_RC4_128_MD5,
     SSL3_CK_ADH_RC4_128_MD5,
     SSL_kEDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 19 */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_DES_40_CBC_SHA,
     SSL3_CK_ADH_DES_40_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
#endif

/* Cipher 1A */
#ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_ADH_DES_64_CBC_SHA,
     SSL3_CK_ADH_DES_64_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
#endif

/* Cipher 1B */
    {
     1,
     SSL3_TXT_ADH_DES_192_CBC_SHA,
     SSL3_CK_ADH_DES_192_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Fortezza ciphersuite from SSL 3.0 spec */
#if 0
/* Cipher 1C */
    {
     0,
     SSL3_TXT_FZA_DMS_NULL_SHA,
     SSL3_CK_FZA_DMS_NULL_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 1D */
    {
     0,
     SSL3_TXT_FZA_DMS_FZA_SHA,
     SSL3_CK_FZA_DMS_FZA_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_eFZA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

/* Cipher 1E */
    {
     0,
     SSL3_TXT_FZA_DMS_RC4_SHA,
     SSL3_CK_FZA_DMS_RC4_SHA,
     SSL_kFZA,
     SSL_aFZA,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#ifndef OPENSSL_NO_KRB5
/* The Kerberos ciphers*/
/* Cipher 1E */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_64_CBC_SHA,
     SSL3_CK_KRB5_DES_64_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

/* Cipher 1F */
    {
     1,
     SSL3_TXT_KRB5_DES_192_CBC3_SHA,
     SSL3_CK_KRB5_DES_192_CBC3_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_3DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 20 */
    {
     1,
     SSL3_TXT_KRB5_RC4_128_SHA,
     SSL3_CK_KRB5_RC4_128_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 21 */
    {
     1,
     SSL3_TXT_KRB5_IDEA_128_CBC_SHA,
     SSL3_CK_KRB5_IDEA_128_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_IDEA,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 22 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_64_CBC_MD5,
     SSL3_CK_KRB5_DES_64_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_LOW,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

/* Cipher 23 */
    {
     1,
     SSL3_TXT_KRB5_DES_192_CBC3_MD5,
     SSL3_CK_KRB5_DES_192_CBC3_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_3DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

/* Cipher 24 */
    {
     1,
     SSL3_TXT_KRB5_RC4_128_MD5,
     SSL3_CK_KRB5_RC4_128_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 25 */
    {
     1,
     SSL3_TXT_KRB5_IDEA_128_CBC_MD5,
     SSL3_CK_KRB5_IDEA_128_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_IDEA,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 26 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_40_CBC_SHA,
     SSL3_CK_KRB5_DES_40_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
# endif

/* Cipher 27 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC2_40_CBC_SHA,
     SSL3_CK_KRB5_RC2_40_CBC_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC2,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 28 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC4_40_SHA,
     SSL3_CK_KRB5_RC4_40_SHA,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_SHA1,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 29 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_DES_40_CBC_MD5,
     SSL3_CK_KRB5_DES_40_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_DES,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     56,
     },
# endif

/* Cipher 2A */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC2_40_CBC_MD5,
     SSL3_CK_KRB5_RC2_40_CBC_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC2,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif

/* Cipher 2B */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     SSL3_TXT_KRB5_RC4_40_MD5,
     SSL3_CK_KRB5_RC4_40_MD5,
     SSL_kKRB5,
     SSL_aKRB5,
     SSL_RC4,
     SSL_MD5,
     SSL_SSLV3,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP40,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     40,
     128,
     },
# endif
#endif                          /* OPENSSL_NO_KRB5 */
#endif                          /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ or __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
/* New AES ciphersuites */
/* Cipher 2F */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA,
     TLS1_CK_RSA_WITH_AES_128_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 30 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_SHA,
     TLS1_CK_DH_DSS_WITH_AES_128_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 31 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_SHA,
     TLS1_CK_DH_RSA_WITH_AES_128_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 32 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 33 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
/* Cipher 34 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA,
     TLS1_CK_ADH_WITH_AES_128_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

/* Cipher 35 */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA,
     TLS1_CK_RSA_WITH_AES_256_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
/* Cipher 36 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_SHA,
     TLS1_CK_DH_DSS_WITH_AES_256_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 37 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_SHA,
     TLS1_CK_DH_RSA_WITH_AES_256_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 38 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

/* Cipher 39 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 3A */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA,
     TLS1_CK_ADH_WITH_AES_256_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* TLS v1.2 ciphersuites */
    /* Cipher 3B */
    {
     1,
     TLS1_TXT_RSA_WITH_NULL_SHA256,
     TLS1_CK_RSA_WITH_NULL_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher 3C */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_SHA256,
     TLS1_CK_RSA_WITH_AES_128_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 3D */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_SHA256,
     TLS1_CK_RSA_WITH_AES_256_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 3E */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_128_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 3F */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_128_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 40 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

#ifndef OPENSSL_NO_CAMELLIA
    /* Camellia ciphersuites from RFC4132 (128-bit portion) */

    /* Cipher 41 */
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 42 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 43 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 44 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 45 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 46 */
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_128_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_128_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif                          /* OPENSSL_NO_CAMELLIA */
#define TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES 0

#if TLS1_ALLOW_EXPERIMENTAL_CIPHERSUITES
    /* New TLS Export CipherSuites from expired ID */
# if 0
    /* Cipher 60 */
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_MD5,
     TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },

    /* Cipher 61 */
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
     TLS1_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC2,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 62 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_DES_CBC_SHA,
     TLS1_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

    /* Cipher 63 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
     TLS1_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     56,
     },
# endif

    /* Cipher 64 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_RSA_EXPORT1024_WITH_RC4_56_SHA,
     TLS1_CK_RSA_EXPORT1024_WITH_RC4_56_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 65 */
# ifndef OPENSSL_NO_WEAK_SSL_CIPHERS
    {
     1,
     TLS1_TXT_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
     TLS1_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_EXPORT | SSL_EXP56,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     56,
     128,
     },
# endif

    /* Cipher 66 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_RC4_128_SHA,
     TLS1_CK_DHE_DSS_WITH_RC4_128_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },
#endif

    /* TLS v1.2 ciphersuites */
    /* Cipher 67 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 68 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_256_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 69 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_256_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6A */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6B */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 6C */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_SHA256,
     TLS1_CK_ADH_WITH_AES_128_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 6D */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_SHA256,
     TLS1_CK_ADH_WITH_AES_256_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* GOST Ciphersuites */

    {
     1,
     "GOST94-GOST89-GOST89",
     0x3000080,
     SSL_kGOST,
     SSL_aGOST94,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256},
    {
     1,
     "GOST2001-GOST89-GOST89",
     0x3000081,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94 | TLS1_STREAM_MAC,
     256,
     256},
    {
     1,
     "GOST94-NULL-GOST94",
     0x3000082,
     SSL_kGOST,
     SSL_aGOST94,
     SSL_eNULL,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0},
    {
     1,
     "GOST2001-NULL-GOST94",
     0x3000083,
     SSL_kGOST,
     SSL_aGOST01,
     SSL_eNULL,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE,
     SSL_HANDSHAKE_MAC_GOST94 | TLS1_PRF_GOST94,
     0,
     0},

#ifndef OPENSSL_NO_CAMELLIA
    /* Camellia ciphersuites from RFC4132 (256-bit portion) */

    /* Cipher 84 */
    {
     1,
     TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    /* Cipher 85 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 86 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 87 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 88 */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher 89 */
    {
     1,
     TLS1_TXT_ADH_WITH_CAMELLIA_256_CBC_SHA,
     TLS1_CK_ADH_WITH_CAMELLIA_256_CBC_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_CAMELLIA256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_CAMELLIA */

#ifndef OPENSSL_NO_PSK
    /* Cipher 8A */
    {
     1,
     TLS1_TXT_PSK_WITH_RC4_128_SHA,
     TLS1_CK_PSK_WITH_RC4_128_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 8B */
    {
     1,
     TLS1_TXT_PSK_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_PSK_WITH_3DES_EDE_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher 8C */
    {
     1,
     TLS1_TXT_PSK_WITH_AES_128_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 8D */
    {
     1,
     TLS1_TXT_PSK_WITH_AES_256_CBC_SHA,
     TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_PSK */

#ifndef OPENSSL_NO_SEED
    /* SEED ciphersuites from RFC4162 */

    /* Cipher 96 */
    {
     1,
     TLS1_TXT_RSA_WITH_SEED_SHA,
     TLS1_CK_RSA_WITH_SEED_SHA,
     SSL_kRSA,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 97 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_SEED_SHA,
     TLS1_CK_DH_DSS_WITH_SEED_SHA,
     SSL_kDHd,
     SSL_aDH,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 98 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_SEED_SHA,
     TLS1_CK_DH_RSA_WITH_SEED_SHA,
     SSL_kDHr,
     SSL_aDH,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 99 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_SEED_SHA,
     TLS1_CK_DHE_DSS_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aDSS,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 9A */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_SEED_SHA,
     TLS1_CK_DHE_RSA_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aRSA,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher 9B */
    {
     1,
     TLS1_TXT_ADH_WITH_SEED_SHA,
     TLS1_CK_ADH_WITH_SEED_SHA,
     SSL_kEDH,
     SSL_aNULL,
     SSL_SEED,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

#endif                          /* OPENSSL_NO_SEED */

    /* GCM ciphersuites from RFC5288 */

    /* Cipher 9C */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher 9D */
    {
     1,
     TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher 9E */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher 9F */
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A0 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DH_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A1 */
    {
     1,
     TLS1_TXT_DH_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DH_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kDHr,
     SSL_aDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A2 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A3 */
    {
     1,
     TLS1_TXT_DHE_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aDSS,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A4 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DH_DSS_WITH_AES_128_GCM_SHA256,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A5 */
    {
     1,
     TLS1_TXT_DH_DSS_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DH_DSS_WITH_AES_256_GCM_SHA384,
     SSL_kDHd,
     SSL_aDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher A6 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher A7 */
    {
     1,
     TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384,
     SSL_kEDH,
     SSL_aNULL,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },
#ifdef OPENSSL_SSL_DEBUG_BROKEN_PROTOCOL
    {
     1,
     "SCSV",
     SSL3_CK_SCSV,
     0,
     0,
     0,
     0,
     0,
     0,
     0,
     0,
     0},
#endif

#ifndef OPENSSL_NO_ECDH
    /* Cipher C001 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_NULL_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C002 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_RC4_128_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C003 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C004 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C005 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C006 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C007 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C008 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C009 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00A */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C00B */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDH_RSA_WITH_NULL_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C00C */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_RSA_WITH_RC4_128_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00D */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C00E */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_RSA_WITH_AES_128_CBC_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C00F */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_RSA_WITH_AES_256_CBC_SHA,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C010 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_NULL_SHA,
     TLS1_CK_ECDHE_RSA_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C011 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C012 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDHE_RSA_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C013 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C014 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C015 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_NULL_SHA,
     TLS1_CK_ECDH_anon_WITH_NULL_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_eNULL,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_STRONG_NONE | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     0,
     0,
     },

    /* Cipher C016 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA,
     TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_RC4,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C017 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_DES_192_CBC3_SHA,
     TLS1_CK_ECDH_anon_WITH_DES_192_CBC3_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_MEDIUM | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C018 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C019 */
    {
     1,
     TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA,
     SSL_kEECDH,
     SSL_aNULL,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_DEFAULT | SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_ECDH */

#ifndef OPENSSL_NO_SRP
    /* Cipher C01A */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01B */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01C */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_3DES,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     112,
     168,
     },

    /* Cipher C01D */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C01E */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C01F */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES128,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     128,
     128,
     },

    /* Cipher C020 */
    {
     1,
     TLS1_TXT_SRP_SHA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aSRP,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C021 */
    {
     1,
     TLS1_TXT_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },

    /* Cipher C022 */
    {
     1,
     TLS1_TXT_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     TLS1_CK_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
     SSL_kSRP,
     SSL_aDSS,
     SSL_AES256,
     SSL_SHA1,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
#endif                          /* OPENSSL_NO_SRP */
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    {
     1,
     TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_PSK_WITH_CHACHA20_POLY1305,
     SSL_kPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kECDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_DHE_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_PSK_WITH_CHACHA20_POLY1305,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_TXT_RSA_PSK_WITH_CHACHA20_POLY1305,
     TLS1_CK_RSA_PSK_WITH_CHACHA20_POLY1305,
     SSL_kRSAPSK,
     SSL_aRSA,
     SSL_CHACHA20POLY1305,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
#endif                          /* !defined(OPENSSL_NO_CHACHA) &&
                                 * !defined(OPENSSL_NO_POLY1305) */
#ifndef OPENSSL_NO_ECDH

    /* HMAC based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C023 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C024 */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C025 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_SHA256,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C026 */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_SHA384,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C027 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C028 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C029 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDH_RSA_WITH_AES_128_SHA256,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128,
     SSL_SHA256,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02A */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDH_RSA_WITH_AES_256_SHA384,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256,
     SSL_SHA384,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* GCM based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C02B */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02C */
    {
     1,
     TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kEECDH,
     SSL_aECDSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C02D */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C02E */
    {
     1,
     TLS1_TXT_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHe,
     SSL_aECDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C02F */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C030 */
    {
     1,
     TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kEECDH,
     SSL_aRSA,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

    /* Cipher C031 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDH_RSA_WITH_AES_128_GCM_SHA256,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES128GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },

    /* Cipher C032 */
    {
     1,
     TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDH_RSA_WITH_AES_256_GCM_SHA384,
     SSL_kECDHr,
     SSL_aECDH,
     SSL_AES256GCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_EXP | SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384,
     256,
     256,
     },

#endif                          /* OPENSSL_NO_ECDH */

#ifdef TEMP_GOST_TLS
/* Cipher FF00 */
    {
     1,
     "GOST-MD5",
     0x0300ff00,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_MD5,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256,
     },
    {
     1,
     "GOST-GOST94",
     0x0300ff01,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST94,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256},
    {
     1,
     "GOST-GOST89MAC",
     0x0300ff02,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF,
     256,
     256},
    {
     1,
     "GOST-GOST89STREAM",
     0x0300ff03,
     SSL_kRSA,
     SSL_aRSA,
     SSL_eGOST2814789CNT,
     SSL_GOST89MAC,
     SSL_TLSV1,
     SSL_NOT_EXP | SSL_HIGH,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF | TLS1_STREAM_MAC,
     256,
     256},
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    {
     1,
     TLS1_RFC_RSA_WITH_AES_128_CCM,
     TLS1_CK_RSA_WITH_AES_128_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_RSA_WITH_AES_256_CCM,
     TLS1_CK_RSA_WITH_AES_256_CCM,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_RSA_WITH_AES_128_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_RSA_WITH_AES_256_CCM_8,
     SSL_kRSA,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_DHE_RSA_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_128_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_DHE_RSA_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_RSA_WITH_AES_256_CCM_8,
     SSL_kDHE,
     SSL_aRSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_PSK_WITH_AES_128_CCM,
     TLS1_CK_PSK_WITH_AES_128_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_PSK_WITH_AES_256_CCM,
     TLS1_CK_PSK_WITH_AES_256_CCM,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_PSK_WITH_AES_128_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_PSK_WITH_AES_256_CCM_8,
     SSL_kPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_DHE_PSK_WITH_AES_128_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_128_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES128CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_DHE_PSK_WITH_AES_256_CCM_8,
     TLS1_CK_DHE_PSK_WITH_AES_256_CCM_8,
     SSL_kDHEPSK,
     SSL_aPSK,
     SSL_AES256CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
    {
     1,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES128CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     128,
     128,
     },
    {
     1,
     TLS1_RFC_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CCM_8,
     SSL_kECDHE,
     SSL_aECDSA,
     SSL_AES256CCM8,
     SSL_AEAD,
     SSL_TLSV1_2,
     SSL_NOT_DEFAULT | SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256,
     256,
     256,
     },
#endif
/* The list of available TLSv1.3 ciphers */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    {
        1,
        TLS1_3_RFC_AES_128_GCM_SHA256,
        TLS1_3_CK_AES_128_GCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128GCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },
    {
        1,
        TLS1_3_RFC_AES_256_GCM_SHA384,
        TLS1_3_CK_AES_256_GCM_SHA384,
        SSL_kANY,
        SSL_aANY,
        SSL_AES256GCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA384,
        256,
        256,
    },
    {
        1,
        TLS1_3_RFC_AES_128_GCM_SHA256_2,
        TLS1_3_CK_AES_128_GCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128GCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },
    {
        1,
        TLS1_3_RFC_AES_256_GCM_SHA384_2,
        TLS1_3_CK_AES_256_GCM_SHA384,
        SSL_kANY,
        SSL_aANY,
        SSL_AES256GCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA384,
        256,
        256,
    },

#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    {
        1,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256,
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_CHACHA20POLY1305,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        256,
        256,
    },
    {
        1,
        TLS1_3_RFC_CHACHA20_POLY1305_SHA256_2,
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_CHACHA20POLY1305,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        256,
        256,
    },
#endif
    {
        1,
        TLS1_3_RFC_AES_128_CCM_SHA256,
        TLS1_3_CK_AES_128_CCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },
    {
        1,
        TLS1_3_RFC_AES_128_CCM_8_SHA256,
        TLS1_3_CK_AES_128_CCM_8_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM8,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },
    {
        1,
        TLS1_3_RFC_AES_128_CCM_SHA256_2,
        TLS1_3_CK_AES_128_CCM_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },
    {
        1,
        TLS1_3_RFC_AES_128_CCM_8_SHA256_2,
        TLS1_3_CK_AES_128_CCM_8_SHA256,
        SSL_kANY,
        SSL_aANY,
        SSL_AES128CCM8,
        SSL_AEAD,
        TLS1_3_VERSION,
        SSL_NOT_DEFAULT | SSL_HIGH,
        SSL_HANDSHAKE_MAC_SHA256,
        128,
        128,
    },

#endif
/* end of list */
};
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define SSL_DEFAULT_CIPHER_LIST "ALL:!COMPLEMENTOFDEFAULT:!eNULL"
/* This is the default set of TLSv1.3 ciphersuites */
# if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                   "TLS_CHACHA20_POLY1305_SHA256:" \
                                   "TLS_AES_128_GCM_SHA256"
# else
#  define TLS_DEFAULT_CIPHERSUITES "TLS_AES_256_GCM_SHA384:" \
                                   "TLS_AES_128_GCM_SHA256"
#endif
#else
#define SSL_DEFAULT_CIPHER_LIST "ALL:!EXPORT:!LOW:!aNULL:!eNULL:!SSLv2"
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int stopped;
static int ssl_base_inited     = 0;
static int ssl_strings_inited  = 0;
static CRYPTO_ONCE ssl_base    = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_ONCE ssl_strings = CRYPTO_ONCE_STATIC_INIT;

static CRYPTO_ONCE ssl_x509_store_ctx_once = CRYPTO_ONCE_STATIC_INIT;
static volatile int ssl_x509_store_ctx_idx = -1;
static void ssl_library_stop(void);
int SSL_state(const SSL *ssl);
int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS * settings);
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int SSL_connectEx(SSL *s, ubyte *pEarlyData, ubyte4 earlyDataLen, ubyte4 *bytesWritten);
#endif
static int OSSL_shutdown(void);

int ssl2_num_ciphers(void);
const SSL_CIPHER *ssl2_get_cipher(unsigned int u);
int ssl23_num_ciphers(void);
const SSL_CIPHER *ssl23_get_cipher(unsigned int u);
int ssl3_num_ciphers(void);
const SSL_CIPHER *ssl3_get_cipher(unsigned int u);

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define ZEROS_26 ,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 

/* RGK Add support for SSLv2 and DTLS v0.9, 1,0 and 1.2 */
static SSL_METHOD sslv23_client_method = {TLS_ANY_VERSION, 0, 0 ZEROS_26};
static SSL_METHOD sslv23_server_method = {TLS_ANY_VERSION, 0, 0 ZEROS_26};
static SSL_METHOD sslv23_method = {TLS_ANY_VERSION, 0, 0 ZEROS_26};

static SSL_METHOD sslv3_client_method = {SSL3_VERSION, 0, 0 ZEROS_26};
static SSL_METHOD sslv3_server_method = {SSL3_VERSION, 0, 0 ZEROS_26};
static SSL_METHOD sslv3_method = {SSL3_VERSION, 0, 0 ZEROS_26};

static SSL_METHOD tlsv1_client_method = {TLS1_VERSION, 0, SSL_OP_NO_TLSv1 ZEROS_26};
static SSL_METHOD tlsv1_server_method = {TLS1_VERSION, 0, SSL_OP_NO_TLSv1 ZEROS_26};
static SSL_METHOD tlsv1_1_client_method = {TLS1_1_VERSION, 0, SSL_OP_NO_TLSv1_1 ZEROS_26};
static SSL_METHOD tlsv1_1_server_method = {TLS1_1_VERSION, 0, SSL_OP_NO_TLSv1_1 ZEROS_26};
static SSL_METHOD tlsv1_2_client_method = {TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2 ZEROS_26};
static SSL_METHOD tlsv1_2_server_method = {TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2 ZEROS_26};

static SSL_METHOD tlsv1_method = {TLS1_VERSION, 0, SSL_OP_NO_TLSv1 ZEROS_26};
static SSL_METHOD tlsv1_1_method = {TLS1_1_VERSION, 0, SSL_OP_NO_TLSv1_1 ZEROS_26};
static SSL_METHOD tlsv1_2_method = {TLS1_2_VERSION, 0, SSL_OP_NO_TLSv1_2 ZEROS_26};

static const SSL_METHOD TLS_method_data = {TLS_ANY_VERSION, 0, 0 ZEROS_26};

const SSL_METHOD *TLS_method()
{
    return &TLS_method_data;
}

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
const SSL_CIPHER *dtls1_get_cipher(unsigned int u);
int dtls1_num_ciphers(void);

static SSL_METHOD dtls_method = {DTLS_ANY_VERSION, 0, SSL_OP_NO_DTLSv1 ZEROS_26};
static SSL_METHOD dtlsv1_method = {DTLSV1_VERSION, 0, SSL_OP_NO_DTLSv1 ZEROS_26};
static SSL_METHOD dtlsv1_client_method = {DTLSV1_VERSION, 0, SSL_OP_NO_DTLSv1 ZEROS_26};
static SSL_METHOD dtlsv1_server_method = {DTLSV1_VERSION, 0, SSL_OP_NO_DTLSv1 ZEROS_26};
#endif

#else


/* RGK Add support for SSLv2 and DTLS v0.9, 1,0 and 1.2 */
static SSL_METHOD sslv23_client_method = {0, SSLV2_VERSION, SSL_CLIENT_METHOD, "TLSv1.2",ssl23_get_cipher,ssl23_num_ciphers,0,0,0};
static SSL_METHOD sslv23_server_method = {0, SSLV2_VERSION, SSL_SERVER_METHOD, "TLSv1.2",ssl23_get_cipher,ssl23_num_ciphers,0,0,0};
static SSL_METHOD sslv23_method = {0, SSLV2_VERSION, SSL_SERVER_METHOD|SSL_CLIENT_METHOD, "TLSv1.2",ssl23_get_cipher,ssl23_num_ciphers,0,0,0};

static SSL_METHOD sslv3_client_method = {3, 0, SSL_CLIENT_METHOD, "SSLv3",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD sslv3_server_method = {3, 0, SSL_SERVER_METHOD, "SSLv3",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD sslv3_method = {3, 0, SSL_SERVER_METHOD|SSL_CLIENT_METHOD, "SSLv3",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};

static SSL_METHOD tlsv1_client_method = {3, 1, SSL_CLIENT_METHOD, "TLSv1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_server_method = {3, 1, SSL_SERVER_METHOD, "TLSv1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_1_client_method = {3, 2, SSL_CLIENT_METHOD, "TLSv1.1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_1_server_method = {3, 2, SSL_SERVER_METHOD, "TLSv1.1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_2_client_method = {3, 3, SSL_CLIENT_METHOD, "TLSv1.2",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_2_server_method = {3, 3, SSL_SERVER_METHOD, "TLSv1.2",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};

static SSL_METHOD tlsv1_method = {3, 1, SSL_CLIENT_METHOD|SSL_SERVER_METHOD, "TLSv1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_1_method = {3, 2, SSL_CLIENT_METHOD|SSL_SERVER_METHOD, "TLSv1.1",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};
static SSL_METHOD tlsv1_2_method = {3, 3, SSL_CLIENT_METHOD|SSL_SERVER_METHOD, "TLSv1.2",ssl3_get_cipher,ssl3_num_ciphers,0,0,0};

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
const SSL_CIPHER *dtls1_get_cipher(unsigned int u);
int dtls1_num_ciphers(void);

static SSL_METHOD dtls_method = {1, DTLS_ANY_VERSION, SSL_CLIENT_METHOD|SSL_SERVER_METHOD, "DTLSv1",dtls1_get_cipher,dtls1_num_ciphers,0,0,0};
static SSL_METHOD dtlsv1_method = {1, DTLSV1_VERSION, SSL_CLIENT_METHOD|SSL_SERVER_METHOD, "DTLSv1",dtls1_get_cipher,dtls1_num_ciphers,0,0,0};
static SSL_METHOD dtlsv1_client_method = {1, DTLSV1_VERSION, SSL_CLIENT_METHOD, "DTLSv1",dtls1_get_cipher,dtls1_num_ciphers,0,0,0};
static SSL_METHOD dtlsv1_server_method = {1, DTLSV1_VERSION, SSL_SERVER_METHOD, "DTLSv1",dtls1_get_cipher,dtls1_num_ciphers,0,0,0};
#endif
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ or __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

static int ssl_cipher_process_rulestr(const char *rule_str,
                                      CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const SSL_CIPHER **ca_list);

STACK_OF(SSL_CIPHER) *OSSL_sslCreateCipherList(const SSL_METHOD *ssl_method,
                                    const char *str,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                    STACK_OF(SSL_CIPHER) *tls13_ciphersuites,
#endif
                                    STACK_OF(SSL_CIPHER) **cipher_list,
                                    STACK_OF(SSL_CIPHER) **cipher_list_by_id);

static const EVP_CIPHER *ssl_cipher_methods[SSL_ENC_NUM_IDX] = {
      NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
      NULL, NULL
};

#define SSL_MD_NUM_IDX  SSL_MAX_DIGEST
static const EVP_MD *ssl_digest_methods[SSL_MD_NUM_IDX] = {
      NULL, NULL, NULL, NULL, NULL, NULL
};

static int ssl_mac_secret_size[SSL_MD_NUM_IDX] = {
    0, 0, 0, 0, 0, 0
};

static int ssl_mac_pkey_id[SSL_MD_NUM_IDX] = {
      EVP_PKEY_HMAC, EVP_PKEY_HMAC, EVP_PKEY_HMAC, NID_undef,
      EVP_PKEY_HMAC, EVP_PKEY_HMAC
};

static int OSSL_get_major_proto_version(int version);
static int OSSL_verify_proto_version(int version);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/*
 * Clear the state machine state and reset back to MSG_FLOW_UNINITED
 */
void ossl_statem_clear(SSL *s)
{
    if (s == NULL) return;
    s->orig_s.statem.state = MSG_FLOW_UNINITED;
    s->orig_s.statem.hand_state = TLS_ST_BEFORE;
    s->orig_s.statem.in_init = 1;
    s->orig_s.statem.no_cert_verify = 0;
}
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static sbyte4 OSSL_psk_get_session_callback(sbyte4 connectionInstance, ubyte *pPskIdentity,
                                             ubyte4 pskIdentityLength, ubyte **ppPsk, ubyte4 *pPskLen,
                                             intBoolean *pFreeMemory);
static sbyte4 OSSL_set_server_psk_save_session_callback(sbyte4 connectionInstance,
                                                         ubyte *pServerName, ubyte4 serverNameLen,
                                                         ubyte *pIdentityPSK, ubyte4 identityLengthPSK,
                                                         ubyte *pPskData, ubyte4 pskDataLen);

static void SSL_set_server_psk_save_session_callback(SSL *pSSL);
#endif

#if defined(__RTOS_VXWORKS__) && defined(IPSSL)
/*------------------------------------------------------------------*/

static sbyte4
moc_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    Ipcom_mutex* pPthreadMutex;
    sbyte4 status = ERR_RTOS_MUTEX_CREATE;

    if (NULL == (pPthreadMutex = (Ipcom_mutex*) OSSL_CALLOC(1, sizeof(Ipcom_mutex))))
        goto exit;

    if (IPCOM_SUCCESS == ipcom_mutex_create(pPthreadMutex))
    {
        *pMutex = (RTOS_MUTEX)pPthreadMutex;
        status = OK;
    }
    else
        OSSL_FREE (pPthreadMutex);  /* free unused pointer */

exit:
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexWait(RTOS_MUTEX mutex)
{
    Ipcom_mutex* pPthreadMutex = (Ipcom_mutex *)mutex;
    MSTATUS          status = ERR_RTOS_MUTEX_WAIT;

    if ((NULL != pPthreadMutex))
    {
        ipcom_mutex_lock(*pPthreadMutex);
        status = OK;
    }
    else
    {
        /*PRINT("mutex is NULL");*/
    }
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexRelease(RTOS_MUTEX mutex)
{
    Ipcom_mutex* pPthreadMutex = (Ipcom_mutex *)mutex;
    sbyte4 status  = ERR_RTOS_MUTEX_RELEASE;

    if (NULL != pPthreadMutex)
    {
        ipcom_mutex_unlock(*pPthreadMutex);
        status = OK;
    }
    return status;
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexFree(RTOS_MUTEX* pMutex)
{
    Ipcom_mutex* pPthreadMutex;
    sbyte4 status = ERR_RTOS_MUTEX_FREE;

    if ((NULL == pMutex) || (NULL == *pMutex))
        goto exit;

    pPthreadMutex = (Ipcom_mutex *)(*pMutex);

    if (IPCOM_SUCCESS == ipcom_mutex_delete(pPthreadMutex))
    {
        OSSL_FREE(*pMutex);
        *pMutex = NULL;
        status = OK;
    }

exit:
    return status;
}

#else

static sbyte4
moc_mutexCreate(RTOS_MUTEX* pMutex, enum mutexTypes mutexType, int mutexCount)
{
    return NSSL_CHK_CALL(rtosMutexCreate, pMutex, mutexType, mutexCount);
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexWait(RTOS_MUTEX mutex)
{
    return NSSL_CHK_CALL(rtosMutexWait, mutex);
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexRelease(RTOS_MUTEX mutex)
{
    return NSSL_CHK_CALL(rtosMutexRelease, mutex);
}


/*------------------------------------------------------------------*/

static sbyte4
moc_mutexFree(RTOS_MUTEX* pMutex)
{
    return NSSL_CHK_CALL(rtosMutexFree, pMutex);
}
#endif

/*------------------------------------------------------------------*/

MSTATUS OSSL_DATETIME_getTime(TimeDate *pTime, long *pRetTime)
{
    MSTATUS status;
    TimeDate epochTime = { 0, 1, 1, 0, 0, 0 }; /* Jan 1, 1970 12:00:00 AM */
    sbyte4 diffTime;

    if ( (NULL == pTime) || (NULL == pRetTime) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = NSSL_CHK_CALL(diffTime, pTime, &epochTime, &diffTime);
    if (OK != status)
    {
        goto exit;
    }

    *pRetTime = (long) diffTime;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS OSSL_DATETIME_getDateTime(long sTime, TimeDate *pRetTime)
{
    MSTATUS status;
    TimeDate epochTime = { 0, 1, 1, 0, 0, 0 };

    if (NULL == pRetTime)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = NSSL_CHK_CALL(getNewTime, &epochTime, (sbyte4) sTime, pRetTime);

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv23_server_method(void)
{
    return &sslv23_server_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv3_server_method(void)
{
    return &sslv3_server_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_server_method(void)
{
    return &tlsv1_server_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_1_server_method(void)
{
    return &tlsv1_1_server_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_2_server_method(void)
{
    return &tlsv1_2_server_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv23_client_method(void)
{
    return &sslv23_client_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv3_client_method(void)
{
    return &sslv3_client_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_client_method(void)
{
    return &tlsv1_client_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_1_client_method(void)
{
    return &tlsv1_1_client_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_2_client_method(void)
{
    return &tlsv1_2_client_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_2_method(void)
{
    return &tlsv1_2_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_1_method(void)
{
    return &tlsv1_1_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *TLSv1_method(void)
{
    return &tlsv1_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv3_method(void)
{
    return &sslv3_method;
}

/*------------------------------------------------------------------*/

extern const
SSL_METHOD *SSLv23_method(void)
{
    return &sslv23_method;
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern const
SSL_METHOD *TLS_client_method(void)
{
    return &sslv23_client_method;
}

extern const
SSL_METHOD *TLS_server_method(void)
{
    return &sslv23_server_method;
}
#endif

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

/*------------------------------------------------------------------*/

int ssl2_num_ciphers(void)
{
    return (SSL2_NUM_CIPHERS);
}

/*------------------------------------------------------------------*/

const SSL_CIPHER *ssl2_get_cipher(unsigned int u)
{
    if (u < SSL2_NUM_CIPHERS)
        return (&(ssl2_ciphers[SSL2_NUM_CIPHERS - 1 - u]));
    else
        return (NULL);
}

/*------------------------------------------------------------------*/

#endif

int ssl23_num_ciphers(void)
{
    return (ssl3_num_ciphers());
}

/*------------------------------------------------------------------*/

const SSL_CIPHER *ssl23_get_cipher(unsigned int u)
{
    unsigned int uu = ssl3_num_ciphers();

    if (u < uu)
        return (ssl3_get_cipher(u));
    else
        return (NULL);
}

/*------------------------------------------------------------------*/

int ssl3_num_ciphers(void)
{
    return (SSL3_NUM_CIPHERS);
}

/*------------------------------------------------------------------*/

const SSL_CIPHER *ssl3_get_cipher(unsigned int u)
{
    if (u < SSL3_NUM_CIPHERS)
        return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u]));
    else
        return (NULL);
}

/*------------------------------------------------------------------*/
static SSL* findSSLFromInstance(sbyte4 instance)
{
    void *s = NULL;
    SSL *ssl = NULL;

    intBoolean isFound;

    if(instance)
        (void) NSSL_CHK_CALL(hashTableFindPtr, m_ssl_table, instance, NULL, NULL, (void**)&s, &isFound);
    ssl = (SSL*)s;
    if(NULL != ssl)
        return (ssl);
    else
        return NULL;
}

#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)

#if defined(__RTOS_LINUX__)
static void getProcessCommand(pid_t pid, char* buffer, size_t bufferSize)
{
    char fileNamePath[32];
    FILE* fp = NULL;

    (void) snprintf(fileNamePath, sizeof(fileNamePath), "/proc/%d/cmdline", (int) pid);

    if ((fp = fopen(fileNamePath, "r")) != NULL)
    {
        (void) fgets(buffer, bufferSize, fp);
        fclose(fp);
    }
}
#endif

static void writeLogErrorToFile(sbyte4 instance, MSTATUS mocError, int error, int errReason)
{
    char *pTimeStr = NULL;

    time_t logTime; /* calendar time */
#if defined(__RTOS_LINUX__)
    pid_t pid;
    char bufProcessCommand[64] = "";
#endif

    if (pLogBio != NULL)
    {
        logTime = time(NULL);
        pTimeStr = asctime(localtime(&logTime));
        pTimeStr[strlen(pTimeStr) - 1] = '\0';
#if defined(__RTOS_LINUX__)
        pid = getpid();
        getProcessCommand(pid, bufProcessCommand, sizeof(bufProcessCommand));

        BIO_printf(pLogBio, "[%s] Process Name/Command: %s | ProcessID: %d |  Connection Instance : %d | Mocana Error : %s (%d) | OpenSSL Error : %d | OpenSSL Reason : %d\n", pTimeStr, bufProcessCommand, (int) pid, (int)instance, MERROR_lookUpErrorCode(mocError), (int)mocError, error, errReason);
#else
        BIO_printf(pLogBio, "[%s] Connection Instance : %d | Mocana Error : %s (%d) | OpenSSL Error : %d | OpenSSL Reason : %d\n",
                   pTimeStr, (int)instance, MERROR_lookUpErrorCode(mocError), (int)mocError, error, errReason);
#endif
        BIO_flush(pLogBio);

    }
}
#endif

/*------------------------------------------------------------------*/

static void convertMocStatus(
    SSL *pSsl, MSTATUS status, int defaultErr, int defaultReason, int *pError, int *pErrReason)
{
    int error  = 0;
    int reason = 0;

    switch (status)
    {
        case ERR_SSL_RSA_KEY_SIZE:
        case ERR_SSL_DH_KEY_SIZE:
            error  = SSL_F_SSL3_CHECK_CERT_AND_ALGORITHM;
            reason = SSL_R_WRONG_NUMBER_OF_KEY_BITS;
            break;

        case ERR_SSL_PROTOCOL_VERSION:
            error  = SSL_F_SSL3_GET_RECORD;
            reason = SSL_R_WRONG_VERSION_NUMBER;
            break;

        case ERR_SSL_INVALID_CERT_REQUEST_MSG_SIZE:
            error  = SSL_F_SSL3_GET_CERTIFICATE_REQUEST;
            reason = SSL_R_LENGTH_MISMATCH;
            break;

        case ERR_SSL_EXTENSION_LENGTH:
            error  = SSL_F_SSL3_GET_CLIENT_HELLO;
            reason = SSL_R_LENGTH_MISMATCH;
            break;

        case ERR_SSL_INVALID_MAC:
        case ERR_SSL_INVALID_PADDING:
            error  = SSL_F_SSL3_GET_RECORD;
            reason = SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC;
            break;

        case ERR_SSL_NO_CIPHER_MATCH:
            if (SSL_SERVER_FLAG == pSsl->clientServerFlag)
            {
                error  = SSL_F_SSL3_GET_CLIENT_HELLO;
                reason = SSL_R_NO_SHARED_CIPHER;
            }
            else
            {
                error = SSL_F_SSL3_CONNECT;
                reason = SSL_R_WRONG_CIPHER_RETURNED;
            }
            break;

        case ERR_SSL_NO_CIPHERSUITE:
            error  = SSL_F_SSL3_CLIENT_HELLO;
            reason = SSL_R_NO_CIPHERS_AVAILABLE;
            break;

        case ERR_SSL_UNSUPPORTED_CURVE:
            if (SSL_CLIENT_FLAG == pSsl->clientServerFlag)
            {
                error = SSL_F_SSL3_CONNECT;
                reason = SSL_R_UNSUPPORTED_ELLIPTIC_CURVE;
            }
            break;

        case ERR_MEM_ALLOC_FAIL:
            error  = SSL_F_SSL3_WRITE_BYTES;
            reason = ERR_R_MALLOC_FAILURE;
            break;

        case ERR_SSL_CERT_VALIDATION_FAILED:
        case ERR_CERT_CHAIN_NO_TRUST_ANCHOR:
        case ERR_CERT_REVOKED:
        case ERR_CERT_EXPIRED:
            if (SSL_SERVER_FLAG == pSsl->clientServerFlag)
            {
            error  = SSL_F_SSL3_GET_CLIENT_CERTIFICATE;
            reason = SSL_R_CERTIFICATE_VERIFY_FAILED;
            }
            else
            {
            error  = SSL_F_SSL3_GET_SERVER_CERTIFICATE;
            reason = SSL_R_CERTIFICATE_VERIFY_FAILED;
            }
            break;

        case ERR_SSL_HASH_ALGO_NULL:
            error  = SSL_F_SSL3_HANDSHAKE_MAC;
            reason = SSL_R_NO_REQUIRED_DIGEST;
            break;

        case ERR_SSL_INVALID_SIGNATURE:
            if (SSL_SERVER_FLAG == pSsl->clientServerFlag)
            {
            error  = SSL_F_SSL3_GET_CERT_VERIFY;
            reason = SSL_R_BAD_SIGNATURE;
            }
            else
            {
            error  = SSL_F_SSL3_GET_KEY_EXCHANGE;
            reason = SSL_R_BAD_SIGNATURE;
            }
            break;

        case ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE:
            error  = SSL_F_SSL3_GET_CERT_STATUS;
            reason = SSL_R_INVALID_STATUS_RESPONSE;
            break;

        case ERR_CERT_INVALID_PARENT_CERTIFICATE:
            error  = SSL_F_SSL_BUILD_CERT_CHAIN;
            reason = SSL_R_CERTIFICATE_VERIFY_FAILED;
            break;

        default:
            error  = defaultErr;
            reason = defaultReason;
            break;
    }

#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
    writeLogErrorToFile(pSsl->instance, status, error, reason);
#endif

    *pError = error;
    *pErrReason = reason;
}

/*------------------------------------------------------------------*/

static void convertMocStatusToSslErr(
    SSL *pSsl, MSTATUS status, int defaultErr, int defaultReason)
{
    int error;
    int reason;

    convertMocStatus(pSsl, status, defaultErr, defaultReason, &error, &reason);
    SSLerr(error, reason);
}

/*------------------------------------------------------------------*/

static int asyncSendDataBio(
    SSL *pSsl, const void *pDataBuf, int dataLen, int *pSent)
{
    int i = 0;
    char *pData = (char *) pDataBuf;

    if (NULL != pSent)
        *pSent = 0;

    pSsl->io_state = OSSL_IN_WRITE;
    pSsl->orig_s.rwstate = SSL_WRITING;

    /* Loop until all the data is sent.
     *
     * Exit conditions
     *   - All data is sent
     *   - BIO_write fails
     *   - BIO_should_retry is false
     */
    while (dataLen > 0)
    {
        while (0 >= (i = BIO_write(pSsl->wbio, pData, dataLen)))
        {
            if ((0 > i) || (!BIO_should_retry(pSsl->wbio)))
            {
                goto exit;
            }
        }

        (void) BIO_flush(pSsl->wbio);

        dataLen -= i;
        pData += i;

        if (NULL != pSent)
            *pSent += i;
    }

    pSsl->io_state = 0;
    pSsl->orig_s.rwstate = SSL_NOTHING;

exit:

    return i;
}

/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
MSTATUS OSSL_sessionAcquireMutex(SSL *s)
{
    if (NULL == s)
        return -1;

    if (NULL != s->session_mutex)
        return moc_mutexWait(s->session_mutex);
    else
        return -1;
}
#endif

static sbyte4 asyncSendPendingData(SSL *pSsl)
{
    ubyte4 mySendBufLen = 0;
    sbyte4 status = 0;
    int i = 0, bytesSent = 0;
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    int mutexAcquired = 0;
#endif

    mySendBufLen = pSsl->szTxHoldingBuf;
    while (OK == status)
    {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(pSsl);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif
        status = NSSL_CHK_CALL(getPreparedSslRec, pSsl->instance, pSsl->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(pSsl);
                mutexAcquired = 0;
            }
#endif
        if (OK > status)
            break;

        i = asyncSendDataBio(pSsl, pSsl->pTxHoldingBuf, mySendBufLen, &bytesSent);
        if (0 >= i)
        {
            pSsl->bytesSentRemaining = mySendBufLen - bytesSent;
            pSsl->txHoldingBufOffset = bytesSent;
            status = 0;
            goto exit;
        }

        pSsl->orig_s.rwstate = SSL_READING;
        mySendBufLen    = pSsl->szTxHoldingBuf;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
int dtls1_num_ciphers(void)
{
    return (SSL3_NUM_CIPHERS);
}


#ifdef __ENABLE_DIGICERT_IPV6__
/*------------------------------------------------------------------*/
/* convert an ipv6 string addr to MOC_IP_ADDRESS  */
static MSTATUS
mocNetNameToIpaddr(MOC_IP_ADDRESS destAddr, ubyte * name)
{
    MSTATUS status = OK;

    struct addrinfo        Hints, *AddrInfo = NULL;
    int                       RetVal;

    memset(&Hints, 0, sizeof (Hints));
    Hints.ai_family = AF_INET;
    Hints.ai_socktype = SOCK_DGRAM;
    Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    RetVal = getaddrinfo((const char *)name, NULL, &Hints, &AddrInfo);
    if (RetVal != 0) {

        status = ERR_INVALID_ARG;

        goto exit;
    }

    memcpy((*destAddr).uin.addr6, &((struct sockaddr_in6 *)(AddrInfo->ai_addr))->sin6_addr, 16);
exit:
    if (NULL != AddrInfo)
    {
        freeaddrinfo(AddrInfo);
    }
    return status;
}
#else
/*------------------------------------------------------------------*/

static MSTATUS
mocNetNameToIpaddr(MOC_IP_ADDRESS_S * destAddr, ubyte * name)
{
    struct in_addr iar;

#ifdef __RTOS_WIN32__
    if(!inet_pton(AF_INET, (const char*)name, &iar))
#else
    if(!inet_aton((const char*)name, &iar))
#endif
        return ERR_INVALID_INPUT;

    *destAddr = iar.s_addr;

   return OK;
}
#endif /* __ENABLE_DIGICERT_IPV6__ */

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* Return values:
 * < 0 - Fatal Error
 * = 0 - HelloVerifyRequest was sent; This is handled by stack and 0 return value is ignored
 * = 1 -  Success*/
int DTLSv1_listen(SSL *s, BIO_ADDR *peer)
{
    sbyte4 status = OK;
    sbyte4 ret = -1;
    BIO *rbio, *wbio;
    ubyte *pInBuffer = NULL;
    ubyte4 inBufferLen;
    ubyte outBuffer[128]; /* HelloVerifyRequest message size */
    ubyte4 mySendBufLen = 0;
    ubyte4 bytesSent;
    ubyte4 bytesRead;

    int           i = 0;
    intBoolean cookieVerified = FALSE;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     peerDescr myPeerDescr = {0};
     ubyte *srcAddr  = (ubyte *)"0.0.0.0";
     ubyte *peerAddr = (ubyte *)"1.1.1.1";
#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */

    if (NULL == s)
    {
        /* Error File may not be SSL3. Check*/
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        return -1;
    }

    ERR_clear_error();

    if (!s->rbio || !s->wbio) {
        return -1;
    }

    pInBuffer = OSSL_MALLOC(OSSL_MAX_SSL_RX_MSG_SZ);
    if (NULL == pInBuffer)
    {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
        return -1;
    }
    inBufferLen = OSSL_MAX_SSL_RX_MSG_SZ;

    s->io_state       = OSSL_IN_READ;
    s->orig_s.rwstate = SSL_READING;
    while( 0 >= (i = BIO_read(s->rbio, pInBuffer, inBufferLen)))
    {
        if ((i < 0)||(!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
        {
            goto exit;
        }
    }
    bytesRead = i;

    status = NSSL_CHK_CALL(dtlsVerifyClientHelloCookie, &myPeerDescr, pInBuffer, bytesRead, outBuffer, &mySendBufLen);
    if (OK > status && ERR_DTLS_BAD_HELLO_COOKIE != status)
    {
        goto exit;
    }

    if (mySendBufLen > 0 && ERR_DTLS_BAD_HELLO_COOKIE == status) /* client hello had no cookie */
    {
        i = asyncSendDataBio(s, outBuffer, mySendBufLen, (int *) &bytesSent);
        if (0 >= i)
        {
            goto exit;
        }
        ret = 0;
        goto exit;
    }

    s->pHoldingBuf          = pInBuffer;
    s->szHoldingBuf         = inBufferLen;
    s->bytesRcvdRemaining   = bytesRead;
    s->pFirstRcvdUnreadByte = s->pHoldingBuf;

    SSL_set_options (s, SSL_OP_COOKIE_EXCHANGE);

    (void) BIO_dgram_get_peer(SSL_get_rbio(s), peer);
    ret = s->hello_verify_done = 1;
exit:
    if (ret < 1)
        OSSL_FREE(pInBuffer);
    return ret;
}
#endif
/*-----------------------------------------------------------------*/
static sbyte4 OSSL_DTLS_listen(SSL *s, void *client)
{
    sbyte4 status = OK;


    if(OK > (status = SSL_accept(s)))
    {
        goto exit;
    }

    (void) BIO_dgram_get_peer(SSL_get_rbio(s), client);

exit:
    return status;
}

static sbyte4 OSSL_DTLS_handleTimeout(SSL *s)
{
    ubyte   *pSendBuffer = NULL;
    ubyte4  numBytes = OSSL_MAX_SSL_MSG_SZ;
    sbyte4 status = OK;
    int i;

    pSendBuffer = OSSL_MALLOC(numBytes);
    if (NULL == pSendBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = NSSL_CHK_CALL(dtlsHandleTimeout, s->instance);
    if(OK > status)
        goto exit;

    s->io_state = OSSL_IN_WRITE;

    while (OK == (status = NSSL_CHK_CALL(dtlsGetSendBuffer,s->instance, pSendBuffer, &numBytes)))
    {
        i = asyncSendDataBio(s, pSendBuffer, numBytes, NULL);
        if (0 >= i)
        {
            status = i;
            goto exit;
        }

        numBytes = OSSL_MAX_SSL_MSG_SZ;
    }

exit:

    if (NULL != pSendBuffer)
    {
        OSSL_FREE(pSendBuffer);
    }

    return status;
}

sbyte4 DTLS_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    sbyte4 status = 0;
    switch(cmd)
    {
    case DTLS_CTRL_GET_TIMEOUT:
        if (s == NULL) {
            status = ERR_SSL_BAD_ID;
        } else {
            status = NSSL_CHK_CALL(dtlsGetTimeout, s->instance, parg);
        }
        break;
    case DTLS_CTRL_HANDLE_TIMEOUT:
        status = OSSL_DTLS_handleTimeout(s);
        break;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case DTLS_CTRL_LISTEN:
        status = OSSL_DTLS_listen(s, parg);
        break;
#endif
    case SSL_CTRL_CHECK_PROTO_VERSION:
        if (s == NULL) 
        {
            status = 0;
        }
        else if(s->version == s->ssl_ctx->ssl_method->version)
        {
            status = 1;
        }
        else
        {
            status = 0;
        }
        break;
    case SSL_CTRL_SET_MTU:
        if (s == NULL) {
            status = ERR_SSL_BAD_ID;
        } else {
            status = NSSL_CHK_CALL(dtlsIoctl, s->instance, DTLS_SET_PMTU, parg);
        }
        break;
    default:
        break;
    }
    return status;
}

/* DTLS SRTP */
static SRTP_PROTECTION_PROFILE srtp_known_profiles[] = {
    {
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
     "SRTP_AES128_CM_SHA1_80",
     SRTP_AES128_CM_SHA1_80,
     },
    {
     "SRTP_AES128_CM_SHA1_32",
     SRTP_AES128_CM_SHA1_32,
     },
#endif
#ifdef __ENABLE_DIGICERT_GCM__
#ifndef __DISABLE_AES128_CIPHER__
    {
     "SRTP_AEAD_AES_128_GCM",
     SRTP_AEAD_AES_128_GCM,
    },
#endif
#ifndef __DISABLE_AES256_CIPHER__
    {
     "SRTP_AEAD_AES_256_GCM",
     SRTP_AEAD_AES_256_GCM,
    },
#endif
#endif
#endif
    {
     "SRTP_NULL_SHA1_80",
     SRTP_NULL_SHA1_80,
    },
    {
     "SRTP_NULL_SHA1_32",
     SRTP_NULL_SHA1_32,
    },
    {0}
};

static sbyte4 OSSL_srtpInitCallback(sbyte4 connectionInstance, void *pChannelDescr,
                                     void *pProfileAux, void* keyMaterials, ubyte* mki)
{
    SSL *pSsl = NULL;
    OSSL_SrtpProfileInfo *pProfile = (OSSL_SrtpProfileInfo*) pProfileAux;
    pSsl = (SSL *) findSSLFromInstance(connectionInstance);
    if ((NULL == pSsl) || (NULL == pSsl->ssl_ctx) || (NULL == pProfile))
    {
        return -1;
    }

    if (pSsl->numSrtpProfileIds > 0)
    {
        pSsl->selectedSrtpId = pProfile->profileId;
    }

    return OK;
}

static sbyte4 OSSL_srtpEncodeCallback(sbyte4 connectionInstance, void *pChannelDescr,
                                 const sbyte* pData, ubyte4 pDataLength,
                                 ubyte** encodedData, ubyte4* encodedLength)
{
    return OK;
}


static sbyte4 OSSL_setSrtpInitCallBack()
{
     SrtpInitCallback srtpInitCallback;
     srtpInitCallback = OSSL_srtpInitCallback;
     if (OK > NSSL_CHK_CALL(setSrtpInitCallback, srtpInitCallback))
     {
        return -1;
     }
     return 0;
}

static sbyte4 OSSL_setSrtpEncodeCallBack()
{
     SrtpEncodeCallback srtpEncodeCallback;
     srtpEncodeCallback = OSSL_srtpEncodeCallback;
     if (OK > NSSL_CHK_CALL(setSrtpEncodeCallback, srtpEncodeCallback))
     {
        return -1;
     }
     return 0;
}


static int find_profile_by_id(unsigned long id,
                                SRTP_PROTECTION_PROFILE **pptr)
{
    SRTP_PROTECTION_PROFILE *p;

    p = srtp_known_profiles;
    while (p->name)
    {
        if (id == p->id)
        {
            *pptr = p;
            return 0;
        }
        p++;
    }

    return 1;
}

static int find_profile_by_name(char *profile_name,
                                SRTP_PROTECTION_PROFILE **pptr, unsigned len)
{
    SRTP_PROTECTION_PROFILE *p;

    p = srtp_known_profiles;
    while (p->name) {
        if ((len == strlen(p->name)) && !strncmp(p->name, profile_name, len)) {
            *pptr = p;
            return 0;
        }

        p++;
    }

    return 1;
}

static int ssl_ctx_make_profiles(const char *profiles_string,
                                 STACK_OF(SRTP_PROTECTION_PROFILE) **out,
                                 ubyte2 **ppProfileIds, ubyte4 *pNumProfileId)
{
    STACK_OF(SRTP_PROTECTION_PROFILE) *profiles;

    char *col;
    char *ptr = (char *)profiles_string;
    ubyte2 pProfileIds[MAX_NUM_SRTP_PROFILE_IDS] = {0};
    ubyte4 numProfileIds = 0;

    SRTP_PROTECTION_PROFILE *p;

    if (!(profiles = sk_SRTP_PROTECTION_PROFILE_new_null())) {
        SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
               SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES);
        return 1;
    }

    do {
        col = strchr(ptr, ':');

        if (!find_profile_by_name(ptr, &p,
                                  col ? col - ptr : (int)strlen(ptr))) {
            if (sk_SRTP_PROTECTION_PROFILE_find(profiles, p) >= 0) {
                SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
                       SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST);
                sk_SRTP_PROTECTION_PROFILE_free(profiles);
                return 1;
            }
            sk_SRTP_PROTECTION_PROFILE_push(profiles, p);
            pProfileIds[numProfileIds] = (ubyte2)p->id;
            numProfileIds++;

        } else {
            SSLerr(SSL_F_SSL_CTX_MAKE_PROFILES,
                   SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE);
            sk_SRTP_PROTECTION_PROFILE_free(profiles);
            return 1;
        }

        if (col)
            ptr = col + 1;
    } while (col);

    *out = profiles;
    memcpy(*ppProfileIds, pProfileIds, numProfileIds * sizeof(ubyte2));
    *pNumProfileId = numProfileIds;

    return 0;
}

/* 0 == success
 * 1 == failure
 */
int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *ctx, const char *profiles)
{
    int rVal = 0;
    if (ctx == NULL)
        return 1;

    rVal = ssl_ctx_make_profiles(profiles, &ctx->orig_ssl_ctx.srtp_profiles,
                                 (ubyte2 **)&ctx->srtpProfileIds, &ctx->numSrtpProfileIds);
    if (0 == rVal)
    {
        OSSL_setSrtpInitCallBack();
    }
    return rVal;
}

/* 0 == success
 * 1 == failure
 */
int SSL_set_tlsext_use_srtp(SSL *s, const char *profiles)
{
    int rVal = 0;

    if (s == NULL)
        return 1;

    rVal = ssl_ctx_make_profiles(profiles, &s->orig_s.srtp_profiles,
                                 (ubyte2 **)&s->srtpProfileIds, &s->numSrtpProfileIds);
    if (0 == rVal)
    {
        OSSL_setSrtpInitCallBack();
    }
    return rVal;
}

STACK_OF(SRTP_PROTECTION_PROFILE) *SSL_get_srtp_profiles(SSL *s)
{
    if (s != NULL)
    {
        if (s->orig_s.srtp_profiles != NULL)
        {
            return s->orig_s.srtp_profiles;
        }
        else if ((s->ssl_ctx != NULL) && (s->ssl_ctx->orig_ssl_ctx.srtp_profiles != NULL))
        {
            return s->ssl_ctx->orig_ssl_ctx.srtp_profiles;
        }
    }

    return NULL;
}

SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *s)
{
    SRTP_PROTECTION_PROFILE *pProfile = NULL;
    if (NULL == s)
    {
        return pProfile;
    }

    find_profile_by_id(s->selectedSrtpId, &pProfile);
    return pProfile;
}

extern const SSL_METHOD
*DTLSv1_method(void)
{
  return &dtlsv1_method;
}

/*-----------------------------------------------------------------*/

extern const SSL_METHOD
*DTLSv1_client_method(void)
{
    return &dtlsv1_client_method;
}

/*-----------------------------------------------------------------*/
extern const SSL_METHOD
*DTLSv1_server_method(void)
{
    return &dtlsv1_server_method;
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLS_server_method(void)
{
  return &dtlsv1_server_method;
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLS_client_method(void)
{
  return &dtlsv1_client_method;
}

/*------------------------------------------------------------------*/

const SSL_CIPHER *dtls1_get_cipher(unsigned int u)
{
    const SSL_CIPHER *ciph = ssl3_get_cipher(u);

    if (ciph != NULL)
    {
        if (ciph->algorithm_enc == SSL_RC4)
        return NULL;
    }

    return ciph;
}
#endif

/*------------------------------------------------------------------*/

int SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg)
{
    if(s == NULL)
        return 0;

    return (CRYPTO_set_ex_data(&s->ex_data, idx, arg));
}

/*------------------------------------------------------------------*/

void *SSL_get_ex_data(const SSL *s, int idx)
{
    if (NULL == s)
        return NULL;

    if (NULL != s->ex_data.sk)
        return (CRYPTO_get_ex_data(&s->ex_data, idx));

    if (NULL != s->orig_s.ex_data.sk)
        return (CRYPTO_get_ex_data(&s->orig_s.ex_data, idx));

    return NULL;
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

/* Not implemented yet.
 */
int SSL_session_reused(SSL *s)
{
    intBoolean isResumed;
    if (s == NULL)
        return 0;

    if (OK == NSSL_CHK_CALL(isSessionResumed, s->instance, &isResumed))
    {
        return (int) isResumed;
    }

    return 0;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

void *SSL_CTX_get_ex_data(const SSL_CTX *s, int idx)
{
    if (s == NULL) return NULL;
    return (CRYPTO_get_ex_data(&s->ex_data, idx));
}

/*------------------------------------------------------------------*/

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*cb) (struct ssl_st *ssl,
                                        SSL_SESSION *sess))
{
    if(NULL != ctx)
        ctx->new_session_cb = cb;
}

/*------------------------------------------------------------------*/

/**
 * Sets the callback function which is called, whenever a SSL/TLS client
 * proposed to resume a session but the session could not be found in the
 * internal session cache (see SSL_CTX_set_session_cache_mode(3)).
 * (SSL/TLS server only.)
 *
 * (from OpenSSL docs)
 */
void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*cb) (struct ssl_st *ssl,
                                                 unsigned char *data, int len,
                                                 int *copy))
{
    if(NULL != ctx)
        ctx->get_session_cb = cb;
}

/*------------------------------------------------------------------*/

SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx)) (SSL *ssl,
                                                       unsigned char *data,
                                                       int len, int *copy)
{
    if (NULL == ctx) return NULL;
    return ctx->get_session_cb;
}

/*------------------------------------------------------------------*/

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
                                void (*cb) (SSL_CTX *ctx, SSL_SESSION *sess))
{
    if(NULL != ctx)
        ctx->remove_session_cb = cb;
}

/*------------------------------------------------------------------*/

extern long SSL_CTX_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp) (void))
{
    if(NULL == ctx)
        return 0;

    switch (cmd) {

    case SSL_CTRL_SET_TMP_RSA_CB:
        {
         ctx->rsa_tmp_cb = (RSA *(*)(SSL *, int, int))fp;
        }
        break;
    case SSL_CTRL_SET_TMP_DH_CB:
        {
         ctx->dh_tmp_cb = (DH *(*)(SSL *, int, int))fp;
        }
        break;
#if (defined (__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
    case SSL_CTRL_SET_TMP_ECDH_CB:
        {
         ctx->ecdh_tmp_cb = (EC_KEY *(*)(SSL *, int, int))fp;
        }
        break;
#endif
    case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
        {
         ctx->tlsext_servername_callback = (int (*)(SSL *, int *, void *))fp;
        }
        break;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB:
        {
            ctx->tlsext_status_cb = (int (*)(SSL *, void *))fp;
        }
        break;
    case SSL_CTRL_SET_MSG_CALLBACK:
        {
         ctx->msg_callback =  (void (*)
                             (int write_p, int version, int content_type,
                              const void *buf, size_t len, SSL *ssl,
                              void *arg))(fp);
         }
        break;
    case SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB:
        /* Not implemented */
        return 0;
    default:
        return (0);
    }
    return (1);
}

/*------------------------------------------------------------------*/

void SSL_CTX_set_msg_callback(SSL_CTX *ctx,
                              void (*cb) (int write_p, int version,
                                          int content_type, const void *buf,
                                          size_t len, SSL *ssl, void *arg))
{
    if(NULL != ctx)
        (void) SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

/*------------------------------------------------------------------*/

void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
                                 DH *(*dh) (SSL *ssl, int is_export,
                                            int keylength))
{
     if(NULL != ctx)
        (void) SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TMP_DH_CB, (void (*)(void))dh);
}

/*------------------------------------------------------------------*/

/**
 * Sets the callback function, that can be used to obtain state information for
 * SSL objects created from ctx during connection setup and use.
 * The setting for ctx is overridden from the setting for a specific SSL object,
 * if specified.  When callback is NULL, not callback function is used.
 *
 * (from OpenSSL docs)
 */
void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                               void (*cb) (const SSL *ssl, int type, int val))
{
    if(NULL != ctx)
        ctx->info_callback = cb;
}

void (*SSL_CTX_get_info_callback(SSL_CTX *ctx)) (const SSL *ssl, int type,int val)
{
    if (ctx == NULL) return NULL;
    return ctx->info_callback;
}

/*------------------------------------------------------------------*/

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
    return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL, argl, argp,
                                   new_func, dup_func, free_func);
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
{
    if ((NULL == ctx) || (NULL == x))
        return 0;

    if (NULL == ctx->client_CA)
        ctx->client_CA = sk_X509_NAME_new_null();

    (void)sk_X509_NAME_push(ctx->client_CA, X509_NAME_dup(X509_get_subject_name(x)));
    return 1;
}

/*------------------------------------------------------------------*/

int SSL_CTX_check_private_key(const SSL_CTX *ctx)
{
    if (NULL == ctx)
    {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }
    if (NULL == ctx->cert_x509)
    {
        SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
            SSL_R_NO_CERTIFICATE_ASSIGNED);
        return (0);
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    return 1;
#else
    return (X509_check_private_key(ctx->cert_x509,
                                   ctx->privatekey[ctx->ossl_pkey_idx]));
#endif
}

/*------------------------------------------------------------------*/

X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx)
{
    if (NULL != ctx->cert_x509 )
        return ctx->cert_x509;
    else
        return NULL;
}

/*------------------------------------------------------------------*/

void DIGI_PKEY_EX_DATA_free(void *pParent, void *pData, CRYPTO_EX_DATA *pAd,
                       int idx, long argl, void *pArgp)
{
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
    MOC_EVP_KEY_DATA *pExData = (MOC_EVP_KEY_DATA *)pData;
    if (NULL != pExData->pContents)
    {
        memset(pExData->pContents, 0, pExData->contentsLen);
        NSSL_CHK_CALL(mocFree, (void **) &pExData->pContents);
    }

    if (NULL != pExData->pData)
    {
        NSSL_CHK_CALL(mocFree, (void **) &pExData->pData);
    }

    if (NULL != pExData->pCred)
    {
        memset(pExData->pCred, 0, pExData->credLen);
        NSSL_CHK_CALL(mocFree, (void **) &pExData->pCred);
    }

    NSSL_CHK_CALL(mocFree, (void **) &pExData);
#else
    OSSL_KeyBlobInfo *pExData = (OSSL_KeyBlobInfo *)pData;
    if (pData == NULL)
        return;

    OSSL_FREE(pExData->pKeyBlob);
    pExData->pKeyBlob = NULL;
    pExData->keyBlobLength = 0;
    OSSL_FREE(pExData);
#endif
}

static void
SSL_CTX_clear(SSL_CTX *ctx)
{
     int i;
     if (ctx == NULL)
        return;

#ifdef __ENABLE_DIGICERT_CERT_FREE__
     if (NULL != ctx->cert_x509)
     {
         X509_free(ctx->cert_x509);
         ctx->cert_x509 = NULL;
     }

     if (NULL != ctx->peerCert)
     {

         X509_free(ctx->peerCert);
         ctx->peerCert = NULL;
     }
#endif /* __ENABLE_DIGICERT_CERT_FREE__ */

     if (NULL != ctx->peerCertChain)
      sk_X509_pop_free(ctx->peerCertChain, X509_free);

     for (i = 0; i < OSSL_PKEY_MAX; ++i) {
      if (NULL != ctx->privatekey[i])
      {
           void *exData = NULL;
           EVP_PKEY *pkey = ctx->privatekey[i];

           if (ctx->privatekey[i]->type == EVP_PKEY_RSA)
           {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
               exData = RSA_get_ex_data(pkey->keydata, moc_get_rsa_ex_app_data());
#else
               exData = RSA_get_ex_data(pkey->pkey.rsa, rsaExAppDataIndex);
#endif
           }
#if (defined(__ENABLE_DIGICERT_ECC__))
           else if (ctx->privatekey[i]->type == EVP_PKEY_EC)
           {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
               exData = EC_KEY_get_ex_data(pkey->keydata, moc_get_ecc_ex_app_data());
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
               exData = EC_KEY_get_ex_data(pkey->pkey.ec, eccExAppDataIndex);
#else
               exData = ECDSA_get_ex_data(pkey->pkey.ec, eccExAppDataIndex);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ or __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
           }
#endif
            if (exData)
            {
                DIGI_PKEY_EX_DATA_free(NULL, exData, NULL, 0, 0, NULL);
            }
           EVP_PKEY_free(ctx->privatekey[i]);
           ctx->privatekey[i] = NULL;
      }
     }
     if (NULL != ctx->pCertStore) {
      NSSL_CHK_CALL(releaseCertStore, &ctx->pCertStore);
     }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) && defined(__ENABLE_DIGICERT_TAP__)
     ossl_clearCredentials();
#endif

     if (NULL != ctx->client_CA)
      sk_X509_NAME_pop_free(ctx->client_CA, X509_NAME_free);

     if (ctx->alpn_client_proto_list != NULL)
        OSSL_FREE(ctx->alpn_client_proto_list);

      if (ctx->cert_store != NULL)
        X509_STORE_free(ctx->cert_store);

     if (ctx->orig_ssl_ctx.param)
        X509_VERIFY_PARAM_free(ctx->orig_ssl_ctx.param);

     if (ctx->cipher_list != NULL)
     {
        sk_SSL_CIPHER_free(ctx->cipher_list);
     }

    if (ctx->cipher_list_by_id != NULL)
    {
        sk_SSL_CIPHER_free(ctx->cipher_list_by_id);
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (ctx->tls13_ciphersuites != NULL)
    {
        sk_SSL_CIPHER_free(ctx->tls13_ciphersuites);
        ctx->tls13_ciphersuites = NULL;
    }
#endif

    if (ctx->pEccCurves != NULL)
    {
        OSSL_FREE(ctx->pEccCurves);
    }

    if (ctx->orig_ssl_ctx.cert != NULL)
    {
        if (ctx->orig_ssl_ctx.cert->conf_sigalgs != NULL)
        {
            OSSL_FREE(ctx->orig_ssl_ctx.cert->conf_sigalgs);
        }
        OSSL_FREE(ctx->orig_ssl_ctx.cert);
    }

    if (NULL != ctx->orig_ssl_ctx.srtp_profiles)
    {
        sk_SRTP_PROTECTION_PROFILE_free(ctx->orig_ssl_ctx.srtp_profiles);
    }

    if (ctx->pKeyAlias != NULL)
    {
        OSSL_FREE(ctx->pKeyAlias);
        ctx->pKeyAlias = NULL;
    }

    for (i = 0; i < ctx->cert_x509_list.count; i++)
    {
        X509_free(ctx->cert_x509_list.certs[i]);
        ctx->cert_x509_list.certs[i] = NULL;
    }
    ctx->cert_x509_list.count = 0;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    CRYPTO_THREAD_lock_free(ctx->orig_ssl_ctx.lock);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (ctx->tls13_ciphersuites != NULL)
    {
        sk_SSL_CIPHER_free(ctx->tls13_ciphersuites);
        ctx->tls13_ciphersuites = NULL;
    }
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != ctx->verify_store)
    {
        X509_STORE_free(ctx->verify_store);
        ctx->verify_store = NULL;
    }
#endif

     memset((ubyte*)ctx, 0, sizeof(*ctx));
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_free(SSL_CTX *ctx)
{
    int i;
    if (NULL != ctx)
    {
        /* Decrement CTX count. Proceed to clear only if
         * there are no CTX present.
         * OpenLDAP increments the counter directly, need to use
         * original attribute
         */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        CRYPTO_atomic_add(&ctx->orig_ssl_ctx.references, -1, &i, ctx->orig_ssl_ctx.lock);
#else
        i = CRYPTO_add(&ctx->orig_ssl_ctx.references, -1, CRYPTO_LOCK_SSL_CTX);
#endif
        if (i > 0)
            return;
        if (i < 0)
            return ; /* ERROR */
        CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_CTX, ctx, &ctx->ex_data);
        SSL_CTX_clear(ctx);
        OSSL_FREE(ctx);
        ctx = NULL;
    }
}

/*------------------------------------------------------------------*/

extern X509_STORE *
SSL_CTX_get_cert_store(const SSL_CTX *ctx)
{
     if(NULL == ctx)
        return NULL;
     return ctx->cert_store;
}

/*------------------------------------------------------------------*/

extern
void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
                                    unsigned *len)
{
    SSLerr(SSL_F_SSL_UNDEFINED_FUNCTION, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    /* @Note: Unsupported. We do not support NPN */
}

/*------------------------------------------------------------------*/

extern
const COMP_METHOD *SSL_get_current_compression(SSL *s)
{
    if (s == NULL) return NULL;
    if (s->compress != NULL)
        return (s->compress->meth);
    return NULL;
}

/*------------------------------------------------------------------*/

/**
 * (Per OpenSSL docs)
 * returns a pointer to the selected protocol in data with length len. It is not
 * NUL-terminated. data is set to NULL and len is set to 0 if no protocol has
 * been selected. data must not be freed.*/
extern
void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
                            unsigned *len)
{
    ubyte4 alpn_len = 0;
    if(NULL != ssl){
        NSSL_CHK_CALL(get_alpn_selected, ssl->instance, data, &alpn_len);
       *len = (unsigned)alpn_len;
    }
}

/*------------------------------------------------------------------*/

extern
size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count)
{
    size_t ret = 0;

    if(NULL == s)
        return (size_t) 0;

    if (NULL != s->s3 ) {
        ret = s->s3->tmp.peer_finish_md_len;
        if (count > ret)
            count = ret;
        memcpy(buf, s->s3->tmp.peer_finish_md, count);
    }
    return ret;
}

/*------------------------------------------------------------------*/

extern
size_t SSL_get_finished(const SSL *s, void *buf, size_t count)
{
    size_t ret = 0;
    if(s == NULL)
        return (size_t) 0;

    if (s->s3 != NULL) {
        ret = s->s3->tmp.finish_md_len;
        if (count > ret)
            count = ret;
        memcpy(buf, s->s3->tmp.finish_md, count);
    }
    return ret;
}

/*------------------------------------------------------------------*/


/* (From OpenSSL docs)
 * Used by the client to set the list of protocols available to be negotiated.
 *
 * OpenSSL and NanoSSL format the ALPN list differently. OpenSSL uses "wire-
 * format", where the protocols are defined like:
 *
 *   unsigned char vector[] = {
 *       6, 's', 'p', 'd', 'y', '/', '1',
 *       8, 'h', 't', 't', 'p', '/', '1', '.', '1'
 *   };
 *   unsigned int length = sizeof(vector);
 *
 * NanoSSL expects an array of (null-terminated) strings to define the
 * protocols. We have to convert the wire-format to an array of strings.
 */
int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                        unsigned int protos_len){
    /* This function is also called internally in Opessl wrapper,
     * error codes are set as per Openssl. So, default return value
     * can be 0.*/
    sbyte4 status = 0;
    unsigned int i;
    ubyte curProtoLen,curProto;
    ubyte numProtos = 0;
    ubyte** protoList = NULL;
    ubyte j,k;

    if( NULL == ssl ) {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        status = SSL_R_UNINITIALIZED;
        goto exit;
    }

    if ((!protos) || (protos_len < 1))
    {
      SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_BAD_VALUE);
      status = SSL_R_BAD_VALUE;
      goto exit;
    }
    /* We iterate through once to determine total size of all the protocol
     * text
     **/
    i = 0;
    while(i < protos_len){
        numProtos++;
        i = i+ protos[i] +1; /* Jump ahead in the string by the size of the string*/
    }

     if (NULL == (protoList = OSSL_MALLOC(numProtos * sizeof(char*)))) {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
        status = ERR_R_MALLOC_FAILURE;
        goto exit;
      }

    i = 0;
    curProto = 0;
    while(i < protos_len){
        curProtoLen = protos[i];

        /* curProto started with 0 and it is updated at the end of the loop */
        if(curProto >= numProtos){
            /* We counted wrong somehow, since the number we find should match
             * what we calculated above */
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL);
            status = ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL;
            goto exit;
        }
        if((unsigned)(curProtoLen + i) >= protos_len){
            /* The string length given in the input is bad since it puts our
             * index past the end of the string */
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL);
            status = ERR_SSL_EXTENSION_INVALID_ALPN_PROTOCOL;
            goto exit;
        }

     if (NULL == (protoList[curProto] = OSSL_CALLOC(curProtoLen + 1,sizeof(char)))) { /* Add 1 for terminating null */
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            status = ERR_R_MALLOC_FAILURE;
            goto exit;
      }
      /* Skip value with Length of the string. Should not be the part of the List */
      j =i+1;
      k=0;
      while(k < curProtoLen){
        protoList[curProto][k] = protos[j];
        j++;
        k++;
      }
      protoList[curProto][k] = '\0';
      i = i+curProtoLen+1; /* Get to the right pointer which has string length */
      curProto++;
    }
    NSSL_CHK_CALL(set_alpn_protos, ssl->instance, numProtos, (const char **)protoList);

    /*set_alpn_protos is allocating new protolist. So, protolist here can be free'ed*/
    i= 0;
    while(i < numProtos){
        OSSL_FREE(protoList[i]);
        i++;
    }

exit:
    if(protoList)
    {
        OSSL_FREE(protoList);
        protoList = NULL;
    }
    return status;
}

static int OSSL_verify_proto_version(int version)
{
    int versionCheckflag = 0;

    if ((version == TLS1_VERSION)   ||
             (version == TLS1_1_VERSION) ||
             (version == TLS1_2_VERSION) ||
             (version == TLS1_3_VERSION))
    {
        versionCheckflag = 1;
    }

    return versionCheckflag;
}

static void OSSL_get_proto_version(const char* versionString, ubyte4 *pversion)
{
    /*convert the string to integer , openssl protcol version number are used*/
    if (strcmp(versionString, "TLS1_VERSION") == 0)
    {
        *pversion = TLS1_VERSION;
    }
    else if (strcmp(versionString, "TLS1_1_VERSION") == 0)
    {
        *pversion = TLS1_1_VERSION;
    }
    else if (strcmp(versionString, "TLS1_2_VERSION") == 0)
    {
        *pversion = TLS1_2_VERSION;
    }
    else if (strcmp(versionString, "TLS1_3_VERSION") == 0)
    {
        *pversion = TLS1_3_VERSION;
    }
    else
    {   /* either it is invalid value or version is not supported , it is set to invalid value (0)
           OSSL_verify_proto_version api checks for valid value and calls ssl min apis*/
        *pversion = 0;
    }
}

static void OSSL_conf_get_proto_version(const char *pVersionString, int *pVersion)
{
    if (strcmp(pVersionString, "ssl3") == 0)
    {
        *pVersion = TLS1_VERSION;
    }
    else if (strcmp(pVersionString, "tls1") == 0)
    {
        *pVersion = TLS1_VERSION;
    }
    else if (strcmp(pVersionString, "tls1.1") == 0)
    {
        *pVersion = TLS1_1_VERSION;
    }
    else if (strcmp(pVersionString, "tls1.2") == 0)
    {
        *pVersion = TLS1_2_VERSION;
    }
    else if (strcmp(pVersionString, "tls1.3") == 0)
    {
        *pVersion = TLS1_3_VERSION;
    }
    else
    {   /* either it is invalid value or version is not supported , it is set to invalid value (0)
           OSSL_verify_proto_version api checks for valid value and calls ssl min apis*/
        *pVersion = 0;
    }
}

static int OSSL_get_major_proto_version(int version)
{
    int majorversion = 0;

    if ((version == SSL3_VERSION_MINOR)   ||
             (version == TLS1_VERSION_MINOR)   ||
             (version == TLS1_1_VERSION_MINOR) ||
             (version == TLS1_2_VERSION_MINOR) ||
             (version == TLS1_3_VERSION_MINOR))
    {
        majorversion = TLS1_VERSION_MAJOR;
    }

    return majorversion;
}

static int OSSL_convert_minor_version_to_ossl(int version)
{
    if ((version & 0x00FF) == SSL3_MINORVERSION)
    {
        return SSL3_VERSION_MINOR;
    }
    if ((version & 0x00FF) == TLS10_MINORVERSION)
    {
        return TLS1_VERSION_MINOR;
    }
    if ((version & 0x00FF) == TLS11_MINORVERSION)
    {
        return TLS1_1_VERSION_MINOR;
    }
    if ((version & 0x00FF) == TLS12_MINORVERSION)
    {
        return TLS1_2_VERSION_MINOR;
    }
    if ((version & 0x00FF) == TLS13_MINORVERSION)
    {
        return TLS1_3_VERSION_MINOR;
    }

    SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_BAD_VALUE);
    return -1;
}

static int OSSL_convert_minor_version_from_ossl(int version)
{
    if ((version & 0x00FF) == SSL3_VERSION_MINOR)
    {
        return SSL3_MINORVERSION;
    }
    if ((version & 0x00FF) == TLS1_VERSION_MINOR)
    {
        return TLS10_MINORVERSION;
    }
    if ((version & 0x00FF) == TLS1_1_VERSION_MINOR)
    {
        return TLS11_MINORVERSION;
    }
    if ((version & 0x00FF) == TLS1_2_VERSION_MINOR)
    {
        return TLS12_MINORVERSION;
    }
    if ((version & 0x00FF) == TLS1_3_VERSION_MINOR)
    {
        return TLS13_MINORVERSION;
    }

    SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_BAD_VALUE);
    return -1;
}

static int setMinAndMaxVersion(int maxVersion, int minVersion)
{
    sbyte4 status = OK;
    ubyte currMaxVersion, currMinVersion;
    int minVersionCheckFlag = -1;
    int maxVersionCheckFlag = -1;

    /* Get current values set */
    currMaxVersion = NSSL_CHK_CALL(sslGetMaxVersion, " ");
    currMinVersion = NSSL_CHK_CALL(sslGetMinVersion, " ");

    /* Verify the new values */
    minVersionCheckFlag = OSSL_verify_proto_version(minVersion);
    maxVersionCheckFlag = OSSL_verify_proto_version(maxVersion);

    /* Convert the new values */
    if (minVersionCheckFlag)
    {
        minVersion = OSSL_convert_minor_version_from_ossl(minVersion);
        if (-1 == minVersion)
            return 0;
    }

    if (maxVersionCheckFlag)
    {
        maxVersion = OSSL_convert_minor_version_from_ossl(maxVersion);
        if (-1 == maxVersion)
            return 0;
    }

    if(minVersionCheckFlag && maxVersionCheckFlag)
    {
        if (minVersion > currMaxVersion)
        {
            status = NSSL_CHK_CALL(sslSetMaxVersion, maxVersion);
            if (OK > status)
                return 0;

            status = NSSL_CHK_CALL(sslSetMinVersion, minVersion);
            if (OK > status)
                return 0;
        }
        else
        {
            status = NSSL_CHK_CALL(sslSetMinVersion, minVersion);
            if (OK > status)
                return 0;

            status = NSSL_CHK_CALL(sslSetMaxVersion, maxVersion);
            if (OK > status)
                return 0;
        }
    }
    else if (minVersionCheckFlag)
    {
        status = NSSL_CHK_CALL(sslSetMinVersion, minVersion);
        if (OK > status)
            return 0;
    }
    else if (maxVersionCheckFlag)
    {
        status = NSSL_CHK_CALL(sslSetMaxVersion, maxVersion);
        if (OK > status)
            return 0;
    }

    /* If no versions are set, return 1 */
    return 1;
}

/* 6 bits used to set the version options : 0xCF
 * [TLS1.3][TLS 1.1][TLS1.2][TLS1.0][SSLV3][SSLV2]*/
static unsigned long
OSSL_set_version_options(int min_version_index, int max_version_index, ubyte mapping[])
{
    int i = 0;
    unsigned long version_options = 0xCF;
    for(i = min_version_index; i <= max_version_index; i++ )
    {
        switch(mapping[i])
        {
#if 0
            case SSL2_MINORVERSION:
                /* Unset the 1st LSB */
                version_options = (version_options & 0x3E);
                break;
#endif
            case SSL3_MINORVERSION:
                /* Unset the 2nd LSB */
                version_options = (version_options & 0x3D);
                break;
            case TLS10_MINORVERSION:
                /* Unset 3rd LSB */
                version_options = (version_options & 0x3B);
                break;
            case TLS11_MINORVERSION:
                /* Unset 5th LSB */
                version_options = (version_options & 0x2F);
                break;
            case TLS12_MINORVERSION:
                /* Unset 4th LSB */
                version_options = (version_options & 0x37);
                break;
            case TLS13_MINORVERSION:
                /* Unset 6th LSB */
                version_options = (version_options & 0x1F);
                break;
            default:
                break;
        }
    }
    return version_options;
}

static void getVersionIndex(ubyte4 version, int *pIndex)
{
    switch (version)
    {
        case SSL3_MINORVERSION:
            *pIndex = 1;
            break;
        case TLS10_MINORVERSION:
            *pIndex = 2;
            break;
        case TLS11_MINORVERSION:
            *pIndex = 3;
            break;
        case TLS12_MINORVERSION:
            *pIndex = 4;
            break;
        case TLS13_MINORVERSION:
            *pIndex = 5;
            break;
        default:
            break;
    }
}

static void resetVersionOptions(SSL *s)
{
    int max_version_index;
    int min_version_index;
    char *pminiVersion = NULL;
    char* pMaxVersion  = NULL;
    ubyte4 max_version = 0, min_version = 0;
    ubyte osslMapVersion[] = { SSL3_MINORVERSION, /* We dont define SSL2_MINORVERSION */
                            SSL3_MINORVERSION,
                            TLS10_MINORVERSION,
                            TLS11_MINORVERSION,
                            TLS12_MINORVERSION,
                            TLS13_MINORVERSION,
                            };

    unsigned long version_options;

    if (NULL != (pMaxVersion = getenv("OPENSSL_MAX_TLS_VERSION")))
    {
        OSSL_get_proto_version(pMaxVersion, (ubyte4*)&max_version);
    }
    else
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        max_version = TLS1_3_VERSION;
#else
        max_version = TLS1_2_VERSION;
#endif
    }

    getVersionIndex(OSSL_convert_minor_version_from_ossl(max_version), &max_version_index);

    if (NULL != (pminiVersion = getenv("OPENSSL_MIN_TLS_VERSION")))
    {
        OSSL_get_proto_version(pminiVersion, (ubyte4*)&min_version);
    }
    else
    {
        min_version = TLS1_VERSION_MINOR;
    }

    getVersionIndex(OSSL_convert_minor_version_from_ossl(min_version), &min_version_index);

    /* Set the min and max version */
    if (0 == (setMinAndMaxVersion(max_version, min_version)))
    {
        PRINT("OSSL version is either invalid or version is not supported\n");
        SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_BAD_VALUE);
        return;
    }

    version_options = OSSL_set_version_options(min_version_index, max_version_index, osslMapVersion);
    version_options = version_options << 24;
    if (s == NULL) return;
    s->options &= 0xC0FFFFFFL;
    s->options |= version_options;
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

unsigned long SSL_CTX_set_options(SSL_CTX *ctx, unsigned long op)
{
    if (NULL == ctx)
        return 0;

    return ctx->options |= op;
}

unsigned long SSL_CTX_clear_options(SSL_CTX *ctx, unsigned long op)
{
    if (NULL == ctx)
        return 0;

    return ctx->options &= ~op;
}

/*------------------------------------------------------------------*/
unsigned long SSL_clear_options(SSL *s, unsigned long op)
{
    if (s == NULL) return 0;
    resetVersionOptions(s);
    return (s->options &= ~op);
}

/*------------------------------------------------------------------*/

unsigned long SSL_CTX_get_options(const SSL_CTX *ctx)
{
    if (NULL == ctx)
        return 0;

    return ctx->options;
}

/*------------------------------------------------------------------*/

int SSL_in_init(SSL *s)
{
    if (NULL == s)
        return -1;

    if (SSL_ST_OK == SSL_state(s))
        return 0;
    else
        return 1;
}

/*------------------------------------------------------------------*/

unsigned long SSL_get_options(SSL *s)
{
    if (NULL == s)
        return 0;

    return s->options;
}

/*------------------------------------------------------------------*/

unsigned long SSL_set_options(SSL *s, unsigned long op)
{
    if (NULL == s)
        return 0;

    return s->options |= op;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__|| __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

extern
int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                            unsigned protos_len){
    int status = 0;

    if(NULL == ctx)
    {
        status =  -1;
        goto exit;
    }

    if (protos && (protos_len > 0)) {
        if(ctx->alpn_client_proto_list)
        {
            OSSL_FREE(ctx->alpn_client_proto_list);
            ctx->alpn_client_proto_list = NULL;
        }

        ctx->alpn_client_proto_list = OSSL_MALLOC(protos_len);
        if (ctx->alpn_client_proto_list == NULL){
            status = -1; /* @Openssl: No error code by openssl here*/
            goto exit;
        }

        memcpy(ctx->alpn_client_proto_list, protos, protos_len);
        ctx->alpn_client_proto_list_len = protos_len;
        /*  SSL_set_alpn_protos - called in SSL_new */
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern
int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
                          const unsigned char *server,
                          unsigned int server_len,
                          const unsigned char *client,
                          unsigned int client_len)
{
    unsigned int i, j;
    const unsigned char *result;
    int status = OPENSSL_NPN_UNSUPPORTED;

    /*
     * For each protocol in server preference order, see if we support it.
     */
    for (i = 0; i < server_len;) {
        for (j = 0; j < client_len;) {
            if (server[i] == client[j] &&
                memcmp(&server[i + 1], &client[j + 1], server[i]) == 0) {
                /* We found a match */
                result = &server[i];
                status = OPENSSL_NPN_NEGOTIATED;
                goto found;
            }
            j += client[j];
            j++;
        }
        i += server[i];
        i++;
    }

    /* There's no overlap between our protocols and the server's list. */
    result = client;
    status = OPENSSL_NPN_NO_OVERLAP;

found:
    *out = (unsigned char *)result + 1;
    *outlen = result[0];
    return status;
}

/*------------------------------------------------------------------*/

extern
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx,
                                      int (*cb) (SSL *s,
                                                 unsigned char **out,
                                                 unsigned char *outlen,
                                                 const unsigned char *in,
                                                 unsigned int inlen,void *arg), void *arg)
{
    if (ctx == NULL) return;
    ctx->next_proto_select_cb = cb;
    ctx->next_proto_select_cb_arg = arg;
    return;
}

/*------------------------------------------------------------------*/

extern
void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *ctx,
                                           int (*cb) (SSL *ssl,
                                                      const unsigned char
                                                      **out,
                                                      unsigned int *outlen,
                                                      void *arg), void *arg)
{
    if (ctx == NULL) return;
    /* @Note: Unsupported. We do not support NPN */
    ctx->next_protos_advertised_cb = cb;
    ctx->next_protos_advertised_cb_arg = arg;
    return;

}

/*------------------------------------------------------------------*/

/*
 * This is used in client mode (ex. MOD_SSL proxy) to setup root CAs to
 * verify the server certificate
 */
#ifdef __RTOS_WIN32__
static int loadCertFilesFromDir(const char *CApath, X509_STORE *store)
{
    int rval = 0;
    WIN32_FIND_DATA findFileData;
    HANDLE          hFind;
    char fullpath[MAX_FILE_NAME_SIZE] = "\0";

    if (NULL == CApath)
    {
        return 0;
    }
    /* open the directory */
    hFind = FindFirstFile (CApath, &findFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        return 0;
    }

    do
    {
        if ((strcmp(findFileData.cFileName, ".") != 0) &&
            (strcmp(findFileData.cFileName, "..") != 0))
        {
            memset((void *)fullpath, 0, sizeof(fullpath));
            snprintf(fullpath, MAX_FILE_NAME_SIZE, "%s\\%s",
                    CApath, findFileData.cFileName);
            rval = X509_STORE_load_locations(store, fullpath, NULL);
        }
    }
    while (0 != FindNextFile(hFind, &findFileData));

    FindClose(hFind);
    return rval;
}
#endif

extern int
SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                  const char *CApath)
{
     int        i, rval=0, derLen;
     size_t crt_len = 0;
     X509_STORE          * store;
     X509_OBJECT      * pobj;
     X509          * x;
     u_int8_t          * pDerBuf, *to;

     if (NULL != ctx) {
        store = ctx->cert_store;
        if ((CAfile == NULL) && (CApath != NULL))
        {
          /* CApath is provided. We parse the directory for .pem files,
           * load all of them into the cert store */
#ifdef __RTOS_WIN32__
            rval = loadCertFilesFromDir(CApath, store);
#else
            DIR *dir = NULL;
            char fullpath[MAX_FILE_NAME_SIZE] = "\0";
            struct dirent *crt_file = NULL;
            /* open the directory and read/load certs in each file */
            dir = opendir(CApath);
            if (NULL == dir)
            {
                return 0;
            }
            while( (crt_file=readdir(dir)) != NULL)
            {
                if (!strcmp (crt_file->d_name, "."))
                    continue;
                if (!strcmp (crt_file->d_name, ".."))
                    continue;
                
                /* Skip any files which end in .der or .DER or any mixed cases like .Der */
                crt_len = strlen(crt_file->d_name);
                if ( (4 <= crt_len) && (!STR_CASE_CMP (crt_file->d_name + crt_len - 4, ".der")) )
                    continue;

                memset((void *)fullpath, 0, sizeof(fullpath));
                if (0 <= snprintf(fullpath, MAX_FILE_NAME_SIZE, "%s/%s", CApath, crt_file->d_name))
                {
                    /* As long as a single valid file was loaded, return success */
                    if (1 == X509_STORE_load_locations(store, fullpath, NULL))
                    {
                        rval = 1;
                    }
                }
            }
            closedir(dir);
#endif
      }
      else
      {
          /* CAfile is provided. */
          rval = X509_STORE_load_locations(store, CAfile, CApath);
      }

      /* Loop through all certs and add to Mocana CERT_STORE */
      for (i = 0; i < sk_X509_OBJECT_num(store->objs); i++) {
           pobj = sk_X509_OBJECT_value(store->objs, i);
           if (X509_LU_X509 == pobj->type) {
            x         = pobj->data.x509;
            derLen     = i2d_X509(x, NULL);
            if (0 > derLen)
            {
                return 0;/* return error */
            }

            if (NULL == (pDerBuf = OSSL_MALLOC(derLen))) {
             rval = 0; /* @Openssl: Does not define error code */
             break;
            }
            to = pDerBuf;
            derLen     = i2d_X509(x, &to);
            NSSL_CHK_CALL(addTrustPoint, ctx->pCertStore, pDerBuf, derLen);
            OSSL_FREE(pDerBuf);
            pDerBuf = NULL;
           }
        }
        return rval;
     } else
        return 0; /*  ERR_INVALID_ARG; */
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

int SSL_CTX_up_ref(SSL_CTX *ctx)
{
    int i;

    if (ctx == NULL) return 0;
    if (CRYPTO_atomic_add(&ctx->orig_ssl_ctx.references, 1, &i, ctx->orig_ssl_ctx.lock) <= 0)
        return 0;

    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

static int OSSL_CTX_load_x509_store(SSL_CTX *ctx)
{
     int        i, rval=0, derLen;
     X509_STORE          * store;
     X509_OBJECT      * pobj;
     X509          * x;
     u_int8_t          * pDerBuf, *to;

     if ((NULL != ctx)  && (NULL != ctx->cert_store)) {
      store     = ctx->cert_store;
      /* Loop through all certs and add to Mocana CERT_STORE */
      for (i = 0; i < sk_X509_OBJECT_num(store->objs); i++) {
           pobj = sk_X509_OBJECT_value(store->objs, i);
           if (X509_LU_X509 == pobj->type) {
            x         = pobj->data.x509;
            derLen     = i2d_X509(x, NULL);
            if (0 > derLen)
            {
                rval = -1;/* return error */
                break;
            }

            if (NULL == (pDerBuf = OSSL_MALLOC(derLen))) {
             rval = -1;
             break;
            }
            to = pDerBuf;
            derLen     = i2d_X509(x, &to);
            if (0 > derLen)
            {
                rval = -1;/* return error */
                break;
            }
            NSSL_CHK_CALL(addTrustPoint, ctx->pCertStore, pDerBuf, derLen);
            OSSL_FREE(pDerBuf);
            pDerBuf = NULL;
           }
      }
      return rval;
     } else
     return 0; /*  ERR_INVALID_ARG; */

}


/*------------------------------------------------------------------*/

#if 0

static int
OSSL_MocCertChainToX509sk(certChainPtr pCertChain, STACK_OF(X509) * sk)
{
     unsigned int    derLen, done=0, idxCert=0;
     sbyte4        status;
     const unsigned char    * p;
     const u_int8_t   * pDerData;
     X509          * x;

     while (0 == done) {
      status = CERTCHAIN_getCertificate(pCertChain, idxCert, &pDerData, (ubyte4 *)&derLen);
      if (ERR_INDEX_OOB == status) {
           done = 1;
           break;
      }
      if (OK > status)
           return -1;
      ++idxCert;
      p = pDerData;
      x = d2i_X509(NULL, &p, derLen);
      if (x == NULL) {
           return -1;
      }
      if (!sk_X509_push(sk, x)) {
           return -1;
      }
      x = NULL;
     }
     return 0;
}

#endif

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
DEFINE_RUN_ONCE_STATIC(ssl_x509_store_ctx_init)
{
    ssl_x509_store_ctx_idx = X509_STORE_CTX_get_ex_new_index(0,
                                                             "SSL for verify callback",
                                                             NULL, NULL, NULL);
    return (ssl_x509_store_ctx_idx >= 0);
}
#endif

int SSL_get_ex_data_X509_STORE_CTX_idx(void)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (!RUN_ONCE(&ssl_x509_store_ctx_once, ssl_x509_store_ctx_init))
        return -1;
    return ssl_x509_store_ctx_idx;
#else
    static volatile int ssl_x509_store_ctx_idx = -1;
    int got_write_lock = 0;

    if (((size_t)(&ssl_x509_store_ctx_idx) &
         (sizeof(ssl_x509_store_ctx_idx) - 1))
        == 0) {                 /* check alignment, practically always true */
        int ret;

        if ((ret = ssl_x509_store_ctx_idx) < 0) {
            CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
            if ((ret = ssl_x509_store_ctx_idx) < 0) {
                ret = ssl_x509_store_ctx_idx =
                    X509_STORE_CTX_get_ex_new_index(0,
                                                    "SSL for verify callback",
                                                    NULL, NULL, NULL);
            }
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
        }

        return ret;
    } else {                    /* commonly eliminated */

        CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);

        if (ssl_x509_store_ctx_idx < 0) {
            CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);
            CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
            got_write_lock = 1;

            if (ssl_x509_store_ctx_idx < 0) {
                ssl_x509_store_ctx_idx =
                    X509_STORE_CTX_get_ex_new_index(0,
                                                    "SSL for verify callback",
                                                    NULL, NULL, NULL);
            }
        }

        if (got_write_lock)
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
        else
            CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

        return ssl_x509_store_ctx_idx;
    }
#endif
}

/*------------------------------------------------------------------*/

#if 0

static int
OSSL_shimAppVerifyCert(certChainPtr pCertChain, void *arg)
{
     /* Convert pCertChain to X509 format and call into Application */
     STACK_OF(X509)   * sk = NULL;
     X509           * x = NULL;
     SSL          * s = (SSL *)arg;
     SSL_CTX          * ctx;
     X509_STORE_CTX     x509ctx;
     int        rval=0;

     ctx = s->ssl_ctx;
     if ((sk = sk_X509_new_null()) == NULL) {
      return 0;
     }
     if (OSSL_MocCertChainToX509sk(pCertChain, sk) < 0)
      return -1;

     x = sk_X509_value(sk, 0);
     if (!X509_STORE_CTX_init(&x509ctx, ctx->cert_store, x, sk)) {
      SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, ERR_R_X509_LIB);
      return (0);
     }
     (void) X509_STORE_CTX_set_ex_data(&x509ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);
     if (SSL_SERVER_FLAG == s->clientServerFlag)
      (void) X509_STORE_CTX_set_default(&x509ctx, "ssl_server");
     else if (SSL_CLIENT_FLAG == s->clientServerFlag)
      (void) X509_STORE_CTX_set_default(&x509ctx, "ssl_client");
     if(s->orig_s.verify_callback)
        X509_STORE_CTX_set_verify_cb(&x509ctx, s->orig_s.verify_callback);
     else if (ctx->verify_callback)
        X509_STORE_CTX_set_verify_cb(&x509ctx, ctx->verify_callback);

     if (ctx->app_verify_callback) {
      rval = (*ctx->app_verify_callback)(&x509ctx, ctx->app_verify_arg);
     }
    return rval;
}

#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

int ssl_undefined_function(SSL *s)
{
    ERR_raise(ERR_LIB_SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
}

static int ssl_do_config(SSL *s, SSL_CTX *ctx, const char *name, int system)
{
    SSL_CONF_CTX *cctx = NULL;
    size_t i, idx, cmd_count;
    int rv = 0;
    unsigned int flags;
    const SSL_METHOD *meth;
    const SSL_CONF_CMD *cmds;

    if (s == NULL && ctx == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        goto err;
    }

    if (name == NULL && system)
        name = "system_default";
    if (!conf_ssl_name_find(name, &idx)) {
        if (!system)
            ERR_raise_data(ERR_LIB_SSL, SSL_R_INVALID_CONFIGURATION_NAME,
                           "name=%s", name);
        goto err;
    }
    cmds = conf_ssl_get(idx, &name, &cmd_count);
    cctx = SSL_CONF_CTX_new();
    if (cctx == NULL)
        goto err;
    flags = SSL_CONF_FLAG_FILE;
    if (!system)
        flags |= SSL_CONF_FLAG_CERTIFICATE | SSL_CONF_FLAG_REQUIRE_PRIVATE;
    if (s != NULL) {
        meth = s->method;
        SSL_CONF_CTX_set_ssl(cctx, s);
    } else {
        meth = ctx->ssl_method;
        SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
    }
    if (meth->ssl_accept != ssl_undefined_function)
        flags |= SSL_CONF_FLAG_SERVER;
    if (meth->ssl_connect != ssl_undefined_function)
        flags |= SSL_CONF_FLAG_CLIENT;
    SSL_CONF_CTX_set_flags(cctx, flags);
    for (i = 0; i < cmd_count; i++) {
        char *cmdstr, *arg;

        conf_ssl_get_cmd(cmds, i, &cmdstr, &arg);
        rv = SSL_CONF_cmd(cctx, cmdstr, arg);
        if (rv <= 0) {
            int errcode = rv == -2 ? SSL_R_UNKNOWN_COMMAND : SSL_R_BAD_VALUE;

            ERR_raise_data(ERR_LIB_SSL, errcode,
                           "section=%s, cmd=%s, arg=%s", name, cmdstr, arg);
            goto err;
        }
    }
    rv = SSL_CONF_CTX_finish(cctx);
 err:
    SSL_CONF_CTX_free(cctx);
    return rv <= 0 ? 0 : 1;
}

void ssl_ctx_system_config(SSL_CTX *ctx)
{
    ssl_do_config(NULL, ctx, NULL, 1);
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/**
 * Creates a new SSL_CTX object as framework to establish TLS/SSL enabled connections.
 *
 * See man SSL_CTX_new for a complete list of possible SSL methods
 */
extern SSL_CTX *
SSL_CTX_new(const SSL_METHOD *meth)
{
     sbyte4    status = OK;
     sbyte4    status1 = OK;
     SSL_CTX *ctx;
    SSL_LIB_INIT

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
    intBoolean isFIPSEnabled = 0;
#endif

     if (meth == NULL) {
         SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_NULL_SSL_METHOD_PASSED);
         return (NULL);
     }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL))
        return NULL;
#else

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
    if (!register_pem_bio_handler())
        return NULL;
#endif /* __ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__ */
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

     if (NULL== (ctx = OSSL_MALLOC(sizeof(*ctx))))
     {
        SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
        goto exit;
     }

      memset((ubyte*)ctx, 0, sizeof(*ctx));
      ctx->ssl_method = meth;
#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
    /* Resync the FIPS mode value;
     * This is for applications who set FIPS mode after
     * initializing the SSL library
     */
    if (0 == g_FIPSInitialized)
    {
        g_FIPSInitialized = 1;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        /* returns 1 if the 'fips=yes' default property is set for the given
           libctx, otherwise it returns 0. */
        isFIPSEnabled = EVP_default_properties_is_fips_enabled(NULL);
#else
        isFIPSEnabled = FIPS_mode();
#endif

        /* Check the valid values */
        if ((1 == isFIPSEnabled) || (0 == isFIPSEnabled))
        {
            if (OK > (status = NSSL_CHK_CALL(setFIPSEnabled, isFIPSEnabled)))
            {
                goto exit;
            }
        }
    }
#endif

      if (OK > (status = NSSL_CHK_CALL(createCertStore, &ctx->pCertStore))) {
           goto exit;
      }
      ctx->verify_mode = SSL_VERIFY_NONE;
      if (NULL == (ctx->cert_store = X509_STORE_new())) {
           goto exit;
      }
      if (NULL == (ctx->client_CA = sk_X509_NAME_new_null())) {
           goto exit;
      }
      if (NULL == (ctx->orig_ssl_ctx.param = X509_VERIFY_PARAM_new())) {
           goto exit;
      }
      ctx->ossl_pkey_idx = OSSL_PKEY_MAX;
      /* Default read_ahead to 1 to allow extra data to be read from the TCP
       * buffer
       */
      ctx->orig_ssl_ctx.read_ahead = OSSL_DEFAULT_READ_AHEAD;

     ctx->orig_ssl_ctx.references = 1;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     ctx->orig_ssl_ctx.lock = CRYPTO_THREAD_lock_new();
     if (NULL == ctx->orig_ssl_ctx.lock)
     {
        SSLerr(SSL_F_SSL_CTX_NEW, ERR_R_MALLOC_FAILURE);
        OSSL_FREE(ctx);
        return NULL;
     }
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /*
     * We cannot usefully set a default max_early_data here (which gets
     * propagated in SSL_new(), for the following reason: setting the
     * SSL field causes tls_construct_stoc_early_data() to tell the
     * client that early data will be accepted when constructing a TLS 1.3
     * session ticket, and the client will accordingly send us early data
     * when using that ticket (if the client has early data to send).
     * However, in order for the early data to actually be consumed by
     * the application, the application must also have calls to
     * SSL_read_early_data(); otherwise we'll just skip past the early data
     * and ignore it.  So, since the application must add calls to
     * SSL_read_early_data(), we also require them to add
     * calls to SSL_CTX_set_max_early_data() in order to use early data,
     * eliminating the bandwidth-wasting early data in the case described
     * above.
     */
    ctx->orig_ssl_ctx.max_early_data = 0;

    /*
     * Default recv_max_early_data is a fully loaded single record. Could be
     * split across multiple records in practice. We set this differently to
     * max_early_data so that, in the default case, we do not advertise any
     * support for early_data, but if a client were to send us some (e.g.
     * because of an old, stale ticket) then we will tolerate it and skip over
     * it.
     */
    ctx->orig_ssl_ctx.recv_max_early_data = SSL3_RT_MAX_PLAIN_LENGTH;

    /* By default we send two session tickets automatically in TLSv1.3 */
    ctx->orig_ssl_ctx.num_tickets = 2;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

     if (NULL != ctx->orig_ssl_ctx.cert)
     {
         OSSL_FREE(ctx->orig_ssl_ctx.cert);
     }

     ctx->orig_ssl_ctx.cert = OSSL_CALLOC(sizeof(struct cert_st), 1);

     /* SSL_CTX does not contain OCSP status for OpenSSL 1.0.2 */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
     ctx->orig_ssl_ctx.tlsext_status_type = TLSEXT_STATUSTYPE_nothing;
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     ctx->tlsext_status_type = TLSEXT_STATUSTYPE_nothing;
#endif

     /* Openssl is not adding a reference here.CRYPTO_add is called in
      * SSL_new as SSL gets it's CTX in SSL_new. */
     /* CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);*/
     status = OK;

     /* Successfully created the context; Load the default ciphers */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (!SSL_CTX_set_ciphersuites(ctx, TLS_DEFAULT_CIPHERSUITES))
        goto exit;

    if (!OSSL_sslCreateCipherList(ctx->ssl_method,
                                SSL_DEFAULT_CIPHER_LIST,
                                ctx->tls13_ciphersuites,
                                &ctx->cipher_list, &ctx->cipher_list_by_id)
        || sk_SSL_CIPHER_num(ctx->cipher_list) <= 0) {
        SSLerr(SSL_F_SSL_CTX_NEW, SSL_R_LIBRARY_HAS_NO_CIPHERS);
        goto exit;
    }
#else
     if ((ctx->numCipherIds < 1) || (ctx->cipher_list == NULL))
     {
        (void) SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
     }
#endif

    if (OK > (status = moc_mutexWait(m_connectionCountMutex)))
    {
        goto exit;
    }

    status1 = NSSL_CHK_CALL(sslInitializeVersion, "");

    if (OK > (status = moc_mutexRelease(m_connectionCountMutex)))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl_ctx_system_config(ctx);
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

    if (OK > status1)
    {
        status = status1;
    }

exit:
    /* If ctx is initialized and status is not an error,
     * if version is DTLSv1, initialize the handshake timer
     */
     if ((OK != status) && ctx)
     {
        OSSL_FREE((void *)ctx);
        ctx = NULL;
     }

     return ctx;
}

/*-----------------------------------------------------------------*/

static void ll_append_tail(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *tail)
        return;
    if (curr == *head)
        *head = curr->next;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    (*tail)->next = curr;
    curr->prev = *tail;
    curr->next = NULL;
    *tail = curr;
}

/*-----------------------------------------------------------------*/

static void ll_append_head(CIPHER_ORDER **head, CIPHER_ORDER *curr,
                           CIPHER_ORDER **tail)
{
    if (curr == *head)
        return;
    if (curr == *tail)
        *tail = curr->prev;
    if (curr->next != NULL)
        curr->next->prev = curr->prev;
    if (curr->prev != NULL)
        curr->prev->next = curr->next;
    (*head)->prev = curr;
    curr->next = *head;
    curr->prev = NULL;
    *head = curr;
}

/*----------------------------------------------------------------*/

static void ssl_cipher_apply_rule(unsigned long cipher_id,
                                  unsigned long alg_mkey,
                                  unsigned long alg_auth,
                                  unsigned long alg_enc,
                                  unsigned long alg_mac,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                  int min_tls,
#else
                                  unsigned long alg_ssl,
#endif
                                  unsigned long algo_strength, int rule,
                                  int strength_bits, CIPHER_ORDER **head_p,
                                  CIPHER_ORDER **tail_p)
{
    CIPHER_ORDER *head, *tail, *curr, *next, *last;
    const SSL_CIPHER *cp;
    int reverse = 0;

    if (rule == CIPHER_DEL)
        reverse = 1;            /* needed to maintain sorting between
                                 * currently deleted ciphers */

    head = *head_p;
    tail = *tail_p;

    if (reverse) {
        next = tail;
        last = head;
    } else {
        next = head;
        last = tail;
    }
   curr = NULL;
    for (;;) {
        if (curr == last)
            break;

        curr = next;

        if (curr == NULL)
            break;

        next = reverse ? curr->prev : curr->next;

        cp = curr->cipher;

        /*
         * Selection criteria is either the value of strength_bits
         * or the algorithms used.
         */
        if (strength_bits >= 0) {
            if (strength_bits != cp->strength_bits)
                continue;
        } else {
            if (alg_mkey && !(alg_mkey & cp->algorithm_mkey))
                continue;
            if (alg_auth && !(alg_auth & cp->algorithm_auth))
                continue;
            if (alg_enc && !(alg_enc & cp->algorithm_enc))
                continue;
            if (alg_mac && !(alg_mac & cp->algorithm_mac))
                continue;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            if (min_tls && (min_tls != cp->min_tls))
                continue;
#else
            if (alg_ssl && !(alg_ssl & cp->algorithm_ssl))
                continue;
#endif
            if ((algo_strength & SSL_EXP_MASK)
                && !(algo_strength & SSL_EXP_MASK & cp->algo_strength))
                continue;
            if ((algo_strength & SSL_STRONG_MASK)
                && !(algo_strength & SSL_STRONG_MASK & cp->algo_strength))
                continue;
            if ((algo_strength & SSL_NOT_DEFAULT)
                && !(cp->algo_strength & SSL_NOT_DEFAULT))
                continue;
        }


        /* add the cipher if it has not been added yet. */
        if (rule == CIPHER_ADD) {
            /* reverse == 0 */
            if (!curr->active) {
                ll_append_tail(&head, curr, &tail);
                curr->active = 1;
            }
        }
        /* Move the added cipher to this location */
        else if (rule == CIPHER_ORD) {
            /* reverse == 0 */
            if (curr->active) {
                ll_append_tail(&head, curr, &tail);
            }
        } else if (rule == CIPHER_DEL) {
            /* reverse == 1 */
            if (curr->active) {
                /*
                 * most recently deleted ciphersuites get best positions for
                 * any future CIPHER_ADD (note that the CIPHER_DEL loop works
                 * in reverse to maintain the order)
                 */
                ll_append_head(&head, curr, &tail);
                curr->active = 0;
            }
        } else if (rule == CIPHER_KILL) {
            /* reverse == 0 */
            if (head == curr)
                head = curr->next;
            else
                curr->prev->next = curr->next;
            if (tail == curr)
                tail = curr->prev;
            curr->active = 0;
            if (curr->next != NULL)
                curr->next->prev = curr->prev;
            if (curr->prev != NULL)
                curr->prev->next = curr->next;
            curr->next = NULL;
            curr->prev = NULL;
        }
    }

    *head_p = head;
    *tail_p = tail;
}

/*-----------------------------------------------------------------*/

static int ssl_cipher_strength_sort(CIPHER_ORDER **head_p,
                                    CIPHER_ORDER **tail_p)
{
    int max_strength_bits, i, *number_uses;
    CIPHER_ORDER *curr;

    /*
     * This routine sorts the ciphers with descending strength. The sorting
     * must keep the pre-sorted sequence, so we apply the normal sorting
     * routine as '+' movement to the end of the list.
     */
    max_strength_bits = 0;
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active && (curr->cipher->strength_bits > max_strength_bits))
            max_strength_bits = curr->cipher->strength_bits;
        curr = curr->next;
    }

    if (NULL == (number_uses = OSSL_MALLOC((max_strength_bits + 1) * sizeof(int))))
    {
        SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
        return (0);
    }
    memset(number_uses, 0, (max_strength_bits + 1) * sizeof(int));

    /*
     * Now find the strength_bits values actually used
     */
    curr = *head_p;
    while (curr != NULL) {
        if (curr->active)
            number_uses[curr->cipher->strength_bits]++;
        curr = curr->next;
    }
    /*
     * Go through the list of used strength_bits values in descending
     * order.
     */
    for (i = max_strength_bits; i >= 0; i--)
        if (number_uses[i] > 0)
            ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ORD, i, head_p,
                                                    tail_p);

    OSSL_FREE(number_uses);
    number_uses = NULL;
    return (1);
}

/*----------------------------------------------------------------------------*/

static int ssl_cipher_process_rulestr(const char *rule_str,
                                      CIPHER_ORDER **head_p,
                                      CIPHER_ORDER **tail_p,
                                      const SSL_CIPHER **ca_list)
{
    unsigned long alg_mkey, alg_auth, alg_enc, alg_mac,
                algo_strength;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    int min_tls;
#else
    unsigned long alg_ssl;
#endif
    const char *l,*buf;
    int multi, found, rule, retval, buflen;
    int ok, j;
    unsigned long cipher_id = 0;
    char ch;
    retval = 1;

    if(NULL == ca_list)
        return 0; /* Return as ca_list is required for sorting cipher list*/

    l = rule_str;
    for (;;) {
        ch = *l;

        if (ch == '\0')
            break;              /* done */
        if (ch == '-') {
            rule = CIPHER_DEL;
            l++;
        } else if (ch == '+') {
            rule = CIPHER_ORD;
            l++;
        } else if (ch == '!') {
            rule = CIPHER_KILL;
            l++;
        } else if (ch == '@') {
            rule = CIPHER_SPECIAL;
            l++;
        } else {
            rule = CIPHER_ADD;
        }

        if (ITEM_SEP(ch)) {
            l++;
            continue;
        }

        alg_mkey = 0;
        alg_auth = 0;
        alg_enc = 0;
        alg_mac = 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        min_tls = 0;
#else
        alg_ssl = 0;
#endif
        algo_strength = 0;

        for (;;) {
            ch = *l;
            buf = l;
            buflen = 0;

#ifndef CHARSET_EBCDIC
            while (((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   ((ch >= 'a') && (ch <= 'z')) ||
                   (ch == '-') || (ch == '.') || (ch == '='))
#else
            while (isalnum(ch) || (ch == '-') || (ch == '.') || (ch == '='))
#endif
            {
                ch = *(++l);
                buflen++;
            }

            if (buflen == 0) {
                /*
                 * We hit something we cannot deal with,
                 * it is no command or separator nor
                 * alphanumeric, so we call this an error.
                 */
                retval = found = 0;
                l++;
                break;
            }

            if (rule == CIPHER_SPECIAL) {
                found = 0;      /* unused -- avoid compiler warning */
                break;          /* special treatment */
            }

            /* check for multi-part specification */
            if (ch == '+') {
                multi = 1;
                l++;
            } else
                multi = 0;

            /*
             * Now search for the cipher alias in the ca_list. Be careful
             * with the strncmp, because the "buflen" limitation
             * will make the rule "ADH:SOME" and the cipher
             * "ADH-MY-CIPHER" look like a match for buflen=3.
             * So additionally check whether the cipher name found
             * has the correct length. We can save a strlen() call:
             * just checking for the '\0' at the right place is
             * sufficient, we have to strncmp() anyway. (We cannot
             * use strcmp(), because buf is not '\0' terminated.)
             */
            j = found = 0;
            cipher_id = 0;

            while (ca_list[j]) {

                if (!strncmp(buf, ca_list[j]->name, buflen) &&
                    (ca_list[j]->name[buflen] == '\0')) {
                    found = 1;
                    break;
                } else
                    j++;
            }

            if (!found)
                break;          /* ignore this entry */

            if (ca_list[j]->algorithm_mkey) {
                if (alg_mkey) {
                    alg_mkey &= ca_list[j]->algorithm_mkey;
                    if (!alg_mkey) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mkey = ca_list[j]->algorithm_mkey;
            }

            if (ca_list[j]->algorithm_auth) {
                if (alg_auth) {
                    alg_auth &= ca_list[j]->algorithm_auth;
                    if (!alg_auth) {
                        found = 0;
                        break;
                    }
                } else
                    alg_auth = ca_list[j]->algorithm_auth;
            }

            if (ca_list[j]->algorithm_enc) {
                if (alg_enc) {
                    alg_enc &= ca_list[j]->algorithm_enc;
                    if (!alg_enc) {
                        found = 0;
                        break;
                    }
                } else
                    alg_enc = ca_list[j]->algorithm_enc;
            }

            if (ca_list[j]->algorithm_mac) {
                if (alg_mac) {
                    alg_mac &= ca_list[j]->algorithm_mac;
                    if (!alg_mac) {
                        found = 0;
                        break;
                    }
                } else
                    alg_mac = ca_list[j]->algorithm_mac;
            }
            if (ca_list[j]->algo_strength & SSL_EXP_MASK) {
                if (algo_strength & SSL_EXP_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & SSL_EXP_MASK) |
                        ~SSL_EXP_MASK;
                    if (!(algo_strength & SSL_EXP_MASK)) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength |= ca_list[j]->algo_strength & SSL_EXP_MASK;
            }

            if (ca_list[j]->algo_strength & SSL_STRONG_MASK) {
                if (algo_strength & SSL_STRONG_MASK) {
                    algo_strength &=
                        (ca_list[j]->algo_strength & SSL_STRONG_MASK) |
                        ~SSL_STRONG_MASK;
                    if (!(algo_strength & SSL_STRONG_MASK)) {
                        found = 0;
                        break;
                    }
                } else
                    algo_strength |=
                        ca_list[j]->algo_strength & SSL_STRONG_MASK;
            }

            if (ca_list[j]->algo_strength & SSL_NOT_DEFAULT) {
                algo_strength |= SSL_NOT_DEFAULT;
            }

            if(NULL != ca_list && NULL != *ca_list){
                if (ca_list[j]->valid) {
                    /*
                     * explicit ciphersuite found; its protocol version does not
                     * become part of the search pattern!
                     */

                    cipher_id = ca_list[j]->id;
                } else {
                    /*
                     * not an explicit ciphersuite; only in this case, the
                     * protocol version is considered part of the search pattern
                     */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                    if (ca_list[j]->min_tls) {
                        if (min_tls != 0 && min_tls != ca_list[j]->min_tls) {
                            found = 0;
                            break;
                        } else {
                            min_tls = ca_list[j]->min_tls;
                        }
                    }
#else
                    if (ca_list[j]->algorithm_ssl) {
                        if (alg_ssl) {
                            alg_ssl &= ca_list[j]->algorithm_ssl;
                            if (!alg_ssl) {
                                found = 0;
                                break;
                            }
                        } else
                            alg_ssl = ca_list[j]->algorithm_ssl;
                    }
#endif
                }
            }
            if (!multi)
                break;
        }
        /*
         * Ok, we have the rule, now apply it
         */
        if (rule == CIPHER_SPECIAL) { /* special command */
            ok = 0;
            if ((buflen == 8) && !strncmp(buf, "STRENGTH", 8)) {
                ok = ssl_cipher_strength_sort(head_p, tail_p);
            } else if (buflen == 10 && strncmp(buf, "SECLEVEL=", 9) == 0) {
                int level = buf[9] - '0';
                if (level < 0 || level > 5) {
                    ok = 0;
                } else {
                    ok = 1;
                }
            }

#if 0  /* comment out old else placeholder to eliminate warning */
            else
                ; /*ERROR*/
#endif
            if (ok == 0)
                retval = 0;
            /*
             * We do not support any "multi" options
             * together with "@", so throw away the
             * rest of the command, if any left, until
             * end or ':' is found.
             */
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        } else if (found) {
            ssl_cipher_apply_rule(cipher_id,
                                  alg_mkey, alg_auth, alg_enc, alg_mac,
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                  min_tls,
#else
                                  alg_ssl,
#endif
                                  algo_strength, rule, -1, head_p,
                                  tail_p);
        } else {
            while ((*l != '\0') && !ITEM_SEP(*l))
                l++;
        }
        if (*l == '\0')
            break;              /* done */
    }

    return (retval);
}

/*-----------------------------------------------------------------*/

SSL_CIPHER *OSSL_convert_cipher_list(int index)
{
     if (index < (int)SSL3_NUM_CIPHERS)
        return (&(ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - index]));
     else
        return (NULL);
}

/*-----------------------------------------------------------------*/
/* @Note: Not using this function should not affect the overall
 * functionality.
 */

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

static void ssl_cipher_get_disabled(unsigned long *mkey, unsigned long *auth,
                                    unsigned long *enc, unsigned long *mac,
                                    unsigned long *ssl)
{
    *mkey = 0;
    *auth = 0;
    *enc = 0;
    *mac = 0;
    *ssl = 0;

#ifdef OPENSSL_NO_RSA
    *mkey |= SSL_kRSA;
    *auth |= SSL_aRSA;
#endif
#ifdef OPENSSL_NO_DSA
    *auth |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
    *mkey |= SSL_kDHr | SSL_kDHd | SSL_kEDH;
    *auth |= SSL_aDH;
#endif
#ifdef OPENSSL_NO_KRB5
    *mkey |= SSL_kKRB5;
    *auth |= SSL_aKRB5;
#endif
#ifdef OPENSSL_NO_ECDSA
    *auth |= SSL_aECDSA;
#endif
#ifdef OPENSSL_NO_ECDH
    *mkey |= SSL_kECDHe | SSL_kECDHr;
    *auth |= SSL_aECDH;
#endif
#ifdef OPENSSL_NO_PSK
    *mkey |= SSL_kPSK;
    *auth |= SSL_aPSK;
#endif
#ifdef OPENSSL_NO_SRP
    *mkey |= SSL_kSRP;
#endif
    /* Note: Currently not needed */
    /*
     * Check for presence of GOST 34.10 algorithms, and if they do not
     * present, disable appropriate auth and key exchange
     */
    /*if (!get_optional_pkey_id("gost94")) {
        *auth |= SSL_aGOST94;
    }
    if (!get_optional_pkey_id("gost2001")) {
        *auth |= SSL_aGOST01;
    }*/
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((*auth & (SSL_aGOST94 | SSL_aGOST01)) == (SSL_aGOST94 | SSL_aGOST01)) {
        *mkey |= SSL_kGOST;
    }
#ifdef SSL_FORBID_ENULL
    *enc |= SSL_eNULL;
#endif

    *enc |= (ssl_cipher_methods[SSL_ENC_DES_IDX] == NULL) ? SSL_DES : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_3DES_IDX] == NULL) ? SSL_3DES : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_RC4_IDX] == NULL) ? SSL_RC4 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_RC2_IDX] == NULL) ? SSL_RC2 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_IDEA_IDX] == NULL) ? SSL_IDEA : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_AES128_IDX] == NULL) ? SSL_AES128 : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_AES256_IDX] == NULL) ? SSL_AES256 : 0;
#ifdef __ENABLE_DIGICERT_GCM__
    *enc |=
        (ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] ==
         NULL) ? SSL_AES128GCM : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] ==
         NULL) ? SSL_AES256GCM : 0;
#endif
    *enc |=
        (ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] ==
         NULL) ? SSL_CAMELLIA128 : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] ==
         NULL) ? SSL_CAMELLIA256 : 0;
    *enc |=
        (ssl_cipher_methods[SSL_ENC_GOST89_IDX] ==
         NULL) ? SSL_eGOST2814789CNT : 0;
    *enc |= (ssl_cipher_methods[SSL_ENC_SEED_IDX] == NULL) ? SSL_SEED : 0;

    *mac |= (ssl_digest_methods[SSL_MD_MD5_IDX] == NULL) ? SSL_MD5 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA1_IDX] == NULL) ? SSL_SHA1 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA256_IDX] == NULL) ? SSL_SHA256 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_SHA384_IDX] == NULL) ? SSL_SHA384 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_GOST94_IDX] == NULL) ? SSL_GOST94 : 0;
    *mac |= (ssl_digest_methods[SSL_MD_GOST89MAC_IDX] == NULL
             || ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] ==
             NID_undef) ? SSL_GOST89MAC : 0;

}

#endif

/*-----------------------------------------------------------------*/

static void ssl_cipher_collect_ciphers(  const SSL_METHOD *ssl_method,
                                         int num_of_ciphers,
                                         unsigned long disabled_mkey,
                                         unsigned long disabled_auth,
                                         unsigned long disabled_enc,
                                         unsigned long disabled_mac,
                                         unsigned long disabled_ssl,
                                         CIPHER_ORDER *co_list,
                                         CIPHER_ORDER **head_p,
                                         CIPHER_ORDER **tail_p)
{
      int i, co_list_num;
      SSL_CIPHER *c=NULL;

      /* Get the initial list of ciphers */

      co_list_num = 0;            /* actual count of ciphers */
      /* Note: Get everything that presents in SSLv3.
       * Later on, we would sort the list based on various parameters.
       * And then use the Rule string to eliminate Ciphers from the list
       * and use selected one. The list will then be used to further select
       * cipher from Mocana's cipher suite. The final list would contain Ciphers
       * from Mocana's cipher suite.
       */
      for (i = 0; i < num_of_ciphers; i++) {
          c = OSSL_convert_cipher_list(i);
           /* Note: Get everything that presents in SSLv3*/

              co_list[co_list_num].cipher = c;
              co_list[co_list_num].next = NULL;
              co_list[co_list_num].prev = NULL;
              co_list[co_list_num].active = 0;
              co_list_num++;
      }

      /*
       * Prepare linked list from list entries
       */
      if (co_list_num > 0) {
          co_list[0].prev = NULL;

          if (co_list_num > 1) {
              co_list[0].next = &co_list[1];

              for (i = 1; i < co_list_num - 1; i++) {
                  co_list[i].prev = &co_list[i - 1];
                  co_list[i].next = &co_list[i + 1];
              }

              co_list[co_list_num - 1].prev = &co_list[co_list_num - 2];
          }

          co_list[co_list_num - 1].next = NULL;

          *head_p = &co_list[0];
          *tail_p = &co_list[co_list_num - 1];
      }
}

/*------------------------------------------------------------------*/

int ssl_cipher_ptr_id_cmp(const SSL_CIPHER *const *ap,
                            const SSL_CIPHER *const *bp)
{
      long l;
      l = (*ap)->id - (*bp)->id;
      if (l == 0L)
          return (0);
      else
          return ((l > 0) ? 1 : -1);
}

/*------------------------------------------------------------------*/

static void ssl_cipher_collect_aliases(const SSL_CIPHER **ca_list,
                                       int num_of_group_aliases,
                                       unsigned long disabled_mkey,
                                       unsigned long disabled_auth,
                                       unsigned long disabled_enc,
                                       unsigned long disabled_mac,
                                       unsigned long disabled_ssl,
                                       CIPHER_ORDER *head)
{
    CIPHER_ORDER *ciph_curr;
    const SSL_CIPHER **ca_curr;
    int i;
    unsigned long mask_mkey = ~disabled_mkey;
    unsigned long mask_auth = ~disabled_auth;
    unsigned long mask_enc = ~disabled_enc;
    unsigned long mask_mac = ~disabled_mac;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    unsigned long mask_ssl = ~disabled_ssl;
#endif

    /*
     * First, add the real ciphers as already collected
     */
    ciph_curr = head;
    ca_curr = ca_list;
    while (ciph_curr != NULL) {
        *ca_curr = ciph_curr->cipher;
        ca_curr++;
        ciph_curr = ciph_curr->next;
    }

    /*
     * Now we add the available ones from the cipher_aliases[] table.
     * They represent either one or more algorithms, some of which
     * in any affected category must be supported (set in enabled_mask),
     * or represent a cipher strength value (will be added in any case because algorithms=0).
     */
    for (i = 0; i < num_of_group_aliases; i++) {
        unsigned long algorithm_mkey = cipher_aliases[i].algorithm_mkey;
        unsigned long algorithm_auth = cipher_aliases[i].algorithm_auth;
        unsigned long algorithm_enc = cipher_aliases[i].algorithm_enc;
        unsigned long algorithm_mac = cipher_aliases[i].algorithm_mac;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        unsigned long algorithm_ssl = cipher_aliases[i].algorithm_ssl;
#endif

        if (algorithm_mkey)
            if ((algorithm_mkey & mask_mkey) == 0)
                continue;

        if (algorithm_auth)
            if ((algorithm_auth & mask_auth) == 0)
                continue;

        if (algorithm_enc)
            if ((algorithm_enc & mask_enc) == 0)
                continue;

        if (algorithm_mac)
            if ((algorithm_mac & mask_mac) == 0)
                continue;

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (algorithm_ssl)
            if ((algorithm_ssl & mask_ssl) == 0)
                continue;
#endif

        *ca_curr = (SSL_CIPHER *)(cipher_aliases + i);
        ca_curr++;
    }

    *ca_curr = NULL;            /* end of list */
}

/*---------------------------------------------------------------------------*/

/* Currently not enabled SUITEB ciphers */

#if 0
static int check_suiteb_cipher_list(const char **prule_str)
{
    unsigned int suiteb_flags = 0, suiteb_comb2 = 0;

    if (strncmp(*prule_str, "SUITEB128ONLY", 13) == 0)
    {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS_ONLY;
    } else if (strncmp(*prule_str, "SUITEB128C2", 11) == 0)
    {
        suiteb_comb2 = 1;
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB128", 9) == 0)
    {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_128_LOS;
    } else if (strncmp(*prule_str, "SUITEB192", 9) == 0)
    {
        suiteb_flags = SSL_CERT_FLAG_SUITEB_192_LOS;
    }

    if (!suiteb_flags)
        return 1;

    switch (suiteb_flags) {
        case SSL_CERT_FLAG_SUITEB_128_LOS:
            if (suiteb_comb2)
                *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
            else
                *prule_str =
                    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384";
            break;
        case SSL_CERT_FLAG_SUITEB_128_LOS_ONLY:
            *prule_str = "ECDHE-ECDSA-AES128-GCM-SHA256";
            break;
        case SSL_CERT_FLAG_SUITEB_192_LOS:
            *prule_str = "ECDHE-ECDSA-AES256-GCM-SHA384";
            break;
    }
    return 1;
}
#endif

/*----------------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

static int cipher_compare(const void *a, const void *b)
{
    const SSL_CIPHER *ap = (const SSL_CIPHER *)a;
    const SSL_CIPHER *bp = (const SSL_CIPHER *)b;

    if (ap->id == bp->id)
        return 0;
    return ap->id < bp->id ? -1 : 1;
}

void ssl_sort_cipher_list(void)
{
    qsort(ssl3_ciphers, SSL3_NUM_CIPHERS, sizeof(ssl3_ciphers[0]),
          cipher_compare);
}

/* masks of disabled algorithms */
static uint32_t disabled_enc_mask;
static uint32_t disabled_mac_mask;
static uint32_t disabled_mkey_mask;
static uint32_t disabled_auth_mask;
extern const ssl_cipher_table ssl_cipher_table_cipher[];
extern const ssl_cipher_table ssl_cipher_table_mac[];

/*
 * Search for public key algorithm with given name and return its pkey_id if
 * it is available. Otherwise return 0
 */
#ifdef OPENSSL_NO_ENGINE

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, pkey_name, -1);
    if (ameth && EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                         ameth) > 0)
        return pkey_id;
    return 0;
}

#else

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    ENGINE_finish(tmpeng);
    return pkey_id;
}

#endif

int ssl_load_ciphers(void)
{
    size_t i;
    const ssl_cipher_table *t;

    disabled_enc_mask = 0;
    ssl_sort_cipher_list();
    for (i = 0, t = ssl_cipher_table_cipher; i < SSL_ENC_NUM_IDX; i++, t++) {
        if (t->nid == NID_undef) {
            ssl_cipher_methods[i] = NULL;
        } else {
            const EVP_CIPHER *cipher = EVP_get_cipherbynid(t->nid);
            ssl_cipher_methods[i] = cipher;
            if (cipher == NULL)
                disabled_enc_mask |= t->mask;
        }
    }
    disabled_mac_mask = 0;
    for (i = 0, t = ssl_cipher_table_mac; i < SSL_MD_NUM_IDX; i++, t++) {
        const EVP_MD *md = EVP_get_digestbynid(t->nid);
        ssl_digest_methods[i] = md;
        if (md == NULL) {
            disabled_mac_mask |= t->mask;
        } else {
            int tmpsize = EVP_MD_size(md);
            if (!ossl_assert(tmpsize >= 0))
                return 0;
            ssl_mac_secret_size[i] = tmpsize;
        }
    }
    /* Make sure we can access MD5 and SHA1 */
    if (!ossl_assert(ssl_digest_methods[SSL_MD_MD5_IDX] != NULL))
        return 0;
    if (!ossl_assert(ssl_digest_methods[SSL_MD_SHA1_IDX] != NULL))
        return 0;

    disabled_mkey_mask = 0;
    disabled_auth_mask = 0;

#ifdef OPENSSL_NO_RSA
    disabled_mkey_mask |= SSL_kRSA | SSL_kRSAPSK;
    disabled_auth_mask |= SSL_aRSA;
#endif
#ifdef OPENSSL_NO_DSA
    disabled_auth_mask |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
    disabled_mkey_mask |= SSL_kDHE | SSL_kDHEPSK;
#endif
#ifdef OPENSSL_NO_EC
    disabled_mkey_mask |= SSL_kECDHE | SSL_kECDHEPSK;
    disabled_auth_mask |= SSL_aECDSA;
#endif
#ifdef OPENSSL_NO_PSK
    disabled_mkey_mask |= SSL_PSK;
    disabled_auth_mask |= SSL_aPSK;
#endif
#ifdef OPENSSL_NO_SRP
    disabled_mkey_mask |= SSL_kSRP;
#endif

    /*
     * Check for presence of GOST 34.10 algorithms, and if they are not
     * present, disable appropriate auth and key exchange
     */
    ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX])
        ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
    else
        disabled_mac_mask |= SSL_GOST89MAC;

    ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX] =
        get_optional_pkey_id("gost-mac-12");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX])
        ssl_mac_secret_size[SSL_MD_GOST89MAC12_IDX] = 32;
    else
        disabled_mac_mask |= SSL_GOST89MAC12;

    if (!get_optional_pkey_id("gost2001"))
        disabled_auth_mask |= SSL_aGOST01 | SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_256"))
        disabled_auth_mask |= SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_512"))
        disabled_auth_mask |= SSL_aGOST12;
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((disabled_auth_mask & (SSL_aGOST01 | SSL_aGOST12)) ==
        (SSL_aGOST01 | SSL_aGOST12))
        disabled_mkey_mask |= SSL_kGOST;

    return 1;
}

#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
static int cipher_compare(const void *a, const void *b)
{
    const SSL_CIPHER *ap = (const SSL_CIPHER *)a;
    const SSL_CIPHER *bp = (const SSL_CIPHER *)b;

    if (ap->id == bp->id)
        return 0;
    return ap->id < bp->id ? -1 : 1;
}

/*
 * Search for public key algorithm with given name and return its pkey_id if
 * it is available. Otherwise return 0
 */
#ifdef OPENSSL_NO_ENGINE

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(NULL, pkey_name, -1);
    if (ameth && EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                         ameth) > 0) {
        return pkey_id;
    }
    return 0;
}

#else

static int get_optional_pkey_id(const char *pkey_name)
{
    const EVP_PKEY_ASN1_METHOD *ameth;
    ENGINE *tmpeng = NULL;
    int pkey_id = 0;
    ameth = EVP_PKEY_asn1_find_str(&tmpeng, pkey_name, -1);
    if (ameth) {
        if (EVP_PKEY_asn1_get0_info(&pkey_id, NULL, NULL, NULL, NULL,
                                    ameth) <= 0)
            pkey_id = 0;
    }
    ENGINE_finish(tmpeng);
    return pkey_id;
}

#endif

void ssl_sort_cipher_list(void)
{
    qsort(ssl3_ciphers, OSSL_NELEM(ssl3_ciphers), sizeof(ssl3_ciphers[0]),
          cipher_compare);
}

/* masks of disabled algorithms */
static uint32_t disabled_enc_mask;
static uint32_t disabled_mac_mask;
static uint32_t disabled_mkey_mask;
static uint32_t disabled_auth_mask;
extern const ssl_cipher_table ssl_cipher_table_cipher[];
extern const ssl_cipher_table ssl_cipher_table_mac[];

void ssl_load_ciphers(void)
{
    size_t i;
    const ssl_cipher_table *t;

    disabled_enc_mask = 0;
    ssl_sort_cipher_list();
    for (i = 0, t = ssl_cipher_table_cipher; i < SSL_ENC_NUM_IDX; i++, t++) {
        if (t->nid == NID_undef) {
            ssl_cipher_methods[i] = NULL;
        } else {
            const EVP_CIPHER *cipher = EVP_get_cipherbynid(t->nid);
            ssl_cipher_methods[i] = cipher;
            if (cipher == NULL)
                disabled_enc_mask |= t->mask;
        }
    }
#ifdef SSL_FORBID_ENULL
    disabled_enc_mask |= SSL_eNULL;
#endif
    disabled_mac_mask = 0;
    for (i = 0, t = ssl_cipher_table_mac; i < SSL_MD_NUM_IDX; i++, t++) {
        const EVP_MD *md = EVP_get_digestbynid(t->nid);
        ssl_digest_methods[i] = md;
        if (md == NULL) {
            disabled_mac_mask |= t->mask;
        } else {
            ssl_mac_secret_size[i] = EVP_MD_size(md);
            OPENSSL_assert(ssl_mac_secret_size[i] >= 0);
        }
    }
    /* Make sure we can access MD5 and SHA1 */
    OPENSSL_assert(ssl_digest_methods[SSL_MD_MD5_IDX] != NULL);
    OPENSSL_assert(ssl_digest_methods[SSL_MD_SHA1_IDX] != NULL);

    disabled_mkey_mask = 0;
    disabled_auth_mask = 0;

#ifdef OPENSSL_NO_RSA
    disabled_mkey_mask |= SSL_kRSA | SSL_kRSAPSK;
    disabled_auth_mask |= SSL_aRSA;
#endif
#ifdef OPENSSL_NO_DSA
    disabled_auth_mask |= SSL_aDSS;
#endif
#ifdef OPENSSL_NO_DH
    disabled_mkey_mask |= SSL_kDHE | SSL_kDHEPSK;
#endif
#ifdef OPENSSL_NO_EC
    disabled_mkey_mask |= SSL_kECDHEPSK;
    disabled_auth_mask |= SSL_aECDSA;
#endif
#ifdef OPENSSL_NO_PSK
    disabled_mkey_mask |= SSL_PSK;
    disabled_auth_mask |= SSL_aPSK;
#endif
#ifdef OPENSSL_NO_SRP
    disabled_mkey_mask |= SSL_kSRP;
#endif

    /*
     * Check for presence of GOST 34.10 algorithms, and if they are not
     * present, disable appropriate auth and key exchange
     */
    ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
    } else {
        disabled_mac_mask |= SSL_GOST89MAC;
    }

    ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX] =
        get_optional_pkey_id("gost-mac-12");
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC12_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC12_IDX] = 32;
    } else {
        disabled_mac_mask |= SSL_GOST89MAC12;
    }

    if (!get_optional_pkey_id("gost2001"))
        disabled_auth_mask |= SSL_aGOST01 | SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_256"))
        disabled_auth_mask |= SSL_aGOST12;
    if (!get_optional_pkey_id("gost2012_512"))
        disabled_auth_mask |= SSL_aGOST12;
    /*
     * Disable GOST key exchange if no GOST signature algs are available *
     */
    if ((disabled_auth_mask & (SSL_aGOST01 | SSL_aGOST12)) ==
        (SSL_aGOST01 | SSL_aGOST12))
        disabled_mkey_mask |= SSL_kGOST;
}
#else

void ssl_load_ciphers(void)
{
    SSL_LIB_INIT
    ssl_cipher_methods[SSL_ENC_DES_IDX] = EVP_get_cipherbyname(SN_des_cbc);
    ssl_cipher_methods[SSL_ENC_3DES_IDX] =
        EVP_get_cipherbyname(SN_des_ede3_cbc);
    ssl_cipher_methods[SSL_ENC_RC4_IDX] = EVP_get_cipherbyname(SN_rc4);
    ssl_cipher_methods[SSL_ENC_RC2_IDX] = EVP_get_cipherbyname(SN_rc2_cbc);
#ifndef OPENSSL_NO_IDEA
    ssl_cipher_methods[SSL_ENC_IDEA_IDX] = EVP_get_cipherbyname(SN_idea_cbc);
#else
    ssl_cipher_methods[SSL_ENC_IDEA_IDX] = NULL;
#endif
    ssl_cipher_methods[SSL_ENC_AES128_IDX] =
        EVP_get_cipherbyname(SN_aes_128_cbc);
    ssl_cipher_methods[SSL_ENC_AES256_IDX] =
        EVP_get_cipherbyname(SN_aes_256_cbc);
    ssl_cipher_methods[SSL_ENC_CAMELLIA128_IDX] =
        EVP_get_cipherbyname(SN_camellia_128_cbc);
    ssl_cipher_methods[SSL_ENC_CAMELLIA256_IDX] =
        EVP_get_cipherbyname(SN_camellia_256_cbc);
    ssl_cipher_methods[SSL_ENC_GOST89_IDX] =
        EVP_get_cipherbyname(SN_gost89_cnt);
    ssl_cipher_methods[SSL_ENC_SEED_IDX] = EVP_get_cipherbyname(SN_seed_cbc);

#if defined(__ENABLE_DIGICERT_GCM__)
    ssl_cipher_methods[SSL_ENC_AES128GCM_IDX] =
        EVP_get_cipherbyname(SN_aes_128_gcm);
    ssl_cipher_methods[SSL_ENC_AES256GCM_IDX] =
        EVP_get_cipherbyname(SN_aes_256_gcm);
#endif
    ssl_digest_methods[SSL_MD_MD5_IDX] = EVP_get_digestbyname(SN_md5);
    ssl_mac_secret_size[SSL_MD_MD5_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_MD5_IDX]);
    OPENSSL_assert(ssl_mac_secret_size[SSL_MD_MD5_IDX] >= 0);
    ssl_digest_methods[SSL_MD_SHA1_IDX] = EVP_get_digestbyname(SN_sha1);
    ssl_mac_secret_size[SSL_MD_SHA1_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA1_IDX]);
    OPENSSL_assert(ssl_mac_secret_size[SSL_MD_SHA1_IDX] >= 0);
    ssl_digest_methods[SSL_MD_GOST94_IDX] =
        EVP_get_digestbyname(SN_id_GostR3411_94);
    if (ssl_digest_methods[SSL_MD_GOST94_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST94_IDX] =
            EVP_MD_size(ssl_digest_methods[SSL_MD_GOST94_IDX]);
        OPENSSL_assert(ssl_mac_secret_size[SSL_MD_GOST94_IDX] >= 0);
    }
    ssl_digest_methods[SSL_MD_GOST89MAC_IDX] =
        EVP_get_digestbyname(SN_id_Gost28147_89_MAC);
   /* ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX] = get_optional_pkey_id("gost-mac");*/
    if (ssl_mac_pkey_id[SSL_MD_GOST89MAC_IDX]) {
        ssl_mac_secret_size[SSL_MD_GOST89MAC_IDX] = 32;
    }

    ssl_digest_methods[SSL_MD_SHA256_IDX] = EVP_get_digestbyname(SN_sha256);
    ssl_mac_secret_size[SSL_MD_SHA256_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA256_IDX]);
    ssl_digest_methods[SSL_MD_SHA384_IDX] = EVP_get_digestbyname(SN_sha384);
    ssl_mac_secret_size[SSL_MD_SHA384_IDX] =
        EVP_MD_size(ssl_digest_methods[SSL_MD_SHA384_IDX]);
}

#endif

extern
STACK_OF(SSL_CIPHER) *OSSL_sslCreateCipherList(const SSL_METHOD *ssl_method,
                                         const char *rule_str,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                            STACK_OF(SSL_CIPHER) *tls13_ciphersuites,
#endif
                            STACK_OF(SSL_CIPHER) **cipher_list,
                            STACK_OF(SSL_CIPHER) **cipher_list_by_id)
{
    int ok=1,i,num_of_alias_max,num_of_group_aliases,num_of_ciphers;

    unsigned long disabled_mkey, disabled_auth, disabled_enc, disabled_mac,
        disabled_ssl;
    STACK_OF(SSL_CIPHER) *cipherstack,*tmp_cipher_list;
    const char *rule_p;
    CIPHER_ORDER *co_list = NULL, *head = NULL, *tail = NULL,*curr=NULL;
    const SSL_CIPHER **ca_list = NULL;

    /* Currently SUITEB not enabled. */

    /*if(!check_suiteb_cipher_list(&rule_str))
        return NULL;*/

    ssl_load_ciphers();

    disabled_ssl = 0;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    disabled_mkey = disabled_mkey_mask;
    disabled_auth = disabled_auth_mask;
    disabled_enc = disabled_enc_mask;
    disabled_mac = disabled_mac_mask;
#else
    disabled_mkey= disabled_auth = disabled_enc = disabled_mac = 0;

    ssl_cipher_get_disabled(&disabled_mkey, &disabled_auth, &disabled_enc,
                            &disabled_mac, &disabled_ssl);
#endif

    num_of_ciphers = SSL3_NUM_CIPHERS;

    co_list = (CIPHER_ORDER *)OSSL_MALLOC(sizeof(CIPHER_ORDER) * num_of_ciphers);
    if (co_list == NULL) {
        SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
        return (NULL);          /* Failure */
    }
    ssl_cipher_collect_ciphers(ssl_method,num_of_ciphers,
                                 disabled_mkey, disabled_auth, disabled_enc,
                                 disabled_mac, disabled_ssl, co_list, &head,
                                 &tail);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) 
    ssl_cipher_apply_rule(0, SSL_kECDHE, SSL_aECDSA, 0, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);
    ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kECDHE, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* Within each strength group, we prefer GCM over CHACHA... */
    ssl_cipher_apply_rule(0, 0, 0, SSL_AESGCM, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);
    ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);

    /*
     * ...and generally, our preferred cipher is AES.
     * Note that AEADs will be bumped to take preference after sorting by
     * strength.
     */
    ssl_cipher_apply_rule(0, 0, 0, SSL_AES ^ SSL_AESGCM, 0, 0, 0, CIPHER_ADD,
                          -1, &head, &tail);
#else
    ssl_cipher_apply_rule(0, SSL_kEECDH, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kEECDH, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head,
                          &tail);

    /* AES is our preferred symmetric cipher */
    ssl_cipher_apply_rule(0, 0, 0, SSL_AES, 0, 0, 0, CIPHER_ADD, -1, &head,
                          &tail);

    ssl_cipher_apply_rule(0, 0, 0, SSL_CHACHA20, 0, 0, 0, CIPHER_ADD, -1,
                          &head, &tail);
#endif
    /* Temporarily enable everything else for sorting */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_ADD, -1, &head, &tail);

    /* Low priority for MD5 */
    ssl_cipher_apply_rule(0, 0, 0, 0, SSL_MD5, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    /*
     * Move anonymous ciphers to the end.  Usually, these will remain
     * disabled. (For applications that allow them, they aren't too bad, but
     * we prefer authenticated ciphers.)
     */
    ssl_cipher_apply_rule(0, 0, SSL_aNULL, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Move ciphers without forward secrecy to the end */
    ssl_cipher_apply_rule(0, 0, SSL_aECDH, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);

    ssl_cipher_apply_rule(0, 0, SSL_aDH, 0, 0, 0, 0, CIPHER_ORD, -1,
      &head, &tail);
#endif

    ssl_cipher_apply_rule(0, SSL_kRSA, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    ssl_cipher_apply_rule(0, SSL_kPSK, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl_cipher_apply_rule(0, SSL_kKRB5, 0, 0, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
#endif

    /* RC4 is sort-of broken -- move the the end */
    ssl_cipher_apply_rule(0, 0, 0, SSL_RC4, 0, 0, 0, CIPHER_ORD, -1, &head,
                          &tail);
    /*
     * Now sort by symmetric encryption strength.  The above ordering remains
     * in force within each class
     */
    if (!ssl_cipher_strength_sort(&head, &tail)) {
        OSSL_FREE(co_list);
        co_list = NULL;
        return NULL;
    }

    /* Now disable everything (maintaining the ordering!) */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /*
     * Partially overrule strength sort to prefer TLS 1.2 ciphers/PRFs.
     * (openssl-team): is there an easier way to accomplish all this?
     */
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, TLS1_2_VERSION, 0, CIPHER_BUMP, -1,
                          &head, &tail);

    /*
     * Irrespective of strength, enforce the following order:
     * (EC)DHE + AEAD > (EC)DHE > rest of AEAD > rest.
     * Within each group, ciphers remain sorted by strength and previous
     * preference, i.e.,
     * 1) ECDHE > DHE
     * 2) GCM > CHACHA
     * 3) AES > rest
     * 4) TLS 1.2 > legacy
     *
     * Because we now bump ciphers to the top of the list, we proceed in
     * reverse order of preference.
     */
    ssl_cipher_apply_rule(0, 0, 0, 0, SSL_AEAD, 0, 0, CIPHER_BUMP, -1,
                          &head, &tail);
    ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, 0, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);
    ssl_cipher_apply_rule(0, SSL_kDHE | SSL_kECDHE, 0, 0, SSL_AEAD, 0, 0,
                          CIPHER_BUMP, -1, &head, &tail);
#endif
    ssl_cipher_apply_rule(0, 0, 0, 0, 0, 0, 0, CIPHER_DEL, -1, &head, &tail);

    /*
     * We also need cipher aliases for selecting based on the rule_str.
     * There might be two types of entries in the rule_str: 1) names
     * of ciphers themselves 2) aliases for groups of ciphers.
     * For 1) we need the available ciphers and for 2) the cipher
     * groups of cipher_aliases added together in one list (otherwise
     * we would be happy with just the cipher_aliases table).
     */
    num_of_group_aliases = sizeof(cipher_aliases) / sizeof(SSL_CIPHER);
    num_of_alias_max = num_of_ciphers + num_of_group_aliases + 1;
    ca_list = OSSL_MALLOC(sizeof(SSL_CIPHER *) * num_of_alias_max);
    if (ca_list == NULL) {
        SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST,ERR_R_MALLOC_FAILURE);
        OSSL_FREE(co_list);
        ca_list=NULL;
        return (NULL);          /* Failure */
    }
    ssl_cipher_collect_aliases(ca_list, num_of_group_aliases,
                               disabled_mkey, disabled_auth, disabled_enc,
                               disabled_mac, disabled_ssl, head);

    /*
     * If the rule_string begins with DEFAULT, apply the default rule
     * before using the (possibly available) additional rules.
     */
    ok = 1;
    rule_p = rule_str;
    if (strncmp(rule_str, "DEFAULT", 7) == 0) {
        ok = ssl_cipher_process_rulestr(SSL_DEFAULT_CIPHER_LIST,
                                          &head, &tail,ca_list);
        rule_p += 7;
        if (*rule_p == ':')
            rule_p++;
    }

    if (ok && (strlen(rule_p) > 0))
        ok = ssl_cipher_process_rulestr(rule_p, &head, &tail,ca_list);

    OSSL_FREE((void *) ca_list);
    ca_list = NULL;

    if(!ok) {
        OSSL_FREE(co_list);
        co_list = NULL;
        return (NULL);
    }

    if ((cipherstack = sk_SSL_CIPHER_new_null()) == NULL)
    {
          OSSL_FREE(co_list);
          co_list = NULL;
          return (NULL);
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Add TLSv1.3 ciphers first - we always prefer those if possible */
    for (i = 0; i < sk_SSL_CIPHER_num(tls13_ciphersuites); i++) {
        if (!sk_SSL_CIPHER_push(cipherstack,
                                sk_SSL_CIPHER_value(tls13_ciphersuites, i))) {
            sk_SSL_CIPHER_free(cipherstack);
            return NULL;
        }
    }
#endif

    for (curr = head; curr != NULL; curr = curr->next)
    {
         for(i=0;i<(int)NUM_CIPHERS;i++)
         {
            if (curr->active)
            {
                if(!strncmp(curr->cipher->name,gCipherDescs[i].OpenSSLcipherName,strlen(curr->cipher->name)))
                {
                    /*Interested in ID's from Mocana list*/
                    (void) sk_SSL_CIPHER_push(cipherstack, curr->cipher);
                    break;
                }
            }
        }
    }

    OSSL_FREE(co_list);      /* Not needed any longer */
    co_list = NULL;

    tmp_cipher_list = sk_SSL_CIPHER_dup(cipherstack);

    if (tmp_cipher_list == NULL)
    {
        sk_SSL_CIPHER_free(cipherstack);
        return NULL;
    }
    if (*cipher_list != NULL)
    {
        sk_SSL_CIPHER_free(*cipher_list);
    }
    *cipher_list = cipherstack;
    if (*cipher_list_by_id != NULL)
    {
        sk_SSL_CIPHER_free(*cipher_list_by_id);
    }
    *cipher_list_by_id = tmp_cipher_list;
    (void)sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id,
                                       ssl_cipher_ptr_id_cmp);
    sk_SSL_CIPHER_sort(*cipher_list_by_id);

    return (cipherstack);
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

STACK_OF(SSL_CIPHER) *SSL_CTX_get_ciphers(const SSL_CTX *ctx)
{
    if (ctx != NULL)
    {
        if (ctx->cipher_list != NULL)
        {
            return ctx->cipher_list;
        }
    }
    return NULL;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

extern int
SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
     STACK_OF(SSL_CIPHER) *sk;
     ubyte4     i;

     if (0 == strcmp(str, "DEFAULT@SECLEVEL=1"))
     {
         /* We do not apply this, ignore and return with successful status */
         return 1;
     }

     if (ctx == NULL)
        return 0;
    sk = OSSL_sslCreateCipherList(ctx->ssl_method,str,
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                                  ctx->tls13_ciphersuites,
#endif
                                  &ctx->cipher_list,
                                  &ctx->cipher_list_by_id);
     if (sk == NULL)
          return 0;
     else if ((ctx->numCipherIds = (sk_SSL_CIPHER_num(sk))) == 0)
     {
          SSLerr(SSL_F_SSL_CTX_SET_CIPHER_LIST, SSL_R_NO_CIPHER_MATCH);
          return 0;
      }

      sk = ctx->cipher_list_by_id;
      for (i=0; i < ctx->numCipherIds; i++){
          ctx->cipherIds[i] = (ubyte2)(((SSL_CIPHER *)sk_SSL_CIPHER_value(sk,i))->id) & 0xFFFF;
      }
     return 1;

}

/*------------------------------------------------------------------*/

const SSL_CIPHER *SSL_get_current_cipher(const SSL *s)
{
     ubyte2 selectedCipherId,cipherId;
     ubyte4 peerEcCurves;
     ubyte4 numCipherIds;
     sbyte4 status;
     ubyte4 i;
     STACK_OF(SSL_CIPHER) *sk;

     if((NULL != s) && (NULL != s->ssl_ctx))
     {
        sk = s->ssl_ctx->cipher_list_by_id;

        if(NULL == sk)
            goto exit;

        numCipherIds = (sk_SSL_CIPHER_num(sk));

        if ((s->session != NULL))
        {
            status = NSSL_CHK_CALL(getCipherInfo, s->instance,
                                   &selectedCipherId, &peerEcCurves);

            if(OK > status)
                goto exit;

            for (i = 0; i < numCipherIds; i++)
            {
                cipherId = (ubyte2)(((SSL_CIPHER *)sk_SSL_CIPHER_value(sk,i))->id) & 0xFFFF;
                if(cipherId == selectedCipherId)
                {
                    s->session->cipher = (((SSL_CIPHER *)sk_SSL_CIPHER_value(sk,i)));
                    break;
                }
            }
            return (s->session->cipher);
        }
     }
exit:
     return NULL;
}

/*------------------------------------------------------------------*/

STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s)
{
     if (s != NULL)
     {
        if (s->cipher_list != NULL) {
            return (s->cipher_list);
        } else if ((s->ssl_ctx != NULL) && (s->ssl_ctx->cipher_list != NULL)) {
            return (s->ssl_ctx->cipher_list);
        }
     }
    return NULL;
}

/*------------------------------------------------------------------*/
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

pem_password_cb *SSL_CTX_get_default_passwd_cb(SSL_CTX *ctx)
{
    if (NULL == ctx)
        return 0;

    return ctx->default_passwd_callback;
}

void *SSL_CTX_get_default_passwd_cb_userdata(SSL_CTX *ctx)
{
    if (NULL == ctx)
        return 0;

    return ctx->default_passwd_callback_userdata;
}
#endif

extern void
SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
{
   if (ctx && cb)
       ctx->default_passwd_callback = cb;
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)
{
    if (ctx && u)
        ctx->default_passwd_callback_userdata = u;
}

/*------------------------------------------------------------------*/

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx,
                                int (*cb) (SSL *ssl, X509 **x509,
                                           EVP_PKEY **pkey))
{
    if(NULL != ctx)
        ctx->client_cert_cb = cb;
}

/*------------------------------------------------------------------*/

int (*SSL_CTX_get_client_cert_cb(SSL_CTX *pCtx))(SSL *ssl, X509 **ppCert,
                                                 EVP_PKEY **ppKey)
{
    if (pCtx == NULL) return NULL;
    return pCtx->client_cert_cb;
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                      int (*cb) (X509_STORE_CTX *, void *),
                                      void *arg)
{
    if(NULL != ctx)
    {
        ctx->app_verify_callback = cb;
        ctx->app_verify_arg = arg;
    }
}

/*------------------------------------------------------------------*/
extern void
SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
           int (*callback)(int, X509_STORE_CTX *))
{
    if (NULL != ctx)
    {
        ctx->verify_mode = mode;
        if (callback)
            ctx->verify_callback = callback;
    }
}


/*------------------------------------------------------------------*/

extern long SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);

/**
 * Sets the timeout for newly created sessions for ctx to t. The timeout value
 * t must be given in seconds.
 *
 * All sessions behave according to the timeout value valid at the time of the
 * session negotiation. Changes of the timeout value do not affect
 * already established sessions.
 *
 * (from OpenSSL Docs)
 */
extern long SSL_CTX_set_timeout(SSL_CTX *s, long t)
{
    long l;

    if (s == NULL)
        return (0);
    l = s->session_timeout;
    s->session_timeout = t;

    (void) NSSL_CHK_CALL(setSessionResumeTimeout, (t * 1000));

    return (l);
}

/*------------------------------------------------------------------*/

extern long SSL_CTX_get_timeout(const SSL_CTX *s)
{
    if (s == NULL)
        return (0);
    return (s->session_timeout);
}

long dtls1_default_timeout(void)
{
    /* Openssl implementation has the default timeout as 2 hours.
     * Keeping it consistent.
     */
    return (60 * 60 * 2);
}
/*------------------------------------------------------------------*/

/* Calls made by MOD_SSL in the I/O Path are below */
void SSL_set_bio(SSL *s, BIO *rbio, BIO *wbio)
{
    /*
     * If the output buffering BIO is still in place, remove it
     */
    if(NULL != s)
    {
        if (s->bbio != NULL) {
            if (s->wbio == s->bbio) {
                s->wbio = s->wbio->next_bio;
                s->bbio->next_bio = NULL;
            }
        }
        /*
         * Increase ref count if rbio and wbio are the same to avoid double free
         */
        if (rbio != NULL && rbio == wbio)
            BIO_up_ref(rbio);
        if ((s->rbio != NULL) && (s->rbio != rbio))
            BIO_free_all(s->rbio);
        if ((s->wbio != NULL) && (s->wbio != wbio) && (s->rbio != s->wbio))
            BIO_free_all(s->wbio);

        s->rbio        = rbio;
        s->wbio        = wbio;
        s->orig_s.rbio = s->rbio;
        s->orig_s.wbio = s->wbio;
        s->orig_s.bbio = s->bbio;
    }
}

/*------------------------------------------------------------------*/

BIO *SSL_get_rbio(const SSL *s)
{
    if(NULL != s)
        return (s->rbio);
    return NULL;
}

/*------------------------------------------------------------------*/

BIO *SSL_get_wbio(const SSL *s)
{
    if(NULL != s)
        return (s->wbio);

    return NULL;
}

/*------------------------------------------------------------------*/

/**
 * connect the SSL object with a file descriptor
 *
 * Sets the file descriptor fd as the input/output facility for the TLS/SSL
 * (encrypted) side of ssl. fd will typically be the socket file descriptor of
 * a network connection.
 *
 * (from OpenSSL docs)
 */
int SSL_set_fd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    if(s == NULL) {
        SSLerr(SSL_F_SSL_SET_FD,SSL_R_UNINITIALIZED);
        goto err;
    }
    bio = BIO_new(BIO_s_socket());
    s->fd = fd;

    if (bio == NULL) {
        SSLerr(SSL_F_SSL_SET_FD, ERR_R_BUF_LIB);
        goto err;
    }
    (void) BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(s, bio, bio);
    ret = 1;
 err:
    return (ret);
}

/*------------------------------------------------------------------*/

int SSL_set_wfd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    if(s == NULL) {
        SSLerr(SSL_F_SSL_SET_WFD,SSL_R_UNINITIALIZED);
        goto err;
    }
    s->wfd = fd;

    if ((s->rbio == NULL) || (BIO_method_type(s->rbio) != BIO_TYPE_SOCKET)
        || ((int)BIO_get_fd(s->rbio, NULL) != fd)) {
        bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            SSLerr(SSL_F_SSL_SET_WFD, ERR_R_BUF_LIB);
            goto err;
        }
        (void) BIO_set_fd(bio, fd, BIO_NOCLOSE);
        SSL_set_bio(s, SSL_get_rbio(s), bio);
    } else
        SSL_set_bio(s, SSL_get_rbio(s), SSL_get_rbio(s));
    ret = 1;
 err:
    return (ret);
}

/*------------------------------------------------------------------*/

int SSL_set_rfd(SSL *s, int fd)
{
    int ret = 0;
    BIO *bio = NULL;

    if(s == NULL) {
        SSLerr(SSL_F_SSL_SET_RFD, ERR_R_BUF_LIB);
        goto err;
    }
    s->rfd = fd;
    if ((s->wbio == NULL) || (BIO_method_type(s->wbio) != BIO_TYPE_SOCKET)
        || ((int)BIO_get_fd(s->wbio, NULL) != fd)) {
        bio = BIO_new(BIO_s_socket());

        if (bio == NULL) {
            SSLerr(SSL_F_SSL_SET_RFD, ERR_R_BUF_LIB);
            goto err;
        }
        (void) BIO_set_fd(bio, fd, BIO_NOCLOSE);
        SSL_set_bio(s, bio, SSL_get_wbio(s));
    } else
        SSL_set_bio(s, SSL_get_wbio(s), SSL_get_wbio(s));
    ret = 1;
 err:
    return (ret);
}

/*------------------------------------------------------------------*/

void SSL_set_read_ahead(SSL *s, int yes)
{
    if(NULL != s)
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        s->orig_s.rlayer.read_ahead = yes;
#else
        s->orig_s.read_ahead = yes;
#endif
}

/*------------------------------------------------------------------*/

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx)
{
    if(NULL == ctx)
        return 0;

    return (X509_STORE_set_default_paths(ctx->cert_store));
}

/*------------------------------------------------------------------*/

const char *SSL_get_version(const SSL *s)
{
    int version = -1;

    if (NULL == s)
      return ("unknown");

    version = NSSL_CHK_CALL(sslGetVersion, s->instance);

    if (version == SSL3_MINORVERSION)
    {
        return ("SSLv3");
    }
    else if (version == TLS10_MINORVERSION)
    {
        return ("TLSv1.0");
    }
    else if (version == TLS11_MINORVERSION)
    {
        return ("TLSv1.1");
    }
    else if (version == TLS12_MINORVERSION)
    {
        return ("TLSv1.2");
    }
    else if (version == TLS13_MINORVERSION)
    {
        return ("TLSv1.3");
    }
    else
    {
        return ("unknown");
    }
}

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

/* Return values :
 *  0 - Error
 *  1 - Version matches
 */
static int SSL_verify_version(const SSL *pSsl, int verifyVersion)
{
    int nanoSslversion = -1;
    int rval = 0;

    /* openssl version range is  0x0300 to 0x0304 */
    if ((NULL == pSsl) || (verifyVersion <= SSL3_VERSION) || (verifyVersion > TLS1_3_VERSION))
    {
        goto exit;
    }

    nanoSslversion = NSSL_CHK_CALL(sslGetVersion, pSsl->instance);

    /* Only versions TLS 1.0 to TLS 1.3 are supported */
    if ((nanoSslversion > SSL3_VERSION_MINOR) || (verifyVersion <= TLS1_3_VERSION_MINOR))
    {
        /* NanoSSL returns 0x00 to 0x04 */
        if ((verifyVersion & 0x0F) == nanoSslversion)
        {
            rval = 1;
            goto exit;
        }
    }

exit:
    return rval;
}

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

static int sslSetMinProtoVersion(int version)
{
    int versionCheckflag = -1;
    MSTATUS status;

    versionCheckflag = OSSL_verify_proto_version(version);

    if(versionCheckflag)
    {
        version = OSSL_convert_minor_version_from_ossl(version);
        if (-1 == version)
            return 0;
        status = NSSL_CHK_CALL(sslSetMinVersion, version);
        if (OK > status)
            return 0;
        else
            return 1;
    }
    else
    {
        return 0;
    }
}

int SSL_set_min_proto_version(SSL *s, int version)
{
    if (NULL == s)
        return 0;

    return sslSetMinProtoVersion(version);
}

int SSL_get_min_proto_version(SSL *s)
{
     ubyte version = 0;
     int osslVersion;

      if (NULL == s)
         return 0;

      version = NSSL_CHK_CALL(sslGetMinVersion, " ");
      osslVersion = OSSL_convert_minor_version_to_ossl(version);
      if (-1 == osslVersion)
        return 0;
      osslVersion = (OSSL_get_major_proto_version(osslVersion) << 8 ) + osslVersion;
      return osslVersion;
 }

static int sslSetMaxProtoVersion(int version)
{
    MSTATUS status;
    int versionCheckflag = -1;


    versionCheckflag = OSSL_verify_proto_version(version);

    if(versionCheckflag)
    {
        version = OSSL_convert_minor_version_from_ossl(version);
        if (-1 == version)
            return 0;
        status = NSSL_CHK_CALL(sslSetMaxVersion, version);
        if (OK > status)
            return 0;
        else
            return 1;
    }
    else
    {
        return 0;
    }
}
/*------------------------------------------------------------------*/

int SSL_set_max_proto_version(SSL *s, int version)
{
      if (NULL == s)
         return 0;

    return sslSetMaxProtoVersion(version);
}

/*------------------------------------------------------------------*/

int SSL_get_max_proto_version(SSL *s)
{
      ubyte version;
      int osslVersion = 0;
      if (NULL == s)
         return 0;

      version = NSSL_CHK_CALL(sslGetMaxVersion, " ");
      osslVersion = OSSL_convert_minor_version_to_ossl(version);
      osslVersion = (OSSL_get_major_proto_version(osslVersion) << 8 ) + osslVersion;
      return osslVersion;
}

/*------------------------------------------------------------------*/

extern int
SSL_do_handshake(SSL *s)
{
    int status = 1;
    if(NULL == s) {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE, SSL_R_UNINITIALIZED);
        status = -1;
        goto err;
    }

    if (s->clientServerFlag == SSL_CLIENT_FLAG)
    {
        status = SSL_connect(s);
        if(ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE == status){
            SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            goto err;
        }
    }
    else
    {
        status = SSL_accept(s);
        if(ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE == status){
            SSLerr(SSL_F_REQUEST_CERTIFICATE, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
            goto err;
        }
    }
err:
    return status;
}

/*------------------------------------------------------------------*/

/* @Note:
 * Call Mocana's Rehandshake if REHANDSHAKE is enabled.
 * Else set error and return value as per Openssl.
 */
extern int SSL_renegotiate(SSL *s)
{
    sbyte4    status = 0;
    int authModeFlag = 0;
    ubyte4 sslFlags  = 0;
	void (*cb) (const SSL *ssl, int type, int val) = NULL;

    if (NULL == s) {
        SSLerr(SSL_R_NO_RENEGOTIATION,SSL_R_UNINITIALIZED);
        return 0;
    }

    /* Handshake status callback */
    if (s->info_callback != NULL)
    {
        cb = s->info_callback;
    }
    else if (s->ssl_ctx->info_callback != NULL)
    {
        cb = s->ssl_ctx->info_callback;
    }

    if (SSL_SERVER_FLAG == s->clientServerFlag)
    {
        if((s->orig_s.verify_mode & SSL_VERIFY_PEER) || (s->ssl_ctx->verify_mode & SSL_VERIFY_PEER))
        {
            /* allow mutual auth */
           authModeFlag = SSL_FLAG_REQUIRE_MUTUAL_AUTH;
        }
        else
        {
            authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;
        }
    }
    else
    {
        if ((s->orig_s.verify_mode   == SSL_VERIFY_NONE) &&
            (s->ssl_ctx->verify_mode == SSL_VERIFY_NONE) &&
            (NULL == SSL_get_privatekey(s)))
        {
            authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REPLY;
        }
    }

    if (OK > (status = NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags)))
    {
         return -1;
    }

    /* Reset the flags before setting */
    sslFlags &= ~(SSL_FLAG_NO_MUTUAL_AUTH_REQUEST);
    sslFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);

    /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
    if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (sslFlags) | (authModeFlag))))
    {
         return -1;
    }

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
    status = NSSL_CHK_CALL(initiateRehandshake, s->instance);
    if (OK > status)
    {
        goto exit;
    }
    else
    {
        /* No errors in constructing the HelloRequest;
         * Send the buffer with Hello Request
         */
        status = asyncSendPendingData(s);

        /* All the data was sent */
        if (ERR_SSL_NO_DATA_TO_SEND == status)
        {
            status = OK;
        }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        s->orig_state = SSL_ST_RENEGOTIATE;
#else
        s->orig_s.state = SSL_ST_RENEGOTIATE;
#endif
        /* Notify that handshake is done*/
        if (cb != NULL)
        {
            cb(s, SSL_CB_HANDSHAKE_START, 1);
        }
    }
#else
    if (SSL_SERVER_FLAG == s->clientServerFlag){
        SSLerr(SSL_R_NO_RENEGOTIATION, ERR_R_DISABLED);
        return 0;
    }else {
        SSLerr(SSL_R_NO_RENEGOTIATION, ERR_R_DISABLED);
        return 0;
    }
#endif
exit:
    if (OK > status)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

/*------------------------------------------------------------------*/

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
void SSL_set_state(SSL *ssl, int state)
{
    if(NULL != ssl)

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
        ssl->orig_state = state;
#else
        ssl->orig_s.state = state;
#endif
}
#endif

/*------------------------------------------------------------------*/

/*
 * prepare SSL object to work server mode
 */
extern void
SSL_set_accept_state(SSL *s)
{
    if (NULL != s)
    {
        s->clientServerFlag = SSL_SERVER_FLAG;
        s->orig_s.shutdown = 0;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        ossl_statem_clear(s);
        s->orig_state = SSL_ST_ACCEPT | SSL_ST_BEFORE;
#else
        s->orig_s.state = SSL_ST_ACCEPT | SSL_ST_BEFORE;
#endif
    }
}

/*------------------------------------------------------------------*/
SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx)
{
    /* No Error Code in Openssl */
     if(ssl == NULL)
        return NULL;
    /* As per Openssl, it does not increment as it is case of
     * (ssl->ctx == ctx ) for it. For nanossl, case is different.
     */

     if(ssl->ssl_ctx == ctx)
        return ssl->ssl_ctx;
     if(NULL != ctx)
     {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        SSL_CTX_up_ref(ctx);
#else
        (void) CRYPTO_add(&ctx->orig_ssl_ctx.references, 1, CRYPTO_LOCK_SSL_CTX);
#endif
        if (ssl->ssl_ctx != NULL)
            SSL_CTX_free(ssl->ssl_ctx);

        ssl->ssl_ctx = ctx;
     }
        return ssl->ssl_ctx;
#if 0
CERT *ocert = ssl->cert;
    if (ssl->ctx == ctx)
        return ssl->ctx;
#ifndef OPENSSL_NO_TLSEXT
    if (ctx == NULL)
        ctx = ssl->initial_ctx;
#endif
    ssl->cert = ssl_cert_dup(ctx->cert);
    if (ocert) {
        /* Preserve any already negotiated parameters */
        if (ssl->server) {
            ssl->cert->peer_sigalgs = ocert->peer_sigalgs;
            ssl->cert->peer_sigalgslen = ocert->peer_sigalgslen;
            ocert->peer_sigalgs = NULL;
            ssl->cert->ciphers_raw = ocert->ciphers_raw;
            ssl->cert->ciphers_rawlen = ocert->ciphers_rawlen;
            ocert->ciphers_raw = NULL;
        }
#ifndef OPENSSL_NO_TLSEXT
        ssl->cert->alpn_proposed = ocert->alpn_proposed;
        ssl->cert->alpn_proposed_len = ocert->alpn_proposed_len;
        ocert->alpn_proposed = NULL;
        ssl->cert->alpn_sent = ocert->alpn_sent;
#endif
        ssl_cert_free(ocert);
    }

    /*
     * Program invariant: |sid_ctx| has fixed size (SSL_MAX_SID_CTX_LENGTH),
     * so setter APIs must prevent invalid lengths from entering the system.
     */
    OPENSSL_assert(ssl->sid_ctx_length <= sizeof(ssl->sid_ctx));

    /*
     * If the session ID context matches that of the parent SSL_CTX,
     * inherit it from the new SSL_CTX as well. If however the context does
     * not match (i.e., it was set per-ssl with SSL_set_session_id_context),
     * leave it unchanged.
     */
    if ((ssl->ctx != NULL) &&
        (ssl->sid_ctx_length == ssl->ctx->sid_ctx_length) &&
        (memcmp(ssl->sid_ctx, ssl->ctx->sid_ctx, ssl->sid_ctx_length) == 0)) {
        ssl->sid_ctx_length = ctx->sid_ctx_length;
        memcpy(&ssl->sid_ctx, &ctx->sid_ctx, sizeof(ssl->sid_ctx));
    }

    CRYPTO_add(&ctx->references, 1, CRYPTO_LOCK_SSL_CTX);
    if (ssl->ctx != NULL)
        SSL_CTX_free(ssl->ctx); /* decrement reference count */
    ssl->ctx = ctx;

    return (ssl->ctx);
#endif
}

/*------------------------------------------------------------------*/

extern SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl)
{
    if (NULL == ssl)
        return NULL;

    return (ssl->ssl_ctx);
}

/*------------------------------------------------------------------*/

extern int
SSL_is_init_finished(SSL *s)
{
    int retValue = 0;

     if (NULL == s)
        return 0;

    retValue = NSSL_CHK_CALL(isEstablished, s->instance);
    if (1 == retValue)
    {
        return 1;
    }
    else
    {
        /* TODO: OpenSSL 3.0 does not have "state", uses "statem" instead,
                 same goes for OpenSSL 1.1.1c */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if ((s->orig_state == SSL_ST_OK) || (s->orig_state == SSL_ST_RENEGOTIATE))
#else
        if ((s->orig_s.state == SSL_ST_OK) || (s->orig_s.state == SSL_ST_RENEGOTIATE))
#endif
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

/*------------------------------------------------------------------*/

#if 0
/* This is a macro in the openssl implementation. So this function is never called */
extern int
SSL_in_connect_init(SSL *s)
{
     if (NULL == s)
        return 0;

     return (NSSL_CHK_CALL(inConnectInit, s->instance));
}
#endif

/*------------------------------------------------------------------*/

extern int
SSL_total_renegotiations(SSL *s)
{
     /* Openssl has no error code*/
     return 0;
}

/*------------------------------------------------------------------*/

SSL_SESSION *SSL_get_session(const SSL *s)
/* aka SSL_get0_session; gets 0 objects, just returns a copy of the pointer */
{
    sbyte4    status;
    ubyte sessionIdLen = 0;
#ifdef __ENABLE_DIGICERT_SSL_SERVER_TLS_UNIQUE__
    ubyte4 tlsUniqueLen = 0;
#endif
    char *pHostname = NULL;
    ubyte4 size;

    if ((s == NULL) || (s->session == NULL))
        return NULL;

    /* Only the client can get the session ID.
     */
    if (SSL_CLIENT_FLAG == s->clientServerFlag)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pHostname = s->session->ext.hostname;
#else
        pHostname = s->session->tlsext_hostname;
#endif

        if (NULL != pHostname)
        {
            OSSL_FREE(pHostname);
            pHostname = NULL;
        }

        if (s->tlsext_hostname)
        {
            size = strlen(s->tlsext_hostname);
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            s->session->ext.hostname = OSSL_MALLOC(size + 1);
            if (NULL == s->session->ext.hostname)
            {
                return NULL;
            }
            memcpy(s->session->ext.hostname, s->tlsext_hostname, size);
            s->session->ext.hostname[size] = '\0';
#else
            s->session->tlsext_hostname = OSSL_MALLOC(size + 1);
            if (NULL == s->session->tlsext_hostname)
            {
                return NULL;
            }
            memcpy(s->session->tlsext_hostname, s->tlsext_hostname, size);
            s->session->tlsext_hostname[size] = '\0';
#endif
        }

        status = NSSL_CHK_CALL(
            getClientSessionInfo, s->instance, &sessionIdLen, s->session->session_id,
            s->session->master_key);
        if (OK > status)
            goto exit;

        if (0 != sessionIdLen)
            s->session->session_id_length = sessionIdLen;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_SSL_SERVER_TLS_UNIQUE__

        /* The server can request the TLS unique value by piggybacking off of
         * the session method. If the server calls this method then it can
         * expect to find the TLS unique value in place of the session ID. The
         * TLS unique length will also be stored as the session length.
         */
        ubyte *pSessionId = NULL;
        status = NSSL_CHK_CALL(
            getTlsUnique, s->instance, &tlsUniqueLen, &pSessionId);
        if (OK > status)
            return NULL;

        if (tlsUniqueLen > 0)
        {
            s->session->session_id_length = tlsUniqueLen;
            memcpy(s->session->session_id, pSessionId, tlsUniqueLen);
        }

        if (pSessionId != NULL)
        {
            free(pSessionId);
        }
#else
        return NULL;
#endif /* __ENABLE_DIGICERT_SSL_SERVER_TLS_UNIQUE__ */
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

    if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_GET_MAX_EARLY_DATA, &s->session->ext.max_early_data))
    {
        goto exit;
    }
#endif

    status = NSSL_CHK_CALL(
        sslIoctl, s->instance, SSL_GET_CLIENT_RANDOM, s->s3->client_random);
    if (OK > status)
        goto exit;

    status = NSSL_CHK_CALL(
        sslIoctl, s->instance, SSL_GET_SERVER_RANDOM, s->s3->server_random);
exit:
    if (OK > status)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (NULL != s->session->ext.hostname)
        {
            OSSL_FREE(s->session->ext.hostname);
            s->session->ext.hostname = NULL;
        }
#else
        if (s->session->tlsext_hostname != NULL)
        {
            OSSL_FREE(s->session->tlsext_hostname);
            s->session->tlsext_hostname = NULL;
        }
#endif
        return NULL;
    }
    else
    {
        return (s->session);
    }
}

/*------------------------------------------------------------------*/

void SSL_set_shutdown(SSL *s, int mode)
{
    /*Openssl has no error code*/
    if(NULL != s)
        s->orig_s.shutdown = mode;
}

/*------------------------------------------------------------------*/

int SSL_get_shutdown(const SSL *s)
{
    if(NULL != s)
        return (s->orig_s.shutdown);
    return 0; /* No shutdown setting */
}

/*------------------------------------------------------------------*/

/* Certificate chain callback function.
 *
 * This function is the default certificate callback function. NanoSSL will call
 * this function during a TLS handshake to verify the certificate chain. Before
 * this function is called, NanoSSL will perform its own certificate chain
 * validation. This function is only used to set the proper OpenSSL status.
 * Certain applications may expect a certain OpenSSL only error status therefore
 * this callback is used to verify the certificate chain using OpenSSL. This way
 * if OpenSSL produces an error, the exact error code can be recorded in the SSL
 * struct and any applications built using the OpenSSL shim/connector will now
 * be able to retrieve the OpenSSL error.
 *
 * NOTE: The error returned is still a Mocana MSTATUS error, however the error
 * stored within the SSL struct will be the OpenSSL error.
 */
static MSTATUS OSSL_certCallback(
    sbyte4 connectionInstance,
    struct certChain *pCertChain,
    MSTATUS nsslCertStatus
    )
{
    MSTATUS status;

    SSL *pSsl;
    X509 *pCert = NULL;
    struct stack_st_X509 *pStack = NULL;
    X509_STORE_CTX *pStoreCtx = NULL;
    sbyte4 certIndex;
    ubyte *pCertEntry = NULL;
    int osslStatus;

    status = ERR_NULL_POINTER;
    if (NULL == pCertChain)
        goto exit;

    pSsl = (SSL *) findSSLFromInstance(connectionInstance);
    if ( (NULL == pSsl) || (NULL == pSsl->ssl_ctx) )
        goto exit;

    /* Default error codes in case anything goes wrong.
     */
    pSsl->verify_result = X509_V_ERR_UNSPECIFIED;
    status = ERR_SSL_CERT_VALIDATION_FAILED;

    /* If there are no certificates in the certificate chain then return an
     * error.
     */
    if (0 == pCertChain->numCerts)
        goto exit;

    pStack = sk_X509_new_null();
    if (NULL == pStack)
        goto exit;

    /* Loop through all the certificates in the certificate chain. Each
     * certificate will be loaded into a X509 object. Once the certificate is
     * loaded in, it will put into a stack that will be passed into a X509
     * store context.
     */
    for (certIndex = 0; certIndex < pCertChain->numCerts; certIndex++)
    {
        pCertEntry = (ubyte *) (pCertChain->certs[certIndex].cert);

        /* Create a X509 object from each certificate. Each pointer will be
         * stored in the stack and freed once the stack is freed.
         */
        pCert = d2i_X509(
            NULL, (const unsigned char **) &pCertEntry,
            pCertChain->certs[certIndex].certLength);
        if (NULL == pCert)
            goto exit;

        if (!sk_X509_push(pStack, pCert))
            goto exit;
    }

    if (pSsl->session != NULL)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (NULL != pSsl->session->peer_chain)
        {
            sk_X509_pop_free(pSsl->session->peer_chain, X509_free);
        }

        pSsl->session->peer_chain = pStack;
#else
        if (NULL != pSsl->session->sess_cert)
        {
            if (NULL != pSsl->session->sess_cert->cert_chain)
            {
                sk_X509_pop_free(pSsl->session->sess_cert->cert_chain, X509_free);
            }

            pSsl->session->sess_cert->cert_chain = pStack;
        }
#endif

    }

    /* Check to see if the leaf certificate is valid. It will be retrieved from
     * the stack.
     */
    pCert = sk_X509_value(pStack, 0);

    /* Create the store context. For this step, a X509_STORE_CTX will be used to
     * check the certificate chain against the certificate store.
     */
    pStoreCtx = X509_STORE_CTX_new();
    if (NULL == pStoreCtx)
        goto exit;

    /* Initialize the store context with the store from the SSL struct and set
     * the certificate to verify as the leaf certificate provided in the
     * certificate chain. The stack of certificates will also be provided. They
     * will effectively be the certificate chain that will be verified.
     */
    osslStatus = X509_STORE_CTX_init(
        pStoreCtx, pSsl->ssl_ctx->cert_store, pCert, pStack);
    if (1 != osslStatus)
        goto exit;

    X509_STORE_CTX_set_ex_data(
        pStoreCtx, SSL_get_ex_data_X509_STORE_CTX_idx(), pSsl);

    /* Apply verify parameters set in SSL structure.
     */
    X509_VERIFY_PARAM_set1(
        X509_STORE_CTX_get0_param(pStoreCtx), pSsl->orig_s.param);

    /* Verify the certificate chain. If the chain verifies then return the
     * status that NanoSSL produced regardless of whether it passed or failed,
     * but store success in the SSL struct.
     *
     * If the verification failed, then the error will be stored in the SSL
     * struct. Depending on which flags are set, the function may also allow
     * a self-signed certificate to be allowed.
     */
    if (pSsl->orig_s.verify_callback)
    {
        X509_STORE_CTX_set_verify_cb(pStoreCtx, pSsl->orig_s.verify_callback);
    }

    if (pSsl->ssl_ctx->app_verify_callback)
    {
        osslStatus = pSsl->ssl_ctx->app_verify_callback(
            pStoreCtx, pSsl->ssl_ctx->app_verify_arg);
    }
    else
    {
        osslStatus = X509_verify_cert(pStoreCtx);
    }

    pSsl->verify_result = pStoreCtx->error;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    sk_X509_pop_free(pSsl->verified_chain, X509_free);
    pSsl->verified_chain = NULL;
    if (X509_STORE_CTX_get0_chain(pStoreCtx) != NULL) {
        pSsl->verified_chain = X509_STORE_CTX_get1_chain(pStoreCtx);
        if (pSsl->verified_chain == NULL) {
            SSLerr(SSL_F_SSL_VERIFY_CERT_CHAIN, ERR_R_MALLOC_FAILURE);
            osslStatus = 0;
        }
    }
#endif

#ifdef __ENABLE_DIGICERT_SSL_NONTRUSTED_CERT__
    status = OK;
#else
    if ( (0 < osslStatus) || ((SSL_VERIFY_NONE == pSsl->ssl_ctx->verify_mode) && (SSL_VERIFY_NONE == pSsl->orig_s.verify_mode))
#if defined(__ENABLE_DIGICERT_SSL_CERT_STATUS_OVERRIDE__)
         || (OK == nsslCertStatus)
#endif
       )
    {
#if defined(__ENABLE_DIGICERT_SSL_CERT_STATUS_OVERRIDE__)
        if (OK == nsslCertStatus)
        {
            pSsl->verify_result = X509_V_OK;
        }
#endif
        status = OK;
    }
    else
    {
        switch (pStoreCtx->error)
        {
            /* unknown_ca alert */
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case X509_V_ERR_INVALID_CA:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            case X509_V_ERR_CERT_CHAIN_TOO_LONG:
            case X509_V_ERR_PATH_LENGTH_EXCEEDED:
            case X509_V_ERR_UNABLE_TO_GET_CRL:
            case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
            case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
                status = ERR_CERT_CHAIN_NO_TRUST_ANCHOR;
                break;

            /* bad_certificate alert */
            case X509_V_ERR_CERT_SIGNATURE_FAILURE:
                status = ERR_SSL_CERT_VALIDATION_FAILED;
                break;

            /* certificate_revoked alert */
            case X509_V_ERR_CERT_REVOKED:
                status = ERR_CERT_REVOKED;
                break;

            /* certificate_expired alert */
            case X509_V_ERR_CERT_HAS_EXPIRED:
                status = ERR_CERT_EXPIRED;
                break;

            default:
                status = ERR_SSL_CERT_VALIDATION_FAILED;
        }

#ifdef __ENABLE_DIGICERT_SSL_SELF_SIGNED_CERT__
        if ( (X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT       == pStoreCtx->error) ||
             (X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN         == pStoreCtx->error) ||
             (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY == pStoreCtx->error) ||
             (X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE   == pStoreCtx->error))
        {
            status = OK;
        }
#endif /* __ENABLE_DIGICERT_SSL_SELF_SIGNED_CERT__ */
    }
#endif /* __ENABLE_DIGICERT_SSL_NONTRUSTED_CERT__ */
    pStack = NULL;

exit:
    if (0 == status)
    {
        ERR_clear_error();
    }

    if (NULL != pStoreCtx)
        X509_STORE_CTX_free(pStoreCtx);

    if (NULL != pStack)
    {
        sk_X509_pop_free(pStack, X509_free);
        pStack = NULL;
    }

    return status;
}

/*------------------------------------------------------------------*/

static int ca_dn_cmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return (X509_NAME_cmp(*a, *b));
}

static MSTATUS OSSL_clientCertAuthorityCallback(
    sbyte4 connectionInstance, SizedBuffer *pCertAuth, ubyte4 certAuthCount)
{
    SSL *pSsl;
    ubyte4 i;
    X509_NAME *pTemp = NULL;
    STACK_OF(X509_NAME) *pCAStack = NULL;

    /* Get SSL object based on connection instance */
    pSsl = (SSL *) findSSLFromInstance(connectionInstance);
    if ( (NULL == pSsl) || (NULL == pSsl->ssl_ctx) )
        goto exit;

    /* Create stack object to hold X509_NAMEs. The Certificate Authorities
     * extension will be parsed and this stack will be populated with each
     * entry. */
    pCAStack = sk_X509_NAME_new(ca_dn_cmp);
    if (NULL == pCAStack)
    {
        SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
        goto exit;
    }

    /* Loop through Certificate Authorities extension and populate the stack. */
    for (i = 0; i < certAuthCount; i++)
    {
        const unsigned char *pPtr = pCertAuth[i].data;

        pTemp = d2i_X509_NAME(NULL, &pPtr, pCertAuth[i].length);
        if (NULL == pTemp)
        {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_ASN1_LIB);
            goto exit;
        }

        if (!sk_X509_NAME_push(pCAStack, pTemp))
        {
            SSLerr(SSL_F_SSL3_GET_CERTIFICATE_REQUEST, ERR_R_MALLOC_FAILURE);
            goto exit;
        }
    }

    /* Free the existing stack if one exists and set the new stack */
    if (NULL != pSsl->s3->tmp.ca_names)
    {
        sk_X509_NAME_pop_free(pSsl->s3->tmp.ca_names, X509_NAME_free);
    }

    pSsl->s3->tmp.ca_names = pCAStack;
    return OK;

exit:

    if(NULL != pCAStack)
    {
        sk_X509_NAME_pop_free(pCAStack, X509_NAME_free);
        pCAStack = NULL;
    }
    return ERR_SSL_BAD_ID;
}

extern int
osslGetCertAndKey(X509 *pCert, EVP_PKEY *pKey, X509 *pCACert,
                  SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                  ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                  ubyte **ppRetCACert, ubyte4 *pRetCACertLen);

/*------------------------------------------------------------------*/

static MSTATUS OSSL_clientCertCallback(sbyte4 connInstance,
                                      SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                                      ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                                      ubyte **ppRetCACert, ubyte4 *pRetNumCACerts)
{
    SSL *pSSL = NULL;
    X509 *pCert = NULL;
    EVP_PKEY *pKey = NULL;
    int retValue = 0;
    MSTATUS status = 0;

    pSSL = (SSL*) findSSLFromInstance(connInstance);

    if((NULL == pSSL) || (NULL == pSSL->ssl_ctx))
    {
        status = -1;
        goto exit;
    }

    if (pSSL->ssl_ctx->client_cert_cb != NULL)
    {
        /* Return value of client_cert_cb will be 1 if there is a key and
         * certificate to send. Return value of 0 means an empty certificate
         * message should be sent.
         */
        retValue = pSSL->ssl_ctx->client_cert_cb(pSSL, &pCert, &pKey);

        if (0 > retValue)
        {
            status = -1;
            goto exit;
        }

        if (retValue == 1)
        {
            status = osslGetCertAndKey(pCert, pKey, NULL,
                                    ppRetCert, pRetNumCerts,
                                    ppRetKeyBlob, pRetKeyBlobLen,
                                    ppRetCACert, pRetNumCACerts);
        }

        /* A valid certificate obtained; Add the certificate even if key is NULL */
        if (*ppRetCert != NULL)
        {
            status = OK;
            pSSL->pClientCert       = pCert;

            pSSL->pClientPrivateKey = pKey;
        }
    }
exit:
    if (0 == status)
    {
        ERR_clear_error();
    }

    return status;
}

/*------------------------------------------------------------------*/

static EVP_MD_CTX *OSSL_createEvpMdCtx()
{
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    return EVP_MD_CTX_new();
#else
    EVP_MD_CTX *pNewMdCtx = NULL;
    pNewMdCtx = OSSL_CALLOC(sizeof(EVP_MD_CTX), 1);
    if (NULL != pNewMdCtx)
    {
        EVP_MD_CTX_init(pNewMdCtx);
    }
    return pNewMdCtx;
#endif
}

static void OSSL_freeEvpMdCtx(EVP_MD_CTX *pEvpMdCtx)
{
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != pEvpMdCtx)
    {
        EVP_MD_CTX_free(pEvpMdCtx);
    }
#else
    if (NULL != pEvpMdCtx)
    {
        EVP_MD_CTX_cleanup(pEvpMdCtx);
        OSSL_FREE(pEvpMdCtx);
    }
#endif
}

static sbyte4 OSSL_CertVerifySignCallback(sbyte4 connInstance, const ubyte* pHash, ubyte4 hashLen,
                                          ubyte* pSignature, ubyte4 signatureLen)
{
    SSL *pSSL = NULL;
    X509 *pCert = NULL;
    EVP_PKEY *pKey = NULL;
    MSTATUS status = -1;
    EVP_PKEY_CTX *pEvpCtx = NULL;
    EVP_MD_CTX *pMdCtx = NULL;
    const EVP_MD *pMd = NULL;
    ubyte* pSig   = NULL;
    size_t sigLen = 0;
    ubyte2 sigAlgo = 0;
    int saltLen = 0;
    ubyte4 version = 0;
    ubyte *pHashData = NULL;
    ubyte4 hashDataLen = 0;

#ifdef __ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__
    ubyte *pHashOID = NULL;
    ubyte4 hashOIDLen = 0;
    ubyte4 hashAlgo = 0;
#endif

    pSSL = (SSL*)findSSLFromInstance(connInstance);

    if((NULL == pSSL) || (NULL == pSSL->ssl_ctx))
    {
        status = -1;
        goto exit;
    }

    pKey  = pSSL->pClientPrivateKey;
    pCert = pSSL->pClientCert;

    if (pKey != NULL)
    {
        status = NSSL_CHK_CALL(sslGetSSLTLSVersion, connInstance, &version);
        if (OK != status)
        {
            goto exit;
        }

        if (pKey->type == EVP_PKEY_RSA && TLS13_MINORVERSION == version)
        {
            /* Get signing algorithm */
            status = NSSL_CHK_CALL(sslGetSigAlgo, connInstance, &sigAlgo);
            if (OK != status)
            {
                goto exit;
            }

            /* Choose appropriate digest */
            switch (sigAlgo)
            {
                case 0x0804:
                case 0x0809:
                    pMd = EVP_get_digestbyname(SN_sha256);
                    saltLen = 32;
                    break;

                case 0x0805:
                case 0x080a:
                    pMd = EVP_get_digestbyname(SN_sha384);
                    saltLen = 48;
                    break;

                case 0x0806:
                case 0x080b:
                    pMd = EVP_get_digestbyname(SN_sha512);
                    saltLen = 64;
                    /* Special case, SHA-512 digest and salt length of 64
                     * is too large for 1024 RSA key, reduce salt length */
                    if (1024 == EVP_PKEY_bits(pKey))
                    {
                        saltLen -= 2;
                    }
                    break;

                default:
                    status = ERR_RSA_SIGN_CALLBACK_FAIL;
                    goto exit;
            }

            pMdCtx = OSSL_createEvpMdCtx();

            if (0 > EVP_DigestSignInit(pMdCtx, &pEvpCtx, pMd, NULL, pKey))
            {
                status = -1;
                goto exit;
            }

            /* Set RSA-PSS parameters */
            if (0 > EVP_PKEY_CTX_set_rsa_padding(pEvpCtx, RSA_PKCS1_PSS_PADDING))
            {
                status = -1;
                goto exit;
            }
            if (0 > EVP_PKEY_CTX_set_rsa_mgf1_md(pEvpCtx, pMd))
            {
                status = -1;
                goto exit;
            }
            if (0 > EVP_PKEY_CTX_set_rsa_pss_saltlen(pEvpCtx, saltLen))
            {
                status = -1;
                goto exit;
            }

            /* Perform digest operation */
            if (0 > EVP_DigestSignUpdate(pMdCtx, pHash, hashLen))
            {
                status = -1;
                goto exit;
            }

            sigLen = signatureLen;
            pSig   = OPENSSL_malloc(signatureLen);

            /* Generate signature */
            if (0 > EVP_DigestSignFinal(pMdCtx, pSig, &sigLen))
            {
                status = -1;
                goto exit;
            }

            /* Copy the signature */
            memcpy((void *)pSignature, pSig, sigLen);
            /* This callback should return the length of the signature */
            status = sigLen;
        }
        else
        {
            /* env var for engine name */
            pEvpCtx = EVP_PKEY_CTX_new(pKey, NULL);
            if (NULL == pEvpCtx)
            {
                status = -1;
                goto exit;
            }

            /* Set the signing scheme */
            if (0 >= EVP_PKEY_sign_init(pEvpCtx))
            {
                status = -1;
                goto exit;
            }

            if (pKey->type == EVP_PKEY_RSA)
            {
                EVP_PKEY_CTX_set_rsa_padding(pEvpCtx, RSA_PKCS1_PADDING);
            }

            sigLen = signatureLen;
            pSig   = OPENSSL_malloc(signatureLen);

#ifdef __ENABLE_DIGICERT_DEFER_CLIENT_CERT_VERIFY_ENCODING__
            if (pKey->type == EVP_PKEY_RSA)
            {
                status = NSSL_CHK_CALL(parseDigestInfo,
                    (ubyte *)pHash,
                    hashLen,
                    &pHashOID,
                    &hashOIDLen,
                    &pHashData,
                    &hashDataLen,
                    &hashAlgo);
                if (OK != status)
                {
                    status = -1;
                    goto exit;
                }

                /* Choose appropriate digest */
                switch (hashAlgo)
                {
                    case ht_sha224:
                        pMd = EVP_get_digestbyname(SN_sha224);
                        break;
                    case ht_sha256:
                        pMd = EVP_get_digestbyname(SN_sha256);
                        break;
                    case ht_sha384:
                        pMd = EVP_get_digestbyname(SN_sha384);
                        break;
                    case ht_sha512:
                        pMd = EVP_get_digestbyname(SN_sha512);
                        break;
                    default:
                        status = ERR_RSA_SIGN_CALLBACK_FAIL;
                        goto exit;
                }

            }
            else
            {
                status = NSSL_CHK_CALL(sslGetSigAlgo, connInstance, &sigAlgo);
                if (OK != status)
                {
                    goto exit;
                }

                /* Choose appropriate digest */
                switch (sigAlgo)
                {
                    case 0x0403:
                        pMd = EVP_get_digestbyname(SN_sha256);
                        break;
                    case 0x0503:
                        pMd = EVP_get_digestbyname(SN_sha384);
                        saltLen = 48;
                        break;
                    case 0x0603:
                        pMd = EVP_get_digestbyname(SN_sha512);
                        break;
                    default:
                        status = -1;
                        goto exit;
                }

                pHashData = (ubyte*) pHash;
                hashDataLen = hashLen;
            }

            if (0 >= EVP_PKEY_CTX_set_signature_md(pEvpCtx, pMd))
            {
                status = -1;
                goto exit;
            }
#else
            pHashData = (ubyte*) pHash;
            hashDataLen = hashLen;
#endif

            /* Sign the data based using private key */
            if (0 >= EVP_PKEY_sign(pEvpCtx, pSig, &sigLen, pHashData, hashDataLen))
            {
                status = -1;
                goto exit;
            }

            /* Copy the signature */
            memcpy((void *)pSignature, pSig, sigLen);
            /* This callback should return the length of the signature */
            status = sigLen;
        }
    }

exit:
    if (pSig != NULL)
        OPENSSL_free(pSig);

    if (pEvpCtx != NULL && NULL == pMdCtx)
        EVP_PKEY_CTX_free(pEvpCtx);

    if (NULL != pMdCtx)
        OSSL_freeEvpMdCtx(pMdCtx);

    return status;
}

static sbyte4 OSSL_setCertVerifySignCb(SSL *ssl)
{
    CertVerifySignCallback signCallback;
    signCallback = OSSL_CertVerifySignCallback;

    if (OK > NSSL_CHK_CALL(setCertVerifySignCallback, signCallback))
        return -1;
    return 0;
}

static sbyte OSSL_setClientCertCallback(SSL *pSSL)
{
    ClientCertCallback clientCertCb;
    clientCertCb = OSSL_clientCertCallback;

    if (OK > NSSL_CHK_CALL(setClientCertCallback, pSSL->instance, clientCertCb))
    {
        return -1;
    }
    return 0;
}

static sbyte4 OSSL_tlsExtStatusCallback(sbyte4 connectionInstance, const ubyte *pCert, ubyte4 certLen,
                                        ubyte* pOcspResp, ubyte4 ocspRespLen, sbyte4 ocspStatus)
{
    SSL *pSSL = NULL;
    pSSL = (SSL*) findSSLFromInstance(connectionInstance);
    int ret = 0;
    sbyte4 status = ocspStatus;

    if((NULL == pSSL) || (NULL == pSSL->ssl_ctx))
    {
        status = -1;
        goto exit;
    }

    /* Deep copy OCSP response */
    if (NULL != pOcspResp)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pSSL->tlsext_ocsp_resp    = BUF_memdup(pOcspResp, ocspRespLen);
        pSSL->tlsext_ocsp_resplen = ocspRespLen;
#else
        pSSL->orig_s.tlsext_ocsp_resp    = BUF_memdup(pOcspResp, ocspRespLen);
        pSSL->orig_s.tlsext_ocsp_resplen = ocspRespLen;
#endif
    }

    if (pSSL->ssl_ctx->tlsext_status_cb != NULL)
    {
        ret = pSSL->ssl_ctx->tlsext_status_cb(pSSL, pSSL->ssl_ctx->tlsext_status_arg);
        if (0 == ret)
        {
            status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
            SSLerr(SSL_F_TLS_PROCESS_SERVER_DONE, SSL_R_INVALID_STATUS_RESPONSE);
        }
        else if (0 > ret)
        {
            status = ERR_MEM_ALLOC_FAIL;
            SSLerr(SSL_F_TLS_PROCESS_SERVER_DONE, ERR_R_MALLOC_FAILURE);
        }
        else
        {
            /* Override OCSP status provided by stack */
            status = OK;
        }
    }

exit:
    if (0 == status)
    {
        ERR_clear_error();
    }
    return status;
}

static sbyte4 OSSL_setTLSExtStatusCallback()
{
    OCSPCallback certStatusCb;
    certStatusCb = OSSL_tlsExtStatusCallback;

    if (OK > NSSL_CHK_CALL(setOCSPCallback, certStatusCb))
    {
        return -1;
    }
    return 0;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__

static void PrintHandshakeVersion(
    sbyte *pHeader,
    ubyte4 version
    )
{
    PRINT("%s - ", pHeader);
    switch (version)
    {
        case SSL3_MINORVERSION:
            PRINT("SSL v3");
            break;

        case TLS10_MINORVERSION:
            PRINT("TLS v1.0");
            break;

        case TLS11_MINORVERSION:
            PRINT("TLS v1.1");
            break;

        case TLS12_MINORVERSION:
            PRINT("TLS v1.2");
            break;

        case TLS13_MINORVERSION:
            PRINT("TLS v1.3");
            break;

        case DTLS10_MINORVERSION:
            PRINT("DTLS v1.0");
            break;

        case DTLS12_MINORVERSION:
            PRINT("DTLS v1.2");
            break;

        default:
            PRINT("Unknown Version");
            break;
    }
    PRINT("\n");
}

static MSTATUS OSSL_versionCallback(
    ubyte4 serverVersion,
    ubyte4 clientVersion,
    MSTATUS sslStatus
    )
{
    PrintHandshakeVersion("Server Version", serverVersion);
    PrintHandshakeVersion("Client Version", clientVersion);
    if (OK == sslStatus)
        PrintHandshakeVersion("Negotiated Version", serverVersion);
    PRINT("Status = %d\n", sslStatus);
    return OK;
}

#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

/*------------------------------------------------------------------*/


static sbyte4 OSSL_AlpnCallback(sbyte4 connectionInstance,
                                    ubyte** out[],
                                    sbyte4* outlen,
                                    ubyte* in,
                                    sbyte4 inlen)
{
    sbyte4 status = 0;
    SSL *ssl;
    ubyte numProtos = 0;
    const unsigned char *protos=NULL;
    unsigned char protos_len = 0;

    ssl = (SSL*) findSSLFromInstance(connectionInstance);
    if((NULL == ssl) || (NULL == ssl->ssl_ctx))
        goto exit;
    if(ssl->ssl_ctx->alpn_select_cb)
        ssl->ssl_ctx->alpn_select_cb(ssl,&protos,&protos_len,in,inlen,
            ssl->ssl_ctx->alpn_select_cb_arg);

    if ((!protos) || (protos_len < 1))
    {
       status = -1;
       goto exit;
    }
    /* SSL Callback Response contains the selected string only */
    /* Convert into String Array */

    numProtos = 1;

    if (ssl->mocAlpnList != NULL)
    {
        OSSL_FREE(ssl->mocAlpnList);
    }

    /* Add 1 for terminating null */
    if (NULL == (ssl->mocAlpnList = OSSL_CALLOC((protos_len + 1), sizeof(char))))
    {
       status = -1;
       goto exit;
    }

    memcpy(ssl->mocAlpnList, protos, protos_len);

    *out = &(ssl->mocAlpnList);
    *outlen = numProtos;

exit:
    if (0 == status)
    {
        ERR_clear_error();
    }
    return status;
}

/*------------------------------------------------------------------*/

static sbyte4 SSL_set_alpn_select_cb(SSL *ssl)
{
     ALPN_CALLBACK alpn_callback;
     alpn_callback = OSSL_AlpnCallback;
     if (OK > NSSL_CHK_CALL(set_alpn_callback,ssl->instance,alpn_callback))
        return -1;
     return 0;
}

/*------------------------------------------------------------------*/

static sbyte4
OSSL_AlertCallback(sbyte4 connectionInstance, sbyte4 alertId, sbyte4 alertClass)
{
    MSTATUS status = OK;
    SSL *ssl;
#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
    sbyte4 errorCode;
    int error;
    int reason;
#endif
    int version = -1;
    unsigned char handshake_fragment[4] = {0};
    int direction = alertClass & SSL_ALERT_DIRECTION_BIT ? 1 : 0;

    alertClass &= ~SSL_ALERT_DIRECTION_BIT;

    ssl = (SSL*) findSSLFromInstance(connectionInstance);
    if (NULL == ssl)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    version = NSSL_CHK_CALL(sslGetVersion, ssl->instance);

    if (version == SSL3_MINORVERSION)
    {
        version = SSL3_VERSION;
    }
    else if (version == TLS10_MINORVERSION)
    {
        version =  TLS1_VERSION;
    }
    else if (version == TLS11_MINORVERSION)
    {
        version =  TLS1_1_VERSION;
    }
    else if (version == TLS12_MINORVERSION)
    {
        version =  TLS1_2_VERSION;
    }
    else if (version == TLS13_MINORVERSION)
    {
        version =  TLS1_3_VERSION;
    }
    else if (version == DTLS10_MINORVERSION)
    {
        version =  DTLS1_VERSION;
    }
    else if (version == DTLS12_MINORVERSION)
    {
        version =  DTLS1_2_VERSION;
    }
    else
    {
        version = 0;
    }

    handshake_fragment[0] = alertClass;
    handshake_fragment[1] = alertId;


    if ( (SSL_ALERT_CLOSE_NOTIFY == alertId) &&
         (SSLALERTLEVEL_WARNING == alertClass) )
    {
        if (direction)
        {
            ssl->orig_s.shutdown |= SSL_SENT_SHUTDOWN;
        }
        else
        {
            ssl->orig_s.shutdown |= SSL_RECEIVED_SHUTDOWN;
        }
    }

    if (SSLALERTLEVEL_FATAL == alertClass)
    {
        ssl->s3->fatal_alert = 1;
#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
        status = NSSL_CHK_CALL(
            sslParseAlert, connectionInstance, alertId,
            alertClass, &errorCode);
        if (OK == status)
        {
            convertMocStatus(ssl, errorCode, SSL3_RT_ALERT, ERR_R_INTERNAL_ERROR, &error, &reason);
        }
#endif
    }

    if (ssl->msg_callback)
        ssl->msg_callback (direction, version, SSL3_RT_ALERT, handshake_fragment, 2, ssl, ssl->msg_callback_arg);
exit:
    return status;
}

/*------------------------------------------------------------------*/

static sbyte4 OSSL_set_alert_cb(SSL *ssl)
{
     ALERT_CALLBACK alert_callback;
     alert_callback = OSSL_AlertCallback;
     if (OK > NSSL_CHK_CALL(set_alert_callback, ssl->instance, alert_callback))
        return -1;
     return 0;
}

/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__

static sbyte4 OSSL_setCertAndStatusCallBack(SSL *ssl)
{
     CERTSTATUS_CALLBACK certAndStatusCallBack;
     certAndStatusCallBack = OSSL_certCallback;
     if (OK > NSSL_CHK_CALL(setCertAndStatusCallBack, ssl->instance, certAndStatusCallBack))
        return -1;
     return 0;
}

static sbyte4 OSSL_setClientCertAuthorityCallback(SSL *ssl)
{
    if (OK > NSSL_CHK_CALL(setClientCertAuthorityCallback, ssl->instance, OSSL_clientCertAuthorityCallback))
    {
        return -1;
    }
    return 0;
}

#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__
static sbyte4 OSSL_setVersionCallback(SSL *ssl)
{
    VersionCallback versionCallback;
    char* pPrintTLSVersion  = NULL;
    pPrintTLSVersion = getenv("OPENSSL_ENABLE_VERSION_LOGGING");

    if (NULL != pPrintTLSVersion)
    {
        /* If the TLS Version Log environment variable is provided and it is equal to 1.  */
        if ((1 == DIGI_STRLEN(pPrintTLSVersion)) && (0 == DIGI_STRCMP(pPrintTLSVersion, "1")))
        {
            versionCallback = OSSL_versionCallback;
            if (OK > NSSL_CHK_CALL(setVersionCallback, ssl->instance, versionCallback))
            {
                return -1;
            }
        }
    }
    return 0;
}
#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

/*------------------------------------------------------------------*/

/* Load certificates
 * If the SSL_CERT_DIR is defined, load all the files in that directory.
 * Otherwise, try the default ca store
 * Returns 0 on error, 1 on success
 */
#ifdef __RTOS_WIN32__
static int
SSL_CTX_load_default_certs(SSL_CTX *ctx)
{
    char *cert_dir = NULL;
    char fullpath[255] = "\0";
    char sPath[2048];
    WIN32_FIND_DATA findFileData;
    HANDLE          hFind;
    ubyte *pCertFilePath = NULL;
    MSTATUS status = OK;
    int rval = 0;

    if (!ctx)
    {
        rval = 0;
        goto exit;
    }

    /* if the SSL_CERT_DIR environment variable is set, load all the certs */
    if (NULL != (cert_dir = getenv("SSL_CERT_DIR")))
    {
        snprintf(sPath, 2048, "%s\\*.*", cert_dir);
        /* open the directory and read/load certs in each file */
        /* open the directory */
        hFind = FindFirstFile (sPath, &findFileData);
        if (INVALID_HANDLE_VALUE == hFind)
        {
            rval = 0;
            goto exit;
        }
        do
        {
            if ((strcmp(findFileData.cFileName, ".") != 0) &&
                (strcmp(findFileData.cFileName, "..") != 0))
            {
                memset((void *)fullpath, 0, sizeof(fullpath));
                snprintf(fullpath, MAX_FILE_NAME_SIZE, "%s\\%s",
                    cert_dir, findFileData.cFileName);
                if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                {
                    (void)SSL_CTX_load_verify_locations(ctx, fullpath, NULL);
                }
            }
        }
        while (0 != FindNextFile(hFind, &findFileData));

        FindClose(hFind);
    }

    rval = 1;

exit:
    if (NULL != pCertFilePath)
    {
        NSSL_CHK_CALL(mocFree, (void **) &pCertFilePath);
    }

    return rval;
}

#else
static int
SSL_CTX_load_default_certs(SSL_CTX *ctx)
{
    int rval = 0;
    char *cert_dir = NULL;
    DIR *dir = NULL;
    struct dirent *crt_file = NULL;
    char fullpath[255] = "\0";

    if (!ctx)
    {
        return rval;
    }

    /* if the SSL_CERT_DIR environment variable is set, load all the certs */
    if (NULL != (cert_dir = getenv("SSL_CERT_DIR")))
    {
        /* open the directory and read/load certs in each file */
        dir = opendir(cert_dir);
        if (NULL == dir)
        {
            return 0;
        }
        while( (crt_file=readdir(dir)) != NULL)
        {
            if (!strcmp (crt_file->d_name, "."))
                continue;
            if (!strcmp (crt_file->d_name, ".."))
                continue;

            memset((void *)fullpath, 0, sizeof(fullpath));
            if (0 <= snprintf(fullpath, sizeof(fullpath), "%s/%s", cert_dir, crt_file->d_name))
            {
                (void)SSL_CTX_load_verify_locations(ctx, fullpath, NULL);
            }
        }
        closedir(dir);
    }
    else
    {
        /* Load default openssl certs */
        (void) SSL_CTX_load_verify_locations(ctx,"/etc/ssl/certs/ca-certificates.crt",NULL);
    }
    return (1);
}
#endif

static void OSSL_checkSha1CipherSupport(SSL *s)
{
    char *pSha1CipherSupport;

    pSha1CipherSupport = getenv("SSL_SHA1_CIPHER_SUPPORT");
    if (NULL != pSha1CipherSupport)
    {
        /* If the SHA-1 environment variable is provided then it must be 0.
         * By default SHA-1 is enabled. Setting the SSL_SHA1_CIPHER_SUPPORT
         * environment variable to a value of 0 will disable the SHA-1 cipher
         * suites.
         */
        if ( (1 == strlen(pSha1CipherSupport)) &&
             (0 == strcmp(pSha1CipherSupport, "0")) )
        {
            NSSL_CHK_CALL(
                disableCipherHash, s->instance, OSSL_TLS_SHA1);
        }
    }
}

static void OSSL_checkDSACipherSupport(SSL *s)
{
    char *pDSACiphers = NULL;

    pDSACiphers = getenv("SSL_DSA_CIPHER_SUPPORT");

    if (NULL != pDSACiphers)
    {
        if ((0 == strcmp(pDSACiphers , "0")) || (0 == strcmp(pDSACiphers, "1")))
        {
            NSSL_CHK_CALL(setDSACiphers, s->instance, atoi(pDSACiphers));
        }
    }
    else
    {
        /* By default disable the DSA ciphers if no env variable is specified */
        ubyte defaultDSA = 0;
        NSSL_CHK_CALL(setDSACiphers, s->instance, defaultDSA);
    }
}
/*------------------------------------------------------------------*/

/*
 *  client_hello_cb returns
 *  SSL_CLIENT_HELLO_SUCCESS    on success
 *  SSL_CLIENT_HELLO_ERROR      on failure
 *  SSL_CLIENT_HELLO_RETRY      to suspend processing
 */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int getClientHelloData(struct ClientHelloData * pHelloData, void *pCtx)
{
    int ret;
    SSL *ssl = (SSL *)pCtx;
    int alertDescr;

    ssl->client_hello_data = pHelloData;
    ret = ssl->ssl_ctx->orig_ssl_ctx.client_hello_cb(ssl, &alertDescr,
                                    ssl->ssl_ctx->orig_ssl_ctx.client_hello_cb_arg);

    /* only used for the duration of client_hello_cb call */
    ssl->client_hello_data = NULL; 

    if (ret == 0)
    {
        /* send alert */
        (void)NSSL_CHK_CALL(sslSendAlert, ssl->instance, alertDescr, SSLALERTLEVEL_FATAL);
    }
    else if (ret < 0)
    {
        ssl->orig_s.rwstate = SSL_CLIENT_HELLO_CB;
    }

    /* ret == -1 or ret == 1 is success  */
    return (ret == 0)? -1 : OK;
}
#endif

#define MY_SENDBUF_SZ    8192
extern int SSL_accept(SSL *s)
{
     ubyte         *pFirstUnusedByte = 0;
     ubyte4        bytesRemaining = 0;
     sbyte4        status = OK;
     ubyte4        mySendBufLen = 0;
     int           i = 0;
     int           bytesSent = 0;
     int           retValue = 0;
     int           certCbReturn = 1; /* 1 indicates success; By default set to 1 */
     intBoolean    localState= FALSE;
     SSL_CTX       * ctx;
     ubyte4 sslFlags  = 0;
     int authModeFlag = 0;
     void (*cb) (const SSL *ssl, int type, int val) = NULL;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     peerDescr myPeerDescr = {0};
     ubyte *srcAddr  = (ubyte *)"0.0.0.0";
     ubyte *peerAddr = (ubyte *)"1.1.1.1";
#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */
#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte enableExtendedMasterSecret = 1;
#endif

    if (NULL == s)
    {
        /* Error File may not be SSL3. Check*/
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        return -1;
    }

    ERR_clear_error();
    clear_sys_error();

    /* If a shutdown notification was received then don't send or process any data. */
    if (SSL_RECEIVED_SHUTDOWN & s->orig_s.shutdown)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

    /* Reset the flag */
    s->state &= ~(SSL_ST_ACCEPT_NEGOTIATING);

     /* Initialize myPeerDescr for DTLS */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
     {
        myPeerDescr.pUdpDescr = NULL;
        mocNetNameToIpaddr(&(myPeerDescr.srcAddr), srcAddr);
        myPeerDescr.srcPort   = s->appId;
        mocNetNameToIpaddr(&(myPeerDescr.peerAddr), peerAddr);
        myPeerDescr.peerPort  = s->appId;
     }
#endif

     ctx    = s->ssl_ctx;

    if(TRUE == setTlsPfsCiphersOnly)
    {
        /* The existing cipher_list should be updated to contain only PFS ciphers. */
        if(1 != update_cipher_list_with_pfs_ciphers_only(ctx))
        {
            SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
    }
    /* Application loads the cert and key at the time of connection instead of init with this callback;
     * For a given context we go to the application only once
     */
    if (s->ssl_ctx->isCertInitialized == 0)
    {
        if ((s->ssl_ctx->orig_ssl_ctx.cert != NULL) &&
            (s->ssl_ctx->orig_ssl_ctx.cert->cert_cb != NULL))
        {
            certCbReturn = s->ssl_ctx->orig_ssl_ctx.cert->cert_cb(s, s->ssl_ctx->orig_ssl_ctx.cert->cert_cb_arg);
        }

        if (0 == certCbReturn)
        {
            SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        else if (0 > certCbReturn)
        {
            /* This will return SSL_ERROR_WANT_X509_LOOKUP when application calls SSL_get_error */
            s->io_state = OSSL_X509_LOOKUP;
            return -1;
        }
        else
        {
            /* The callback successfully initialized the cert and key */
            s->ssl_ctx->isCertInitialized = 1;
        }
    }

    /* Nano SSL stack Uses the socket to correlate the connectionInstance
       to SSL Socket Session */
    if((s->orig_s.verify_mode & SSL_VERIFY_PEER) || (ctx->verify_mode & SSL_VERIFY_PEER)){
        /* allow mutual auth */
        authModeFlag = SSL_FLAG_REQUIRE_MUTUAL_AUTH;
    } else {
        authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;
    }

    /* Handshake status callback */
    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ssl_ctx->info_callback != NULL)
        cb = s->ssl_ctx->info_callback;

     if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
     {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            s->instance = NSSL_CHK_CALL(dtlsAccept, &myPeerDescr, ctx->pCertStore);
        }
        else
#endif
        {
            s->instance = NSSL_CHK_CALL(accept, s->appId, ctx->pCertStore);
        }

        if (OK > s->instance)
        {
           return -1;
        }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (s->ssl_ctx->orig_ssl_ctx.client_hello_cb)
        {
            /* Register function to get client hello data back
             * from NanoSSL stack */
            status = NSSL_CHK_CALL(setClientHelloCallback, s->instance,
                                   getClientHelloData, (void *)s);
            if (OK > status)
            {
                return -1;
            }
        }
#endif

       /* Add entry of instance into HASH table to create map with ssl*/
        if (OK > (status = moc_mutexWait(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexWait() failed : %d\n", status);*/
            return -1;
        }

        (void) NSSL_CHK_CALL(hashTableAddPtr, m_ssl_table, s->instance,(SSL*)s);

        if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexRelease() failed : %d\n", status);*/
            return -1;
        }

        OSSL_checkSha1CipherSupport(s);

        OSSL_checkDSACipherSupport(s);

        if (s->numCipherIds > 0)
        {
            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, s->cipherIds, s->numCipherIds)))
            {
                return -1;
            }
        }
        else
        {
            /* Choose default Cipher Suites */
            if ((ctx->numCipherIds < 1) || (ctx->cipher_list == NULL))
            {
                (void) SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
            }

            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, ctx->cipherIds, ctx->numCipherIds)))
            {
                return -1;
            }
        }

        if (s->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = s->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                return -1;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = s->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }
        else if (ctx->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = ctx->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                return -1;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = ctx->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            if (s->numSrtpProfileIds > 0)
            {
                NSSL_CHK_CALL(setSrtpProfiles, s->instance, s->srtpProfileIds, s->numSrtpProfileIds);
            }
            else
            {
                if (ctx->numSrtpProfileIds > 0)
                {
                    NSSL_CHK_CALL(setSrtpProfiles, s->instance, ctx->srtpProfileIds, ctx->numSrtpProfileIds);
                }
            }
        }
#endif

        if (OK > (status = NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags)))
        {
            return -1;
        }

        /* Reset the flags before setting */
        sslFlags &= ~(SSL_FLAG_NO_MUTUAL_AUTH_REQUEST);
        sslFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);

        if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (sslFlags) | (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        {
            return -1;
        }


        if ((NULL != s->ssl_ctx->orig_ssl_ctx.cert) && (NULL != s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs))
        {
            if (OK > (status = NSSL_CHK_CALL(setCipherAlgorithm, s->instance, s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs,
                                   (ubyte4) s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgslen, 2 /* signature algorithms */)))
            {
                return -1;
            }
        }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
         /* Extended master secret is enabled by default */
        if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void*)((OSSL_UINT_PTR)enableExtendedMasterSecret)))
        {
            return -1;
        }
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (0 != ctx->orig_ssl_ctx.num_tickets)
        {
            if (OK == NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_NUM_TICKETS, (void*)((OSSL_UINT_PTR)ctx->orig_ssl_ctx.num_tickets)))
            {
                status = 1;
            }
        }

        if (s->orig_s.max_early_data)
        {
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)s->orig_s.max_early_data)))
            {
                return 0;
            }
        }

        if (s->orig_s.recv_max_early_data)
        {
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)s->orig_s.recv_max_early_data)))
            {
                return 0;
            }
        }

        /* Saving PSK on Server */
        SSL_set_server_psk_save_session_callback(s);

        if (s->ssl_ctx->get_session_cb != NULL)
        {
            pskFindSessionCallbackFuncPtr  psk_find_session_callback;
            psk_find_session_callback  = OSSL_psk_get_session_callback;

            NSSL_CHK_CALL(setPskFindSessionCb, psk_find_session_callback);
        }
#endif

      if(s->ssl_ctx->alpn_select_cb)
        (void) SSL_set_alpn_select_cb(s);

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
      OSSL_setCertAndStatusCallBack(s);
#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */
#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__
      OSSL_setVersionCallback(s);
#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

      /* Set the callback alert by default. This will allow proper handling of
       * alert messages.
       */
      OSSL_set_alert_cb(s);

     }
     else
     {
        /* EIPTEST MOC_SSL_CONN_INSTANCE_UNASSIGNED != s->instance condition */
        if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        {
            return -1; /* XXX: cleanup instance */
        }
     }
     s->clientServerFlag    = SSL_SERVER_FLAG;
    retValue = NSSL_CHK_CALL(isEstablished, s->instance);
    if (1 == retValue)
    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        s->orig_state = SSL_ST_OK;
#else
        s->orig_s.state = SSL_ST_OK;
#endif
        return 1;
    }
    else if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

     if (NULL == s->pHoldingBuf)
     {
        s->pHoldingBuf = OSSL_MALLOC(OSSL_MAX_SSL_RX_MSG_SZ);
        if (NULL == s->pHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            return -1;
        }
        s->szHoldingBuf         = OSSL_MAX_SSL_RX_MSG_SZ;
        s->bytesRcvdRemaining   = 0;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
     }

     if (NULL == s->pTxHoldingBuf)
     {
        s->pTxHoldingBuf    = OSSL_MALLOC(OSSL_MAX_SSL_MSG_SZ);
        if (NULL == s->pTxHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            return -1;
        }
        s->szTxHoldingBuf    = OSSL_MAX_SSL_MSG_SZ;
        s->bytesSentRemaining = 0;
        s->txHoldingBufOffset = 0;
     }
#if 0
     if (ctx->app_verify_callback)
     {
      int rval = NSSL_CHK_CALL(setAppCertVrfyCB, s->instance, OSSL_shimAppVerifyCert, (void *)s);
      if (rval < 0)
           return -1;
     }
#endif
     while (0 == (retValue = NSSL_CHK_CALL(isEstablished, s->instance))) {

      if (s->bytesSentRemaining > 0)
      {
          i = asyncSendDataBio(
            s, s->pTxHoldingBuf + s->txHoldingBufOffset, s->bytesSentRemaining,
            &bytesSent);
          if (0 >= i)
          {
            s->bytesSentRemaining -= bytesSent;
            s->txHoldingBufOffset += bytesSent;
            return i;
          }

          s->bytesSentRemaining = 0;
          s->txHoldingBufOffset = 0;
      }

      if (0 == s->bytesRcvdRemaining) {
          s->io_state        = OSSL_IN_READ;
          s->orig_s.rwstate = SSL_READING;
          while( 0 >= (i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf)))
          {
            /* XXX: check errors
             *
             * OpenSSL BIO_read documentation specifies that a return value of
             * 0 or -1 does not necessarily indicate an error and that
             * BIO_should_retry should be checked.
             */
             if ((i < 0)||(!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
             {
                return i;
             }
           }
           s->io_state    = 0;
           s->orig_s.rwstate = SSL_NOTHING;
           s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
           s->bytesRcvdRemaining    = i;
      }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
      if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
      {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (s->hello_verify_done)
        {
            if (OK > NSSL_CHK_CALL(dtlsIoctl, s->instance, DTLS_SET_HELLO_VERIFIED, (void*)((OSSL_UINT_PTR)1))) {
                asyncSendPendingData(s);
                convertMocStatusToSslErr(s, status, SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                return -1;
            }
        }
        else if (SSL_get_options(s)&SSL_OP_COOKIE_EXCHANGE)
        {
            /* if no helloVerifyRequest was negotiated and we enforce cookie exchange, end handshake. */
            convertMocStatusToSslErr(s, status, SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
#endif

        status = NSSL_CHK_CALL(dtlsParseSslBuf,s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                 &pFirstUnusedByte, &bytesRemaining);
        if (OK > status) {
            asyncSendPendingData(s);
            convertMocStatusToSslErr(s, status, SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
      }
      else
#endif
      {
        status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                 &pFirstUnusedByte, &bytesRemaining);
        if (OK > status) {
            asyncSendPendingData(s);
            convertMocStatusToSslErr(s, status, SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
      }

      /* While in the Handshake phase, recvMessage2 calls SSL_SOCK_receive in a loop
       * until it absorbs all the TCP sock data we give it; and the return value in
       * status is normally 0. On Failure, status will be (-)ve. pFirstUnusedByte
       * will be NULL and bytesRemaining will be 0. These 2 will be set to meaningful vals
       * normally only after HShake is complete. For ex. status will be # of cleartext bytes avail.
       * for harvest; In this case i.e status > 0, pFirstUnusedByte will point to 1st un-used
       * TCP sock data in the buffer given to recvMessage2; bytesRemaining will indicate # of
       * un-used bytes in above buffer. If this happens before Hshake is finished, it may
       * indicate an ALERT was received and should be harvested (see else clause below)
       */
      if (0 == status)
      {
           s->pFirstRcvdUnreadByte   = s->pHoldingBuf;
           s->bytesRcvdRemaining     = 0;
      } else {
           /* This should not happen; if it does, it means during Hshake some
        * other non-Hshake msg was received; most likely ALERT. Must harvest
        * and continue feeding bytes to Hshake.
        * XXX: Harvest Alerts here !!
        */
           s->pFirstRcvdUnreadByte  = pFirstUnusedByte;
           s->bytesRcvdRemaining    = bytesRemaining;
      }
      /* Now send any pending bytes */
      mySendBufLen        = s->szTxHoldingBuf;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
      if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
      {
        while (OK == (status = NSSL_CHK_CALL(dtlsGetSendBuffer,s->instance, s->pTxHoldingBuf, &mySendBufLen))) {

           i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
           if (0 >= i)
           {
               s->bytesSentRemaining = mySendBufLen - bytesSent;
               s->txHoldingBufOffset = bytesSent;
               return i;
           }

           mySendBufLen    = s->szTxHoldingBuf;
        }
      }
      else
#endif
      {
        while (OK == (status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen))) {

           i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
           if (0 >= i)
           {
               s->bytesSentRemaining = mySendBufLen - bytesSent;
               s->txHoldingBufOffset = bytesSent;
               return i;
           }

           mySendBufLen    = s->szTxHoldingBuf;

           /* The above BIO_write is used to send the handshake packets.
            * The first packet sent will be ServerHello.
            * In RUI and Libwebsockets application, the client can send application data
            * before the server has sent its last handshake message;
            * In that case, that data is in the buffer, but application might be waiting
            * for data on socket before it calls SSL_read. That causes a timeout.
            * To prevent that we send out first packet and say handshake went through,
            * so that application calls SSL_read for the next incoming handshake packet.
            * SSL_read checks if session is established. If it is not it calls the SSL_do_handshake.
            * So the incomplete session is handled and the application data is also read and processed.
            */
            retValue = NSSL_CHK_CALL(isEstablished, s->instance);
            if (0 == retValue)
            {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                retValue = NSSL_CHK_CALL(getLocalState, s->instance, &localState);
                if (0 != retValue)
                    return -1;

                if (SSL_HELLO_RETRY_REQUEST == localState)
                    continue;
#endif

                /* Immediately after SSL_accept returns, application can call SSL_state;
                 * In SSL_state negotiation should continue only in this case;
                 * If SSL_state is called from any other context, we should not
                 * attempt to negotiate. This new state flag is added to indicate
                 * the context of the negotiation to SSL_state.
                 */
                s->state |= SSL_ST_ACCEPT_NEGOTIATING;
                return 1;
            }
            else if (-1 == retValue)
            {
                SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                return -1;
            }
            else
            {
                goto exit;
            }
      }
     }
    }

    if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

exit:
     /* Notify that handshake is done*/
    if (cb != NULL)
      cb(s, SSL_CB_HANDSHAKE_DONE, 1);


#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    s->orig_state = SSL_ST_OK;
    s->orig_s.statem.state = MSG_FLOW_FINISHED;
    s->orig_s.statem.hand_state = TLS_ST_OK;
    s->orig_s.statem.in_init = 0;
#else
    s->orig_s.state = SSL_ST_OK;
#endif
     return 1;
}

/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

static MSTATUS checkRxBuffer(SSL *s, ubyte4 size);
static int SSL_acceptEx(SSL *s, void *buf, size_t num, size_t *readBytes)
{
    ubyte         *pFirstUnusedByte = 0;
    ubyte4        bytesRemaining = 0;
    sbyte4        status = OK;
    int           retValue = 0;
    int           certCbReturn = 1; /* 1 indicates success; By default set to 1 */
    ubyte4        mySendBufLen = 0;
    ubyte         *pBuf = NULL;
    ubyte4        toCopy = 0;
    int           i = 0;
    int           bytesSent = 0;
    SSL_CTX       * ctx;
    int authModeFlag = 0;
    ubyte4 sslFlags  = 0;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    peerDescr myPeerDescr = {0};
    ubyte *srcAddr  = (ubyte *)"0.0.0.0";
    ubyte *peerAddr = (ubyte *)"1.1.1.1";
#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte enableExtendedMasterSecret = 1;
#endif

    if (NULL == s)
    {
        /* Error File may not be SSL3. Check*/
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        return -1;
    }

    ERR_clear_error();
    clear_sys_error();

    /* Initialize myPeerDescr for DTLS */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
    {
        myPeerDescr.pUdpDescr = NULL;
        mocNetNameToIpaddr(&(myPeerDescr.srcAddr), srcAddr);
        myPeerDescr.srcPort   = s->appId;
        mocNetNameToIpaddr(&(myPeerDescr.peerAddr), peerAddr);
        myPeerDescr.peerPort  = s->appId;
    }
#endif

    ctx    = s->ssl_ctx;

    /* Application loads the cert and key at the time of connection instead of init with this callback;
     * For a given context we go to the application only once
     */
    if (s->ssl_ctx->isCertInitialized == 0)
    {
        if ((s->ssl_ctx->orig_ssl_ctx.cert != NULL) &&
            (s->ssl_ctx->orig_ssl_ctx.cert->cert_cb != NULL))
        {
            certCbReturn = s->ssl_ctx->orig_ssl_ctx.cert->cert_cb(s, s->ssl_ctx->orig_ssl_ctx.cert->cert_cb_arg);
        }

        if (0 == certCbReturn)
        {
            SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
        else if (0 > certCbReturn)
        {
            /* This will return SSL_ERROR_WANT_X509_LOOKUP when application calls SSL_get_error */
            s->io_state = OSSL_X509_LOOKUP;
            return -1;
        }
        else
        {
            /* The callback successfully initialized the cert and key */
            s->ssl_ctx->isCertInitialized = 1;
        }
    }

    /* Nano SSL stack Uses the socket to correlate the connectionInstance
    to SSL Socket Session */
    if((s->orig_s.verify_mode & SSL_VERIFY_PEER) || (ctx->verify_mode & SSL_VERIFY_PEER))
    {
        /* allow mutual auth */
        authModeFlag = SSL_FLAG_REQUIRE_MUTUAL_AUTH;
    }
    else
    {
        authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;
    }

    /* Handshake status callback */
    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (s->ssl_ctx->info_callback != NULL)
        cb = s->ssl_ctx->info_callback;

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
    {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            s->instance = NSSL_CHK_CALL(dtlsAccept, &myPeerDescr, ctx->pCertStore);
        }
        else
#endif
        {
            s->instance = NSSL_CHK_CALL(accept, s->appId, ctx->pCertStore);
        }

        if (OK > s->instance)
        {
            return -1;
        }

        /* Add entry of instance into HASH table to create map with ssl*/
        if (OK > (status = moc_mutexWait(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexWait() failed : %d\n", status);*/
            return -1;
        }

        (void) NSSL_CHK_CALL(hashTableAddPtr, m_ssl_table, s->instance,(SSL*)s);

        if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexRelease() failed : %d\n", status);*/
            return -1;
        }
        if (s->numCipherIds > 0)
        {
            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, s->cipherIds, s->numCipherIds)))
            {
                return -1;
            }
        }
        else
        {
            /* Choose default Cipher Suites */
            if ((ctx->numCipherIds < 1) || (ctx->cipher_list == NULL))
            {
                (void) SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
            }

            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, ctx->cipherIds, ctx->numCipherIds)))
            {
                return -1;
            }
        }

        if (s->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = s->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                return -1;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = s->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }
        else if (ctx->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = ctx->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                return -1;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = ctx->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            if (s->numSrtpProfileIds > 0)
            {
                NSSL_CHK_CALL(setSrtpProfiles, s->instance, s->srtpProfileIds, s->numSrtpProfileIds);
            }
            else
            {
                if (ctx->numSrtpProfileIds > 0)
                {
                    NSSL_CHK_CALL(setSrtpProfiles, s->instance, ctx->srtpProfileIds, ctx->numSrtpProfileIds);
                }
            }
        }
#endif

        if (OK > (status = NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags)))
        {
            return -1;
        }

        /* Reset the flags before setting */
        sslFlags &= ~(SSL_FLAG_NO_MUTUAL_AUTH_REQUEST);
        sslFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);

        /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
        if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (sslFlags) | (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        {
            return -1; /* XXX: cleanup instance */
        }


        if ((NULL != s->ssl_ctx->orig_ssl_ctx.cert) && (NULL != s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs))
        {
            if (OK > NSSL_CHK_CALL(setCipherAlgorithm, s->instance, s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs,
                                   (ubyte4) s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgslen, 2 /* signature algorithms */))
            {
                return -1;
            }
        }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
         /* Extended master secret is enabled by default */
        if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void*)((OSSL_UINT_PTR)enableExtendedMasterSecret)))
        {
            return -1;
        }
#endif

#if defined ( __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (0 != ctx->orig_ssl_ctx.num_tickets)
        {
            if (OK == NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_NUM_TICKETS, (void*)((OSSL_UINT_PTR)ctx->orig_ssl_ctx.num_tickets)))
            {
                status = 1;
            }
        }

        if (s->orig_s.max_early_data)
        {
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)s->orig_s.max_early_data)))
            {
                return 0;
            }
        }

        if (s->orig_s.recv_max_early_data)
        {
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)s->orig_s.recv_max_early_data)))
            {
                return 0;
            }
        }

        /* Saving PSK on Server */
        SSL_set_server_psk_save_session_callback(s);

        if (s->ssl_ctx->get_session_cb != NULL)
        {
            pskFindSessionCallbackFuncPtr  psk_find_session_callback;
            psk_find_session_callback  = OSSL_psk_get_session_callback;
            NSSL_CHK_CALL(setPskFindSessionCb, psk_find_session_callback);
        }
#endif
        if(s->ssl_ctx->alpn_select_cb)
            (void) SSL_set_alpn_select_cb(s);

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
        OSSL_setCertAndStatusCallBack(s);
#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */
#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__
        OSSL_setVersionCallback(s);
#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

        /* Set the callback alert by default. This will allow proper handling of
        * alert messages.
        */
        OSSL_set_alert_cb(s);
    }
    else
    {
        /* EIPTEST MOC_SSL_CONN_INSTANCE_UNASSIGNED != s->instance condition */
        if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        {
            return -1;
        }
    }

    s->clientServerFlag    = SSL_SERVER_FLAG;
    retValue = NSSL_CHK_CALL(isEstablished, s->instance);
    if (1 == retValue)
    {
        return 1;
    }
    else if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (NULL == s->pHoldingBuf)
    {
        s->pHoldingBuf = OSSL_MALLOC(OSSL_MAX_SSL_RX_MSG_SZ);
        if (NULL == s->pHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            return -1;
        }
        s->szHoldingBuf         = OSSL_MAX_SSL_RX_MSG_SZ;
        s->bytesRcvdRemaining   = 0;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
    }

    if (NULL == s->pTxHoldingBuf)
    {
        s->pTxHoldingBuf    = OSSL_MALLOC(OSSL_MAX_SSL_MSG_SZ);
        if (NULL == s->pTxHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            return -1;
        }
        s->szTxHoldingBuf     = OSSL_MAX_SSL_MSG_SZ;
        s->bytesSentRemaining = 0;
        s->txHoldingBufOffset = 0;
    }

    while (0 == (retValue = NSSL_CHK_CALL(isEstablished, s->instance)))
    {

        if (s->bytesSentRemaining > 0)
        {
            i = asyncSendDataBio(
                s, s->pTxHoldingBuf + s->txHoldingBufOffset, s->bytesSentRemaining,
                &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining -= bytesSent;
                s->txHoldingBufOffset += bytesSent;
                return i;
            }
    
            s->bytesSentRemaining = 0;
            s->txHoldingBufOffset = 0;
        }

        if (0 == s->bytesRcvdRemaining)
        {
            s->io_state       = OSSL_IN_READ;
            s->orig_s.rwstate = SSL_READING;
            if ( 0 >= (i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf)))
            {
                /* XXX: check errors
                 * OpenSSL BIO_read documentation specifies that a return value of
                 * 0 or -1 does not necessarily indicate an error and that
                 * BIO_should_retry should be checked.
                 */
                if ((i < -1)||(!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
                {
                    return i;
                }
            }
            s->io_state             = 0;
            s->orig_s.rwstate       = SSL_NOTHING;
            s->pFirstRcvdUnreadByte = s->pHoldingBuf;
            s->bytesRcvdRemaining   = i;
        }
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            status = NSSL_CHK_CALL(dtlsParseSslBuf,s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                                   &pFirstUnusedByte, &bytesRemaining);
            if (OK > status)
            {
                asyncSendPendingData(s);
                convertMocStatusToSslErr(s, status, SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                return -1;
            }

            if (0 < status)
            {
                status = NSSL_CHK_CALL(dtlsReadSslRec, s->instance, (ubyte**)&pBuf, (ubyte4*)readBytes, NULL);
                if (OK > status)
                {
                    asyncSendPendingData(s);
                    convertMocStatusToSslErr(s, status, SSL_F_DTLS1_ACCEPT, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
            }
        }
        else
#endif
        {
            status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                                   &pFirstUnusedByte, &bytesRemaining);
            if (OK > status)
            {
                asyncSendPendingData(s);
                convertMocStatusToSslErr(s, status, SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                return -1;
            }

            if (0 < status)
            {
                status = NSSL_CHK_CALL(readSslRec, s->instance, (ubyte**)&pBuf, (ubyte4*)readBytes, NULL);
                if (OK > status)
                {
                    asyncSendPendingData(s);
                    convertMocStatusToSslErr(s, status, SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
                    return -1;
                }
            }
        }

        if ((*readBytes > 0) && (pBuf != NULL))
        {
            toCopy = ((num > (size_t) *readBytes) ? (ubyte4) *readBytes : (ubyte4) num);
            memcpy((ubyte *)buf, pBuf, toCopy);
        }
        if ((*readBytes > (ubyte4)toCopy) && (pBuf != NULL)) { /* store left over plaintext data */
            ubyte4    toKeep;
            toKeep    = (*readBytes - toCopy);
            checkRxBuffer(s, toKeep); /* Sets rxDatabufOffset to 0 if it allocates */
            memcpy(s->pRxDataBuf + s->rxDataBufOffset + s->rxDataBufLen, pBuf + toCopy, toKeep);
            s->rxDataBufLen        += toKeep;
            *readBytes = toCopy;
        }
        /* While in the Handshake phase, recvMessage2 calls SSL_SOCK_receive in a loop
         * until it absorbs all the TCP sock data we give it; and the return value in
         * status is normally 0. On Failure, status will be (-)ve. pFirstUnusedByte
         * will be NULL and bytesRemaining will be 0. These 2 will be set to meaningful vals
         * normally only after HShake is complete. For ex. status will be # of cleartext bytes avail.
         * for harvest; In this case i.e status > 0, pFirstUnusedByte will point to 1st un-used
         * TCP sock data in the buffer given to recvMessage2; bytesRemaining will indicate # of
         * un-used bytes in above buffer. If this happens before Hshake is finished, it may
         * indicate an ALERT was received and should be harvested (see else clause below)
         */
        if (0 == status)
        {
            s->pFirstRcvdUnreadByte   = s->pHoldingBuf;
            s->bytesRcvdRemaining     = 0;
        }
        else
        {
            /* This should not happen; if it does, it means during Hshake some
             * other non-Hshake msg was received; most likely ALERT. Must harvest
             * and continue feeding bytes to Hshake.
             * OR this is the early application data in 0-RTT handshake flow
             */
            s->pFirstRcvdUnreadByte  = pFirstUnusedByte;
            s->bytesRcvdRemaining    = bytesRemaining;
            /* If the buffer provided is big enough, copy the data */
            if ((sbyte4) num > status)
            {
                memcpy((void *)buf, pFirstUnusedByte, status);
                *readBytes = status;
                return status;
            }
            else
            {
                buf        = NULL;
                *readBytes = 0;
                return bytesRemaining;
            }
        }
        /* Now send any pending bytes */
        mySendBufLen = s->szTxHoldingBuf;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            while (OK == (status = NSSL_CHK_CALL(dtlsGetSendBuffer,s->instance, s->pTxHoldingBuf, &mySendBufLen)))
            {
                i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    return i;
                }

                mySendBufLen      = s->szTxHoldingBuf;
            }
        }
        else
#endif
        {
            while (OK == (status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen)))
            {
                i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    return i;
                }

                mySendBufLen    = s->szTxHoldingBuf;

                /* The above BIO_write is used to send the handshake packets.
                * The first packet sent will be ServerHello.
                * In RUI and Libwebsockets application, the client can send application data
                * before the server has sent its last handshake message;
                * In that case, that data is in the buffer, but application might be waiting
                * for data on socket before it calls SSL_read. That causes a timeout.
                * To prevent that we send out first packet and say handshake went through,
                * so that application calls SSL_read for the next incoming handshake packet.
                * SSL_read checks if session is established. If it is not it calls the SSL_do_handshake.
                * So the incomplete session is handled and the application data is also read and processed.
                */
                return 1;
            }
        }
    }

    if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

    (void) BIO_flush(s->wbio);
    /* Notify that handshake is done*/
    if (cb != NULL)
    cb(s, SSL_CB_HANDSHAKE_DONE, 1);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    s->orig_state = SSL_ST_OK;
#else
    s->orig_s.state = SSL_ST_OK;
#endif
    return 1;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*------------------------------------------------------------------*/

int OSSL_getNewSession(SSL *s)
{
    SSL_SESSION *ss = NULL;

    if ((ss = SSL_SESSION_new()) == NULL)
          return (0);

    if (s->session != NULL) {
          SSL_SESSION_free(s->session);
          s->session = NULL;
    }
    s->session = ss;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    s->session->peer_chain = NULL;
#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    s->session->peer_type = 0;
#endif
#else
    s->session->sess_cert = (SESS_CERT*) OSSL_CALLOC(1, sizeof(SESS_CERT));
    if (s->session->sess_cert)
    {
        s->session->sess_cert->cert_chain     = NULL;
        s->session->sess_cert->peer_cert_type = 0;
    }
#endif

    return 1;
}

/*------------------------------------------------------------------*/

/* Our NanoSSL Hshake SM will never transition to a good state
 * if the signature sent by the client in the verification payload was invalid
 * So checking if the state is established is a good way to tell if client
 * verify succeeded or not
 */
long SSL_get_verify_result(const SSL *s)
{
     if(NULL == s)
        return -1;
     if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
        return -1;

     return s->verify_result;
}

/*------------------------------------------------------------------*/

void SSL_set_verify_result(SSL *ssl, long arg)
{
    if (NULL != ssl)
    {
        ssl->verify_result = arg;
    }
}

/*-----------------------------------------------------------------*/
static int
getSharedSignatureAlgorithms(SSL *pSsl, int idx,
                             int *psign, int *phash, int *psignhash,
                             unsigned char *rsig, unsigned char *rhash,
                             ubyte isPeer)
{
    ubyte2 sigAlgo;
    sbyte4 status;
    if (OK > (status = NSSL_CHK_CALL(getSharedSignatureAlgorithm, pSsl->instance, idx, &sigAlgo, isPeer)))
    {
        return 0;
    }

    if (rsig != NULL)
    {
        *rsig = sigAlgo & 0xFF;
    }

    if (rhash != NULL)
    {
        *rhash = (sigAlgo >> 8) & 0xFF;
    }

    switch((sigAlgo >> 8) & 0xFF)
    {
        case OSSL_TLS_ECDSA:
            switch(sigAlgo & 0xFF)
            {
                case TLS_SHA512:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_ecdsa_with_SHA512;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha512;
                    }
                    break;

                case TLS_SHA384:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_ecdsa_with_SHA384;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha384;
                    }
                    break;

                case TLS_SHA256:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_ecdsa_with_SHA256;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha256;
                    }
                    break;
                case TLS_SHA224:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_ecdsa_with_SHA224;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha224;
                    }
                    break;
                case TLS_SHA1:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_ecdsa_with_SHA1;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha1;
                    }
                    break;
                default:
                    break;
            }
            break;
        case OSSL_TLS_RSA:
            if (psign != NULL)
            {
                *psign = NID_rsaEncryption;
            }
            switch(sigAlgo & 0xFF)
            {
                case TLS_SHA512:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_sha512WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha512;
                    }
                    break;
                case TLS_SHA384:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_sha384WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha384;
                    }
                    break;
                case TLS_SHA256:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_sha256WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha256;
                    }
                    break;
                case TLS_SHA224:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_sha224WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha224;
                    }
                    break;
                case TLS_SHA1:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_sha1WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha1;
                    }
                    break;
                case TLS_MD5:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_md5WithRSAEncryption;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_md5;
                    }
                    break;
                default:
                    break;
            }
            break;

        case OSSL_TLS_DSA:
            if (psign != NULL)
            {
                *psign = NID_dsa;
            }
            switch(sigAlgo & 0xFF)
            {
                case TLS_SHA256:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_dsa_with_SHA256;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha256;
                    }
                    break;
                case TLS_SHA224:
                    if (psignhash != NULL)
                    {
                        *psignhash =  NID_dsa_with_SHA224;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha224;
                    }
                    break;
                case TLS_SHA1:
                    if (psignhash != NULL)
                    {
                        *psignhash = NID_dsaWithSHA1;
                    }
                    if (phash != NULL)
                    {
                        *phash = NID_sha1;
                    }
                    break;
                default:
                    break;
            }
            break;

        case OSSL_TLS_13_RSA_PSS_PSS_SHA256:
            if (psign != NULL)
            {
                *psign = NID_rsassaPss;
            }
            if (phash != NULL)
            {
                *phash = NID_sha256;
            }
            break;

        case OSSL_TLS_13_RSA_PSS_PSS_SHA384:
            if (psign != NULL)
            {
                *psign = NID_rsassaPss;
            }
            if (phash != NULL)
            {
                *phash = NID_sha384;
            }
            break;

        case OSSL_TLS_13_RSA_PSS_PSS_SHA512:
            if (psign != NULL)
            {
                *psign = NID_rsassaPss;
            }
            if (phash != NULL)
            {
                *phash = NID_sha512;
            }
            break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case OSSL_TLS_EDDSA25519:
            if (psignhash != NULL)
            {
                *psignhash = NID_ED25519;
            }
            break;

        case OSSL_TLS_EDDSA448:
            if (psignhash != NULL)
            {
                *psignhash = NID_ED448;
            }
            break;
#endif

        default:
            break;
    }
    return status;

}
int SSL_get_shared_sigalgs(SSL *s, int idx,
                           int *psign, int *phash, int *psignhash,
                           unsigned char *rsig, unsigned char *rhash)
{
    return getSharedSignatureAlgorithms(s, idx, psign, phash, psignhash, rsig, rhash, 1/* Peer Sig Algo */);
}

int SSL_get_sigalgs(SSL *s, int idx,
                    int *psign, int *phash, int *psignhash,
                    unsigned char *rsig, unsigned char *rhash)
{
    return getSharedSignatureAlgorithms(s, idx, psign, phash, psignhash, rsig, rhash, 0 /* Own Sig Algo */);
}

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)

static sbyte4
OSSL_saveSessionTicket(sbyte4 connInstance, sbyte *pServerInfo, ubyte4 serverInfoLen,
                       void *pUserData, ubyte *pTicket, ubyte4 ticketLen)
{
    MSTATUS status = OK;
    SSL *s;
    SSL_SESSION *session;
    OSSL_sessionTicket *pTicketData = NULL;

    s = (SSL *) findSSLFromInstance(connInstance);
    if ((NULL == s) || (NULL == s->session))
    {
        goto exit;
    }

    session = s->session;

    /* Delete any old tickets */
    session->cipher_id = 0;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (session->ext.tick)
    {
        OSSL_FREE(session->ext.tick);
        session->ext.tick = NULL;
        session->ext.ticklen = 0;
    }
    session->ext.tick_lifetime_hint = 0;
#else
    if (session->tlsext_tick)
    {
        OSSL_FREE(session->tlsext_tick);
        session->tlsext_tick = NULL;
        session->tlsext_ticklen = 0;
    }
    session->tlsext_tick_lifetime_hint = 0;
#endif

    if (0 != session->master_key_length)
    {
        memset(session->master_key, 0x00, session->master_key_length);
        session->master_key_length = 0;
    }

    /* Deserialize new ticket */
    if (OK > (status = NSSL_CHK_CALL(deserializeTicket, pTicket, ticketLen, &pTicketData)))
    {
        goto exit;
    }

    /* Store ticket values in OpenSSL session structure */
    session->cipher_id = pTicketData->cipherId;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    session->ext.tick = OSSL_MALLOC(ticketLen);
    if (NULL == session->ext.tick)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    memcpy(session->ext.tick, pTicket, ticketLen);
    session->ext.ticklen = ticketLen;
    session->ext.tick_lifetime_hint = pTicketData->lifeTimeHintInSec;
#else
    session->tlsext_tick = OSSL_MALLOC(ticketLen);
    if (NULL == session->tlsext_tick)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    memcpy(session->tlsext_tick, pTicket, ticketLen);
    session->tlsext_ticklen = ticketLen;
    session->tlsext_tick_lifetime_hint = pTicketData->lifeTimeHintInSec;
#endif

    memcpy(session->master_key, pTicketData->masterSecret, SSL_MASTERSECRETSIZE);
    session->master_key_length = SSL_MASTERSECRETSIZE; 

exit:

    if (NULL != pTicketData)
    {
        (void) NSSL_CHK_CALL(freeTicket, &pTicketData);
    }

    return status;
}

static sbyte4
OSSL_retrieveSessionTicket(sbyte4 connInstance, sbyte *pServerInfo, ubyte4 serverInfoLen,
                           void *pUserData, ubyte **ppTicket, ubyte4 *pTicketLen,
                           intBoolean *pFreeMemory)
{
    MSTATUS status = -1;
    SSL_SESSION *pSess       = NULL;
    SSL *pSSL                  = NULL;
    char *pTicket            = NULL;
    size_t ticketLength      = 0;

    pSSL = (SSL*)findSSLFromInstance(connInstance);

    if ((NULL == pSSL) || (NULL == pFreeMemory))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFreeMemory = 0;
    *ppTicket    = NULL;
    *pTicketLen  = 0;

    pSess = pSSL->session;

    if (pSess != NULL)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pTicket      = (char *) pSess->ext.tick;
        ticketLength = pSess->ext.ticklen;
#else
        pTicket      = (char *) pSess->tlsext_tick;
        ticketLength = pSess->tlsext_ticklen;
#endif
        *ppTicket   = (ubyte *) pTicket;
        *pTicketLen = ticketLength;
    }

    status = OK;

exit:
    return status;
}

#endif
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

static size_t getRandom(const SSL *ssl, unsigned char *out, size_t outlen, ubyte isClient)
{
    size_t size = 0;
    sbyte4 status = 0;
    ubyte random[SSL_RANDOMSIZE] = {0};

    if (NULL == ssl)
        goto exit;

    /* If outlen is 0, these functions return the maximum number of bytes they would copy
     * i.e, the length of the underlying field.
     */
    size = SSL_RANDOMSIZE;

    if (0 == outlen)
        goto exit;

    if (outlen > SSL_RANDOMSIZE)
        outlen = SSL_RANDOMSIZE;

    if (isClient)
    {
        status = NSSL_CHK_CALL(sslIoctl, ssl->instance, SSL_GET_CLIENT_RANDOM, random);
    }
    else
    {
        status = NSSL_CHK_CALL(sslIoctl, ssl->instance, SSL_GET_SERVER_RANDOM, random);
    }

    if (OK > status)
    {
        size = 0;
        goto exit;
    }

    /* copy only outlen bytes */
    memcpy(out, random, outlen);
    size = outlen;

exit:
    return size;
}

size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    return getRandom(ssl, out, outlen, 1/* isClient */);
}

size_t SSL_get_server_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    return getRandom(ssl, out, outlen, 0/* server */);
}


/* From OpenSSL Documentation:
 * Note that the SSL_SESSION_get_protocol_version() function does not perform a null check on the provided session s pointer.
 */
int SSL_SESSION_get_protocol_version(const SSL_SESSION *pSession)
{
    return pSession->ssl_version;
}


int SSL_get_security_level(const SSL *s)
{
    /* Not applicable */
    return 0;
}

void SSL_set_security_level(SSL *s, int level)
{
    /* Not applicable */
    return;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

size_t SSL_client_hello_get0_ciphers(SSL *s, const unsigned char **out)
{
    if ((NULL == s) || (NULL == out) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    *out = s->client_hello_data->ciphers;
    return s->client_hello_data->ciphers_len;
}

size_t SSL_client_hello_get0_random(SSL *s, const unsigned char **out)
{
    if ((NULL == s) || (NULL == out) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    *out = s->client_hello_data->random;
    return s->client_hello_data->random_len;
}

size_t SSL_client_hello_get0_compression_methods(SSL *s, const unsigned char **out)
{
    if ((NULL == s) || (NULL == out) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    *out = s->client_hello_data->compression_methods;
    return s->client_hello_data->compression_methods_len;
}

size_t SSL_client_hello_get0_session_id(SSL *s, const unsigned char **out)
{
    if ((NULL == s) || (NULL == out) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    *out = s->client_hello_data->session_id;
    return s->client_hello_data->session_id_len;
}

int SSL_client_hello_get0_ext(SSL *s, unsigned int type, const unsigned char **out,
                              size_t *outlen)
{
    unsigned char *exts;
    int exts_len;
    int len;
    int ext_type;
    int ext_len;

    if ( (NULL == s) || (NULL == out) || (NULL == outlen) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    exts = s->client_hello_data->extensions;
    exts_len = s->client_hello_data->extensions_len;

    len = 0;

    while (len < exts_len)
    {
        ext_type = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += 2;

        ext_len = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += 2;
        if (ext_type == type)
        {
            *out = exts;
            *outlen = ext_len;
            return 1;
        }

        exts += ext_len;

        len += 4 + ext_len;
    }

    return 0;
}

unsigned int SSL_client_hello_get0_legacy_version(SSL *s)
{
    if ((NULL == s) || (NULL == s->client_hello_data))
    {
        return 0;
    }

    return s->client_hello_data->legacy_version;
}

int SSL_client_hello_get1_extensions_present(SSL *s, int **out, size_t *outlen)
{
    int *ext_names;
    int ext_names_len;
    unsigned char *exts;
    int exts_len;
    int count;
    int len;
    int ext_type;
    int ext_len;

    if ( (NULL == s) || (NULL == out) || (NULL == outlen) || (NULL == s->client_hello_data))
        return 0;

    exts = s->client_hello_data->extensions;
    exts_len = s->client_hello_data->extensions_len;

    count = 0;
    len = 0;

    while (len < exts_len)
    {
        ext_type = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += 2;

        ext_len = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += (2 + ext_len);

        len += 4 + ext_len;
        count++; 
    }

    if (len != exts_len) /* jic */
        return 0;

    ext_names = OPENSSL_malloc(count * sizeof(int));
    if (NULL == ext_names)
        return 0;

    exts = s->client_hello_data->extensions;
    ext_names_len = len = 0;
    while (len < exts_len)
    {
        ext_type = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += 2;
        ext_names[ext_names_len] = ext_type;

        ext_len = ((ubyte2)exts[0] << 8) | (exts[1]);
        exts += (2 + ext_len);

        len += 4 + ext_len;
        ext_names_len++; 
    }

    *out = ext_names;
    *outlen = ext_names_len;

    return 1;
}

int SSL_client_hello_isv2(SSL *s)
{
    /* we do not support SSLv2 format */
    return 0; 
}

int SSL_CTX_add_custom_ext(SSL_CTX *pCtx, unsigned int ext_type,
                           unsigned int context,
                           SSL_custom_ext_add_cb_ex add_cb,
                           SSL_custom_ext_free_cb_ex free_cb,
                           void *add_arg,
                           SSL_custom_ext_parse_cb_ex parse_cb, void *parse_arg)
{
    if (NULL == pCtx)
        return 0;

    return 0;/* not supported */
}

/*
 * Create a new SSL_SESSION and duplicate the contents of |src| into it. If
 * ticket == 0 then no ticket information is duplicated, otherwise it is.
 */
SSL_SESSION *ssl_session_dup(SSL_SESSION *src, int ticket)
{
    SSL_SESSION *dest;
    ubyte4 size;

    if (src == NULL)
        return NULL;

    dest = OSSL_MALLOC(sizeof(*src));
    if (dest == NULL) {
        goto err;
    }
    memcpy(dest, src, sizeof(*dest));

    /*
     * Set the various pointers to NULL so that we can call SSL_SESSION_free in
     * the case of an error whilst halfway through constructing dest
     */
    dest->psk_identity_hint = NULL;
    dest->psk_identity = NULL;

    dest->ext.hostname = NULL;
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    dest->ext.ecpointformats = NULL;
    dest->ext.supportedgroups = NULL;
#endif
    dest->ext.tick = NULL;
    dest->ext.alpn_selected = NULL;

#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    dest->ciphers = NULL;
#endif
    dest->srp_username = NULL;
    dest->peer_chain = NULL;
    dest->peer = NULL;

    dest->ticket_appdata = NULL;
    memset(&dest->ex_data, 0, sizeof(dest->ex_data));

    /*  don't copy the prev and next pointers */
    dest->prev = NULL;
    dest->next = NULL;
    dest->references = 1;

    dest->lock = CRYPTO_THREAD_lock_new();
    if (dest->lock == NULL)
        goto err;

    dest->ssl_version = src->ssl_version;
    dest->master_key_length = src->master_key_length;

    memcpy(dest->early_secret, src->early_secret, EVP_MAX_MD_SIZE);

    if (src->master_key_length != 0)
    {
        memcpy(dest->master_key, src->master_key, src->master_key_length);
    }

    dest->session_id_length = src->session_id_length;
    if (src->session_id_length != 0)
    {
        memcpy(dest->session_id, src->session_id, src->session_id_length);
    }

    dest->sid_ctx_length = src->sid_ctx_length;
    if (src->sid_ctx_length != 0)
    {
        memcpy(dest->sid_ctx, src->sid_ctx, src->sid_ctx_length);
    }

    if (src->psk_identity_hint)
    {
        dest->psk_identity_hint = OPENSSL_strdup(src->psk_identity_hint);
        if (dest->psk_identity_hint == NULL)
        {
            goto err;
        }
    }

    if (src->psk_identity)
    {
        dest->psk_identity = OPENSSL_strdup(src->psk_identity);
        if (dest->psk_identity == NULL)
        {
            goto err;
        }
    }

    dest->not_resumable = src->not_resumable;

    if (src->peer != NULL)
    {
        if (!X509_up_ref(src->peer))
            goto err;
        dest->peer = src->peer;
    }

#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    dest->peer_type = src->peer_type;
#endif

    if (src->peer_chain != NULL)
    {
        dest->peer_chain = X509_chain_up_ref(src->peer_chain);
        if (dest->peer_chain == NULL)
            goto err;
    }

    dest->verify_result = src->verify_result;
    dest->timeout       = src->timeout;
    dest->time          = src->time;
    dest->compress_meth = src->compress_meth;
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    dest->cipher        = src->cipher;
#endif
    dest->cipher_id     = src->cipher_id;

#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    if (src->ciphers != NULL)
    {
        dest->ciphers = sk_SSL_CIPHER_dup(src->ciphers);
        if (dest->ciphers == NULL)
            goto err;
    }
#endif

#if 0
    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, dest, &dest->ex_data))
        goto err;

    if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL_SESSION,
                            &dest->ex_data, &src->ex_data))
    {
        goto err;
    }
#endif

    if (src->ext.hostname)
    {
        size = strlen(src->ext.hostname);
        dest->ext.hostname = OSSL_MALLOC(size + 1);
        if (dest->ext.hostname == NULL)
        {
            goto err;
        }
        memcpy(dest->ext.hostname, src->ext.hostname, size);
        dest->ext.hostname[size] = '\0';
    }

#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    dest->ext.supportedgroups_len = src->ext.supportedgroups_len;
    if (src->ext.ecpointformats)
    {
        dest->ext.ecpointformats = OPENSSL_memdup(src->ext.ecpointformats,
                                                  src->ext.ecpointformats_len);
        if (dest->ext.ecpointformats == NULL)
        {
            goto err;
        }
    }

    dest->ext.supportedgroups_len = src->ext.supportedgroups_len;
    if (src->ext.supportedgroups)
    {
        dest->ext.supportedgroups = OPENSSL_memdup(src->ext.supportedgroups,
                                                   src->ext.supportedgroups_len
                                                   * sizeof(*src->ext.supportedgroups));
        if (dest->ext.supportedgroups == NULL)
        {
            goto err;
        }
    }
#endif

    if (ticket != 0 && src->ext.tick != NULL)
    {
        dest->ext.tick = OSSL_MALLOC(src->ext.ticklen);
        if (dest->ext.tick == NULL)
        {
            goto err;
        }
        memcpy(dest->ext.tick, src->ext.tick, src->ext.ticklen);

        dest->ext.ticklen            = src->ext.ticklen;
        dest->ext.tick_lifetime_hint = src->ext.tick_lifetime_hint;
        dest->ext.tick_age_add       = src->ext.tick_age_add;
        dest->ext.max_early_data     = src->ext.max_early_data;
    }
    else
    {
        dest->ext.tick_lifetime_hint = 0;
        dest->ext.ticklen            = 0;
        dest->ext.tick_age_add       = 0;
        dest->ext.max_early_data     = 0;
    }

    if (src->ext.alpn_selected != NULL)
    {
        dest->ext.alpn_selected = OPENSSL_memdup(src->ext.alpn_selected,
                                                 src->ext.alpn_selected_len);
        if (dest->ext.alpn_selected == NULL)
            goto err;
    }

    dest->ext.max_fragment_len_mode = src->ext.max_fragment_len_mode;

    if (src->srp_username)
    {
        dest->srp_username = OPENSSL_strdup(src->srp_username);
        if (dest->srp_username == NULL)
        {
            goto err;
        }
    }

    if (src->ticket_appdata != NULL)
    {
        dest->ticket_appdata = OPENSSL_memdup(src->ticket_appdata, src->ticket_appdata_len);
        if (dest->ticket_appdata == NULL)
            goto err;

        dest->ticket_appdata_len = src->ticket_appdata_len;
    }

    dest->flags = src->flags;

    return dest;

err:
    SSL_SESSION_free(dest);
    return NULL;
}

SSL_SESSION *SSL_SESSION_dup(SSL_SESSION *src)
{
    return ssl_session_dup(src, 1);
}

size_t DTLS_get_data_mtu(const SSL *s)
{
    return 0; /* Not supported */
}

int SSL_get_peer_signature_type_nid(const SSL *pSsl, int *pnid)
{
    return 0; /* Not supported */
}

int SSL_free_buffers(SSL *ssl)
{
    return 0; /* Not supported */
}

int SSL_alloc_buffers(SSL *ssl)
{
    return 0; /* Not supported */
}

int SSL_bytes_to_cipher_list(SSL *pSsl, const unsigned char *bytes, size_t len,
                             int isv2format, STACK_OF(SSL_CIPHER) **sk,
                             STACK_OF(SSL_CIPHER) **scsvs)
{
    return 0; /* not supported */
}


int SSL_CTX_use_serverinfo_ex(SSL_CTX *ctx, unsigned int version,
                              const unsigned char *serverinfo,
                              size_t serverinfo_length)
{
    return 0; /* not supported */
}


int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                             STACK_OF(X509) *chain, int override)
{
    return 0; /* not supported */
}

int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
                         STACK_OF(X509) *chain, int override)
{
   return 0; /* Not supported */
}

/* SSL_SESSION_set_protocol_version() sets the protocol version associated with
 * the SSL_SESSION object s to the value version. This value should be a version
 * constant such as TLS1_3_VERSION etc.
 */

int SSL_SESSION_set_protocol_version(SSL_SESSION *pSession, int version)
{
    if (NULL == pSession)
    {
        return 0;
    }

    pSession->ssl_version = version;
    return 1;
}

/* The max_early_data parameter specifies the maximum amount of early
 * data in bytes that is permitted to be sent on a single connection.
 *
 * function return 1 for success or 0 for failure.
 */

int SSL_SESSION_set_max_early_data(SSL_SESSION *pSession, uint32_t max_early_data)
{
    if (NULL == pSession)
        return 0;

    pSession->ext.max_early_data = max_early_data;

    return 1;
}

/* SSL_SESSION_set_cipher() can be used to set the ciphersuite associated with the SSL_SESSION s to cipher.
 *  returns 1 on success or 0 on failure.
 */

int SSL_SESSION_set_cipher(SSL_SESSION *pSession, const SSL_CIPHER *pCipher)
{
    if (NULL == pSession )
        return 0;
    /* Not supported */
    return 0;
#if 0
    pSession->cipher = pCipher;
    return 1;
#endif
}

/* SSL_SESSION_set1_ticket_appdata() sets the application data specified by data and len into
 * ss which is then placed into any generated session tickets. It can be called at any time
 * before a session ticket is created to update the data placed into the session ticket.
 * However, given that sessions and tickets are created by the handshake, the gen_cb is
 * provided to notify the application that a session ticket is about to be generated.
 *
 * returns 1 on success or 0 on error.
 */

int SSL_SESSION_set1_ticket_appdata(SSL_SESSION *pSession, const void *pData, size_t len)
{
    if ((NULL == pSession) || (NULL == pData))
        return 0;

    OPENSSL_free(pSession->ticket_appdata);
    pSession->ticket_appdata_len = 0;

    if ((pData == NULL) || (len == 0))
    {
        pSession->ticket_appdata = NULL;
        return 1;
    }

    pSession->ticket_appdata = OPENSSL_memdup(pData, len);

    if (NULL != pSession->ticket_appdata)
    {
        pSession->ticket_appdata_len = len;
        return 1;
    }
    return 0;
}

/* SSL_SESSION_set1_master_key() sets the master key value associated with
 * the SSL_SESSION sess. For example, this could be used to set up a session based
 * PSK (see SSL_CTX_set_psk_use_session_callback(3)). The master key of length len
 * should be provided at in. The supplied master key is copied by the function,
 * so the caller is responsible for freeing and cleaning any memory associated
 * with in. The caller must ensure that the length of the key is suitable for
 * the ciphersuite associated with the SSL_SESSION.
 * returns 1 on success or 0 on error.
 */

int SSL_SESSION_set1_master_key(SSL_SESSION *pSession, const unsigned char *in,
                                size_t len)
{
    if (NULL == pSession)
        return 0;
    if (len > sizeof(pSession->master_key))
        return 0;

    memcpy(pSession->master_key, in, len);
    pSession->master_key_length = len;
    return 1;
}

/* sets the SNI value for the hostname to a copy of the string provided
 * in hostname.
 *
 * returns 1 on success or 0 on error.
 */

int SSL_SESSION_set1_hostname(SSL_SESSION *pSession, const char *pHostname)
{
    ubyte4 size;
    if (NULL == pSession)
        return 0;

    if (NULL != pSession->ext.hostname)
        OSSL_FREE(pSession->ext.hostname);

    if (NULL == pHostname)
    {
        pSession->ext.hostname = NULL;
        return 1;
    }

    size = strlen(pHostname);
    pSession->ext.hostname = OSSL_MALLOC(size + 1);

    if (NULL == pSession->ext.hostname)
        return 0;

    memcpy(pSession->ext.hostname, pHostname, size);
    pSession->ext.hostname[size] = '\0';
    return 1;
}

/* SSL_SESSION_set1_alpn_selected() sets the ALPN protocol for this
 * session to the value in alpn which should be of length len bytes.
 * A copy of the input value is made, and the caller retains ownership of
 * the memory pointed to by alpn.
 * returns 1 on success or 0 on error.
 */

int SSL_SESSION_set1_alpn_selected(SSL_SESSION *pSession, const unsigned char *pAlpn,
                                   size_t len)
{
    if (NULL == pSession)
        return 0;

    OPENSSL_free(pSession->ext.alpn_selected);
    if ((NULL == pAlpn) || (0 == len))
    {
        pSession->ext.alpn_selected = NULL;
        pSession->ext.alpn_selected_len = 0;
        return 1;
    }

    pSession->ext.alpn_selected = OPENSSL_memdup(pAlpn, len);
    if (NULL == pSession->ext.alpn_selected)
    {
        pSession->ext.alpn_selected_len = 0;
        return 0;
    }

    pSession->ext.alpn_selected_len = len;
    return 1;
}

/* determines whether an SSL_SESSION object can be used to resume a session or not.
 * Returns 1 if it can or 0 if not. Note that attempting to resume with a non-resumable
 * session will result in a full handshake
 * @return   function returns 1 if the session is resumable or 0 otherwise.
 */

int SSL_SESSION_is_resumable(const SSL_SESSION *pSession)
{
    if (NULL == pSession)
        return 0;

    /* Not supported */
    return 0;
#if 0
    /*
     * In the case of EAP-FAST, we can have a pre-shared "ticket" without a
     * session ID.
     */
    return !pSession->not_resumable
           && (pSession->session_id_length > 0 || pSession->ext.ticklen > 0);
#endif
}

/* SSL_SESSION_get_max_fragment_length() gets the maximum fragment
 * length negotiated in session.
 * it returns the maximum fragment length negotiated in session or
 * TLSEXT_max_fragment_length_DISABLED.
 */

uint8_t SSL_SESSION_get_max_fragment_length(const SSL_SESSION *pSession)
{
    if (NULL == pSession)
    {
        return TLSEXT_max_fragment_length_DISABLED;
    }

    return pSession->ext.max_fragment_len_mode;
}

/* SSL_SESSION_get_max_early_data() can be used to determine
 * if a session established with a server can be used to send early data. If the session
 * cannot be used then this function will return 0. Otherwise it will return the
 * maximum number of early data bytes that can be sent.
 * it returns maximum number of early data bytes that can be sent or return 0.
 */

uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *pSession)
{
    if (NULL == pSession)
        return 0;

    return pSession->ext.max_early_data;
}

/* SSL_SESSION_get0_ticket_appdata() assigns data to the session ticket application
 * data and assigns len to the length of the session ticket application data from pSession.
 * returns 0
 */

int SSL_SESSION_get0_ticket_appdata(SSL_SESSION *pSession, void **pData, size_t *pLen)
{
    if ((NULL == pSession) || (NULL == *pData) || (NULL == pLen))
    {
        return 0;
    }

    *pData = pSession->ticket_appdata;
    *pLen  = pSession->ticket_appdata_len;
    return 1;
}

/* SSL_SESSION_get0_alpn_selected() retrieves the selected ALPN protocol
 * for this session and its associated length in bytes. The returned value of *pAlpn is a
 * pointer to memory maintained within pSession and should not be free'd.
 * returns none
 */

void SSL_SESSION_get0_alpn_selected(const SSL_SESSION *pSession,
                                    const unsigned char **pAlpn,
                                    size_t *pLen)
{
    if ((NULL == pSession) || (NULL == *pAlpn) || (NULL == pLen))
    {
        return;
    }

    *pAlpn = pSession->ext.alpn_selected;
    *pLen  = pSession->ext.alpn_selected_len;
}

/* A server may choose to ignore early data that has been sent to it.
 * Once the connection has been completed you can determine whether the server
 * accepted or rejected the early data by calling SSL_get_early_data_status().
 *
 * SSL_get_early_data_status() returns SSL_EARLY_DATA_ACCEPTED
 * if early data was accepted by the server, SSL_EARLY_DATA_REJECTED if early data was
 * rejected by the server, or SSL_EARLY_DATA_NOT_SENT if no early data was sent.
 */

int SSL_get_early_data_status(const SSL *pSsl)
{
    sbyte4 earlyDataStatus = 0;

    if (NULL == pSsl)
        return SSL_EARLY_DATA_NOT_SENT;

    if (pSsl->instance > 0)
    {
        if (OK == NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_GET_EARLY_DATA_STATUS, &earlyDataStatus))
        {
           if (1 == earlyDataStatus)
           {
                return SSL_EARLY_DATA_ACCEPTED;
           }
           else
           {
                return SSL_EARLY_DATA_REJECTED;
           }
        }
    }

    return SSL_EARLY_DATA_NOT_SENT;
}

/*
 * SSL_get_key_update_type() can be used to determine whether a key update
 * operation has been scheduled but not yet performed. The type of the pending
 * key update operation will be returned if there is one, or SSL_KEY_UPDATE_NONE
 * otherwise. If the updatetype parameter is set to SSL_KEY_UPDATE_NOT_REQUESTED
 * then the sending keys for this connection will be updated and the peer will
 * be informed of the change. If the updatetype parameter is set to
 * SSL_KEY_UPDATE_REQUESTED then the sending keys for this connection will be
 * updated and the peer will be informed of the change along with a request
 * for the peer to additionally update its sending keys. It is an error if
 * updatetype is set to SSL_KEY_UPDATE_NONE.
 * The type of the pending key update operation will be returned if there
 *  is one, or SSL_KEY_UPDATE_NONE otherwise.
 */

int SSL_get_key_update_type(const SSL *pSsl)
{
    sbyte4 keyUpdateType = 0;

    if (NULL == pSsl)
        return SSL_KEY_UPDATE_NONE;

    if (OK == NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_GET_KEY_UPDATE_DATA_TYPE, &keyUpdateType))
    {
        /* In NanoSSL, this is stored as ubyte */
        if (255 == keyUpdateType)
        {
            return SSL_KEY_UPDATE_NONE;
        }
        else
        {
            return keyUpdateType;
        }
    }

    return SSL_KEY_UPDATE_NONE;
}

/* SSL_get_max_early_data() function can be used to obtain the current
 * maximum early data settings for the SSL object. return the
 * maximum number of early data bytes that may be sent.
 */

uint32_t SSL_get_max_early_data(const SSL *pSsl)
{
    ubyte4  max_early_data = 0;

    if (NULL == pSsl)
        return 0;

    if (pSsl->instance > 0)
    {
        if (OK == NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_GET_MAX_EARLY_DATA, &max_early_data))
        {
            return max_early_data; /* return max early data */
        }
    }

    /* return 0 on failure */
    return 0;
}

/* The max_early_data parameter specifies the maximum amount of early
 * data in bytes that is permitted to be sent on a single connection.
 * function return 1 for success or 0 for failure.
 */

int SSL_set_max_early_data(SSL *pSsl, uint32_t max_early_data)
{
    if (NULL == pSsl)
        return 0;

    pSsl->orig_s.max_early_data = max_early_data;

    if (pSsl->instance > 0)
    {
        if (OK > NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_SET_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)max_early_data)))
        {
            return 0;
        }
    }

    /* return 1 for success or 0 for failure */
    return 1;
}

/* The max_early_data parameter specifies the maximum amount of early
 * data in bytes that is permitted to be sent on a single connection.
 * function return 1 for success or 0 for failure.
 */

int SSL_CTX_set_max_early_data(SSL_CTX *pCtx, uint32_t max_early_data)
{
    if (NULL == pCtx)
        return 0;

    pCtx->orig_ssl_ctx.max_early_data = max_early_data;

    return 1;
}

/* the SSL_CTX_get_max_early_data() function can be used to obtain the
 * current maximum early data settings for the SSL_CTX objects respectively.
 * return the maximum number of early data bytes that may be sent.
 */

uint32_t SSL_CTX_get_max_early_data(const SSL_CTX *pCtx)
{
    if (NULL == pCtx)
        return 0;

    return pCtx->orig_ssl_ctx.max_early_data;
}

/* this function sets the recv_max_early_data setting. If the server rejects
 * the early data sent by a client then it will skip over the data that is sent.
 * The maximum amount of received early data that is skipped is controlled
 * by the recv_max_early_data setting. If a client sends more than this then the
 * connection will abort.
 * The recv_max_early_data value also has an impact on early data that is accepted.
 * The amount of data that is accepted will always be the lower of the max_early_data for
 * the session and the recv_max_early_data setting for the server.If a client sends
 * more data than this then the connection will abort. The configured value for
 * max_early_data on a server may change over time as required.However clients may have
 * tickets containing the previously configured max_early_data value. The recv_max_early_data
 * should always be equal to or higher than any recently configured max_early_data value
 * in order to avoid aborted connections. The recv_max_early_data should never be set
 * to less than the current configured max_early_data value.
 * return 1 for success or 0 for failure.
 */

int SSL_CTX_set_recv_max_early_data(SSL_CTX *pCtx, uint32_t recv_max_early_data)
{
    if (NULL == pCtx)
        return 0;

    pCtx->orig_ssl_ctx.recv_max_early_data = recv_max_early_data;

    return 1;
}

/* the SSL_CTX_get_recv_max_early_data() function can be used to obtain the
 * current receive maximum early data settings for the SSL_CTX objects respectively.
 * return the maximum number of early data bytes that may be sent.
*/

uint32_t SSL_CTX_get_recv_max_early_data(const SSL_CTX *pCtx)
{
    if (NULL == pCtx)
        return 0;

    return pCtx->orig_ssl_ctx.recv_max_early_data;
}

/*
 * this function sets the recv_max_early_data setting. If the server rejects
 * the early data sent by a client then it will skip over the data that is sent.
 * The maximum amount of received early data that is skipped is controlled
 * by the recv_max_early_data setting. If a client sends more than this then the
 * connection will abort. The recv_max_early_data value also has an impact on
 * early data that is accepted. The amount of data that is accepted will always
 * be the lower of the max_early_data for the session and the recv_max_early_data
 * setting for the server.If a client sends more data than this then the
 * connection will abort.The configured value for max_early_data on a server may
 * change over time as required. However clients may have tickets containing the
 * previously configured max_early_data value. The recv_max_early_data should
 * always be equal to or higher than any recently configured max_early_data
 * value in order to avoid aborted connections. The recv_max_early_data should
 * never be set to less than the current configured max_early_data value.
 * return 1 for success or 0 for failure.
 */

int SSL_set_recv_max_early_data(SSL *pSsl, uint32_t recv_max_early_data)
{
    MSTATUS status = 0;

    if (NULL == pSsl)
        goto exit;

    pSsl->orig_s.recv_max_early_data = recv_max_early_data;

    if (OK == NSSL_CHK_CALL(sslSettingsIoctl, SSL_SETTINGS_SET_RECV_MAX_EARLY_DATA, (void*)((OSSL_UINT_PTR)recv_max_early_data)))
    {
        status = 1;
    }
exit:
    /* return 1 for success or 0 for failure */
    return status;
}

/* SSL_get_recv_max_early_data() function can be used to obtain the current receive
 * maximum early data settings for the SSL object.
 * return the maximum number of early data bytes that may be sent.
 */

uint32_t SSL_get_recv_max_early_data(const SSL *pSsl)
{
    ubyte4 recv_max_early_data = 0;
    MSTATUS status = 0;

    if (NULL == pSsl)
        goto exit;

    if (OK == NSSL_CHK_CALL(sslSettingsIoctl, SSL_SETTINGS_GET_RECV_MAX_EARLY_DATA, &recv_max_early_data))
    {
        return recv_max_early_data;
    }

exit:
    return status;
}

/* SSL_set_num_tickets() function sets the number of TLSv1.3 session tickets that
 * will be sent to the client after a full handshake. Set the desired value (which could be 0)
 * in the num_tickets argument. Typically these functions should be called before the
 * start of the handshake.
 * it return 1 on success or 0 on failure.
 * Note : In case of error, openssl connectior will send 0 and openssl doesnt check
 * for error case. (pointer validation is missing in openssl)
 */

int SSL_set_num_tickets(SSL *pSsl, size_t numTickets)
{
    MSTATUS status = 1;

    if (NULL == pSsl)
    {
        status = 0;
        goto exit;
    }

    if (pSsl->instance > 0)
    {
        if (OK > NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_SET_NUM_TICKETS, (void*)((OSSL_UINT_PTR)numTickets)))
        {
            status = 0;
            goto exit;
        }
    }

    pSsl->orig_s.num_tickets = numTickets;

exit:
    /* return 1 for success or 0 for failure */
    return status;
}

/* SSL_get_num_tickets() return the number of tickets set by a previous
 * call to SSL_set_num_tickets(), or 2 if no such call has been made.
 * It return the number of tickets that have been previously set.
 * Note : In case of error openssl connectior will send 0 instead of 2,
 * openssl doesnt check for error case. (pointer validation is missing
 * in openssl)
 */

size_t SSL_get_num_tickets(const SSL *pSsl)
{
    ubyte4 numTickets = 0;
    MSTATUS status = 0;

    if (NULL == pSsl)
        goto exit;

    if (pSsl->instance > 0)
    {
        if (OK == NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_GET_NUM_TICKETS, &numTickets))
        {
            return numTickets;
        }
    }

exit:
    return status;
}

/* SSL_CTX_set_num_tickets() function set the number of TLSv1.3 session tickets that
 * will be sent to the client after a full handshake. Set the desired value (which could be 0)
 * in the num_tickets argument. Typically these functions should be called before the
 * start of the handshake.
 * return 1 on success or 0 on failure.
 * Note : In case of error, openssl connectior will send 0 and openssl doesnt check
 * for error case. (pointer validation is missing in openssl)
 */

int SSL_CTX_set_num_tickets(SSL_CTX *pCtx, size_t numTickets)
{
    if (NULL == pCtx)
        return 0;

    pCtx->orig_ssl_ctx.num_tickets = numTickets;

    return 1;
}

/* SSL_CTX_get_num_tickets() return the number of tickets set by a previous call
 * to SSL_CTX_get_num_tickets(), or 2 if no such call has been made.
 * It return the number of tickets that have been previously set.
 * Note : In case of error openssl connectior will send 0 instead of 2,
 * openssl doesnt check for error case. (pointer validation is missing
 * in openssl)
 */

size_t SSL_CTX_get_num_tickets(const SSL_CTX *pCtx)
{
    if (NULL == pCtx)
        return 0;

    return pCtx->orig_ssl_ctx.num_tickets;
}


/* SSL_CTX_set_post_handshake_auth() enable the Post-Handshake
 * Authentication extension to be added to the ClientHello such that
 * post-handshake authentication can be requested by the server.
 * If postHandshakeAuth is 0 then the extension is not sent, otherwise it is.
 * returns  none
 */

void SSL_CTX_set_post_handshake_auth(SSL_CTX *pCtx, int postHandshakeAuth)
{
    if (NULL == pCtx)
        return;

    pCtx->orig_ssl_ctx.pha_enabled = postHandshakeAuth;
}

/* SSL_set_post_handshake_auth() enable the Post-Handshake Authentication
 * extension to be added to the ClientHello such that
 * post-handshake authentication can be requested by the server.
 * If postHandshakeAuth is 0 then the extension is not sent, otherwise it is.
 * returns   none
 */

void SSL_set_post_handshake_auth(SSL *pSsl, int postHandshakeAuth)
{
    ubyte4 sslFlags = 0;

    if (NULL == pSsl)
        return;

    if ((pSsl->instance > 0) && (postHandshakeAuth > 0))
    {
        NSSL_CHK_CALL(getSessionFlags, pSsl->instance, &sslFlags);

      /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
        NSSL_CHK_CALL(setSessionFlags, pSsl->instance, (sslFlags | SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH));
    }

    pSsl->orig_s.pha_enabled = postHandshakeAuth;
}

/* psk_get_session_cb is a server side callback; This callback gives the identity to the application
 * and expects back a SSL_SESSION with matching identity; This will be called when Server receives
 * Client Hello with a list of PSK identities that it wants to use
 */
static sbyte4 OSSL_psk_get_session_callback(sbyte4 connectionInstance, ubyte *pPskIdentity,
                                              ubyte4 pskIdentityLength, ubyte **ppPsk, ubyte4 *pPskLen,
                                              intBoolean *pFreeMemory)
{
    MSTATUS status = 0;
    SSL *pSSL;
    SSL_SESSION *pSess = NULL;
    int copy = 0;
    tls13PSK *pTempPSK = NULL;

    pSSL = (SSL*) findSSLFromInstance(connectionInstance);

    if ((NULL == pSSL) ||  ( NULL == pPskIdentity))
    {
         status = ERR_NULL_POINTER;
         goto exit;
    }

    if (pSSL->ssl_ctx->get_session_cb != NULL)
    {
        pSess = pSSL->ssl_ctx->get_session_cb(pSSL, pPskIdentity, pskIdentityLength, &copy);

        /* Application defined callback returns 0 in case of failure */
        if (NULL == pSess)
        {
            *ppPsk = NULL;
            *pPskLen = 0;
            goto exit;
        }

        pTempPSK = OSSL_MALLOC(sizeof(tls13PSK));
        if (NULL == pTempPSK)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        memset(pTempPSK, 0x00, sizeof(tls13PSK));

        pTempPSK->pskTLS13Identity = OSSL_MALLOC(pskIdentityLength);
        if (NULL == pTempPSK->pskTLS13Identity)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* Write the Identity */
        memcpy((void *)pTempPSK->pskTLS13Identity, pPskIdentity, pskIdentityLength);

        pTempPSK->pskTLS13IdentityLength = pskIdentityLength;
        pTempPSK->pSelectedTlsVersion    = pSess->ssl_version;
        pTempPSK->pskTLS13LifetimeHint   = pSess->ext.tick_lifetime_hint;
        pTempPSK->pskTLS13AgeAdd         = pSess->ext.tick_age_add;
        pTempPSK->selectedCipherSuiteId  = (ubyte2) pSess->cipher_id;
        pTempPSK->isPSKavailable         = 1;
        pTempPSK->isExternal             = 0;
        pTempPSK->maxEarlyDataSize       = pSess->ext.max_early_data;

        if (pSess->master_key_length > 0)
        {
            memcpy((void *)pTempPSK->pskTLS13, pSess->master_key, pSess->master_key_length);
            pTempPSK->pskTLS13Length = (ubyte2) pSess->master_key_length;
        }

        status = OSSL_DATETIME_getDateTime(pSess->time, &(pTempPSK->startTime));
        if (OK != status)
        {
            goto exit;
        }

        switch(pSess->cipher_id)
        {
            /* 0x1301 TLS_AES_128_GCM_SHA256 */
            case 0x1301:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1302 TLS_AES_256_GCM_SHA384 */
            case 0x1302:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA384;
                break;
            /* 0x1303 TLS_CHACHA20_POLY1305_SHA256 */
            case 0x1303:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1304 TLS_AES_128_CCM_SHA256 */
            case 0x1304:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1305 TLS_AES_128_CCM_8_SHA256 */
            case 0x1305:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            default :
                pTempPSK->hashAlgo = 0;
                break;
        }

        status = NSSL_CHK_CALL(serializePsk, (OSSL_tls13PSK*)pTempPSK, ppPsk, pPskLen);

        *pFreeMemory = 1;
    }
exit:
    if (NULL != pSess)
    {
        SSL_SESSION_free(pSess);
    }

    if (NULL != pTempPSK)
    {
        if (NULL != pTempPSK->pskTLS13Identity)
        {
            OSSL_FREE(pTempPSK->pskTLS13Identity);
        }
            OSSL_FREE(pTempPSK);
    }
    return status;
}



/* psk_find_session_cb is a server side callback; This callback gives the identity to the application
 * and expects back a SSL_SESSION with matching identity; This will be called when Server receives
 * Client Hello with a list of PSK identities that it wants to use
 */
static sbyte4 OSSL_psk_find_session_callback(sbyte4 connectionInstance, ubyte *pPskIdentity,
                                              ubyte4 pskIdentityLength, ubyte **ppPsk, ubyte4 *pPskLen,
                                              intBoolean *pFreeMemory)
{
    MSTATUS status = 0;
    SSL *pSSL;
    SSL_SESSION *pSess = NULL;
    tls13PSK *pTempPSK = NULL;

    pSSL = (SSL*) findSSLFromInstance(connectionInstance);

    if ((NULL == pSSL) ||  ( NULL == pPskIdentity) || (NULL == pFreeMemory))
    {
         status = ERR_NULL_POINTER;
         goto exit;
    }

    *pFreeMemory = 0;

    if (pSSL->orig_s.psk_find_session_cb)
    {
        status = pSSL->orig_s.psk_find_session_cb(pSSL, pPskIdentity, pskIdentityLength, &pSess);

        /* Application defined callback returns 0 in case of failure */
        if ((NULL == pSess) || (0 == status))
        {
            *ppPsk = NULL;
            *pPskLen = 0;
            goto exit;
        }

        pTempPSK = OSSL_MALLOC(sizeof(tls13PSK));
        if (NULL == pTempPSK)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        memset(pTempPSK, 0x00, sizeof(tls13PSK));

        pTempPSK->pskTLS13Identity = OSSL_MALLOC(pskIdentityLength);
        if (NULL == pTempPSK->pskTLS13Identity)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* Write the Identity */
        memcpy((void *)pTempPSK->pskTLS13Identity, pPskIdentity, pskIdentityLength);

        pTempPSK->pskTLS13IdentityLength = pskIdentityLength;
        pTempPSK->pSelectedTlsVersion    = pSess->ssl_version;
        pTempPSK->pskTLS13LifetimeHint   = pSess->ext.tick_lifetime_hint;
        pTempPSK->pskTLS13AgeAdd         = pSess->ext.tick_age_add;
        pTempPSK->selectedCipherSuiteId  = (ubyte2) pSess->cipher_id;
        pTempPSK->isPSKavailable         = 1;
        pTempPSK->isExternal             = 0;
        pTempPSK->maxEarlyDataSize       = pSess->ext.max_early_data;

        if (pSess->master_key_length > 0)
        {
            memcpy((void *)pTempPSK->pskTLS13, pSess->master_key, pSess->master_key_length);
            pTempPSK->pskTLS13Length = (ubyte2) pSess->master_key_length;
        }

        status = OSSL_DATETIME_getDateTime(pSess->time, &(pTempPSK->startTime));
        if (OK != status)
        {
            goto exit;
        }

        switch(pSess->cipher_id)
        {
            /* 0x1301 TLS_AES_128_GCM_SHA256 */
            case 0x1301:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1302 TLS_AES_256_GCM_SHA384 */
            case 0x1302:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA384;
                break;
            /* 0x1303 TLS_CHACHA20_POLY1305_SHA256 */
            case 0x1303:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1304 TLS_AES_128_CCM_SHA256 */
            case 0x1304:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            /* 0x1305 TLS_AES_128_CCM_8_SHA256 */
            case 0x1305:
                pTempPSK->hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
                break;
            default :
                pTempPSK->hashAlgo = 0;
                break;
        }

        status = NSSL_CHK_CALL(serializePsk, (OSSL_tls13PSK *) pTempPSK, ppPsk, pPskLen);
    }
exit:
    if (OK == status)
    {
        *pFreeMemory = 1;
    }
    else
    {
        if (pTempPSK != NULL)
        {
            if (pTempPSK->pskTLS13Identity != NULL)
            {
                OSSL_FREE(pTempPSK->pskTLS13Identity);
            }

            OSSL_FREE(pTempPSK);
        }
    }

    return status;
}

void SSL_set_psk_find_session_callback(SSL *pSSL, SSL_psk_find_session_cb_func callbackFuncPtr)
{
    pskFindSessionCallbackFuncPtr  psk_find_session_callback;
    psk_find_session_callback  = OSSL_psk_find_session_callback;

    if ((NULL == pSSL) || (NULL == callbackFuncPtr))
        return;

    pSSL->orig_s.psk_find_session_cb = callbackFuncPtr;

    if (pSSL->instance > 0)
    {
        NSSL_CHK_CALL(setPskFindSessionCb, psk_find_session_callback);
    }
}

void SSL_CTX_set_psk_find_session_callback(SSL_CTX *pCtx,
                                           SSL_psk_find_session_cb_func callbackFuncPtr)
{
    if ((NULL == pCtx) || (NULL == callbackFuncPtr))
        return;

    pCtx->orig_ssl_ctx.psk_find_session_cb = callbackFuncPtr;
}

static sbyte4 OSSL_set_psk_use_session_callback(sbyte4 connectionInstance,
                                                 sbyte* ServerInfo, ubyte4 serverInfoLen,
                                                 void *userData, void **ppPSKs,
                                                 ubyte2 *pNumPSKs, ubyte* selectedIndex,
                                                 intBoolean *pFreeMemory)
{
    MSTATUS status = -1;
    size_t idLen   = 0;
    SSL *pSSL                  = NULL;
    const EVP_MD *pEvpmd       = NULL;
    const unsigned char *pId   = NULL;
    SSL_SESSION *pSess         = NULL;
    tls13PSK pskCopy = { 0 };
    tls13PSKList *pTempPSKList = NULL;

    pSSL = (SSL*)findSSLFromInstance(connectionInstance);

    if ((NULL == pSSL) || (NULL == pFreeMemory))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFreeMemory = 0;

    if (pSSL->orig_s.psk_use_session_cb)
    {
        /* callback should return 1 on success or 0 on failure */
        status = pSSL->orig_s.psk_use_session_cb(pSSL, pEvpmd, &pId, &idLen, &pSess);
    }
    else if (NULL != pSSL->session)
    {
        pSess  = pSSL->session;
        pId    = pSess->session_id;
        idLen  = pSess->session_id_length;
        status = 1;
    }

    /* call back returned error or No identity returned or No sesion structure returned */
    if ((0 == status) || (NULL == pId) || (0 == idLen) || (NULL == pSess))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pskCopy.isExternal = 0;
    pskCopy.isPSKavailable = 1;
    pskCopy.pskTLS13LifetimeHint = pSess->ext.tick_lifetime_hint;
    pskCopy.pskTLS13AgeAdd = pSess->ext.tick_age_add;
    if (pSess->master_key_length > 0)
    {
        memcpy(pskCopy.pskTLS13, pSess->master_key, pSess->master_key_length);
        pskCopy.pskTLS13Length = (ubyte2) pSess->master_key_length;
    }
    pskCopy.pskTLS13Identity = (ubyte *) pId;
    pskCopy.pskTLS13IdentityLength = (ubyte4) idLen;
    /* pskCopy.obfuscatedTicketAge */

    status = OSSL_DATETIME_getDateTime(pSess->time, &(pskCopy.startTime));
    if (OK != status)
    {
        goto exit;
    }

    switch(pSess->cipher_id)
    {
        /* 0x1301 TLS_AES_128_GCM_SHA256 */
        case 0x1301:
            pskCopy.hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
            break;

        /* 0x1302 TLS_AES_256_GCM_SHA384 */
        case 0x1302:
            pskCopy.hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA384;
            break;

        /* 0x1303 TLS_CHACHA20_POLY1305_SHA256 */
        case 0x1303:
            pskCopy.hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
            break;

        /* 0x1304 TLS_AES_128_CCM_SHA256 */
        case 0x1304:
            pskCopy.hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
            break;

        /* 0x1305 TLS_AES_128_CCM_8_SHA256 */
        case 0x1305:
            pskCopy.hashAlgo = (TLS_HashAlgorithm) OSSL_TLS_SHA256;
            break;

        default:
            pskCopy.hashAlgo = 0;
            break;
    }

    pskCopy.maxEarlyDataSize = pSess->ext.max_early_data;
    pskCopy.pSelectedTlsVersion = pSess->ssl_version;
    /* pskCopy.selectedALPN */
    pskCopy.selectedCipherSuiteId  = (ubyte2) pSess->cipher_id;

    if (OK != NSSL_CHK_CALL(mocMalloc, (void **) &pTempPSKList, sizeof(tls13PSKList)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pTempPSKList->pNextPSK = NULL;

    if (OK > (status = NSSL_CHK_CALL(
        serializePsk, (OSSL_tls13PSK *) &pskCopy, &(pTempPSKList->pPskData),
        &(pTempPSKList->pskDataLen))))
    {
        goto exit;
    }


    *ppPSKs = (tls13PSKList *)pTempPSKList;
    *pNumPSKs = 1;
    *selectedIndex = 0;
exit:
    if (OK == status)
    {
        *pFreeMemory = 1;
    }
    else
    {
        if (pTempPSKList != NULL)
        {
            NSSL_CHK_CALL(mocFree, (void **) &pTempPSKList);
        }
    }

    return status;
}

void SSL_set_psk_use_session_callback(SSL *pSSL, SSL_psk_use_session_cb_func ptrCallbackFunc)
{
    pskUseSessionCallbackFuncPtr  psk_use_session_callback;
    psk_use_session_callback  = OSSL_set_psk_use_session_callback;

    if (NULL == pSSL)
        return;

    pSSL->orig_s.psk_use_session_cb = ptrCallbackFunc;
    if (pSSL->instance > 0)
    {
        NSSL_CHK_CALL(setPskUseSessionCb, pSSL->instance, psk_use_session_callback);
    }
}

static sbyte4 OSSL_set_psk_save_session_callback(sbyte4 connectionInstance,
                                                  sbyte* pServerInfo, ubyte4 serverInfoLen,
                                                  void *userData, ubyte *pPskData, ubyte4 pskDataLen)
{
    MSTATUS status = 0;
    SSL *pSSL;
    SSL_SESSION *pSess;
    tls13PSK *pPsk = NULL;

    pSSL = (SSL*) findSSLFromInstance(connectionInstance);

    if ((NULL == pSSL) || (NULL == pSSL->session))
    {
         status = ERR_NULL_POINTER;
         goto exit;
    }

    if (OK > (status = NSSL_CHK_CALL(deserializePsk, pPskData, pskDataLen, (OSSL_tls13PSK **)&pPsk)))
    {
        goto exit;
    }

    if (NULL == pPsk)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSess = (SSL_SESSION *) pSSL->session;

    /* Copy PSK */
    if (NULL != pSess->ext.tick)
    {
        OSSL_FREE(pSess->ext.tick);
    }

    pSess->ext.tick = OSSL_MALLOC(pPsk->pskTLS13Length);
    if (NULL == pSess->ext.tick)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    memcpy(pSess->ext.tick, pPsk->pskTLS13, pPsk->pskTLS13Length);

    status = OSSL_DATETIME_getTime(&(pPsk->startTime), &(pSess->time));
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_MAX_SSL_SESSION_ID_LENGTH >= pPsk->pskTLS13IdentityLength)
    {
        memcpy(pSess->session_id, pPsk->pskTLS13Identity, pPsk->pskTLS13IdentityLength);
        pSess->session_id_length = pPsk->pskTLS13IdentityLength;
    }

    if ((pServerInfo != NULL) && (serverInfoLen != 0))
    {
        if (NULL != pSess->ext.hostname)
        {
            OSSL_FREE(pSess->ext.hostname);
        }

        pSess->ext.hostname = OSSL_MALLOC(serverInfoLen + 1);
        if (NULL == pSess->ext.hostname)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        memcpy(pSess->ext.hostname, pServerInfo, serverInfoLen);
        pSess->ext.hostname[serverInfoLen] = '\0';
    }

    pSess->ext.ticklen            = pPsk->pskTLS13Length;
    pSess->cipher_id              = pPsk->selectedCipherSuiteId;
    pSess->ssl_version            = pPsk->pSelectedTlsVersion;
    pSess->ext.tick_lifetime_hint = pPsk->pskTLS13LifetimeHint;
    pSess->ext.tick_age_add       = pPsk->pskTLS13AgeAdd;
    pSess->ext.max_early_data     = pPsk->maxEarlyDataSize;

    if (pPsk->pskTLS13Length > 0)
    {
        memcpy(pSess->master_key, pPsk->pskTLS13, pPsk->pskTLS13Length);
        pSess->master_key_length = pPsk->pskTLS13Length;
    }

    if (NULL != pSess->ext.alpn_selected)
    {
        OPENSSL_free(pSess->ext.alpn_selected);
    }

    pSess->ext.alpn_selected     = OPENSSL_memdup(pPsk->selectedALPN, SSL_ALPN_MAX_SIZE);
    pSess->ext.alpn_selected_len = SSL_ALPN_MAX_SIZE;

    /*
     * Add the session to the external cache.
     */
    if (pSSL->ssl_ctx->new_session_cb != NULL)
    {
        pSSL->ssl_ctx->new_session_cb(pSSL, pSess);
    }

exit:
    if (NULL != pPsk)
    {
        NSSL_CHK_CALL(freePsk, (OSSL_tls13PSK **) &pPsk);
    }

    return status;
}

void SSL_set_psk_save_session_callback(SSL *pSSL)
{
    pskSaveSessionCallbackFuncPtr  psk_save_session_callback;
    psk_save_session_callback  = OSSL_set_psk_save_session_callback;

    if (NULL == pSSL)
        return;

    if (pSSL->instance > 0)
    {
        NSSL_CHK_CALL(savePskSessionCb, pSSL->instance,
            psk_save_session_callback);
    }
}

static sbyte4 OSSL_set_server_psk_save_session_callback(sbyte4 connectionInstance,
                                                         ubyte *pServerName, ubyte4 serverNameLen,
                                                         ubyte *pIdentityPSK, ubyte4 identityLengthPSK,
                                                         ubyte *pPskData, ubyte4 pskDataLen)
{
    MSTATUS status = 0;
    SSL *pSSL;
    SSL_SESSION *pSess = NULL;
    tls13PSK *pPsk = NULL;

    pSSL = (SSL*) findSSLFromInstance(connectionInstance);

    if ((NULL == pSSL) || (NULL == pIdentityPSK))
    {
         status = ERR_NULL_POINTER;
         goto exit;
    }

    if (OK > (status = NSSL_CHK_CALL(deserializePsk, pPskData, pskDataLen, (OSSL_tls13PSK **)&pPsk)))
    {
        goto exit;
    }

    if (NULL == pPsk)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSess = (SSL_SESSION *)pSSL->session;

    /* Copy PSK */
    pSess->ext.tick = OSSL_MALLOC(pPsk->pskTLS13Length);
    if (NULL == pSess->ext.tick)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    memcpy(pSess->ext.tick, pPsk->pskTLS13, pPsk->pskTLS13Length);

    status = OSSL_DATETIME_getTime(&(pPsk->startTime), &(pSess->time));
    if (OK != status)
    {
        goto exit;
    }

    if (SSL_MAX_SSL_SESSION_ID_LENGTH >= identityLengthPSK)
    {
        memcpy(pSess->session_id, pIdentityPSK, identityLengthPSK);
        pSess->session_id_length = identityLengthPSK;
    }

    if ((pServerName != NULL) && (serverNameLen != 0))
    {
        pSess->ext.hostname = OSSL_MALLOC(serverNameLen + 1);
        if (NULL == pSess->ext.hostname)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        memcpy(pSess->ext.hostname, pServerName, serverNameLen);
        pSess->ext.hostname[serverNameLen] = '\0';
    }

    pSess->ext.ticklen            = pPsk->pskTLS13Length;
    pSess->cipher_id              = pPsk->selectedCipherSuiteId;
    pSess->ssl_version            = pPsk->pSelectedTlsVersion;
    pSess->ext.tick_lifetime_hint = pPsk->pskTLS13LifetimeHint;
    pSess->ext.tick_age_add       = pPsk->pskTLS13AgeAdd;
    pSess->ext.max_early_data     = pPsk->maxEarlyDataSize;

    if (pPsk->pskTLS13Length > 0)
    {
        memcpy(pSess->master_key, pPsk->pskTLS13, pPsk->pskTLS13Length);
        pSess->master_key_length = pPsk->pskTLS13Length;
    }

    pSess->ext.alpn_selected     = OPENSSL_memdup(pPsk->selectedALPN, SSL_ALPN_MAX_SIZE);
    pSess->ext.alpn_selected_len = SSL_ALPN_MAX_SIZE;

    /*
     * Add the session to the external cache.
     */
    if (pSSL->ssl_ctx->new_session_cb != NULL)
    {
        pSSL->ssl_ctx->new_session_cb(pSSL, pSess);
    }

exit:
    if (pSess != NULL)
    {
        if ((pServerName != NULL) && (serverNameLen != 0) && (NULL != pSess->ext.hostname))
        {
            OSSL_FREE(pSess->ext.hostname);
            pSess->ext.hostname = NULL;
        }

        if (NULL != pPsk)
        {
            OPENSSL_free(pSess->ext.alpn_selected);
            pSess->ext.alpn_selected = NULL;
        }

        if (NULL != pSess->ext.tick)
        {
            OSSL_FREE(pSess->ext.tick);
            pSess->ext.tick = NULL;
        }
    }

    if (NULL != pPsk)
    {
        NSSL_CHK_CALL(freePsk, (OSSL_tls13PSK **) &pPsk);
    }
    return status;
}

static void SSL_set_server_psk_save_session_callback(SSL *pSSL)
{
    serverPskSaveSessionCallbackFuncPtr server_psk_save_session_callback;
    server_psk_save_session_callback = OSSL_set_server_psk_save_session_callback;

    if (NULL == pSSL)
        return;

    if (pSSL->instance > 0)
    {
        NSSL_CHK_CALL(saveServerPskSessionCb, server_psk_save_session_callback);
    }
}

void SSL_CTX_set_psk_use_session_callback(SSL_CTX *pCtx,
                                           SSL_psk_use_session_cb_func ptrCallbackFunc)
{
    if ((NULL == pCtx) || (NULL == ptrCallbackFunc))
        return;

    pCtx->orig_ssl_ctx.psk_use_session_cb = ptrCallbackFunc;
}

/* SSL_CTX_set_block_padding() pads the record to a multiple of the block_size.
 * A block_size of 0 or 1 disables block padding. The limit of block_size is
 * SSL3_RT_MAX_PLAIN_LENGTH.
 *
 * function return 1 on success or 0 if block_size is too large.
 * Note: in openssl api it accepts - ve values
 * when are less than SSL3_RT_MAX_PLAIN_LENGTH
 */

int SSL_CTX_set_block_padding(SSL_CTX *pCtx, size_t block_size)
{
     if (NULL == pCtx)
        return 0;

    /* block size of 0 or 1 is basically no padding */
    if (block_size <= 1)
    {
        pCtx->orig_ssl_ctx.block_padding = 0;
    }
    else if (block_size <= SSL3_RT_MAX_PLAIN_LENGTH)
    {
        pCtx->orig_ssl_ctx.block_padding = block_size;
    }
    else
    {
        return 0;
    }
    /* Not supported : function returns 1 on success or 0 if block_size is too large. */
    return 0;
}

/* SSL_set_block_padding() pads the record to a multiple
 * of the block_size. A block_size of 0 or 1 disables block padding.
 * The limit of block_size is SSL3_RT_MAX_PLAIN_LENGTH.
 *
 * function return 1 on success or 0 if block_size is too large.
 *
 * Note: in openssl api it accepts - ve values
 * when are less than SSL3_RT_MAX_PLAIN_LENGTH
 */

int SSL_set_block_padding(SSL *pSsl, size_t block_size)
{
#if 0
    ubyte4 blockpadding = 0;

    if (NULL == pSsl)
        return 0;

    /* block size of 0 or 1 is basically no padding */
    if (block_size <= 1)
    {
        blockpadding = 0;
    }
    else if (block_size <= SSL3_RT_MAX_PLAIN_LENGTH)
    {
        blockpadding = block_size;
    }
    else
    {
        return 0;
    }
#endif
    /* Not supported, function return 1 on success or 0 if block_size is too large. */
    return 0;

}

extern void
SSL_CTX_set_keylog_callback(SSL_CTX *ctx, SSL_CTX_keylog_cb_func cb)
{
    /* @Note : unsupported */
    return;
}

SSL_CTX_keylog_cb_func SSL_CTX_get_keylog_callback(const SSL_CTX *pCtx)
{
    if (NULL == pCtx)
        return NULL;

    /* Not supported */
    return NULL;
}

int SSL_CTX_set_session_ticket_cb(SSL_CTX *pCtx,
                                  SSL_CTX_generate_session_ticket_fn gen_cb,
                                  SSL_CTX_decrypt_session_ticket_fn dec_cb,
                                  void *arg)
{
    if ((NULL == pCtx) || (NULL == gen_cb ) || (NULL == dec_cb ) )
        return 0;

    pCtx->orig_ssl_ctx.generate_ticket_cb = gen_cb;
    pCtx->orig_ssl_ctx.decrypt_ticket_cb = dec_cb;
    pCtx->orig_ssl_ctx.ticket_cb_data = arg;

    return 0;
}

void SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
    if ((NULL == ctx) || (NULL == store ))
        return;

    if (store != NULL)
        X509_STORE_up_ref(store);
    SSL_CTX_set_cert_store(ctx, store);
}

const SSL_CIPHER *SSL_get_pending_cipher(const SSL *pSSL)
{
#if 0
    SSL_CIPHER *ptrPendingCipher;

    if (NULL == pSSL)
    {
        return NULL;
    }
#endif
    /* Not supported */
    return NULL;
}

/*
 * Flush the write BIO
 */
int statem_flush(SSL *pSsl)
{
    if (BIO_flush(pSsl->wbio) <= 0) {
        return 0;
    }

    return 1;
}

int SSL_write_ex(SSL *pSsl, const void *buf, size_t num, size_t *written)
{
    int ret = SSL_write(pSsl, buf, (int) num);

    if (ret > 0)
    {
        *written = (size_t) ret;
    }
    else
    {
        ret = 0;
        *written = 0;
    }

    return ret;
}

/* If connectionInstance is unassigned, invoke SSL_connectEx; This function will
 * initialize data structures, set early data, construct Client Hello, earlyData message
 * and send ClientHello followed by early data.
 *   - If the connection is not established, invoke SSL_connect, to read the server messages,
 *     process them and complete the handshake.
 *   - If connection is already established, but early data was not sent, invoke SSL_write_ex
 *     to send early data.
 *
 * If connectionInstance is valid,
 *  - And if connection is established, invoke SSL_write_ex
 *    to write the early data.
 *  - Set the early_data_state to RETRY and return error.
 */
int SSL_write_early_data(SSL *pSsl, const void *buf, size_t num, size_t *written)
{
    ubyte4 sendEarlyData = 1;
    ubyte4 connState     = 0;
    sbyte4 status        = 0;
    int retValue         = 0;
    *written             = 0;

    if (NULL == pSsl)
    {
        return ERR_NULL_POINTER;
    }

    if (num == 0)
    {
        return 0;
    }

    /* If a shutdown notification was sent by us then don't send any data */
    if (SSL_SENT_SHUTDOWN & pSsl->orig_s.shutdown)
    {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return 0;
    }

    pSsl->orig_s.ext.early_data = 1;

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == pSsl->instance)
    {
        if (pSsl->clientServerFlag == SSL_CLIENT_FLAG)
        {
            status = SSL_connectEx(pSsl, (ubyte *) buf, (ubyte4) num, (ubyte4 *) written);

            if (0 > status)
            {
                return 0;
            }
            else if (0 == status)
            {
                /* Connection already established */
                return SSL_write_ex(pSsl, buf, num, written);
            }
            else
            {
                /* Client Hello and Early Data sent;
                 * Receive Server Messages
                 */
                return SSL_connect(pSsl);
            }
        }
    }
    else
    {
        if (OK > NSSL_CHK_CALL(sslIoctl, pSsl->instance, SSL_SET_SEND_EARLY_DATA, &sendEarlyData))
        {
            return 0;
        }

        if (OK > NSSL_CHK_CALL(getSessionStatus, pSsl->instance, &connState))
        {
            return 0;
        }

        retValue = NSSL_CHK_CALL(isEstablished, pSsl->instance);
        if (1 == retValue)
        {
            /* The connection is established;
             * Write the data using SSL_write_ex
             */
            pSsl->orig_s.early_data_state = SSL_EARLY_DATA_WRITE_RETRY;
            return SSL_write_ex(pSsl, buf, num, written);
        }
        else if (-1 == retValue)
        {
            SSLerr(SSL_F_SSL3_ACCEPT, ERR_R_INTERNAL_ERROR);
            return -1;
        }

        pSsl->orig_s.early_data_state = SSL_EARLY_DATA_CONNECT_RETRY;
    }
        return 0;
}

int SSL_peek_ex(SSL *pSsl, void *buf, size_t num, size_t *readbytes)
{
    int ret = SSL_peek(pSsl, buf, (int) num);

    if (ret > 0)
    {
        *readbytes = (size_t) ret;
        ret = 1;
    }
    else
    {
        ret = 0;
        *readbytes = 0;
    }
    return ret;
}

static int earlyDataBitMapToOsslEnum(ubyte4 bitMap)
{
    ubyte4 state = 0;
    /*  The LSB indicates whether early_data extension was received
        and early data is expected.
            0 : no early_data extension
            1 : early_data extension received

        The second LSB indicates whether EndOfEarlyData message was recieved
        and no more early data can be received.
            0 : no EndOfEarlyData message
            1 : EndOfEarlyData message received
    */
    if ((1 == MOC_BIT_GET(bitMap, 0)) && (0 == MOC_BIT_GET(bitMap, 1)))
    {
        state = SSL_EARLY_DATA_ACCEPTING;
    }

    if ((0 == MOC_BIT_GET(bitMap, 0)) || (1 == MOC_BIT_GET(bitMap, 1)))
    {
        state = SSL_EARLY_DATA_FINISHED_READING;
    }
    return state;
}


int SSL_read_early_data(SSL *pSsl, void *buf, size_t num, size_t *readBytes)
{
    int ret = 0, i = 0, bytesSent = 0;
    int retValue = 0;
    sbyte4 status           = -1;
    ubyte4 mySendBufLen     = 0;
    ubyte4 bytesRemaining   = 0;
    ubyte* pFirstUnusedByte = NULL;
    ubyte4 state;

    if (NULL == pSsl)
    {
        return ERR_NULL_POINTER;
    }

    if (SSL_SERVER_FLAG != pSsl->clientServerFlag)
    {
        SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return SSL_READ_EARLY_DATA_ERROR;
    }

    switch(pSsl->orig_s.early_data_state)
    {
        case SSL_EARLY_DATA_NONE:
        case SSL_EARLY_DATA_ACCEPT_RETRY:
            retValue = NSSL_CHK_CALL(isEstablished, pSsl->instance);
            if (0 == retValue)
            {
                ret = SSL_acceptEx(pSsl, buf, num, readBytes);
                if (0 >= ret)
                {
                    SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                    return SSL_READ_EARLY_DATA_ERROR;
                }

                pSsl->bytesRcvdRemaining = 0;
                pSsl->szTxHoldingBuf     = OSSL_MAX_SSL_MSG_SZ;
                mySendBufLen             = pSsl->szTxHoldingBuf;
                /* If the connection is not established, after reading early data,
                 * write the outgoing handshake packets
                 */
                while (0 == (retValue = NSSL_CHK_CALL(isEstablished, pSsl->instance)))
                {
                    if (pSsl->bytesSentRemaining > 0)
                    {
                        i = asyncSendDataBio(
                            pSsl, pSsl->pTxHoldingBuf + pSsl->txHoldingBufOffset, pSsl->bytesSentRemaining,
                            &bytesSent);
                        if (0 >= i)
                        {
                            pSsl->bytesSentRemaining -= bytesSent;
                            pSsl->txHoldingBufOffset += bytesSent;
                            return i;
                        }

                        pSsl->bytesSentRemaining = 0;
                        pSsl->txHoldingBufOffset = 0;
                    }
                    /* write the handshake packets */
                    while (OK == (status = NSSL_CHK_CALL(getPreparedSslRec, pSsl->instance, pSsl->pTxHoldingBuf, &mySendBufLen)))
                    {
                        i = asyncSendDataBio(pSsl, pSsl->pTxHoldingBuf, mySendBufLen, &bytesSent);
                        if (0 >= i)
                        {
                            pSsl->bytesSentRemaining = mySendBufLen - bytesSent;
                            pSsl->txHoldingBufOffset = bytesSent;
                            return i;
                        }

                        mySendBufLen         = pSsl->szTxHoldingBuf;
                    }

                    /* read the incoming handshake packets */
                    if (0 == pSsl->bytesRcvdRemaining)
                    {
                        pSsl->io_state       = OSSL_IN_READ;
                        pSsl->orig_s.rwstate = SSL_READING;
                        while( 0 >= (i = BIO_read(pSsl->rbio, pSsl->pHoldingBuf, pSsl->szHoldingBuf)))
                        {
                            /* XXX: check errors */
                            if ((i<0)||(!BIO_should_retry(pSsl->rbio) || (SSL_pending(pSsl) <= 0)))
                            {
                                return i;
                            }
                        }
                        pSsl->io_state             = 0;
                        pSsl->orig_s.rwstate       = SSL_NOTHING;
                        pSsl->pFirstRcvdUnreadByte = pSsl->pHoldingBuf;
                        pSsl->bytesRcvdRemaining   = i;
                    }

                    status = NSSL_CHK_CALL(parseSslBuf, pSsl->instance, pSsl->pFirstRcvdUnreadByte, pSsl->bytesRcvdRemaining,
                                           &pFirstUnusedByte, &bytesRemaining);

                    if (OK > status)
                    {
                        convertMocStatusToSslErr(pSsl, status, SSL_F_SSL_READ_EARLY_DATA, ERR_R_INTERNAL_ERROR);
                        return -1;
                    }
                    /* While in the Handshake phase, recvMessage2 calls SSL_SOCK_receive in a loop
                    * until it absorbs all the TCP sock data we give it; and the return value in
                    * status is normally 0. On Failure, status will be (-)ve. pFirstUnusedByte
                    * will be NULL and bytesRemaining will be 0. These 2 will be set to meaningful vals
                    * normally only after HShake is complete. For ex. status will be # of cleartext bytes avail.
                    * for harvest; In this case i.e status > 0, pFirstUnusedByte will point to 1st un-used
                    * TCP sock data in the buffer given to recvMessage2; bytesRemaining will indicate # of
                    * un-used bytes in above buffer. If this happens before Hshake is finished, it may
                    * indicate an ALERT was received and should be harvested (see else clause below)
                    */
                    if (0 == status)
                    {
                        pSsl->pFirstRcvdUnreadByte   = pSsl->pHoldingBuf;
                        pSsl->bytesRcvdRemaining     = 0;
                    }
                    else
                    {
                        /* During Handshake some other non-Handshake msg was received;
                         * most likely ALERT. Must harvest and continue feeding bytes to Handshake.
                         */
                        pSsl->pFirstRcvdUnreadByte  = pFirstUnusedByte;
                        pSsl->bytesRcvdRemaining    = bytesRemaining;
                    }
                }
                if (-1 == retValue)
                {
                    SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                    return SSL_READ_EARLY_DATA_ERROR;
                }
                if (ret > 0)
                {
                    /* Read the early data and connection is established */
                    if (0 > NSSL_CHK_CALL(getEarlyDataState, pSsl->instance, &state))
                    {
                        SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                        return SSL_READ_EARLY_DATA_ERROR;
                    }

                    if (SSL_EARLY_DATA_FINISHED_READING == earlyDataBitMapToOsslEnum(state))
                    {
                        if (pSsl->rxDataBufLen > 0)
                        {
                            pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY;
                            return SSL_READ_EARLY_DATA_SUCCESS;
                        }
                        pSsl->orig_s.early_data_state = SSL_EARLY_DATA_FINISHED_READING;
                        return SSL_READ_EARLY_DATA_FINISH;
                    }
                    pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY;
                    return SSL_READ_EARLY_DATA_SUCCESS;
                }
            }
            else if(1 == retValue)
            {
                ret = SSL_read_ex(pSsl, buf, num, readBytes);
                if (ret >= 0)
                {
                    if (0 > NSSL_CHK_CALL(getEarlyDataState, pSsl->instance, &state))
                    {
                        SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                        return SSL_READ_EARLY_DATA_ERROR;
                    }
                    if (SSL_EARLY_DATA_FINISHED_READING == earlyDataBitMapToOsslEnum(state))
                    {
                        if (pSsl->rxDataBufLen > 0)
                        {
                            pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY;
                            return SSL_READ_EARLY_DATA_SUCCESS;
                        }
                        return SSL_READ_EARLY_DATA_FINISH;
                    }
                    pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY; 
                    return SSL_READ_EARLY_DATA_SUCCESS;
                }
            }
            else
            {
                SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                return SSL_READ_EARLY_DATA_ERROR;
            }
            break;
        case SSL_EARLY_DATA_READ_RETRY:
            ret = SSL_read_ex(pSsl, buf, num, readBytes);
            if (ret >= 0)
            {
                if (0 > NSSL_CHK_CALL(getEarlyDataState, pSsl->instance, &state))
                {
                    SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
                    return SSL_READ_EARLY_DATA_ERROR;
                }
                if (SSL_EARLY_DATA_FINISHED_READING == earlyDataBitMapToOsslEnum(state))
                {
                    if (pSsl->rxDataBufLen > 0)
                    {
                        pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY;
                        return SSL_READ_EARLY_DATA_SUCCESS;
                    }
                    return SSL_READ_EARLY_DATA_FINISH;
                }
                pSsl->orig_s.early_data_state = SSL_EARLY_DATA_READ_RETRY; 
                return SSL_READ_EARLY_DATA_SUCCESS;
            }
            break;
        default:
            SSLerr(SSL_F_SSL_READ_EARLY_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
            return SSL_READ_EARLY_DATA_ERROR;
    }

    return SSL_READ_EARLY_DATA_ERROR;
}

int SSL_read_ex(SSL *pSsl, void *buf, size_t num, size_t *readbytes)
{
    int ret = SSL_read(pSsl, buf, (int) num);

    if (ret > 0)
    {
        *readbytes = (size_t) ret;
    }
    else
    {
        ret = 0;
        *readbytes = 0;
    }

    return ret;
}

/* SSL_verify_client_post_handshake() initiates sending a CertificateRequest message to the server
 * on the given ssl connection. The SSL_VERIFY_PEER flag must be set; the
 * SSL_VERIFY_POST_HANDSHAKE flag is optional.
 * The SSL_verify_client_post_handshake() function returns 1 if the request succeeded,
 * and 0 if the request failed.
 */

int SSL_verify_client_post_handshake(SSL *pSsl)
{
    ubyte4 mySendBufLen = 0;
    int    i = 0, bytesSent = 0;
    sbyte4 status = 0;

    if (0 == SSL_verify_version(pSsl, TLS1_3_VERSION))
    {
        SSLerr(SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE, SSL_R_WRONG_SSL_VERSION);
        status = 0;
        goto exit;
    }

    if (SSL_CLIENT_FLAG == pSsl->clientServerFlag)
    {
        SSLerr(SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE, SSL_R_NOT_SERVER);
        status = 0;
        goto exit;
    }

    if (0 == SSL_is_init_finished(pSsl))
    {
        SSLerr(SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE, SSL_R_STILL_IN_INIT);
        status = 0;
        goto exit;
    }

    status = NSSL_CHK_CALL(sendPostHandshakeAuthCertRequest, pSsl->instance);
    if (0 > status)
    {
        /* 0 is failure */
        status = 0;
        goto exit;
    }

    mySendBufLen    = pSsl->szTxHoldingBuf;

    if (pSsl->bytesSentRemaining > 0)
    {
        i = asyncSendDataBio(
            pSsl, pSsl->pTxHoldingBuf + pSsl->txHoldingBufOffset, pSsl->bytesSentRemaining,
            &bytesSent);
        if (0 >= i)
        {
            pSsl->bytesSentRemaining -= bytesSent;
            pSsl->txHoldingBufOffset += bytesSent;
            return i;
        }

        pSsl->bytesSentRemaining = 0;
        pSsl->txHoldingBufOffset = 0;
    }

    /* Get the encrypted buffer */
    while (OK == (status = NSSL_CHK_CALL(getPreparedSslRec, pSsl->instance, pSsl->pTxHoldingBuf, &mySendBufLen)))
    {
        i = asyncSendDataBio(pSsl, pSsl->pTxHoldingBuf, mySendBufLen, NULL);
        if (0 >= i)
        {
            pSsl->bytesSentRemaining = mySendBufLen - bytesSent;
            pSsl->txHoldingBufOffset = bytesSent;
            status = 0;
            goto exit;
        }

        pSsl->orig_s.rwstate = SSL_READING;
        mySendBufLen    = pSsl->szTxHoldingBuf;
    }

    /* 1 is success */
    pSsl->orig_s.post_handshake_auth = SSL_PHA_REQUESTED;
    status = 1;

exit:
    return status;
}

int SSL_stateless(SSL *pSsl)
{
#if 0
    int ret;
    ubyte4 cookieStatus;
    ubyte4 helloRtyReqStatus;

    /* Ensure there is no state left over from a previous invocation */
    if (!SSL_clear(pSsl))
        return 0;
#endif
    /* Not supported  */
    return -1;
}

/* SSL_CTX_set_tlsext_max_fragment_length() sets the default maximum fragment
 * length negotiation mode via value mode to ctx. This setting affects only SSL
 * instances created after this function is called. It affects the client-side as
 * only its side may initiate this extension use.
 * return 1 on success and 0 on failure.
 */

int SSL_CTX_set_tlsext_max_fragment_length(SSL_CTX *pCtx, uint8_t mode)
{
    MSTATUS status = 0;

    if (NULL == pCtx)
        goto exit;

    if (mode != TLSEXT_max_fragment_length_DISABLED
            && !IS_MAX_FRAGMENT_LENGTH_EXT_VALID(mode))
    {
        SSLerr(SSL_F_SSL_CTX_SET_TLSEXT_MAX_FRAGMENT_LENGTH,
               SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        goto exit;
    }

    pCtx->orig_ssl_ctx.ext.max_fragment_len_mode = mode;

exit:
    return status; /* Not supported , it returns 0 */
}

/* SSL_set_tlsext_max_fragment_length() sets the maximum fragment
 * length negotiation mode via value mode to ssl. This setting will be used
 * during a handshake when extensions are exchanged between client and server.
 * So it only affects SSL sessions created after this function is called.
 * It affects the client-side as only its side may initiate this extension use.
 * return 1 on success and 0 on failure.
 */

int SSL_set_tlsext_max_fragment_length(SSL *pSsl, uint8_t mode)
{
    MSTATUS status = 0;

    if (NULL == pSsl)
        goto exit;

    if (mode != TLSEXT_max_fragment_length_DISABLED
            && !IS_MAX_FRAGMENT_LENGTH_EXT_VALID(mode))
    {
        SSLerr(SSL_F_SSL_SET_TLSEXT_MAX_FRAGMENT_LENGTH,
               SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH);
        goto exit;
    }

exit:
    /* not supported , return 1 for success or 0 for failure */
    return status;
}

int SSL_key_update(SSL *pSsl, int updateType)
{
    ubyte4 mySendBufLen = 0;
    int    i = 0, bytesSent = 0;
    sbyte4 status = 1;

    if (0 == SSL_verify_version(pSsl, TLS1_3_VERSION))
    {
        SSLerr(SSL_F_SSL_KEY_UPDATE, SSL_R_WRONG_SSL_VERSION);
        status = 0;
        goto exit;
    }

    if (0 == SSL_is_init_finished(pSsl))
    {
        SSLerr(SSL_F_SSL_VERIFY_CLIENT_POST_HANDSHAKE, SSL_R_STILL_IN_INIT);
        status = 0;
        goto exit;
    }

    if ((updateType != SSL_KEY_UPDATE_NOT_REQUESTED)
        && (updateType != SSL_KEY_UPDATE_REQUESTED))
    {
        SSLerr(SSL_F_SSL_KEY_UPDATE, SSL_R_INVALID_KEY_UPDATE_TYPE);
        status = 0;
        goto exit;
    }

    if (pSsl->instance > 0)
    {
        if (OK > NSSL_CHK_CALL(sendKeyUpdate, pSsl->instance, updateType))
        {
            status = 0;
            goto exit;
        }
    }

    pSsl->orig_s.key_update = updateType;


    mySendBufLen    = pSsl->szTxHoldingBuf;

    if (pSsl->bytesSentRemaining > 0)
    {
        i = asyncSendDataBio(
            pSsl, pSsl->pTxHoldingBuf + pSsl->txHoldingBufOffset, pSsl->bytesSentRemaining,
            &bytesSent);
        if (0 >= i)
        {
            pSsl->bytesSentRemaining -= bytesSent;
            pSsl->txHoldingBufOffset += bytesSent;
            return i;
        }

        pSsl->bytesSentRemaining = 0;
        pSsl->txHoldingBufOffset = 0;
    }

    while (OK == (status = NSSL_CHK_CALL(getPreparedSslRec, pSsl->instance, pSsl->pTxHoldingBuf, &mySendBufLen)))
    {
        i = asyncSendDataBio(pSsl, pSsl->pTxHoldingBuf, mySendBufLen, &bytesSent);
        if (0 >= i)
        {
            pSsl->bytesSentRemaining = mySendBufLen - bytesSent;
            pSsl->txHoldingBufOffset = bytesSent;
            status = 0;
            goto exit;
        }

        pSsl->orig_s.rwstate = SSL_READING;
        mySendBufLen    = pSsl->szTxHoldingBuf;
    }

exit:
    return status;
}

int SSL_export_keying_material_early(SSL *pSsl, unsigned char *out, size_t olen,
                                     const char *label, size_t llen,
                                     const unsigned char *context,
                                     size_t contextlen)
{
    return 0; /* not supported */
}


static int update_cipher_list_by_id(STACK_OF(SSL_CIPHER) **cipher_list_by_id,
                                    STACK_OF(SSL_CIPHER) *cipherstack)
{
    STACK_OF(SSL_CIPHER) *tmp_cipher_list = sk_SSL_CIPHER_dup(cipherstack);

    if (NULL == tmp_cipher_list)
    {
        return 0;
    }

    sk_SSL_CIPHER_free(*cipher_list_by_id);
    *cipher_list_by_id = tmp_cipher_list;

    (void)sk_SSL_CIPHER_set_cmp_func(*cipher_list_by_id, ssl_cipher_ptr_id_cmp);
    sk_SSL_CIPHER_sort(*cipher_list_by_id);

    return 1;
}

static int update_cipher_list(STACK_OF(SSL_CIPHER) **cipher_list,
                              STACK_OF(SSL_CIPHER) **cipher_list_by_id,
                              STACK_OF(SSL_CIPHER) *tls13_ciphersuites)
{
    int i;
    STACK_OF(SSL_CIPHER) *tmp_cipher_list = sk_SSL_CIPHER_dup(*cipher_list);

    if (NULL == tmp_cipher_list)
    {
        return 0;
    }

    /*
     * Delete any existing TLSv1.3 ciphersuites. These are always first in the
     * list.
     */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    while (sk_SSL_CIPHER_num(tmp_cipher_list) > 0
           && ((SSL_CIPHER *)sk_SSL_CIPHER_value(tmp_cipher_list, 0))->min_tls
              == TLS1_3_VERSION)
        sk_SSL_CIPHER_delete(tmp_cipher_list, 0);
#else
    while ( (sk_SSL_CIPHER_num(tmp_cipher_list) > 0 )
            && (( (SSL_CIPHER *) sk_SSL_CIPHER_value(tmp_cipher_list, 0) )->algorithm_ssl == SSL_TLSV1_3))
    {
        sk_SSL_CIPHER_delete(tmp_cipher_list, 0);
    }
#endif

    /* Insert the new TLSv1.3 ciphersuites */
    for (i = 0; i < sk_SSL_CIPHER_num(tls13_ciphersuites); i++)
    {
        sk_SSL_CIPHER_insert(tmp_cipher_list,
                             sk_SSL_CIPHER_value(tls13_ciphersuites, i), i);
    }

    if (!update_cipher_list_by_id(cipher_list_by_id, tmp_cipher_list))
    {
        sk_SSL_CIPHER_free(tmp_cipher_list);
        return 0;
    }

    sk_SSL_CIPHER_free(*cipher_list);
    *cipher_list = tmp_cipher_list;

    return 1;
}

static intBoolean isTlsPfsCipher(unsigned long cipherSuiteId)
{
    switch(cipherSuiteId)
    {
        case 0x03001302: /* TLS_AES_256_GCM_SHA384 */
        case 0x03001301: /* TLS_AES_128_GCM_SHA256 */
        case 0x03001303: /* TLS_CHACHA20_POLY1305_SHA256 */
        case 0x03001304: /* TLS_AES_128_CCM_SHA256 */
        case 0x03001305: /* TLS_AES_128_CCM_8_SHA256 */

        /* ECDHE-RSA cipher suites */
        case 0x0300C013: /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
        case 0x0300C014: /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
        case 0x0300C027: /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
        case 0x0300C028: /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
        case 0x0300C02F: /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
        case 0x0300C030: /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
        case 0x0300CCA8: /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

        /* ECDHE-ECDSA cipher suites */
        case 0x0300C009: /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
        case 0x0300C00A: /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
        case 0x0300C023: /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
        case 0x0300C024: /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
        case 0x0300C02B: /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
        case 0x0300C02C: /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
        case 0x0300CCA9: /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */

        /* ECDHE-ECDSA CCM cipher suites */
        case 0x0300C0AD: /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
        case 0x0300C0AC: /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
        case 0x0300C0AF: /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
        case 0x0300C0AE: /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */

        /* DHE-RSA cipher suites */
        case 0x03000033: /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
        case 0x03000039: /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
        case 0x03000067: /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
        case 0x0300006B: /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
        case 0x0300009E: /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
        case 0x0300009F: /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
        case 0x0300CCAA: /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

        /* DHE-RSA CCM cipher suites */
        case 0x0300C09F: /* TLS_DHE_RSA_WITH_AES_256_CCM */
        case 0x0300C09E: /* TLS_DHE_RSA_WITH_AES_128_CCM */
        case 0x0300C0A3: /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
        case 0x0300C0A2: /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */

        /* DES */
        case 0x03000015: /* SSL_DHE_RSA_WITH_DES_CBC_SHA */

            return TRUE;
    }

    return FALSE;
}

static int update_cipher_list_with_pfs_ciphers_only(SSL_CTX *pCtx)
{
    int i;
    STACK_OF(SSL_CIPHER) *sk;
    STACK_OF(SSL_CIPHER) *tmp_cipher_list = NULL;

    if (NULL == pCtx)
    {
        return 0;
    }

    tmp_cipher_list = sk_SSL_CIPHER_dup(pCtx->cipher_list);
    if (NULL == tmp_cipher_list)
    {
        return 0;
    }

    /* Keep only ciphersuites which provides perfect forward secrecy. */
    for (i = 0; i < sk_SSL_CIPHER_num(tmp_cipher_list); i++)
    {
        if (FALSE == isTlsPfsCipher(((SSL_CIPHER *)sk_SSL_CIPHER_value(tmp_cipher_list, i))->id))
        {
            sk_SSL_CIPHER_delete(tmp_cipher_list, i);
            i--;
        }
    }

    if (!update_cipher_list_by_id(&pCtx->cipher_list_by_id, tmp_cipher_list))
    {
        sk_SSL_CIPHER_free(tmp_cipher_list);
        return 0;
    }

    sk_SSL_CIPHER_free(pCtx->cipher_list);
    pCtx->cipher_list = tmp_cipher_list;

    sk = pCtx->cipher_list_by_id;

    if (sk == NULL)
    {
        return 0;
    }
    else if ((pCtx->numCipherIds = (sk_SSL_CIPHER_num(sk))) == 0)
    {
        return 0;
    }

    for (i=0; i < pCtx->numCipherIds; i++)
    {
        pCtx->cipherIds[i] = (ubyte2)(((SSL_CIPHER *)sk_SSL_CIPHER_value(sk,i))->id) & 0xFFFF;
    }
    return 1;
}

static const SSL_CIPHER *ssl3_get_cipher_by_std_name(const char *stdname)
{
    SSL_CIPHER *c = NULL, *tbl;
    SSL_CIPHER *alltabs[] = { ssl3_ciphers};
    size_t i, j, tblsize[] = { SSL3_NUM_CIPHERS};

    /* this is not efficient, necessary to optimize this? */
    for (j = 0; j < OSSL_NELEM(alltabs); j++) {
        for (i = 0, tbl = alltabs[j]; i < tblsize[j]; i++, tbl++) {
            if (tbl->stdname == NULL)
                continue;
            if (strcmp(stdname, tbl->stdname) == 0) {
                c = tbl;
                break;
            }
        }
    }
    return c;
}

static int ciphersuite_cb(const char *elem, int len, void *arg)
{
    STACK_OF(SSL_CIPHER) *ciphersuites = (STACK_OF(SSL_CIPHER) *)arg;
    const SSL_CIPHER *cipher;
    /* Arbitrary sized temp buffer for the cipher name. Should be big enough */
    char name[80];

    if (len > (int)(sizeof(name) - 1))
    {
        return 0;
    }

    memcpy(name, elem, len);
    name[len] = '\0';

    cipher = ssl3_get_cipher_by_std_name(name);
    if (cipher == NULL)
    {
        return 0;
    }

    if(!sk_SSL_CIPHER_push(ciphersuites, cipher))
    {
        return 0;
    }

    return 1;
}

/*
 * This function takes a list separated by 'sep' and calls the callback
 * function giving the start and length of each member optionally stripping
 * leading and trailing whitespace. This can be used to parse comma separated
 * lists for example.
 */

static int DIGI_CONF_parse_list(const char *list_, int sep, int nospc,
                    int (*list_cb) (const char *elem, int len, void *usr),
                    void *arg)
{
    int ret;
    const char *lstart, *tmpend, *p;

    if (list_ == NULL)
    {
        return 0;
    }

    lstart = list_;
    for (;;)
    {
        if (nospc)
        {
            while (*lstart && isspace((unsigned char)*lstart))
                lstart++;
        }
        p = strchr(lstart, sep);

        if (p == lstart || !*lstart)
        {
            ret = list_cb(NULL, 0, arg);
        }
        else
        {
            if (p)
            {
                tmpend = p - 1;
            }
            else
            {
                tmpend = lstart + strlen(lstart) - 1;
            }
            if (nospc)
            {
                while (isspace((unsigned char)*tmpend))
                    tmpend--;
            }
            ret = list_cb(lstart, (int) (tmpend - lstart + 1), arg);
        }
        if (ret <= 0)
        {
            return ret;
        }

        if (p == NULL)
        {
            return 1;
        }

        lstart = p + 1;
    }
}

static int set_ciphersuites(STACK_OF(SSL_CIPHER) **pCurrciphers, const char *str)
{
    STACK_OF(SSL_CIPHER) *pNewciphers = sk_SSL_CIPHER_new_null();

    if (NULL == pNewciphers)
    {
        return 0;
    }

    /* Parse the list. We explicitly allow an empty list */
    if (*str != '\0' && !DIGI_CONF_parse_list(str, ':', 1, ciphersuite_cb, pNewciphers))
    {
        sk_SSL_CIPHER_free(pNewciphers);
        return 0;
    }

    sk_SSL_CIPHER_free(*pCurrciphers);
    *pCurrciphers = pNewciphers;

    return 1;
}


int SSL_set_ciphersuites(SSL *pSsl, const char *str)
{
#if 0
    if (NULL == pSsl)
    {
        return pSsl;
    }
#endif
    /* not supported */
    return 0;
}

int SSL_CTX_set_ciphersuites(SSL_CTX *pCtx, const char *str)
{
    STACK_OF(SSL_CIPHER) *sk;
    ubyte4     i;
    ubyte4 status;

    if (NULL == pCtx)
        return 0;

    if (pCtx->tls13_ciphersuites != NULL)
    {
        sk_SSL_CIPHER_free(pCtx->tls13_ciphersuites);
        pCtx->tls13_ciphersuites = NULL;
    }

    status = set_ciphersuites(&(pCtx->tls13_ciphersuites), str);

    if (status && (pCtx->cipher_list != NULL))
    {
        /* We already have a cipher_list, so we need to update it */
        status = update_cipher_list(&pCtx->cipher_list, &pCtx->cipher_list_by_id,
                                  pCtx->tls13_ciphersuites);
    }
    else
    {
        /* If pCtx->cipher_list is NULL or an error occured then return. */
        return status;
    }

    sk = pCtx->cipher_list_by_id;

    if (sk == NULL)
          return 0;
    else if ((pCtx->numCipherIds = (sk_SSL_CIPHER_num(sk))) == 0)
    {
        return 0;
    }

    for (i=0; i < pCtx->numCipherIds; i++)
    {
        pCtx->cipherIds[i] = (ubyte2)(((SSL_CIPHER *)sk_SSL_CIPHER_value(sk,i))->id) & 0xFFFF;
    }

    return status;
}

/*
 * SSL_CIPHER_get_handshake_digest() returns an EVP_MD for the digest used during
 * the SSL/TLS handshake when using the SSL_CIPHER c
 * SSL_CIPHER_get_handshake_digest() returns a valid EVP_MD structure or NULL
 * if an error occurred.
 */

const EVP_MD *SSL_CIPHER_get_handshake_digest(const SSL_CIPHER *c)
{
    int idx = c->algorithm2 & SSL_HANDSHAKE_MAC_MASK;

    if (idx < 0 || idx >= SSL_MD_NUM_IDX)
        return NULL;
    return ssl_digest_methods[idx];
}

/* SSL_CIPHER_get_protocol_id() returns the two-byte ID used in the TLS protocol of the given cipher c. */
uint16_t SSL_CIPHER_get_protocol_id(const SSL_CIPHER *c)
{
    /* check for null value */
    if (NULL == c)
        return 0;

    return c->id & 0xFFFF;
}

/* return the OpenSSL name based on given RFC standard name */
const char *OPENSSL_cipher_name(const char *pStdname)
{
    const SSL_CIPHER *pCipher;

    if (NULL == pStdname)
    {
        return "(NONE)";
    }
    pCipher = ssl3_get_cipher_by_std_name(pStdname);
    return SSL_CIPHER_get_name(pCipher);
}

/*-----------------------------------------------------------------*/

/* Initiates the connection;
 * Sends out Client Hello and Early Data
 * Return : -1 Error
 *           0 Connection already established
 *          > 0 Number of earlydata bytes written
 */
static int SSL_connectEx(SSL *s, ubyte *pEarlyData, ubyte4 earlyDataLen, ubyte4 *bytesWritten)
{
    sbyte4  status             = 0;
    ubyte4  mySendBufLen       = 0;
    ubyte4  bytesRemaining     = 0;
    int     i                  = 0;
    int     bytesSent          = 0;
    int     authModeFlag       = 0;
    int     retValue           = 0;
    ubyte4  sslFlags           = 0;
    SSL_CTX *ctx               = NULL;
    ubyte       *pFirstUnusedByte = NULL;
    void (*cb) (const SSL *ssl, int type, int val) = NULL;
    char *pHostname            = NULL;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    peerDescr myPeerDescr = {0};
    ubyte *srcAddr  = (ubyte *)"0.0.0.0";
    ubyte *peerAddr = (ubyte *)"1.1.1.1";
#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    int mutexAcquired = 0;
#endif
    ubyte requestTicket = 1;

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte enableExtendedMasterSecret = 1;
#endif

    if (s == NULL)
    {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        status = -1;
        goto exit;
    }

    ERR_clear_error();
    clear_sys_error();

    /* Initialize myPeerDescr for DTLS */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
    {
        myPeerDescr.pUdpDescr = NULL;
        mocNetNameToIpaddr(&(myPeerDescr.srcAddr), srcAddr);
        myPeerDescr.srcPort   = s->appId;
        mocNetNameToIpaddr(&(myPeerDescr.peerAddr), peerAddr);
        myPeerDescr.peerPort  = s->appId;
    }
#endif

    ctx    = s->ssl_ctx;
    /* NanoSSL stack Uses the socket to correlate the connectionInstance
     * to SSL Socket Session
     */

    if((s->orig_s.verify_mode == SSL_VERIFY_NONE) && (ctx->verify_mode == SSL_VERIFY_NONE) &&
       (NULL == SSL_get_privatekey(s)))
    {
        authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REPLY;
    }

    /* Handshake status callback */
    if (s->info_callback != NULL)
    {
        cb = s->info_callback;
    }
    else if (s->ssl_ctx->info_callback != NULL)
    {
        cb = s->ssl_ctx->info_callback;
    }

    if (s->session)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pHostname = s->session->ext.hostname;
#else
        pHostname = s->session->tlsext_hostname;
#endif
    }

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
    {
        if ((s->session) && (s->session->session_id_length > 0))
        {

            /* @Note:Currently handling DTLSv1.1. If DTLSv1.2 handling is required,
             * then add methods for the same with version number being 0xFEFD.
             */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
            {
                s->instance = NSSL_CHK_CALL(dtlsConnect,&myPeerDescr,
                              s->session->session_id_length, s->session->session_id,
                              s->session->master_key, (const sbyte *)pHostname,
                              ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                    status = -1;
                    goto exit;
                }
            }
            else
#endif
            {
                s->instance = NSSL_CHK_CALL(connect, (ubyte4) s->appId, (ubyte) s->session->session_id_length,
                                            s->session->session_id, s->session->master_key,
                                            (const sbyte *)pHostname, ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                    status = -1;
                    goto exit;
                }
            }
        }
        else
        {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
            {
                s->instance = NSSL_CHK_CALL(dtlsConnect,&myPeerDescr,0, NULL, NULL,
                              (const sbyte *)s->tlsext_hostname,ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                    status = -1;
                    goto exit;
                }
            }
            else
#endif
            {
                s->instance = NSSL_CHK_CALL(connect, s->appId, 0, NULL, NULL,
                              (const sbyte *)s->tlsext_hostname, ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                    status = -1;
                    goto exit;
                }
            }
        }

        /* Session instance created. Create the OpenSSL client mutex if it
         * hasn't been created */
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (NULL == s->session_mutex)
        {
            if (OK > moc_mutexCreate(&(s->session_mutex), 0, 0))
                return -1;
        }
#endif

        if ((NULL != s->ssl_ctx->orig_ssl_ctx.cert) && (NULL != s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs))
        {
            if (OK > NSSL_CHK_CALL(setCipherAlgorithm, s->instance, s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs,
                                   (ubyte4) s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgslen, 2 /* signature algorithms */))
            {
                status = -1;
                goto exit;
            }
        }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
         /* Extended master secret is enabled by default */
        if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void*)((OSSL_UINT_PTR)enableExtendedMasterSecret)))
        {
            status = -1;
            goto exit;
        }
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        /* Don't use RFC4507 ticket extension */
        if (!(s->ssl_ctx->options & SSL_OP_NO_TICKET))
        {
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_REQUEST_SESSION_TICKET, &requestTicket))
            {
                status = -1;
                goto exit;
            }

            /* Saving PSK on client */
            SSL_set_psk_save_session_callback(s);
        }

        if ((NULL != s->orig_s.psk_use_session_cb) || (1 == s->registerRetrievePSK))
        {
            SSL_set_psk_use_session_callback(s, s->orig_s.psk_use_session_cb);
        }

        if (s->session != NULL)
        {
            if (pHostname)
            {
                /* Set TLS ServerName Extension */
                status = NSSL_CHK_CALL(setServerNameExtension, s->instance,(const char *)pHostname);
            }

            if ((s->session->ext.alpn_selected) && (s->session->ext.alpn_selected_len > 0 ))
            {
                if ((OK != SSL_set_alpn_protos(s, s->session->ext.alpn_selected, (unsigned int) s->session->ext.alpn_selected_len)))
                {
                    status = -1;
                    goto exit;
                }
            }

            if (s->session->ssl_version)
            {
                /* Set version */
                status = NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_VERSION, (void*)((OSSL_UINT_PTR) OSSL_convert_minor_version_from_ossl(s->session->ssl_version)));
            }
        }

        if ((NULL != pEarlyData) || (0 != earlyDataLen))
        {
            ubyte4 sendEarlyData = 1;
            if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_SEND_EARLY_DATA, &sendEarlyData))
            {
                status = -1;
                goto exit;
            }

            if (OK > (NSSL_CHK_CALL(setEarlyData, s->instance, pEarlyData, earlyDataLen)))
            {
                status = -1;
                goto exit;
            }
        }

        if (s->orig_s.pha_enabled)
        {
            NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags);

            /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
            NSSL_CHK_CALL(setSessionFlags, s->instance, SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH);
        }

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
        OSSL_setCertAndStatusCallBack(s);
#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */

#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__
        OSSL_setVersionCallback(s);
#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

        /* Set the callback alert by default. This will allow proper handling of
         * alert messages.
         */
        OSSL_set_alert_cb(s);

        if (ctx->client_cert_cb != NULL)
        {
            if (OK > OSSL_setClientCertCallback(s))
            {
                status = -1;
                goto exit;
            }

            if (OK > OSSL_setCertVerifySignCb(s))
            {
                status = -1;
                goto exit;
            }
        }

        if (OK > (status = moc_mutexWait(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexWait() failed : %d\n", status);*/
            status = -1;
            goto exit;
        }

        (void) NSSL_CHK_CALL(hashTableAddPtr, m_ssl_table, s->instance,(SSL*)s);

        if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexRelease() failed : %d\n", status);*/
            status = -1;
            goto exit;
        }

        if (NULL != s->tlsext_hostname)
        {
            /* Set TLS ServerName Extension */
            status = NSSL_CHK_CALL(setServerNameExtension, s->instance,(const char *)s->tlsext_hostname);
        }

        if((s->ssl_ctx->alpn_client_proto_list) && (s->ssl_ctx->alpn_client_proto_list_len > 0 ))
        {
            if ((OK != SSL_set_alpn_protos(s,s->ssl_ctx->alpn_client_proto_list,s->ssl_ctx->alpn_client_proto_list_len)))
            {
                status = -1;
                goto exit;
            }
        }

        NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags);

        /* Reset the flags before setting */
        sslFlags &= ~(SSL_FLAG_NO_MUTUAL_AUTH_REQUEST);
        sslFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);

        /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
        /* @Note: verify the client enforces auth requirement from server */
        if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, sslFlags | (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
        {
            status = -1;
            goto exit;
        }

#if !defined(__DISABLE_DIGICERT_OSSL_DEFAULT_TRUST_CERTS__)
        if (0 == sk_X509_OBJECT_num(ctx->cert_store->objs))
        {
            SSL_CTX_load_default_certs(ctx);
        }
        else
#endif
        {
            OSSL_CTX_load_x509_store(ctx);
        }

        if (s->numCipherIds > 0)
        {
            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, s->cipherIds, s->numCipherIds)))
            {
                status = -1;
                goto exit;
            }
        }
        else
        {
            /* Choose default Cipher Suites */
            if ((ctx->numCipherIds < 1) || (ctx->cipher_list == NULL))
            {
                (void) SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
            }
            if (ctx->numCipherIds > 0)
            {
                if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, ctx->cipherIds, ctx->numCipherIds)))
                {
                    status = -1;
                    goto exit;
                }
            }
            else
            {
                /* No Cipher Suites */
                status = -1;
                goto exit;
            }
        }
        if (s->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = s->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                status = -1;
                goto exit;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = s->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }
        else if (ctx->numEccCurves > 0)
        {
            ubyte4 i = 0;
            ubyte4 numCurves = ctx->numEccCurves;
            OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
            if (NULL == curvesList)
            {
                status = -1;
                goto exit;
            }
            for (i = 0; i < numCurves; i++)
            {
                curvesList[i] = ctx->pEccCurves[i];
            }

            NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
            OSSL_FREE(curvesList);
        }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            if (s->numSrtpProfileIds > 0)
            {
                NSSL_CHK_CALL(setSrtpProfiles, s->instance, s->srtpProfileIds, s->numSrtpProfileIds);
            }
            else
            {
                if (ctx->numSrtpProfileIds > 0)
                {
                    NSSL_CHK_CALL(setSrtpProfiles, s->instance, ctx->srtpProfileIds, ctx->numSrtpProfileIds);
                }
            }
        }
#endif

        s->clientServerFlag = SSL_CLIENT_FLAG;
    }

    retValue = NSSL_CHK_CALL(isEstablished, s->instance);
    if (1 == retValue)
    {
        s->sent_client_hello = 0;
        status = 1;
        goto exit;
    }
    else if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
        status = -1;
        goto exit;
    }


    if (NULL == s->pHoldingBuf)
    {
        s->pHoldingBuf = OSSL_MALLOC(OSSL_MAX_SSL_RX_MSG_SZ);
        if (NULL == s->pHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            status = -1;
            goto exit;
        }
        s->szHoldingBuf        = OSSL_MAX_SSL_RX_MSG_SZ;
        s->bytesRcvdRemaining  = 0;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
    }

    if (NULL == s->pTxHoldingBuf)
    {
        s->pTxHoldingBuf    = OSSL_MALLOC(OSSL_MAX_SSL_MSG_SZ);
        if (NULL == s->pTxHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            status = -1;
            goto exit;
        }
        s->szTxHoldingBuf     = OSSL_MAX_SSL_MSG_SZ;
        s->bytesSentRemaining = 0;
        s->txHoldingBufOffset = 0;
    }

     /* In case of rehandshake, ClientHello is sent without explicitly invocation of triggerHello
      * It is prepared when processing Helloretry message and written out with BIO_write
      * So checking of sent_client_hello is only valid for the client Hello sent at
      * beginning of th econnection.
      * State is SSL_ST_OK once the initial connection is established.
      */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (!s->sent_client_hello && (s->orig_state != SSL_ST_OK))
#else
    if (!s->sent_client_hello && (s->orig_s.state != SSL_ST_OK))
#endif
    {
        /*Notify that handshake is started*/
        if (cb != NULL)
        {
            cb(s, SSL_CB_HANDSHAKE_START, 1);
        }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            status = NSSL_CHK_CALL(triggerDtlsHello, s->instance);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
            {
                status = -1;
                goto exit;
            }
        }
        else
#endif
        {
            status = NSSL_CHK_CALL(triggerHello, s->instance);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
            {
                status = -1;
                goto exit;
            }
        }
        /* This returns ERR_SSL_NO_DATA_TO_SEND when there is nothing pending to be sent */
        mySendBufLen    = s->szTxHoldingBuf;

        status = OK;
        while (OK == status)
        {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
                break;

            i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining = mySendBufLen - bytesSent;
                s->txHoldingBufOffset = bytesSent;
                status = i;
                goto exit;
            }

            s->sent_client_hello = 1;
            mySendBufLen         = s->szTxHoldingBuf;
        }

        /* Sent all the earlyData */
        *bytesWritten = earlyDataLen;

        /* All the data was written */
        if (ERR_SSL_NO_DATA_TO_SEND == status)
        {
            status = earlyDataLen;
        }
    }

    while ( 0 == (retValue = NSSL_CHK_CALL(isEstablished, s->instance)))
    {
        if (0 == s->bytesRcvdRemaining)
        {
            s->io_state       = OSSL_IN_READ;
            s->orig_s.rwstate = SSL_READING;

            while( 0 >= (i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf)))
            {
                /* check errors */
                if ((i < 0) || (!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
                {
                    status = i;
                    goto exit;
                }
            }
            s->io_state             = 0;
            s->orig_s.rwstate       = SSL_NOTHING;
            s->pFirstRcvdUnreadByte = s->pHoldingBuf;
            s->bytesRcvdRemaining   = i;
        }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif
        status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
             &pFirstUnusedByte, &bytesRemaining);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        if (OK > status)
        {
            asyncSendPendingData(s);
            convertMocStatusToSslErr(s, status, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);

            status = -1;
            goto exit;
        }

        if (0 == status)
        {
            s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
            s->bytesRcvdRemaining     = 0;
        }
        else
        {
            s->pFirstRcvdUnreadByte    = pFirstUnusedByte;
            s->bytesRcvdRemaining    = bytesRemaining;
        }

        if (s->bytesSentRemaining > 0)
        {
            i = asyncSendDataBio(s, s->pTxHoldingBuf + s->txHoldingBufOffset,
                                 s->bytesSentRemaining, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining -= bytesSent;
                s->txHoldingBufOffset += bytesSent;
                return i;
            }

            s->bytesSentRemaining = 0;
            s->txHoldingBufOffset = 0;
        }

        /* Now send any pending bytes */
        mySendBufLen = s->szTxHoldingBuf;

        status = OK;
        while (OK == status)
        {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif

            if (OK > status)
                break;

            i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining = mySendBufLen - bytesSent;
                s->txHoldingBufOffset = bytesSent;
                status = i;
                goto exit;
            }

            mySendBufLen        = s->szTxHoldingBuf;
        }
    }
    if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
        status = -1;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    s->orig_state = SSL_ST_OK;
#else
    s->orig_s.state = SSL_ST_OK;
#endif
    s->sent_client_hello = 0; /* reset for next cycle */
    status = 1;

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

/*-----------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
MSTATUS OSSL_sessionReleaseMutex(SSL *s)
{
    if (NULL != s->session_mutex)
        return moc_mutexRelease(s->session_mutex);
    else
        return -1;
}
#endif

extern int SSL_connect(SSL *s)
{
     sbyte4         status = 0;
     ubyte4         mySendBufLen = 0, bytesRemaining = 0;
     int            i = 0;
     int            bytesSent = 0;
     int            returnValue = -1;
     int            retValue = 0;
#if 0
     int            rval=0;
#endif
     ubyte          * pFirstUnusedByte;
     SSL_CTX        *ctx = NULL;
     int authModeFlag = 0;
     ubyte4 sslFlags  = 0;
     void (*cb) (const SSL *ssl, int type, int val) = NULL;
     char            *pHostname = NULL;

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     peerDescr myPeerDescr = {0};
     ubyte *srcAddr  = (ubyte *)"0.0.0.0";
     ubyte *peerAddr = (ubyte *)"1.1.1.1";
#endif /* (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__)) */

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    int mutexAcquired = 0;
#endif
#if (defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__) || defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__))
    ubyte requestTicket = 1;
#endif

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
    ubyte enableExtendedMasterSecret = 1;
#endif

    if (s == NULL)
    {
        SSLerr(SSL_F_SSL_DO_HANDSHAKE,SSL_R_UNINITIALIZED);
        returnValue = -1;
        goto exit;
    }

    ERR_clear_error();
    clear_sys_error();

    /* If a shutdown notification was received then don't send or process any data. */
    if (SSL_RECEIVED_SHUTDOWN & s->orig_s.shutdown)
    {
        SSLerr(SSL_F_SSL3_ACCEPT, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

     /* Initialize myPeerDescr for DTLS */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
     {
         myPeerDescr.pUdpDescr = NULL;
         mocNetNameToIpaddr(&(myPeerDescr.srcAddr), srcAddr);
         myPeerDescr.srcPort   = s->appId;
         mocNetNameToIpaddr(&(myPeerDescr.peerAddr), peerAddr);
         myPeerDescr.peerPort  = s->appId;
     }
#endif

    ctx    = s->ssl_ctx;
    /* Nano SSL stack Uses the socket to correlate the connectionInstance
       to SSL Socket Session */

    if((s->orig_s.verify_mode == SSL_VERIFY_NONE) && (ctx->verify_mode == SSL_VERIFY_NONE) &&
        (NULL == SSL_get_privatekey(s))){
        authModeFlag = SSL_FLAG_NO_MUTUAL_AUTH_REPLY;
    }

    if(TRUE == setTlsPfsCiphersOnly)
    {
        /* The existing cipher_list should be updated to contain only PFS ciphers. */
        if(1 != update_cipher_list_with_pfs_ciphers_only(ctx))
        {
            SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
            return -1;
        }
    }

    /* Handshake status callback */
    if (s->info_callback != NULL)
        cb = s->info_callback;
    else if (ctx->info_callback != NULL)
        cb = ctx->info_callback;

    if (s->session)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        pHostname = s->session->ext.hostname;
#else
        pHostname = s->session->tlsext_hostname;
#endif
    }

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
    {

        if ((s->session) && (s->session->session_id_length > 0))
        {

            /* @Note:Currently handling DTLSv1.1. If DTLSv1.2 handling is required,
             * then add methods for the same with version number being 0xFEFD.
             */
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
            {
                s->instance = NSSL_CHK_CALL(dtlsConnect,&myPeerDescr,
                              s->session->session_id_length, s->session->session_id,
                              s->session->master_key, (const sbyte *)pHostname,
                              ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                    returnValue = -1;
                    goto exit;
                }
            }
            else
#endif
            {
                s->instance = NSSL_CHK_CALL(connect, s->appId, (ubyte) s->session->session_id_length,
                                            s->session->session_id, s->session->master_key,
                                            (const sbyte *)pHostname, ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                    returnValue = -1;
                    goto exit;
                }
            }
        }
        else
        {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
            if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
            {
                s->instance = NSSL_CHK_CALL(dtlsConnect,&myPeerDescr,0, NULL, NULL,
                              (const sbyte *)s->tlsext_hostname,ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_DTLS1_CONNECT, ERR_R_INTERNAL_ERROR);
                    returnValue = -1;
                    goto exit;
                }
            }
            else
#endif
            {
                s->instance = NSSL_CHK_CALL(connect, s->appId, 0, NULL, NULL,
                              (const sbyte *)s->tlsext_hostname, ctx->pCertStore);
                if (OK > s->instance)
                {
                    convertMocStatusToSslErr(
                        s, s->instance, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
                    returnValue = -1;
                    goto exit;
                }
            }
        }

        /* Session instance created. Create the OpenSSL client mutex if it
         * hasn't been created */
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (NULL == s->session_mutex)
        {
            if (OK > moc_mutexCreate(&(s->session_mutex), 0, 0))
                return -1;
        }
#endif

    if ((NULL != s->ssl_ctx->orig_ssl_ctx.cert) && (NULL != s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs))
    {
        if (OK > NSSL_CHK_CALL(setCipherAlgorithm, s->instance, s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgs,
                               (ubyte4) s->ssl_ctx->orig_ssl_ctx.cert->conf_sigalgslen, 2 /* signature algorithms */))
        {
            returnValue = -1;
            goto exit;
        }
    }

#if defined(__ENABLE_DIGICERT_EXTENDED_MASTERSECRET_RFC7627__)
     /* Extended master secret is enabled by default */
    if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_USE_EXTENDED_MASTERSECRET, (void*)((OSSL_UINT_PTR)enableExtendedMasterSecret)))
    {
        returnValue = -1;
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_SSL_SESSION_TICKET_RFC_5077__)
    if (!(s->ssl_ctx->options & SSL_OP_NO_TICKET))
    {
        if (OK < NSSL_CHK_CALL(sslIoctl, s->instance, SSL_REQUEST_SESSION_TICKET, &requestTicket))
        {
            return 0;
        }
        NSSL_CHK_CALL(setClientSaveTicketCb, s->instance, OSSL_saveSessionTicket);
        NSSL_CHK_CALL(setClientRetrieveTicketCb, s->instance, OSSL_retrieveSessionTicket);

    }
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Don't use RFC4507 ticket extension */
    if (!(s->ssl_ctx->options & SSL_OP_NO_TICKET))
    {
        if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_REQUEST_SESSION_TICKET, &requestTicket))
        {
            returnValue = 0;
            goto exit;
        }

        /* Saving PSK on client */
        SSL_set_psk_save_session_callback(s);
    }

    if ((NULL != s->orig_s.psk_use_session_cb) || (1 == s->registerRetrievePSK))
    {
        SSL_set_psk_use_session_callback(s, s->orig_s.psk_use_session_cb);
    }

    if (s->session != NULL)
    {
        if (pHostname)
        {
            /* Set TLS ServerName Extension */
            status = NSSL_CHK_CALL(setServerNameExtension, s->instance,(const char *)pHostname);
        }

        if ((s->session->ext.alpn_selected) && (s->session->ext.alpn_selected_len > 0 ))
        {
            if ((OK != SSL_set_alpn_protos(s, s->session->ext.alpn_selected, (unsigned int) s->session->ext.alpn_selected_len)))
            {
                returnValue = -1;
                goto exit;
            }
        }

        if (s->session->ssl_version)
        {
            /* Set version */
            status = NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_VERSION, (void*)((OSSL_UINT_PTR)OSSL_convert_minor_version_from_ossl(s->session->ssl_version)));
        }
    }

    if (1 == s->orig_s.ext.early_data)
    {
        ubyte4 sendEarlyData = 1;
        if (OK > NSSL_CHK_CALL(sslIoctl, s->instance, SSL_SET_SEND_EARLY_DATA, &sendEarlyData))
        {
            returnValue = 0;
            goto exit;
        }
    }

    if (s->orig_s.pha_enabled)
    {
        NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags);

        /* SSL_setSession flags resets the flags; So first get the flag value to preserve the previously set flags */
        NSSL_CHK_CALL(setSessionFlags, s->instance, (sslFlags) | SSL_FLAG_ENABLE_POST_HANDSHAKE_AUTH);
    }
#endif

    /* Check if client wants to send an OCSP request */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (TLSEXT_STATUSTYPE_ocsp == s->tlsext_status_type)
#else
    if (TLSEXT_STATUSTYPE_ocsp == s->orig_s.tlsext_status_type)
#endif
    {
        if (OK > NSSL_CHK_CALL(setCertifcateStatusRequestExtensions, s->instance, NULL, 0, NULL, 0))
        {
            return -1;
        }
    }

#ifndef __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__
       OSSL_setCertAndStatusCallBack(s);
       OSSL_setClientCertAuthorityCallback(s);
#endif /* __DISABLE_DIGICERT_SSL_CERTIFICATE_CALLBACK__ */
#ifdef __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__
      OSSL_setVersionCallback(s);
#endif /* __ENABLE_DIGICERT_SSL_VERSION_LOG_CALLBACK__ */

        /* Set the callback alert by default. This will allow proper handling of
         * alert messages.
         */
        OSSL_set_alert_cb(s);

        if (ctx->client_cert_cb != NULL)
        {
            if (OK > OSSL_setClientCertCallback(s))
            {
                returnValue = -1;
                goto exit;
            }

            if (OK > OSSL_setCertVerifySignCb(s))
            {
                status = -1;
                goto exit;
            }
        }

        if (OK > (status = moc_mutexWait(m_hashTableMutex)))
        {
            /*PRINT("RTOS_mutexWait() failed : %d\n", status);*/
            returnValue = -1;
            goto exit;
        }

        (void) NSSL_CHK_CALL(hashTableAddPtr, m_ssl_table, s->instance,(SSL *)s);

        if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
        {
            PRINT("RTOS_mutexRelease() failed : %d\n", status);
            returnValue = -1;
            goto exit;
        }

        if (NULL != s->tlsext_hostname)
        {
            /* Set TLS ServerName Extension */
            status = NSSL_CHK_CALL(setServerNameExtension, s->instance,(const char *)s->tlsext_hostname);
        }

      if((s->ssl_ctx->alpn_client_proto_list) && (s->ssl_ctx->alpn_client_proto_list_len > 0 ))
      {
            if ((OK != SSL_set_alpn_protos(s,s->ssl_ctx->alpn_client_proto_list,s->ssl_ctx->alpn_client_proto_list_len)))
            {
                returnValue = -1;
                goto exit;
            }
      }

      NSSL_CHK_CALL(getSessionFlags, s->instance, &sslFlags);

      /* Reset the flags before setting */
      sslFlags &= ~(SSL_FLAG_NO_MUTUAL_AUTH_REQUEST);
      sslFlags &= ~(SSL_FLAG_REQUIRE_MUTUAL_AUTH);

      /* @Note: verify the client enforces auth requirement from server */
      if (OK > (status = NSSL_CHK_CALL(setSessionFlags, s->instance, (sslFlags) | (authModeFlag) | SSL_FLAG_ENABLE_SEND_BUFFER | SSL_FLAG_ENABLE_RECV_BUFFER)))
      {
           returnValue = -1; /* XXX: cleanup instance */
           goto exit;
      }

#if !defined(__DISABLE_DIGICERT_OSSL_DEFAULT_TRUST_CERTS__)
      if (0 == sk_X509_OBJECT_num(ctx->cert_store->objs))
      {
          SSL_CTX_load_default_certs(ctx);
      }
      else
#endif
      {
          OSSL_CTX_load_x509_store(ctx);
      }

     OSSL_checkSha1CipherSupport(s);

     OSSL_checkDSACipherSupport(s);

    if (s->numCipherIds > 0)
    {
        if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, s->cipherIds, s->numCipherIds)))
        {
            returnValue = -1;
            goto exit;
        }
    }
    else
    {
        /* Choose default Cipher Suites */
        if ((ctx->numCipherIds < 1) || (ctx->cipher_list == NULL))
        {
            (void) SSL_CTX_set_cipher_list(ctx, SSL_DEFAULT_CIPHER_LIST);
        }
        if (ctx->numCipherIds > 0)
        {
            if (OK > (status = NSSL_CHK_CALL(setCiphers, s->instance, ctx->cipherIds, ctx->numCipherIds)))
            {
                returnValue = -1;
                goto exit;
            }
        }
        else
        {
            /* No Cipher Suites */
            returnValue = -1;
            goto exit;
        }
    }

    if (s->numEccCurves > 0)
    {
        ubyte4 i = 0;
        ubyte4 numCurves = s->numEccCurves;
        OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
        if (NULL == curvesList)
        {
            returnValue = -1;
            goto exit;
        }
        for (i = 0; i < numCurves; i++)
        {
            curvesList[i] = s->pEccCurves[i];
        }

        NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
        OSSL_FREE(curvesList);
    }
    else if (ctx->numEccCurves > 0)
    {
        ubyte4 i = 0;
        ubyte4 numCurves = ctx->numEccCurves;
        OSSL_tlsExtNamedCurves *curvesList = OSSL_MALLOC(numCurves * sizeof(OSSL_tlsExtNamedCurves));
        if (NULL == curvesList)
        {
            returnValue = -1;
            goto exit;
        }
        for (i = 0; i < numCurves; i++)
        {
            curvesList[i] = ctx->pEccCurves[i];
        }

        NSSL_CHK_CALL(setEccCurves, s->instance, curvesList, numCurves);
        OSSL_FREE(curvesList);
    }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
    {
        if (s->numSrtpProfileIds > 0)
        {
            NSSL_CHK_CALL(setSrtpProfiles, s->instance, s->srtpProfileIds, s->numSrtpProfileIds);
        }
        else
        {
            if (ctx->numSrtpProfileIds > 0)
            {
                NSSL_CHK_CALL(setSrtpProfiles, s->instance, ctx->srtpProfileIds, ctx->numSrtpProfileIds);
            }
        }
    }
#endif

      s->clientServerFlag    = SSL_CLIENT_FLAG;
     }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (SSL_ST_OK == s->orig_state)
#else
    if (SSL_ST_OK == s->orig_s.state)
#endif
    {
        returnValue = 1;
        goto exit;
    }

    retValue = NSSL_CHK_CALL(isEstablished, s->instance);
    if (1 == retValue)
    {
        s->sent_client_hello = 0;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        s->orig_state      = SSL_ST_OK;
#else
        s->orig_s.state      = SSL_ST_OK;
#endif
        returnValue = 1;
        goto exit;
    }
    else if (-1 == retValue)
    {
        SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
        return -1;
    }

     if (NULL == s->pHoldingBuf)
     {
        s->pHoldingBuf = OSSL_MALLOC(OSSL_MAX_SSL_RX_MSG_SZ);
        if (NULL == s->pHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            returnValue = -1;
            goto exit;
        }
        s->szHoldingBuf    = OSSL_MAX_SSL_RX_MSG_SZ;
        s->bytesRcvdRemaining    = 0;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
     }

     if (NULL == s->pTxHoldingBuf) {
        s->pTxHoldingBuf    = OSSL_MALLOC(OSSL_MAX_SSL_MSG_SZ);
        if (NULL == s->pTxHoldingBuf)
        {
            SSLerr(SSL_F_SSL_DO_HANDSHAKE,ERR_R_MALLOC_FAILURE);
            returnValue = -1;
            goto exit;
        }
        s->szTxHoldingBuf    = OSSL_MAX_SSL_MSG_SZ;
        s->bytesSentRemaining = 0;
        s->txHoldingBufOffset = 0;
     }

     /* In case of rehandshake, ClientHello is sent without explicitly invocation of triggerHello
      * It is prepared when processing Helloretry message and written out with BIO_write
      * So checking of sent_client_hello is only valid for the client Hello sent at
      * beginning of th econnection.
      * State is SSL_ST_OK once the initial connection is established.
      */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     if (!s->sent_client_hello && (s->orig_state != SSL_ST_RENEGOTIATE)) {
#else
     if (!s->sent_client_hello && (s->orig_s.state != SSL_ST_RENEGOTIATE)) {
#endif

        /*Notify that handshake is started*/
        if (cb != NULL)
            cb(s, SSL_CB_HANDSHAKE_START, 1);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            status = NSSL_CHK_CALL(triggerDtlsHello, s->instance);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
            {
                returnValue = -1;
                goto exit;
            }
        }
        else
#endif
        {
            status = NSSL_CHK_CALL(triggerHello, s->instance);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
            {
                returnValue = -1;
                goto exit;
            }
        }
        /* This returns ERR_SSL_NO_DATA_TO_SEND when there is nothing pending to be sent */
        mySendBufLen    = s->szTxHoldingBuf;

        status = OK;
        while (OK == status)
        {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
            if (OK > status)
                break;

            i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining = mySendBufLen - bytesSent;
                s->txHoldingBufOffset = bytesSent;
                returnValue = i;
                goto exit;
            }

            s->sent_client_hello = 1;
            mySendBufLen    = s->szTxHoldingBuf;
        }
     }
     while ( 0 == (retValue = NSSL_CHK_CALL(isEstablished, s->instance))) {
        if (0 == s->bytesRcvdRemaining) {
            s->io_state    = OSSL_IN_READ;
            s->orig_s.rwstate = SSL_READING;

            while( 0 >= (i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf)))
            {
                /* XXX: check errors
                 */
                if ((i < 0) || (!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
                {
                    returnValue = i;
                    goto exit;
                }
            }
            s->io_state    = 0;
            s->orig_s.rwstate = SSL_NOTHING;
            s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
            s->bytesRcvdRemaining    = i;
        }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif
        status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                 &pFirstUnusedByte, &bytesRemaining);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        if (OK > status) {

            asyncSendPendingData(s);
            convertMocStatusToSslErr(s, status, SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);

            returnValue = -1;
            goto exit;
        }
        if (0 == status)
        {
           s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
           s->bytesRcvdRemaining     = 0;
        } else
        {
            s->pFirstRcvdUnreadByte    = pFirstUnusedByte;
            s->bytesRcvdRemaining    = bytesRemaining;
        }


        if (s->bytesSentRemaining > 0)
        {
            i = asyncSendDataBio(
                s, s->pTxHoldingBuf + s->txHoldingBufOffset, s->bytesSentRemaining,
                &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining -= bytesSent;
                s->txHoldingBufOffset += bytesSent;
                return i;
            }

            s->bytesSentRemaining = 0;
            s->txHoldingBufOffset = 0;
        }

        /* Now send any pending bytes */
        mySendBufLen        = s->szTxHoldingBuf;
        status = OK;
        while (OK == status)
        {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif

            if (OK > status)
                break;

            i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining = mySendBufLen - bytesSent;
                s->txHoldingBufOffset = bytesSent;
                returnValue = i;
                goto exit;
            }

            mySendBufLen        = s->szTxHoldingBuf;
        }
     }
     if (-1 == retValue)
     {
        SSLerr(SSL_F_SSL3_CONNECT, ERR_R_INTERNAL_ERROR);
        return -1;
     }

     /* Notify that handshake is done*/
     if (cb != NULL)
        cb(s, SSL_CB_HANDSHAKE_DONE, 1);


#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     s->orig_state = SSL_ST_OK;
     s->orig_s.statem.state = MSG_FLOW_FINISHED;
     s->orig_s.statem.hand_state = TLS_ST_OK;
     s->orig_s.statem.in_init = 0;
#else
     s->orig_s.state = SSL_ST_OK;
#endif
     s->sent_client_hello = 0; /* reset for next cycle */
     returnValue = 1;

exit:
    return returnValue;
}

/*------------------------------------------------------------------*/

/* This function is called if there is leftover cleartext Rx data that
 * app. has not yet requested. If there is already a buffer to hold leftover
 * data and it has enough room for the new size, this function won't alloc
 * anything
 */
static MSTATUS
checkRxBuffer(SSL *s, ubyte4 size)
{
     ubyte    * newBuf = NULL, *to=NULL, *from=NULL;
     sbyte4    spaceNeeded, allocLen;

     if(s == NULL)
     {
        SSLerr(SSL_F_SSL_READ, SSL_R_UNINITIALIZED);
        return (MSTATUS) -1;
     }
     /* rxDataBufLen is the num of bytes remaining to be read */
     spaceNeeded = size - (s->rxDataBufSz - s->rxDataBufLen);
     if (spaceNeeded > 0) {
         allocLen = size + s->rxDataBufLen;
         if (NULL == (newBuf = OSSL_MALLOC(allocLen)))
         {
            SSLerr(SSL_F_SSL_READ, ERR_R_MALLOC_FAILURE);
            return (MSTATUS) -1;
         }

        to = newBuf;
        s->rxDataBufSz = allocLen;
     }
     else
     {
         to = s->pRxDataBuf;
     }

     if (s->rxDataBufLen > 0)
     {
      from = s->pRxDataBuf + s->rxDataBufOffset;
      memmove(to, from, s->rxDataBufLen);
     }

    if (newBuf)
    {
        if (s->pRxDataBuf)
            OSSL_FREE(s->pRxDataBuf);
        s->pRxDataBuf = newBuf;
    }

     s->rxDataBufOffset = 0;
     return (MSTATUS) OK;
}

/*------------------------------------------------------------------*/

extern int
SSL_read(SSL *s, void *buf, int num)
{
     unsigned char *pReadPtr = NULL, *pFirstUnusedByte = NULL;
     ubyte4        bytesAvail = 0;
     int           retCount= 0, toCopy=0, i, bytesSent=0;
     ubyte4        bytesRemaining = 0, protocol;
     int           numBytesRemaining = 0;
     sbyte4        status = 0;
     ubyte4 connState =0;
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
     int        mutexAcquired = 0;
#endif
     int        doHandshakeCount = 0;

     if (s == NULL) {
        SSLerr(SSL_F_SSL_READ, SSL_R_UNINITIALIZED);
        return -1;
     }

    /* If the shutdown signal was recieved from the peer then don't process
     * anymore data.
     */
    if (SSL_RECEIVED_SHUTDOWN & s->orig_s.shutdown)
    {
        return 0;
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if ( (SSL_EARLY_DATA_CONNECT_RETRY == s->orig_s.early_data_state) ||
         (SSL_EARLY_DATA_ACCEPT_RETRY  == s->orig_s.early_data_state )
       )
    {
        SSLerr(SSL_F_SSL_READ, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
#endif

     if ((MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance))
     {
         do
         {
             doHandshakeCount++;
             if(OK >= (status = SSL_do_handshake(s)))
                 return -1;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
        doHandshakeCount = 0;
        if (SSL_ST_OK != s->orig_state)
#else
        } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
        doHandshakeCount = 0;
        if (SSL_ST_OK != s->orig_s.state)
#endif
        {
            return -1;
        }
     }
     else
     {
        if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
            return -1;
        if ((connState == SSL_CONNECTION_NEGOTIATE) || (connState == SSL_CONNECTION_RENEGOTIATE))
        {
            if (connState == SSL_CONNECTION_RENEGOTIATE)
            {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                s->orig_state = SSL_ST_RENEGOTIATE;
#else
                s->orig_s.state = SSL_ST_RENEGOTIATE;
#endif
            }

            do
            {
                doHandshakeCount++;
                if(OK >= (status = SSL_do_handshake(s)))
                    return -1;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

            doHandshakeCount = 0;
            if (SSL_ST_OK != s->orig_state)
#else
            } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

            doHandshakeCount = 0;
            if (SSL_ST_OK != s->orig_s.state)
#endif
            {
                return -1;
            }
        }
     }

     if ((NULL == s->pHoldingBuf) || (NULL == s->pTxHoldingBuf)) {
        return -1;
     }
    /*
     * Special handling if SSL_accept received data that may not
     * have been processed yet
     */

    if (s->clientServerFlag == SSL_SERVER_FLAG)
    {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (NULL != s->session_mutex)
    {
        if (OK > moc_mutexWait(s->session_mutex))
            return -1;

        mutexAcquired = 1;
    }
#endif
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            status = NSSL_CHK_CALL(dtlsReadSslRec,s->instance, &pReadPtr, &bytesAvail, &protocol);
        }
        else
#endif
        {
            status = NSSL_CHK_CALL(readSslRec, s->instance, &pReadPtr, &bytesAvail, &protocol);
        }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        if (bytesAvail > 0)
        {
            goto process_rec;
        }
    }
     if (s->rxDataBufLen > 0) { /* Data left over from before */
        toCopy = (num <= (int)s->rxDataBufLen) ? num : (int)s->rxDataBufLen;
        memcpy(buf, s->pRxDataBuf + s->rxDataBufOffset, toCopy);
        s->rxDataBufLen     -= toCopy;
        s->rxDataBufOffset  += toCopy;
#ifdef __ENABLE_DIGICERT_READAHEAD_OPTIMIZATION__
        if (toCopy >= num)
        {
            return toCopy;
        }
        retCount    = toCopy;
        num         -= toCopy;
#else
        if (toCopy)
        {
            return toCopy;
        }
#endif /* __ENABLE_DIGICERT_READAHEAD_OPTIMIZATION__ */
     }
     /* If we're here, we have no left over data to give. Reset our
      * RxData buffer state
      */
      s->rxDataBufOffset    = 0; /* XXX: rxDataBufLen set to 0 already above */
     /* Get fresh TCP data from socket to look for SSL record */

#ifdef __ENABLE_DIGICERT_OSSL_MULTIPACKET_READ__
read_packet:
#endif
     do
     { /* Loop to read BIO */
      if (0 == s->bytesRcvdRemaining) {
        s->io_state    = OSSL_IN_READ;
        s->orig_s.rwstate = SSL_READING;

        /*
        i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf);
        if (i <= 0)
        {
            return i;
        }
        */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (!s->orig_s.rlayer.read_ahead)
#else
        if (!s->orig_s.read_ahead)
#endif
        {
            numBytesRemaining = 0;
            NSSL_CHK_CALL(recvPending, s->instance, &numBytesRemaining);
        }

        while( 0 >= ( i = BIO_read(s->rbio, s->pHoldingBuf, (((numBytesRemaining > 0) && (s->szHoldingBuf > numBytesRemaining)) ? numBytesRemaining : s->szHoldingBuf))))
        {

            if ((i < 0) || (!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
            {
                /* If we read the left over data which was smaller than num bytes,
                 * and BIO_read could not read anything, we should return the
                 * number of leftover btyes read and not the error */
#if (defined(__ENABLE_DIGICERT_OSSL_MULTIPACKET_READ__) || defined( __ENABLE_DIGICERT_READAHEAD_OPTIMIZATION__))
                if (retCount > 0)
                {
                    return retCount;
                }
                else
#endif
                {
                    if ((s->orig_s.shutdown & SSL_RECEIVED_SHUTDOWN) || (s->orig_s.shutdown & SSL_SENT_SHUTDOWN))
                    {
                        s->orig_s.rwstate       = SSL_NOTHING;
                        return 0; /* if we received SSL_RECEIVED_SHUTDOWN or SSL_SENT_SHUTDOWN, we can exit without error */
                    }
                    else
                    {
                        return i;
                    }
                }
            }
        }


        s->io_state             = 0;
        s->orig_s.rwstate       = SSL_NOTHING;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
        s->bytesRcvdRemaining   = i;
     }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (0 == mutexAcquired)
    {
        status = OSSL_sessionAcquireMutex(s);
        if (OK == status)
            mutexAcquired = 1;
    }
#endif

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
     if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
     {
        status = NSSL_CHK_CALL(dtlsParseSslBuf,s->instance,s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                &pFirstUnusedByte, &bytesRemaining);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        if (OK > status)
        {
            /* If some of the data was consumed, return the number of bytes consumed */
#if (defined(__ENABLE_DIGICERT_OSSL_MULTIPACKET_READ__) || defined( __ENABLE_DIGICERT_READAHEAD_OPTIMIZATION__))
            if (retCount > 0)
            {
                return retCount;
            }
#endif
            convertMocStatusToSslErr(s, status, SSL_F_DTLS1_READ_FAILED, ERR_R_INTERNAL_ERROR);
            return -1;
        }
     }
     else
#endif
     {
        status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                &pFirstUnusedByte, &bytesRemaining);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        if (OK > status)
        {
            /* If some of the data was consumed, return the number of bytes consumed */
#if (defined(__ENABLE_DIGICERT_OSSL_MULTIPACKET_READ__) || defined( __ENABLE_DIGICERT_READAHEAD_OPTIMIZATION__))
            if (retCount > 0)
            {
                return retCount;
            }
#endif
            convertMocStatusToSslErr(s, status, SSL_F_SSL_READ, ERR_R_INTERNAL_ERROR);
            return -1;
        }
     }

     if (NULL != pFirstUnusedByte) { /* 1 full record was extracted and processed */
      if (0 == bytesRemaining)
        {
           /* status set to count */
           s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
           s->bytesRcvdRemaining     = 0;
           break;
        }
        else
        {
           s->pFirstRcvdUnreadByte    = pFirstUnusedByte;
           s->bytesRcvdRemaining    = bytesRemaining;
           status = 1;
           break;
        }
      }
      else
      { /* full rec not present and all bytes were consumed */
        s->bytesRcvdRemaining     = 0; /* necessary; recvMessage2 does not update this */
        if(0 == bytesRemaining)
        {
            /* Incase of HANDSHAKE pending message */
            /* Now send any pending bytes */
            int mySendBufLen        = s->szTxHoldingBuf;

            if (s->bytesSentRemaining > 0)
            {
                i = asyncSendDataBio(
                    s, s->pTxHoldingBuf + s->txHoldingBufOffset, s->bytesSentRemaining,
                    &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining -= bytesSent;
                    s->txHoldingBufOffset += bytesSent;
                    return i;
                }

                s->bytesSentRemaining = 0;
                s->txHoldingBufOffset = 0;
            }

            status = OK;
            while (OK == status)
            {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (0 == mutexAcquired)
                {
                    status = OSSL_sessionAcquireMutex(s);
                    if (OK == status)
                        mutexAcquired = 1;
                }
#endif
                status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf,(ubyte4*) &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (1 == mutexAcquired)
                {
                    (void) OSSL_sessionReleaseMutex(s);
                    mutexAcquired = 0;
                }
#endif
                if (OK > status)
                    break;

                i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    return i;
                }

                mySendBufLen        = s->szTxHoldingBuf;
            }
        }
      }
     } while (0 == s->bytesRcvdRemaining);

    if (0 < status) {
        /* Valid record available to decrypt */
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            status = NSSL_CHK_CALL(dtlsReadSslRec,s->instance, &pReadPtr, &bytesAvail, &protocol);
        }
        else
#endif
        {
            status = NSSL_CHK_CALL(readSslRec, s->instance, &pReadPtr, &bytesAvail, &protocol);
        }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
process_rec:

        if ((bytesAvail > 0) && (pReadPtr != NULL))
        {
            toCopy = num > (int)bytesAvail ? (int)bytesAvail : num;
            memcpy((ubyte *)buf+retCount, pReadPtr, toCopy);
            retCount    += toCopy;
        }
        if ((bytesAvail > (ubyte4)toCopy) && (pReadPtr != NULL)) { /* store left over plaintext data */
            ubyte4    toKeep;
            toKeep    = (bytesAvail - toCopy);
            checkRxBuffer(s, toKeep); /* Sets rxDatabufOffset to 0 if it allocates */
            memcpy(s->pRxDataBuf + s->rxDataBufOffset + s->rxDataBufLen, pReadPtr + toCopy, toKeep);
            s->rxDataBufLen        += toKeep;
        }
#ifdef __ENABLE_DIGICERT_OSSL_MULTIPACKET_READ__
        else /* Check read Buffer bigger than the packet(s) read */
        {
            num -= bytesAvail;
            if ((num > 0)
#ifdef __ENABLE_DIGICERT_OSSL_MUTIPACKET_BIO_RETRY__

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            && ((s->bytesRcvdRemaining > 0) || ((0 == s->bytesRcvdRemaining) && (s->orig_s.rlayer.read_ahead))))
#else
            && ((s->bytesRcvdRemaining > 0) || ((0 == s->bytesRcvdRemaining) && (s->orig_s.read_ahead))))
#endif
#else
            && (s->bytesRcvdRemaining > 0))
#endif
            {
                /* Loop to read more packets */
                goto read_packet;
            }
        }
#endif
    }
    return retCount;
}


/*------------------------------------------------------------------*/

extern int
SSL_write(SSL *s, const void *buf, int num)
{
     sbyte4    bytesSent=0;
     sbyte4    status = OK;
     ubyte4    mySendBufLen = 0;
     sbyte4    holdingBufOffset = 0;
     ubyte4    connState = 0;
     int    i, toSend = num, dataSent = 0;
     sbyte    * pCurPtr = (sbyte *)buf;
     sbyte4    bytesConsumed = 0; /* Total bytes encrypted */
#ifdef __ENABLE_OSSL_ZERO_COPY__
     ubyte    * pOutBuf = NULL;
#endif
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
     int        mutexAcquired = 0;
#endif
     int        doHandshakeCount = 0;
    if(s == NULL)
    {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (num < 0)
    {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_BAD_LENGTH);
        return -1;
    }

    /* If a shutdown notification was sent by us then don't send any data.
     */
    if (SSL_SENT_SHUTDOWN & s->orig_s.shutdown)
    {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return -1;
    }

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED == s->instance)
    {
        do
        {
            doHandshakeCount++;
            if(OK >= (status = SSL_do_handshake(s)))
                return -1;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

        doHandshakeCount = 0;
        if (SSL_ST_OK != s->orig_state)
#else
        } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

        doHandshakeCount = 0;
        if (SSL_ST_OK != s->orig_s.state)
#endif
        {
            return -1;
        }
    }
    else
    {
        if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
            return -1;

        if ((connState == SSL_CONNECTION_NEGOTIATE) || (connState == SSL_CONNECTION_RENEGOTIATE))
        {
            if (connState == SSL_CONNECTION_RENEGOTIATE)
            {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                s->orig_state = SSL_ST_RENEGOTIATE;
#else
                s->orig_s.state = SSL_ST_RENEGOTIATE;
#endif
            }

            do
            {
                doHandshakeCount++;
                if(OK >= (status = SSL_do_handshake(s)))
                    return -1;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

            doHandshakeCount = 0;
            if (SSL_ST_OK != s->orig_state)
#else
            } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);

            doHandshakeCount = 0;
            if (SSL_ST_OK != s->orig_s.state)
#endif
            {
                return -1;
            }
        }
    }

    /* Pick any bytes from previous attempt */
    bytesConsumed = s->applBytesEncoded;

    /* Application attempts to write with the same buffer since all the bytes have not been written;
     * Move the pointers to send out the remaining consumed bytes correctly
     */
    pCurPtr      += bytesConsumed;
    toSend       -= bytesConsumed;

    if (bytesConsumed > 0)
    {
        if ((s->pPendingBuffer != buf) && !(SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER & s->orig_s.mode))
        {
            s->applBytesEncoded = 0;
            /* If there is data pending and the buffer pointer has been moved, throw an error */
            SSLerr(SSL_F_SSL3_WRITE_PENDING, SSL_R_BAD_WRITE_RETRY);
            return -1;
        }
    }

    s->pPendingBuffer = (ubyte *) buf;

    /* Handling for BIO_write failure in the previous attempt */
    /* Current logic will only make one attempt */
    /* Send the bytes already in s->pTxHoldingBuf */
     if (s->bytesSentRemaining > 0)
     {
       holdingBufOffset = s->txHoldingBufOffset;
       mySendBufLen = s->bytesSentRemaining;

       i = asyncSendDataBio(
           s, s->pTxHoldingBuf + holdingBufOffset, mySendBufLen, &bytesSent);
        if (0 >= i)
        {
            s->bytesSentRemaining -= bytesSent;
            s->txHoldingBufOffset += bytesSent;
            return i;
        }

       s->bytesSentRemaining = 0;
       s->txHoldingBufOffset = 0;
       s->applBytesEncoded = 0;

       /* After bytes in s->pTxHoldingBuf (populated in previous SSL_write attempt) are sent,
        * check if we have any more already consumed bytes to send.
        */
       goto sendPendingData;
    }

    mySendBufLen    = s->szTxHoldingBuf;

    /* Even if we dont have any new data to send, we might have some pending data to send;
     * This condition checks for that and attempts to send the pending data
     */
    if (toSend == 0)
    {
        goto sendPendingData;
    }

    while (toSend > 0)
    {
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            /* Make sure to send any pending data. This will empty the o/p buffer.
             * If the o/p buffer is not empty then DTLS_sendMessage will fail with
             * ERR_SSL_SEND_BUFFER_NOT_EMPTY, as there is explicit check for DTLS
             * o/p buffer not empty. This is unlike with TCP */
            status = OK;
            while ( OK == status)
            {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (0 == mutexAcquired)
                {
                    status = OSSL_sessionAcquireMutex(s);
                    if (OK == status)
                        mutexAcquired = 1;
                }
#endif
                status = NSSL_CHK_CALL(dtlsGetSendBuffer,s->instance, s->pTxHoldingBuf,&mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (1 == mutexAcquired)
                {
                    (void) OSSL_sessionReleaseMutex(s);
                    mutexAcquired = 0;
                }
#endif
                if (OK > status)
                    break;

                i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    s->applBytesEncoded = bytesConsumed;
                    return i;
                }

                mySendBufLen    = s->szTxHoldingBuf;
            }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(dtlsSendMessage,s->instance, (sbyte *)pCurPtr, (sbyte4)toSend, &bytesSent);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif

        }
        else
#endif
        {
            status = OK;
            while (OK == status)
            {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (0 == mutexAcquired)
                {
                    status = OSSL_sessionAcquireMutex(s);
                    if (OK == status)
                        mutexAcquired = 1;
                }
#endif
                status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf,&mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (1 == mutexAcquired)
                {
                    (void) OSSL_sessionReleaseMutex(s);
                    mutexAcquired = 0;
                }
#endif
                if (OK > status)
                    break;

                i = asyncSendDataBio(s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    s->applBytesEncoded = bytesConsumed;
                    return -1;
                }

                mySendBufLen    = s->szTxHoldingBuf;
            }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (0 == mutexAcquired)
            {
                status = OSSL_sessionAcquireMutex(s);
                if (OK == status)
                    mutexAcquired = 1;
            }
#endif
            status = NSSL_CHK_CALL(prepareSslRec, s->instance, (sbyte *)pCurPtr, (sbyte4)toSend, &bytesSent);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
            if (1 == mutexAcquired)
            {
                (void) OSSL_sessionReleaseMutex(s);
                mutexAcquired = 0;
            }
#endif
        }

        if (OK > status)
        {
            if (ERR_SSL_NEGOTIATION_STATE == status )
            {
                if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
                {
                    return -1;
                }

                if ((connState == SSL_CONNECTION_NEGOTIATE) || (connState == SSL_CONNECTION_RENEGOTIATE))
                {
                    if (connState == SSL_CONNECTION_RENEGOTIATE)
                    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                        s->orig_state = SSL_ST_RENEGOTIATE;
#else
                        s->orig_s.state = SSL_ST_RENEGOTIATE;
#endif
                    }

                    if (connState == SSL_CONNECTION_NEGOTIATE)
                    {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                        s->orig_state = (s->clientServerFlag == SSL_CLIENT_FLAG) ? SSL_ST_CONNECT : SSL_ST_ACCEPT;
#else
                        s->orig_s.state = (s->clientServerFlag == SSL_CLIENT_FLAG) ? SSL_ST_CONNECT : SSL_ST_ACCEPT;
#endif
                    }

                    do
                    {
                        doHandshakeCount++;
                        if(OK >= (status = SSL_do_handshake(s)))
                            return -1;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                    } while (SSL_ST_OK != s->orig_state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
#else
                    } while (SSL_ST_OK != s->orig_s.state && doHandshakeCount < MAX_HANDSHAKE_ATTEMPT);
#endif

                    doHandshakeCount = 0;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
                    if (SSL_ST_OK != s->orig_state)
#else
                    if (SSL_ST_OK != s->orig_s.state)
#endif
                    {
                        return -1;
                    }
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                    if (NULL != s->session_mutex)
                    {
                        if (OK > moc_mutexWait(s->session_mutex))
                            return -1;

                        mutexAcquired = 1;
                    }
#endif

                }
            }
            if (ERR_SSL_SEND_BUFFER_NOT_EMPTY == status)
            {
                /* If there is still data in the buffer, force sending of the remaining data */
                goto sendPendingData;
            }
            else
            {
                return -1;
            }
        }
        else
        {
            toSend        -= bytesSent;
            pCurPtr       += bytesSent;
            bytesConsumed += bytesSent;
        }

        #ifndef __ENABLE_OSSL_ZERO_COPY__
        mySendBufLen        = s->szTxHoldingBuf;

        /* Handle DTLS seperately. In case we need DTLS_send instead of BIO,
         * it is to be implemented. DTLS_send would require UDP descriptor.
         */

sendPendingData:
        status = OK;
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
        if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
        {
            while ( OK == status)
            {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (0 == mutexAcquired)
                {
                    status = OSSL_sessionAcquireMutex(s);
                    if (OK == status)
                        mutexAcquired = 1;
                }
#endif
                status = NSSL_CHK_CALL(dtlsGetSendBuffer,s->instance, s->pTxHoldingBuf,&mySendBufLen);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (1 == mutexAcquired)
                {
                    (void) OSSL_sessionReleaseMutex(s);
                    mutexAcquired = 0;
                }
#endif
                if (OK != status)
                    break;

                i = asyncSendDataBio(
                    s, s->pTxHoldingBuf, mySendBufLen, &bytesSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - bytesSent;
                    s->txHoldingBufOffset = bytesSent;
                    s->applBytesEncoded = bytesConsumed;
                    return i;
                }

                mySendBufLen    = s->szTxHoldingBuf;
            }
        }
        else
#endif
        {
            status = OK;
            while (OK == status)
            {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (0 == mutexAcquired)
                {
                    status = OSSL_sessionAcquireMutex(s);
                    if (OK == status)
                        mutexAcquired = 1;
                }
#endif
                status = NSSL_CHK_CALL(getPreparedSslRec, s->instance, s->pTxHoldingBuf, &mySendBufLen);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
                if (1 == mutexAcquired)
                {
                    (void) OSSL_sessionReleaseMutex(s);
                    mutexAcquired = 0;
                }
#endif
                if (OK != status)
                    break;

                i = asyncSendDataBio(
                    s, s->pTxHoldingBuf, mySendBufLen, &dataSent);
                if (0 >= i)
                {
                    s->bytesSentRemaining = mySendBufLen - dataSent;
                    s->txHoldingBufOffset = dataSent;
                    s->applBytesEncoded = bytesConsumed;
                    return i;
                }

                mySendBufLen    = s->szTxHoldingBuf;
            }
        }

        #else
        status = NSSL_CHK_CALL(getPreparedSslRecZC, s->instance, &pOutBuf, &mySendBufLen);

        if ((OK == status) && (mySendBufLen > 0))
        {
            i = asyncSendDataBio(s, pOutBuf, mySendBufLen, &bytesSent);
            if (0 >= i)
            {
                s->bytesSentRemaining = mySendBufLen - bytesSent;
                s->txHoldingBufOffset = bytesSent;
                s->applBytesEncoded = bytesConsumed;
                return i;
            }
        }
        NSSL_CHK_CALL(releaseZCsendBuffer, s->instance, 0);
        #endif

        /* If this flag is enabled, exit after writing 1 block of application data */
        if (SSL_MODE_ENABLE_PARTIAL_WRITE & s->orig_s.mode)
        {
            goto exit;
        }
    }

exit:
    s->applBytesEncoded = 0;
    return bytesConsumed;
}
/*---------------------------------------------------------------------------*/

static MSTATUS
allocSslTable(void *pHashCookiee, hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = (MSTATUS) OK;
    if (NULL == (*ppRetNewHashElement = OSSL_MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
freeSslTable(void *pHashCookiee, hashTablePtrElement *pFreeHashElement)
{
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    OSSL_FREE(pFreeHashElement);

    return (MSTATUS) OK;
}

/*------------------------------------------------------------------*/

static int OSSL_init(void);

#if defined(__RTOS_VXWORKS__) && !defined(IPSSL)
/* Note: VxWorks 6.9 Component IPSSL overrides SSL_library_init() */
extern int
SSL_library_init(void)
{
    return ssl_library_init();
}
#endif

#ifdef __RTOS_VXWORKS__
static int
ssl_library_init(void)
#else
extern int
SSL_library_init(void)
#endif
{
     int rval = 1;

#if defined(__ENABLE_DIGICERT_OSSL_LOAD_ALL_ALGORITHMS__)
    OpenSSL_add_all_algorithms();
#endif

     if (g_initialized)
        return rval;

     g_initialized = 1;

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__) && defined(__ENABLE_DIGICERT_FIPS_FORCE_SELFTEST__)
    FIPS_powerupSelfTest();
#endif

     rval = OSSL_bindMethods(&gNsslMethods);
     if (rval <=0)
        goto exit;

     gNsslMethodsValid    = 1;

     (void) NSSL_CHK_CALL(hashTableCreatePtrsTable, &m_ssl_table, 63, pHashCookie, allocSslTable, freeSslTable);

	if (OK > (rval = moc_mutexCreate(&m_connectionCountMutex, 0, 0)))
    {
        rval = 0;
        goto exit;
    }
	if (OK > (rval = moc_mutexCreate(&m_hashTableMutex, 0, 0)))
    {
        rval = 0;
        goto exit;
    }

    rval = OSSL_init();
exit:
     return 1;
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
DEFINE_RUN_ONCE_STATIC(ossl_init_ssl_base)
{
    /* initialize cipher/digest methods table for OpenSSL connector */
    ssl_load_ciphers();

    OPENSSL_load_builtin_modules();
    /*
     * We ignore an error return here. Not much we can do - but not that bad
     * either. We can still safely continue.
     */
    OPENSSL_atexit(ssl_library_stop);
    ssl_base_inited = 1;
    return 1;
}

DEFINE_RUN_ONCE_STATIC(ossl_init_load_ssl_strings)
{
    /* This loads the standard OpenSSL SSL errors; We do not need that */
    ssl_strings_inited = 1;
    return 1;
}

static void ssl_library_stop(void)
{
    /* Might be explicitly called and also by atexit */
    if (stopped)
        return;

    stopped = 1;

    /* This is the clean we need for OpenSSL connector layer and NanoSSL */
    if (g_initialized)
    {
        OSSL_shutdown();

        /* Mutex cleanup added assuming this call is associated with the destructor flow */
        if (m_hashTableMutex)
        {
            moc_mutexFree(&m_hashTableMutex);
            m_hashTableMutex = NULL;
        }

        if (m_connectionCountMutex)
        {
            moc_mutexFree(&m_connectionCountMutex);
            m_connectionCountMutex = NULL;
        }
    }
}

/*
 * If this function is called with a non NULL settings value then it must be
 * called prior to any threads making calls to any OpenSSL functions,
 * i.e. passing a non-null settings value is assumed to be single-threaded.
 */
int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS * settings)
{
    static int stoperrset = 0;

    if (stopped)
    {
        if (!stoperrset)
        {
            stoperrset = 1;
            SSLerr(SSL_F_OPENSSL_INIT_SSL, ERR_R_INIT_FAIL);
        }
        return 0;
    }

    /* initialize SSL library */
    SSL_library_init();

    opts |= OPENSSL_INIT_ADD_ALL_CIPHERS
         |  OPENSSL_INIT_ADD_ALL_DIGESTS;

    if (!OPENSSL_init_crypto(opts, settings))
        return 0;

    if (!RUN_ONCE(&ssl_base, ossl_init_ssl_base))
        return 0;

    if ((opts & OPENSSL_INIT_LOAD_SSL_STRINGS)
        && !RUN_ONCE(&ssl_strings, ossl_init_load_ssl_strings))
        return 0;

#if defined(__ENABLE_DIGICERT_SSL_PEM_READ_BIO_REDEFINE__)
    if (!register_pem_bio_handler())
        return 0;
#endif

    return 1;
}

/* SSL_set1_host() sets the expected DNS hostname to name clearing any previously
 * specified host name or names. If name is NULL, or the empty string the list of
 * hostnames is cleared, and name checks are not performed on the peer certificate.
 * When a non-empty name is specified, certificate verification automatically checks
 * the peer hostname via X509_check_host(3) with flags as specified via SSL_set_hostflags().
 * return 1 for success and 0 for failure.
 */

int SSL_set1_host(SSL *pSsl, const char *pHostname)
{
    if ((NULL == pSsl) || (NULL == pSsl->orig_s.param))
    {
        return 0;
    }

    if (0 == SSL_set_tlsext_host_name(pSsl, pHostname))
    {
        return 0;
    }

    return X509_VERIFY_PARAM_set1_host(pSsl->orig_s.param, pHostname, 0);
}

/* SSL_add1_host() adds name as an additional reference identifier that can match the
 * peer's certificate.Any previous names set via SSL_set1_host() or SSL_add1_host() are
 * retained, no change is made if name is NULL or empty. When multiple names are configured,
 * the peer is considered verified when any name matches.
 * return 1 for success and 0 for failure.
 */

int SSL_add1_host(SSL *pSsl, const char *pHostname)
{
    if ((NULL == pSsl) || (NULL == pSsl->orig_s.param))
    {
        return 0;
    }

    /* NanoSSL supports only one hostname, it overwrites host name
     */
    if (0 == SSL_set_tlsext_host_name(pSsl, pHostname))
    {
        return 0;
    }

    return X509_VERIFY_PARAM_add1_host(pSsl->orig_s.param, pHostname, 0);
}

/* SSL_set_hostflags() sets the flags that will be passed to X509_check_host(3)
 * when name checks are applicable,by default the flags value is 0.
 * See X509_check_host(3) for the list of available flags and their meaning.
 */

void SSL_set_hostflags(SSL *pSsl, unsigned int flags)
{
    if ((NULL == pSsl) || (NULL == pSsl->orig_s.param))
    {
        return;
    }

    X509_VERIFY_PARAM_set_hostflags(pSsl->orig_s.param, flags);
}

/* SSL_get0_peername() returns the DNS hostname or subject CommonName from the peer
 * certificate that matched one of the reference identifiers. When wildcard matching
 * is not disabled, the name matched in the peer certificate may be a wildcard name.
 * When one of the reference identifiers configured via SSL_set1_host() or SSL_add1_host()
 * starts with ".", which indicates a parent domain prefix rather than a fixed name,
 * the matched peer name may be a sub-domain of the reference identifier. The returned
 * string is allocated by the library and is no longer valid once the associated ssl
 * handle is cleared or freed, or a renegotiation takes place. Applications must not
 * free the return value.
 * function returns NULL no trusted peername was matched. Otherwise, it returns the
 * matched peername.
 */

const char *SSL_get0_peername(SSL *pSsl)
{
    if ((NULL == pSsl) || (NULL == pSsl->orig_s.param))
    {
        return NULL;
    }

    return X509_VERIFY_PARAM_get0_peername(pSsl->orig_s.param);
}

int SSL_CTX_dane_enable(SSL_CTX *ctx)
{
    return 0; /* @Note : unsupported */
}

int SSL_CTX_dane_mtype_set(SSL_CTX *ctx, const EVP_MD *md,
                        uint8_t mtype, uint8_t ord)
{
    return 0; /* @Note : unsupported */
}

int SSL_dane_enable(SSL *s, const char *basedomain)
{
    return 0; /* @Note : unsupported */
}

int SSL_dane_tlsa_add(SSL *s, uint8_t usage, uint8_t selector,
                    uint8_t mtype, const unsigned char *data, size_t dlen)
{
    return 0; /* @Note : unsupported */
}

int SSL_get0_dane_authority(SSL *s, X509 **mcert, EVP_PKEY **mspki)
{
    return -1; /* @Note : unsupported */
}

int SSL_get0_dane_tlsa(SSL *s, uint8_t *usage, uint8_t *selector,
                    uint8_t *mtype, const unsigned char **data,
                    size_t *dlen)
{
    return -1; /* @Note : unsupported */
}

unsigned long SSL_CTX_dane_set_flags(SSL_CTX *ctx, unsigned long flags)
{
    return 0; /* @Note : unsupported */
}

unsigned long SSL_CTX_dane_clear_flags(SSL_CTX *ctx, unsigned long flags)
{
    return 0; /* @Note : unsupported */
}

unsigned long SSL_dane_set_flags(SSL *ssl, unsigned long flags)
{
    return 0; /* @Note : unsupported */
}

unsigned long SSL_dane_clear_flags(SSL *ssl, unsigned long flags)
{
    return 0; /* @Note : unsupported */
}

#endif

extern int
OSSL_dummy(void)
{

/* Allows to include the definitions in libraries statically linked to
libcrypto */

#ifdef OPENSSL_LOAD_CONF
  OPENSSL_add_all_algorithms_noconf();
#else
  OPENSSL_add_all_algorithms_noconf();
#endif

  return 0;
}


/*------------------------------------------------------------------*/

extern unsigned long SSLeay(void)
{
    return OPENSSL_VERSION_NUMBER;
}

static unsigned long swapBits(unsigned long n, unsigned int p1, unsigned int p2)
{
  return (((n >> p1) & 1) == ((n >> p2) & 1) ? n : ((n ^ (1 << p2)) ^ (1 << p1)));
}


static int getCurveIdFromNID(int nid)
{
    /* These are all the NIDs supported by nanoSSL;
     * Refer to OSSL_tlsExtNamedCurves enum in src/openssl_wrapper/openssl_shim.h
     */
    switch (nid)
    {
        case NID_X9_62_prime192v1: /* secp192r1 (19) */
            return 19;
        case NID_secp224r1:        /* secp224r1 (21) */
            return 21;
        case NID_X9_62_prime256v1: /* secp256r1 (23) */
            return 23;
        case NID_secp384r1:        /* secp384r1 (24) */
            return 24;
        case NID_secp521r1:        /* secp521r1 (25) */
            return 25;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case NID_X25519:          /* x25519 (29) */
            return 29;
        case NID_X448:            /* x448 (30) */
            return 30;
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        case NID_ffdhe2048:       /* ffdhe2048 (256) */
            return 256;
        case NID_ffdhe3072:       /* ffdhe3072 (257) */
            return 257;
        case NID_ffdhe4096:       /* ffdhe4096 (258) */
            return 258;
        case NID_ffdhe6144:       /* ffdhe6144 (259) */
            return 259;
        case NID_ffdhe8192:       /* ffdhe8192 (260) */
            return 260;
#endif
        default:
            return 0;
    }
}

static int getCurveNIDFromCurveName(const char *name)
{
    if (!strcmp("P-192", name))
    {
        return NID_X9_62_prime192v1;
    }
    else if (!strcmp("P-224", name))
    {
        return NID_secp224r1;
    }
    else if (!strcmp("P-256", name))
    {
        return NID_X9_62_prime256v1;
    }
    else if (!strcmp("P-384", name))
    {
        return NID_secp384r1;
    }
    else if (!strcmp("P-521", name))
    {
        return NID_secp521r1;
    }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    else if (!strcmp("X25519", name))
    {
        return NID_X25519;
    }
    else if (!strcmp("X448", name))
    {
        return NID_X448;
    }
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    else if (!strcmp("ffdhe2048", name))
    {
        return NID_ffdhe2048;
    }
    else if (!strcmp("ffdhe3072", name))
    {
        return NID_ffdhe3072;
    }
    else if (!strcmp("ffdhe4096", name))
    {
        return NID_ffdhe4096;
    }
    else if (!strcmp("ffdhe6144", name))
    {
        return NID_ffdhe6144;
    }
    else if (!strcmp("ffdhe8192", name))
    {
        return NID_ffdhe8192;
    }
#endif
    else
    {
        return NID_undef;
    }
}

static int setEccCurves(ubyte2 **ppEccCurves, ubyte4 *pNumEccCurves,
                           int *pCurves, size_t numCurves)
{
    ubyte4 i;
    ubyte4 count = 0;
    ubyte2 eccCurves[MAX_NUM_ECCCURVES] = { 0 };

    if (ppEccCurves == NULL)
        return 0;

    if (*ppEccCurves != NULL)
    {
        OSSL_FREE(*ppEccCurves);
    }

    *ppEccCurves = OSSL_MALLOC(numCurves * sizeof(ubyte2));
    if (NULL == *ppEccCurves)
    {
        return 0;
    }
    for (i = 0; i < numCurves; i++)
    {
        int id;
        id = getCurveIdFromNID(pCurves[i]);
        eccCurves[count++] = id;
    }

    memcpy(*ppEccCurves, eccCurves, count * sizeof(ubyte2));
    *pNumEccCurves = count;
    return 1;
}

static int setEccCurvesFromString(ubyte2 **ppEccCurves, ubyte4 *pNumEccCurves,
                                  const char *pEccCurvesStr)
{
    const char separator[2] = ":";
    int curves[MAX_NUM_ECCCURVES] = {0};
    int numCurves = 0;
    char *pCurveName = NULL;

    pCurveName = (char *)strtok((char *) pEccCurvesStr, separator);

    while (pCurveName != NULL)
    {
        curves[numCurves] = getCurveNIDFromCurveName(pCurveName);
        numCurves++;

        pCurveName = strtok(NULL, separator);
    }

    return setEccCurves(ppEccCurves, pNumEccCurves, curves, numCurves);
}

static void parseSignAndHashString(ubyte *pSig, ubyte *pHash, char *str)
{
    ubyte parseHash = 1;
    char *pStr = NULL;
    char *pSavedPointer = NULL;
#if defined(__RTOS_WIN32__)
    pStr = strtok_s(str, "+", &pSavedPointer);
#else
    pStr = strtok_r(str, "+", &pSavedPointer);
#endif

    /* Signature */
    if (NULL != pStr)
    {
        if (strcmp(pStr, "RSA") == 0)
        {
            *pSig = OSSL_TLS_RSA;
        }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        else if (strcmp(pStr, "RSA-PSS") == 0 || strcmp(pStr, "PSS") == 0)
        {
            *pHash = TLS_INTRINSIC;
            parseHash = 0;
#if defined(__RTOS_WIN32__)
            pStr = strtok_s(NULL, "+", &pSavedPointer);
#else
            pStr = strtok_r(NULL, "+", &pSavedPointer);
#endif
            if (strcmp(pStr, "SHA256") == 0)
            {
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA256;
            }
            else if (strcmp(pStr, "SHA384") == 0)
            {
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA384;
            }
            else if (strcmp(pStr, "SHA3512") == 0)
            {
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA512;
            }
        }
#endif
        else if (strcmp(pStr, "DSA") == 0)
        {
            *pSig = OSSL_TLS_DSA;
        }
        else if (strcmp(pStr, "ECDSA") == 0)
        {
            *pSig = OSSL_TLS_ECDSA;
        }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        else if (strcmp(pStr, "ED25519") == 0)
        {
            *pHash = TLS_INTRINSIC;
            *pSig = OSSL_TLS_EDDSA25519;
            parseHash = 0;
        }
        else if (strcmp(pStr, "ED448") == 0)
        {
            *pHash = TLS_INTRINSIC;
            *pSig = OSSL_TLS_EDDSA448;
            parseHash = 0;
        }
#endif

        /* Hash */
        if (parseHash)
        {
#if defined(__RTOS_WIN32__)
            pStr = strtok_s(NULL, "+", &pSavedPointer);
#else
            pStr = strtok_r(NULL, "+", &pSavedPointer);
#endif
            if (NULL != pStr)
            {
                if (strcmp(pStr, "SHA1") == 0)
                {
                    *pHash = TLS_SHA1;
                }
                else if (strcmp(pStr, "SHA224") == 0)
                {
                    *pHash = TLS_SHA224;
                }
                else if (strcmp(pStr, "SHA256") == 0)
                {
                    *pHash = TLS_SHA256;
                }
                else if (strcmp(pStr, "SHA384") == 0)
                {
                    *pHash = TLS_SHA384;
                }
                else if (strcmp(pStr, "SHA512") == 0)
                {
                    *pHash = TLS_SHA512;
                }
            }
        }
    }
}

static void parseSignAndHash(ubyte *pSig, ubyte *pHash, int pInHash, int pInSig)
{
    ubyte parseHash = 1;

    if (EVP_PKEY_RSA == pInSig)
    {
        *pSig = OSSL_TLS_RSA;
    }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    else if ( EVP_PKEY_RSA_PSS == pInSig)
    {
        *pHash = TLS_INTRINSIC;
        parseHash = 0;
        switch (pInHash)
        {
            case NID_sha256:
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA256;
                break;
            case NID_sha384:
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA384;
                break;
            case NID_sha512:
                *pSig = OSSL_TLS_13_RSA_PSS_PSS_SHA512;
                break;
            default:
                break;
        }
    }
#endif
    else if (EVP_PKEY_DSA == pInSig)
    {
        *pSig = OSSL_TLS_DSA;
    }
    else if (EVP_PKEY_EC == pInSig)
    {
        *pSig = OSSL_TLS_ECDSA;
    }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    else if (NID_ED25519 == pInSig)
    {
        *pHash = TLS_INTRINSIC;
        *pSig = OSSL_TLS_EDDSA25519;
        parseHash = 0;
    }
    else if (NID_ED448 == pInSig)
    {
        *pHash = TLS_INTRINSIC;
        *pSig = OSSL_TLS_EDDSA448;
        parseHash = 0;
    }
#endif

    if (parseHash)
    {
        if (NID_sha1 == pInHash)
        {
            *pHash = TLS_SHA1;
        }
        else if (NID_sha224 == pInHash)
        {
            *pHash = TLS_SHA224;
        }
        else if (NID_sha256 == pInHash)
        {
            *pHash = TLS_SHA256;
        }
        else if (NID_sha384 == pInHash)
        {
            *pHash = TLS_SHA384;
        }
        else if (NID_sha512 == pInHash)
        {
            *pHash = TLS_SHA512;
        }
    }
}

#define MAX_SIGNATURE_ALGORITHMS 64

static int setCtxSignatureAlgorithmsInternal(SSL_CTX *pCtx, ubyte2 *pSigAlgoList, ubyte4 sigAlgoListLen)
{
    ubyte2 *pConfSigAlgos = NULL;

    if (NULL == pCtx)
    {
        return 0;
    }

    if (NULL == pCtx->orig_ssl_ctx.cert)
    {
        return 0;
    }

    memset(pCtx->orig_ssl_ctx.cert, 0x00, sizeof(struct cert_st));

    pConfSigAlgos = OSSL_MALLOC(sizeof(ubyte2) * (sigAlgoListLen));

    if (NULL == pConfSigAlgos)
    {
        return 0;
    }

    memset(pConfSigAlgos, 0x00, (sizeof(ubyte2) * (sigAlgoListLen)));

    memcpy(pConfSigAlgos, pSigAlgoList, (sizeof(ubyte2) * (sigAlgoListLen)));

    if (pCtx->orig_ssl_ctx.cert->conf_sigalgs != NULL)
    {
        OSSL_FREE(pCtx->orig_ssl_ctx.cert->conf_sigalgs);
    }

    pCtx->orig_ssl_ctx.cert->conf_sigalgs = pConfSigAlgos;
    pCtx->orig_ssl_ctx.cert->conf_sigalgslen = sigAlgoListLen;

    return 1;
}

static int setCtxSignatureAlgorithms(SSL_CTX *pCtx, int *pSigAlgoList, ubyte4 sigAlgoListLen)
{
    ubyte2 signatureAlgorithm[MAX_SIGNATURE_ALGORITHMS] = { 0 };
    ubyte4 i = 0;
    ubyte4 index = 0;
    while( i < sigAlgoListLen)
    {
        ubyte sign = 0, hash = 0;
        parseSignAndHash(&sign, &hash, pSigAlgoList[i], pSigAlgoList[i + 1]);
        i += 2;
        signatureAlgorithm[index++] = ((ubyte)hash << 8 | (ubyte)sign);
    }

    return setCtxSignatureAlgorithmsInternal(pCtx, signatureAlgorithm, index);
}

static int setCtxSignatureAlgorithmsList(SSL_CTX *pCtx, const char *pStr)
{
    char *pSigHashString = NULL;
    char *pNextString = NULL;
    ubyte2 signatureAlgorithm[MAX_SIGNATURE_ALGORITHMS] = { 0 };
    ubyte4 index = 0;
    ubyte4 size;
    char *pAlgoList = NULL;
    int rval = 0;

    if ((NULL == pCtx) || (NULL == pStr))
    {
        return 0;
    }

    size = strlen(pStr);

    if (0 >= size)
    {
        return 0;
    }

    pAlgoList = (char*) OSSL_MALLOC(size + 1);
    if (NULL == pAlgoList)
    {
        return 0;
    }

    memset(pAlgoList, 0x00, size + 1);
    memcpy(pAlgoList, pStr, size);

#if defined(__RTOS_WIN32__)
    pSigHashString = strtok_s(pAlgoList, ":", &pNextString);
#else
    pSigHashString = strtok_r(pAlgoList, ":", &pNextString);
#endif

    while(pSigHashString != NULL)
    {
        ubyte4 len = strlen(pSigHashString);
        char *pTempStr = NULL;
        ubyte sign = 0, hash = 0;

        pTempStr = OSSL_CALLOC(len + 1, 1);
        if (NULL == pTempStr)
        {
            goto exit;
        }
        memcpy(pTempStr, pSigHashString, len);

        parseSignAndHashString(&sign, &hash, pTempStr);
        signatureAlgorithm[index++] = (hash << 8 | sign);

#if defined(__RTOS_WIN32__)
        pSigHashString = strtok_s(pNextString, ":", &pNextString);
#else
        pSigHashString = strtok_r(pNextString, ":", &pNextString);
#endif

        if (NULL != pTempStr)
        {
            OSSL_FREE(pTempStr);
        }
    }

    rval = setCtxSignatureAlgorithmsInternal(pCtx, signatureAlgorithm, index);

exit:
    if (pAlgoList != NULL)
    {
        OSSL_FREE(pAlgoList);
    }

    return rval;
}


static int setSignatureAlgorithms(SSL *pSsl, int *pSigAlgoList, ubyte4 sigAlgoListLen)
{
    ubyte2 signatureAlgorithm[MAX_SIGNATURE_ALGORITHMS] = { 0 };
    ubyte4 i = 0;
    ubyte4 index = 0;
    while( i < sigAlgoListLen)
    {
        ubyte sign = 0, hash = 0;
        parseSignAndHash(&sign, &hash, pSigAlgoList[i], pSigAlgoList[i + 1]);
        i += 2;
        signatureAlgorithm[index++] = ((ubyte)hash << 8 | (ubyte)sign);
    }

    return setCtxSignatureAlgorithmsInternal(pSsl->ssl_ctx, signatureAlgorithm, index);
}

static int setSignatureAlgorithmsList(SSL *pSsl, const char *pStr)
{
    return setCtxSignatureAlgorithmsList(pSsl->ssl_ctx, pStr);
}

static int ssl_cert_add0_chain_cert(SSL_CTX *ctx, X509 *x)
{
    OSSL_X509_LIST *c = NULL;
    sbyte4 status = 0;

    if ((NULL == ctx) || (NULL == x))
    {
        goto exit;
    }

    c = &(ctx->cert_x509_list);
    if (c == NULL)
    {
        goto exit;
    }

    if (OSSL_MAX_CERT_CHAIN_COUNT > c->count)
    {
        c->certs[c->count] = x;
        c->count++;
        status = 1;
    }
    /* If the key and certificate have been loaded, update the existing
     * entry in the certificate store with an additional cert chain. If
     * the key and certificate has not been loaded yet then just store
     * the extra certificates and let them be loaded during the key and
     * certificate API calls.
     */
    if ((ctx->ossl_pkey_idx < OSSL_PKEY_MAX) &&
        (ctx->privatekey[ctx->ossl_pkey_idx]))
    {
        if (ossl_CERT_STORE_addGenericIdentity(ctx, ctx->privatekey[ctx->ossl_pkey_idx]) >= 0)
        {
            status = 1;
        }
    }
    else
    {
        status = 1;
    }

exit:
    return status;
}

static int ssl_cert_add1_chain_cert(SSL_CTX *ctx, X509 *x)
{
    int status = 0;
    if (!ssl_cert_add0_chain_cert(ctx, x))
    {
        /* 0 is error case */
        goto exit;
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    X509_up_ref(x);
#else
    CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
#endif
    status = 1;
exit:
    return status;
}

static int computeAndSetVersion(long option, unsigned long *pVersionOptions)
{
    ubyte osslMapVersion[] = { SSL3_MINORVERSION, /* We dont define SSL2_MINORVERSION */
                               SSL3_MINORVERSION,
                               TLS10_MINORVERSION,
                               TLS11_MINORVERSION,
                               TLS12_MINORVERSION,
                               TLS13_MINORVERSION,
                               };
    int maxVersionIndex = -1, minVersionIndex = -1;
    ubyte4 minVersion = 0, maxVersion = 0;

    minVersion  = NSSL_CHK_CALL(sslGetMinVersion, " ");
    maxVersion  = NSSL_CHK_CALL(sslGetMaxVersion, " ");
    /* Map the min version in NanoSSL stack to the indeices in list above */
    getVersionIndex(minVersion, &minVersionIndex);

    /* Map the max version in NanoSSL stack to the indeices in list above */
    getVersionIndex(maxVersion, &maxVersionIndex);

    if ((maxVersionIndex == -1) || (minVersionIndex == -1))
    {
        /* We were not able to enable any version */
        *pVersionOptions = 0x3F;
        return 0;
    }

    if ((option & SSL_OP_NO_SSLv2) ||
        (option & SSL_OP_NO_SSLv3) ||
        (option & SSL_OP_NO_TLSv1) ||
        (option & SSL_OP_NO_TLSv1_2) ||
        (option & SSL_OP_NO_TLSv1_1) ||
        (option & SSL_OP_NO_TLSv1_3) )
    {
        unsigned long newVersion;
        int counter;
        sbyte4 status = OK;
        /* This bit swappign is needed because tls 1.1 uses MSB bit in 0x3F.
         * It is swapped with the TLS 1.2 bit; So that the osslMapVersion is correctly mapped */
        newVersion = (swapBits(option, 28, 27));
        newVersion = (newVersion & 0x3F000000L) >> 24;
        /*unsigned long currentVersion = (map_version & 0x3F000000L) >> 24;*/
        counter = 6;

        while ((maxVersionIndex > minVersionIndex) && (counter > 0))
        {
            unsigned long versionBit = (newVersion >> counter) & 0x01; /* Get the flags that are to be set */
            /* If we are not disabling this version, then continue */
            if (versionBit != 1)
            {
                counter--;
                continue;
            }

            if (((counter > maxVersionIndex) || (counter < minVersionIndex)))
            {
                /* The version to be disabled is already disabled */
                counter--;
                continue;
            }
            else if (counter == maxVersionIndex)
            {
                maxVersionIndex = counter - 1;

                if (OK > moc_mutexWait(m_connectionCountMutex))
                {
                    break;
                }

                status = NSSL_CHK_CALL(sslSetMaxVersion, osslMapVersion[maxVersionIndex]);

                if (OK > moc_mutexRelease(m_connectionCountMutex))
                {
                    break;
                }

                if (OK > status)
                {
                    SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_BAD_VALUE);
                    break;
                }
                counter--;
            }
            else
            {
                minVersionIndex = counter + 1;
                if (OK > moc_mutexWait(m_connectionCountMutex))
                {
                    break;
                }

                status = NSSL_CHK_CALL(sslSetMinVersion, osslMapVersion[minVersionIndex]);

                if (OK > moc_mutexRelease(m_connectionCountMutex))
                {
                    break;
                }

                if (OK > status)
                {
                    SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_BAD_VALUE);
                    break;
                }
                counter--;
            }
        }
    }

    *pVersionOptions = OSSL_set_version_options(minVersionIndex, maxVersionIndex, osslMapVersion);
    return 0;
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int ssl_cert_set_cert_store(X509_STORE **pstore, X509_STORE *store, int ref)
{
    if (NULL != *pstore)
        X509_STORE_free(*pstore);

    *pstore = store;
    if (ref && store)
        X509_STORE_up_ref(store);
    return 1;
}
#endif

/**
 * Internal handling functions for SSL_CTX and SSL objects
 *
 * The SSL_*_ctrl() family of functions is used to manipulate settings of the
 * SSL_CTX and SSL objects. Depending on the command cmd the arguments larg,
 * parg, or fp are evaluated. These functions should never be called directly.
 * All functionalities needed are made available via other functions or macros.
 *
 * (from OpenSSL docs)
 */
extern long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    int i, rval = 0;
    ubyte *pP = NULL;
    ubyte *pG = NULL;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    int derLen;
    X509_OBJECT *pobj;
    X509 *x;
    X509_STORE *store;
    u_int8_t *pDerBuf;
    u_int8_t *to;
#endif

     ubyte4 max_version, min_version;

     ubyte osslMapVersion[] = { SSL3_MINORVERSION, /* We dont define SSL2_MINORVERSION */
                                SSL3_MINORVERSION,
                                TLS10_MINORVERSION,
                                TLS11_MINORVERSION,
                                TLS12_MINORVERSION,
                                TLS13_MINORVERSION,
                                };
     if(ctx == NULL) {
        SSLerr(SSL_F_SSL3_CTX_CTRL,SSL_R_NULL_SSL_CTX);
        return 0;
     }

     switch(cmd) {
     case SSL_CTRL_EXTRA_CHAIN_CERT:
      rval = 0;
      if (OSSL_MAX_CERT_CHAIN_COUNT >  ctx->cert_x509_list.count)
      {
           ctx->cert_x509_list.certs[ctx->cert_x509_list.count] = (X509 *)parg;
           ctx->cert_x509_list.count++;
           /* If the key and certificate have been loaded, update the existing
            * entry in the certificate store with an additional cert chain. If
            * the key and certificate has not been loaded yet then just store
            * the extra certificates and let them be loaded during the key and
            * certificate API calls. */
           if ( (ctx->ossl_pkey_idx < OSSL_PKEY_MAX) &&
                (ctx->privatekey[ctx->ossl_pkey_idx]) )
           {
               if (ossl_CERT_STORE_addGenericIdentity(ctx, ctx->privatekey[ctx->ossl_pkey_idx]) >= 0)
               {
                   rval = 1;
               }
           }
           else
           {
               rval = 1;
           }
      }
      break;
    case SSL_CTRL_GET_EXTRA_CHAIN_CERTS:
     if (ctx->extra_certs == NULL && larg == 0)
        *(STACK_OF(X509) **)parg = NULL; /* ctx->cert->key->chain;*/
     else
          *(STACK_OF(X509) **)parg = ctx->extra_certs;
     rval = 1;
     break;
     case SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
      for (i = 0; i < ctx->cert_x509_list.count; ++i)
      {
           X509_free(ctx->cert_x509_list.certs[i]);
           ctx->cert_x509_list.certs[i] = NULL;
      }
      ctx->cert_x509_list.count = 0;
      rval = 1;
      break;
     case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
      ctx->tlsext_servername_arg = parg;
      rval = 1;
      break;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_CTRL_GET_VERIFY_CERT_STORE:
        if (NULL == ctx->cert_store)
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        *((X509_STORE **)parg) = ctx->cert_store;
        return 1;
    case SSL_CTRL_SET_VERIFY_CERT_STORE:
        if (!ssl_cert_set_cert_store((&ctx->verify_store), parg, larg))
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        store = ctx->verify_store;
        if (NULL == store)
        {
            SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        for (i = 0; i < sk_X509_OBJECT_num(store->objs); i++) {
            pobj = sk_X509_OBJECT_value(store->objs, i);
            if (X509_LU_X509 == pobj->type) {
                x      = pobj->data.x509;
                derLen = i2d_X509(x, NULL);
                if (0 > derLen)
                {
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0;/* return error */
                }

                /* certificates need to be in SSL_CTX cert_store
                 * for call to X509_verify_cert() in OSSL_certCallback()
                 */
                if (!X509_STORE_add_cert(ctx->cert_store, x))
                {
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0;/* return error */
                }

                if (NULL == (pDerBuf = OSSL_MALLOC(derLen)))
                {
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0; /* @Openssl: Does not define error code */
                }
                to      = pDerBuf;
                derLen  = i2d_X509(x, &to);
                NSSL_CHK_CALL(addTrustPoint, ctx->pCertStore, pDerBuf, derLen);
                OSSL_FREE(pDerBuf);
                pDerBuf = NULL;
            }
        }
        return 1;
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     case SSL_CTRL_SET_MIN_PROTO_VERSION:
     {
        ubyte4 minVersion = 0;
        switch(larg)
        {
            case SSL3_VERSION:
                minVersion = SSL3_MINORVERSION;
                break;
            case TLS1_VERSION:
                minVersion = TLS10_MINORVERSION;
                break;
            case TLS1_1_VERSION:
                minVersion = TLS11_MINORVERSION;
                break;
            case TLS1_2_VERSION:
                minVersion = TLS12_MINORVERSION;
                break;
            case TLS1_3_VERSION:
                minVersion = TLS13_MINORVERSION;
                break;
            default:
                break;
        }
        if (OK > NSSL_CHK_CALL(sslSetMinVersion, minVersion))
        {
            return 0;
        }

        return larg;
     }
     case SSL_CTRL_GET_MIN_PROTO_VERSION:
     {
         ubyte4 minVersion;
         int version = -1;
         minVersion = NSSL_CHK_CALL(sslGetMinVersion, " ");
         switch(minVersion)
         {
            case SSL3_MINORVERSION:
                version = SSL3_VERSION;
                break;
            case TLS10_MINORVERSION:
                version = TLS1_VERSION;
                break;
            case TLS11_MINORVERSION:
                version = TLS1_1_VERSION;
                break;
            case TLS12_MINORVERSION:
                version = TLS1_2_VERSION;
                break;
            case TLS13_MINORVERSION:
                version = TLS1_3_VERSION;
                break;
            default:
                break;
         }
         return version;
     }
     case SSL_CTRL_SET_MAX_PROTO_VERSION:
     {
        ubyte4 maxVersion = 0;
        switch(larg)
        {
            case SSL3_VERSION:
                maxVersion = SSL3_MINORVERSION;
                break;
            case TLS1_VERSION:
                maxVersion = TLS10_MINORVERSION;
                break;
            case TLS1_1_VERSION:
                maxVersion = TLS11_MINORVERSION;
                break;
            case TLS1_2_VERSION:
                maxVersion = TLS12_MINORVERSION;
                break;
            case TLS1_3_VERSION:
                maxVersion = TLS13_MINORVERSION;
                break;
            /* Special case : If value is 0, the version should be set to
             * max version supported by the library
             */
            case 0:
                maxVersion = TLS13_MINORVERSION;
            default:
                break;
        }
        if (OK > NSSL_CHK_CALL(sslSetMaxVersion, maxVersion))
        {
            return 0;
        }

        if (0 == larg)
        {
            larg = TLS1_3_VERSION;
        }
        return larg;
     }
     case SSL_CTRL_GET_MAX_PROTO_VERSION:
     {
         ubyte4 maxVersion;
         int version = -1;
         maxVersion = NSSL_CHK_CALL(sslGetMaxVersion, " ");
         switch(maxVersion)
         {
            case SSL3_MINORVERSION:
                version = SSL3_VERSION;
                break;
            case TLS10_MINORVERSION:
                version = TLS1_VERSION;
                break;
            case TLS11_MINORVERSION:
                version = TLS1_1_VERSION;
                break;
            case TLS12_MINORVERSION:
                version = TLS1_2_VERSION;
                break;
            case TLS13_MINORVERSION:
                version = TLS1_3_VERSION;
                break;
            default:
                break;
         }
         return version;
     }
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
     case SSL_CTRL_OPTIONS:
     {
        unsigned long version_options = 0;
        rval = 1;

        computeAndSetVersion(larg, &version_options);

        version_options = version_options << 24;
        ctx->options |= version_options;

        if (larg & SSL_OP_NO_TICKET)
            ctx->options |= SSL_OP_NO_TICKET;
        rval = ctx->options;
        break;
     }
     case SSL_CTRL_CLEAR_OPTIONS:
     {
        int max_version_index;
        int min_version_index;
        char *pminiVersion = NULL;
        char* pMaxVersion  = NULL;
        ubyte4 max_version = 0, min_version = 0;

        unsigned long version_options;

        if (NULL != (pMaxVersion = getenv("OPENSSL_MAX_TLS_VERSION")))
        {
            OSSL_get_proto_version(pMaxVersion, (ubyte4*)&max_version);
        }
        else
        {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            max_version = TLS1_3_VERSION;
#else
            max_version = TLS1_2_VERSION;
#endif
        }

        getVersionIndex(OSSL_convert_minor_version_from_ossl(max_version), &max_version_index);

        if (NULL != (pminiVersion = getenv("OPENSSL_MIN_TLS_VERSION")))
        {
            OSSL_get_proto_version(pminiVersion, (ubyte4*)&min_version);
        }
        else
        {
            min_version = TLS1_VERSION_MINOR;
        }

        getVersionIndex(OSSL_convert_minor_version_from_ossl(min_version), &min_version_index);

        /* Set the min and max version */
        if (0 == (setMinAndMaxVersion(max_version, min_version)))
        {
            PRINT("OSSL version is either invalid or version is not supported\n");
            SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_BAD_VALUE);
            break;
        }

        version_options = OSSL_set_version_options(min_version_index, max_version_index, osslMapVersion);
        version_options = version_options << 24;
        ctx->options &= 0xC0FFFFFFL;
        ctx->options |= version_options;
        rval = ctx->options;
        break;
     }
        case SSL_CTRL_SET_TMP_DH:
        {
            DH *dh;
            int pLen = 0, gLen = 0;

            dh = (DH *)parg;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            if ((NULL == dh) || (NULL == dh->params.p) || (NULL == dh->params.g))
#else
            if ((NULL == dh) || (NULL == dh->p) || (NULL == dh->g))
#endif
            {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
                return 0;
            }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            pLen = BN_num_bytes(dh->params.p);
#else
            pLen = BN_num_bytes(dh->p);
#endif
            pP = OSSL_MALLOC(pLen);
            if (NULL == pP)
            {
                return 0;
            }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            BN_bn2bin(dh->params.p, pP);
#else
            BN_bn2bin(dh->p, pP);
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            gLen = BN_num_bytes(dh->params.g);
#else
            gLen = BN_num_bytes(dh->g);
#endif
            pG = OSSL_MALLOC(gLen);
            if (NULL == pG)
            {
                OSSL_FREE(pP);
                return 0;
            }
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
            BN_bn2bin(dh->params.g, pG);
#else
            BN_bn2bin(dh->g, pG);
#endif

            rval = NSSL_CHK_CALL(setDHParameters, pP, pLen, pG, gLen, 0);
            OSSL_FREE(pP);
            OSSL_FREE(pG);
            if (rval < 0)
            {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
                return 0;
            }
            else
            {
                return 1;
            }
            /* break; */
        }
#if (defined (__ENABLE_DIGICERT_SSL_ECDH_SUPPORT__))
     case SSL_CTRL_SET_TMP_ECDH:
        {
            EC_KEY *ecdh = NULL;

            if (parg == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                return 0;
            }
            ecdh = EC_KEY_dup((EC_KEY *)parg);
            if (ecdh == NULL) {
                SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_EC_LIB);
                return 0;
            }
            if (!(ctx->options & SSL_OP_SINGLE_ECDH_USE)) {
                if (!EC_KEY_generate_key(ecdh)) {
                    EC_KEY_free(ecdh);
                    SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_ECDH_LIB);
                    return 0;
                }
            }

            if (ctx->ecdh_tmp != NULL) {
                EC_KEY_free(ctx->ecdh_tmp);
            }
            ctx->ecdh_tmp = ecdh;
            return 1;
        /* break */
        }
     case SSL_CTRL_SET_CURVES:
        rval = setEccCurves(&ctx->pEccCurves, &ctx->numEccCurves, parg, larg);
        break;
     case SSL_CTRL_SET_CURVES_LIST:
     case SSL_CTRL_SET_GROUPS_LIST:
         rval = setEccCurvesFromString(&ctx->pEccCurves, &ctx->numEccCurves, parg);
         break;
     case SSL_CTRL_SET_ECDH_AUTO:
        {
            if (1 == larg)
            {
                char list[] = "P-521:P-384:P-256";
                SSL_CTX_set1_curves_list(ctx, list);
            }
            rval = 1;
            break;
        }
#endif
    case SSL_CTRL_SET_MSG_CALLBACK_ARG:
        ctx->msg_callback_arg = parg;
        break;

    case SSL_CTRL_SET_SESS_CACHE_MODE:
        rval = ctx->orig_ssl_ctx.session_cache_mode;
        ctx->orig_ssl_ctx.session_cache_mode = larg;
        break;
    case SSL_CTRL_GET_SESS_CACHE_MODE:
        rval = ctx->orig_ssl_ctx.session_cache_mode;
        break;
    case SSL_CTRL_MODE:
        return (ctx->orig_ssl_ctx.mode |= larg);
    case SSL_CTRL_SET_SIGALGS:
        rval = setCtxSignatureAlgorithms(ctx, (int *)parg, larg);
        break;
    case SSL_CTRL_SET_SIGALGS_LIST:
        rval = setCtxSignatureAlgorithmsList(ctx, parg);
        break;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
        ctx->tlsext_status_arg = parg;
        rval = 1;
        break;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB_ARG:
        *(void**)parg = ctx->tlsext_status_arg;
        break;

    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_CB:
        *(int (**)(SSL*, void*))parg = ctx->tlsext_status_cb;
        break;
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE:
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        return ctx->tlsext_status_type;
#else
        return ctx->orig_ssl_ctx.tlsext_status_type;
#endif

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        ctx->tlsext_status_type = larg;
#else
        ctx->orig_ssl_ctx.tlsext_status_type = larg;
#endif
        rval = 1;
        break;
#endif
    case SSL_CTRL_CHAIN_CERT:
        if (larg)
        {
            return ssl_cert_add1_chain_cert(ctx, (X509 *)parg);
        }
        else
        {
            return ssl_cert_add0_chain_cert(ctx, (X509 *)parg);
        }
    case SSL_CTRL_GET_READ_AHEAD:
        return ctx->orig_ssl_ctx.read_ahead;
    case SSL_CTRL_SET_READ_AHEAD:
        rval = ctx->orig_ssl_ctx.read_ahead;
        ctx->orig_ssl_ctx.read_ahead = larg;
        return rval;
     default:
      break;
     }
     return rval;
}


/*------------------------------------------------------------------*/

long SSL_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    int l;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    int i;
    int derLen;
    X509_OBJECT *pobj;
    X509 *x;
    X509_STORE *store;
    u_int8_t *pDerBuf;
    u_int8_t *to;
#endif
    if(s == NULL) {
        SSLerr(SSL_F_SSL3_CTX_CTRL,SSL_R_UNINITIALIZED);
        return 0;
     }

    switch (cmd) {
    case SSL_CTRL_GET_RI_SUPPORT:
    {
        intBoolean isRehandshake = 0;
        if (s != NULL)
        {
            NSSL_CHK_CALL(isRehandshakeAllowed, s->instance, &isRehandshake);
        }
        return isRehandshake;
    }

    /* WGET uses this control command*/
    case SSL_CTRL_SET_TLSEXT_HOSTNAME:
        if (larg == TLSEXT_NAMETYPE_host_name)
        {
            size_t len;

            if (s->tlsext_hostname != NULL)
                OSSL_FREE(s->tlsext_hostname);
            s->tlsext_hostname = NULL;

            if (parg == NULL)
                break;
            len = strlen((char *)parg);
            if (len == 0 || len > TLSEXT_MAXLEN_host_name)
            {
                SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
                return 0;
            }
            if ((s->tlsext_hostname =(char *) OSSL_MALLOC(len + 1)) == NULL)
            {
                SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            memcpy(s->tlsext_hostname, parg, len);
            s->tlsext_hostname[len] = '\0';
        } else
        {
            SSLerr(SSL_F_SSL3_CTRL, SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
            return 0;
        }

        break;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_CTRL_GET_VERIFY_CERT_STORE:
        if (NULL == s->ssl_ctx || NULL == s->ssl_ctx->cert_store)
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        *((X509_STORE **)parg) = s->ssl_ctx->cert_store;
        return 1;
    case SSL_CTRL_SET_VERIFY_CERT_STORE:
        if (!ssl_cert_set_cert_store((&s->verify_store), parg, larg))
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        store = s->verify_store;
        if (NULL == store)
        {
            SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
            return 0; /* return error */
        }

        for (i = 0; i < sk_X509_OBJECT_num(store->objs); i++) {
            pobj = sk_X509_OBJECT_value(store->objs, i);
            if (X509_LU_X509 == pobj->type) {
                x      = pobj->data.x509;
                derLen = i2d_X509(x, NULL);
                if (0 > derLen)
                {
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0;/* return error */
                }

                /* certificates need to be in SSL_CTX cert_store
                 * for call to X509_verify_cert() in OSSL_certCallback()
                 */
                if (!X509_STORE_add_cert(s->ssl_ctx->cert_store, x))
                {
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0;/* return error */
                }

                if (NULL == (pDerBuf = OSSL_MALLOC(derLen)))
                {
                    SSLerr(SSL_F_SSL3_CTRL, ERR_R_INTERNAL_ERROR);
                    return 0; /* @Openssl: Does not define error code */
                }
                to      = pDerBuf;
                derLen  = i2d_X509(x, &to);
                NSSL_CHK_CALL(addTrustPoint, s->ssl_ctx->pCertStore, pDerBuf, derLen);
                OSSL_FREE(pDerBuf);
                pDerBuf = NULL;
            }
        }
        return 1;
#endif
    case SSL_CTRL_GET_SERVER_TMP_KEY:
      /* this is just a placeholder to allow Openssl Application to continue. */
        return 0;
    case SSL_CTRL_OPTIONS:
        return (s->options |= larg);
     case SSL_CTRL_CLEAR_OPTIONS:
     {
         resetVersionOptions(s);
         return (s->options &= ~larg);
     }

#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    case DTLS_CTRL_LISTEN:
        return DTLS_ctrl(s, cmd, larg, parg);
#endif
    case SSL_CTRL_SET_MSG_CALLBACK_ARG:
        s->msg_callback_arg = parg;
        break;
    case SSL_CTRL_SET_SIGALGS:
        return setSignatureAlgorithms(s, (int *)parg, larg);
    case SSL_CTRL_SET_SIGALGS_LIST:
        return setSignatureAlgorithmsList(s, parg);
     case SSL_CTRL_SET_ECDH_AUTO:
     {
        if (1 == larg)
        {
            char list[] = "P-521:P-384:P-256";
            SSL_set1_curves_list(s, list);
        }
        break;
     }
     case SSL_CTRL_SET_CURVES:
        setEccCurves(&s->pEccCurves, &s->numEccCurves, parg, larg);
        break;

     case SSL_CTRL_SET_CURVES_LIST:
     case SSL_CTRL_SET_GROUPS_LIST:
        setEccCurvesFromString(&s->pEccCurves, &s->numEccCurves, parg);
        break;

    case SSL_CTRL_MODE:
        return (s->orig_s.mode |= larg);
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     case SSL_CTRL_GET_SESSION_REUSED:
        if (NULL != s)
        {
            intBoolean isResumed;
            if (OK == NSSL_CHK_CALL(isSessionResumed, s->instance, &isResumed))
            {
                return (long) isResumed;
            }
        }
        return 0;
#endif


#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) 
    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE:
        return s->orig_s.tlsext_status_type;
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_TYPE:
        return s->tlsext_status_type;
#endif

    /* Set OCSP request type */
    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_TYPE:
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        s->tlsext_status_type = larg;
#else
        s->orig_s.tlsext_status_type = larg;
#endif
        break;

    /* Retrieve the OCSP response saved by the client */
    case SSL_CTRL_GET_TLSEXT_STATUS_REQ_OCSP_RESP:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        *(unsigned char **)parg = s->tlsext_ocsp_resp;
        return s->tlsext_ocsp_resplen;
#else
        *(unsigned char **)parg = s->orig_s.tlsext_ocsp_resp;
        return s->orig_s.tlsext_ocsp_resplen;
#endif

    case SSL_CTRL_CHAIN_CERT:
        if (larg)
        {
            return ssl_cert_add1_chain_cert(s->ssl_ctx, (X509 *)parg);
        }
        else
        {
            return ssl_cert_add0_chain_cert(s->ssl_ctx, (X509 *)parg);
        }
    case SSL_CTRL_GET_READ_AHEAD:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        return (s->orig_s.rlayer.read_ahead);
#else
        return (s->orig_s.read_ahead);
#endif
    case SSL_CTRL_SET_READ_AHEAD:
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        l = s->orig_s.rlayer.read_ahead;
        s->orig_s.rlayer.read_ahead = larg;
#else
        l = s->orig_s.read_ahead;
        s->orig_s.read_ahead = larg;
#endif
        return (l);
    default:
     break;
    }
    return 1;
}

static MSTATUS OSSL_closeConnection(SSL *s)
{
    MSTATUS status;
    void *foundData;
    intBoolean isFound;
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    int mutexAcquired = 0;
#endif

    if (NULL == s)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (0 == mutexAcquired)
    {
        status = OSSL_sessionAcquireMutex(s);
        if (OK == status)
            mutexAcquired = 1;
    }
#endif
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    if ((s->version == DTLSV1_VERSION) || (s->version == DTLS_ANY_VERSION))
    {
        NSSL_CHK_CALL(dtlsCloseConnection, s->instance);
    }
    else
#endif
    {
        NSSL_CHK_CALL(closeConnection, s->instance);
    }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (1 == mutexAcquired)
    {
        (void) OSSL_sessionReleaseMutex(s);
        mutexAcquired = 0;
    }
#endif
    if (OK > (status = moc_mutexWait(m_hashTableMutex)))
    {
        goto exit;
    }

    if (OK <= s->instance && NULL != m_ssl_table)
    {
        NSSL_CHK_CALL(
            hashTableDeletePtr, m_ssl_table, s->instance, s, NULL, &foundData, &isFound);
    }

    if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
    {
        goto exit;
    }

    s->instance = MOC_SSL_CONN_INSTANCE_UNASSIGNED;

exit:

    return status;
}

/*------------------------------------------------------------------*/

/* @Openssl : As per the openssl shutdown method, it should send/receive
 *      the Alert message to/from PEER.
 */

int SSL_shutdown(SSL *s)
{
    MSTATUS status;
    int ret = -1;
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    int mutexAcquired = 0;
#endif

    if (NULL == s)
    {
        goto exit;
    }

    /*
     * Don't do anything much if we have not done the handshake or we don't
     * want to send messages :-)
     */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if ((s->orig_s.quiet_shutdown) || (s->orig_state == 0))
#else
    if ((s->orig_s.quiet_shutdown) || (s->orig_s.state == 0))
#endif
    {
        s->orig_s.shutdown = (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        ret = 1;
        goto exit;
    }
    else if ((!(s->orig_s.shutdown & SSL_SENT_SHUTDOWN)) && (s->s3->fatal_alert != 1))
    {
        /* If the shutdown bit has not been set yet then set the bit and send an
         * alert to the peer to close the connection.
         */
        s->orig_s.shutdown |= SSL_SENT_SHUTDOWN;

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (NULL != s->session_mutex)
        {
            status = moc_mutexWait(s->session_mutex);
            if (status >= OK)
                mutexAcquired = 1;
        }
#endif
        status = NSSL_CHK_CALL(
            sslSendAlert, s->instance, SSL_ALERT_CLOSE_NOTIFY,
            SSLALERTLEVEL_WARNING);

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
        /* Send out alert message */
        asyncSendPendingData(s);

        if (OK > status)
        {
            goto exit;
        }
    }

    if ((s->orig_s.shutdown & SSL_SENT_SHUTDOWN) && (s->orig_s.shutdown & SSL_RECEIVED_SHUTDOWN))
    {
        ret = 1;
    }
    else
    {
        ret = 0;
    }

exit:
    return ret;
}

/*------------------------------------------------------------------*/

extern void
SSL_free(SSL *s)
{

    if (!s)
        return;

    if (MOC_SSL_CONN_INSTANCE_UNASSIGNED != s->instance)
    {
        OSSL_closeConnection(s);
    }

    if(NULL != s->ssl_ctx)
        SSL_CTX_free(s->ssl_ctx);

    if (NULL != s->bbio)
    {
        if (s->bbio == s->wbio)
        {
            s->wbio = BIO_pop(s->wbio);
        }
        (void) BIO_free(s->bbio);
        s->bbio = NULL;
    }

    if (NULL != s->rbio)
    {
        BIO_free_all(s->rbio);
        s->rbio = NULL;
    }
    if ((NULL != s->wbio))
    {
        BIO_free_all(s->wbio);
        s->wbio = NULL;
    }

    if (NULL != s->client_CA)
        sk_X509_NAME_pop_free(s->client_CA, X509_NAME_free);

    if (NULL != s->session)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (NULL != s->session->peer_chain)
        {
            sk_X509_pop_free(s->session->peer_chain, X509_free);
            s->session->peer_chain = NULL;
        }
#else
        if (NULL != s->session->sess_cert)
        {
            if (NULL != s->session->sess_cert->cert_chain)
            {
                sk_X509_pop_free(s->session->sess_cert->cert_chain, X509_free);
                s->session->sess_cert->cert_chain = NULL;
            }
            OSSL_FREE(s->session->sess_cert);
            s->session->sess_cert = NULL;
        }
#endif
    }

    if (NULL != s->orig_s.param)
    {
        X509_VERIFY_PARAM_free(s->orig_s.param);
    }

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL, s, &s->ex_data);

    if (NULL != s->pHoldingBuf)
    {
        OSSL_FREE((void *)s->pHoldingBuf);
        s->pHoldingBuf = NULL;
    }

    if (NULL != s->pTxHoldingBuf)
    {
        OSSL_FREE((void *)s->pTxHoldingBuf);
        s->pTxHoldingBuf = NULL;
    }

    if (NULL != s->pRxDataBuf)
    {
        OSSL_FREE((void *)s->pRxDataBuf);
        s->pRxDataBuf = NULL;
    }

    if (NULL != s->s3)
    {
        if (NULL != s->s3->tmp.ca_names)
        {
            sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
        }

        OSSL_FREE((void *)s->s3);
        s->s3 = NULL;
    }

    if (NULL != s->compress)
    {
       OSSL_FREE((void *)s->compress);
       s->compress = NULL;
    }

    if (NULL != s->session)
    {
        SSL_SESSION_free(s->session);
    }

    if (NULL != s->tlsext_hostname)
    {
        OSSL_FREE((void *)s->tlsext_hostname);
        s->tlsext_hostname = NULL;
    }

    if (NULL != s->cipher_list)
    {
        sk_SSL_CIPHER_free(s->cipher_list);
        s->cipher_list = NULL;
    }

    if (s->pEccCurves != NULL)
    {
        OSSL_FREE(s->pEccCurves);
    }

    if (NULL != s->s3)
    {
        memset(s->s3, 0x00, sizeof(struct ssl3_state_st));
        OSSL_FREE(s->s3);
        s->s3 = NULL;
    }

    if (NULL != s->orig_s.srtp_profiles)
    {
        sk_SRTP_PROTECTION_PROFILE_free(s->orig_s.srtp_profiles);
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != s->tlsext_ocsp_resp)
    {
        OPENSSL_free(s->tlsext_ocsp_resp);
        s->tlsext_ocsp_resplen = 0;
    }
#else
    if (NULL != s->orig_s.tlsext_ocsp_resp)
    {
        OPENSSL_free(s->orig_s.tlsext_ocsp_resp);
        s->orig_s.tlsext_ocsp_resplen = 0;
    }
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (s->tls13_ciphersuites != NULL)
    {
        sk_SSL_CIPHER_free(s->tls13_ciphersuites);
        s->tls13_ciphersuites = NULL;
    }
#endif

    if (s->mocAlpnList != NULL)
    {
        OSSL_FREE(s->mocAlpnList);
    }

    if (s->alpn_client_proto_list != NULL)
    {
        OSSL_FREE(s->alpn_client_proto_list);
    }

#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (NULL != s->session_mutex)
    {
        moc_mutexFree(&s->session_mutex);
    }
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    sk_X509_pop_free(s->verified_chain, X509_free);
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (NULL != s->verify_store)
        X509_STORE_free(s->verify_store);
#endif

    memset((ubyte*)s, 0, sizeof(*s));
    OSSL_FREE(s);
}

/*------------------------------------------------------------------*/

extern X509 *
SSL_get_certificate(const SSL *ssl)
{
    return ssl ? ssl->ssl_ctx->cert_x509 : NULL;
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern X509 *
SSL_get0_peer_certificate(const SSL *s)
{
    X509 *pPeerCert = NULL;
    ubyte4 connState = 0;
    sbyte4 status = 0;

    if ( (NULL == s))
        return NULL;

    if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
        return NULL;

    if ((connState == SSL_CONNECTION_NEGOTIATE) || (connState == SSL_CONNECTION_RENEGOTIATE))
    {
        if(OK >= (status = SSL_do_handshake((SSL *) s)))
            return NULL;
    }

    if (NULL != s->session)
    {
        if (NULL == s->session->peer_chain)
            return NULL;

        pPeerCert = sk_X509_value(s->session->peer_chain, 0);

    }

    if (NULL == pPeerCert)
        return NULL;

    return pPeerCert;
}
#endif

/*------------------------------------------------------------------*/

extern X509 *
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
SSL_get1_peer_certificate(const SSL *s)
#else
SSL_get_peer_certificate(SSL *s)
#endif
{
    X509 *pPeerCert = NULL;
    ubyte4 connState = 0;
    sbyte4 status = 0;

    if ( (NULL == s))
        return NULL;

    if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
        return NULL;

    if ((connState == SSL_CONNECTION_NEGOTIATE) || (connState == SSL_CONNECTION_RENEGOTIATE))
    {
        if(OK >= (status = SSL_do_handshake((SSL *) s)))
            return NULL;
    }

    if (NULL != s->session)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (NULL == s->session->peer_chain)
            return NULL;

        pPeerCert = sk_X509_value(s->session->peer_chain, 0);
#else
        if ((NULL == s->session->sess_cert) || (NULL == s->session->sess_cert->cert_chain))
            return NULL;

        pPeerCert = sk_X509_value(s->session->sess_cert->cert_chain, 0);
#endif

    }

    if (NULL == pPeerCert)
        return NULL;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    X509_up_ref(pPeerCert);
#else
    CRYPTO_add(&pPeerCert->references, 1, CRYPTO_LOCK_X509);
#endif

    return pPeerCert;
}

/*------------------------------------------------------------------*/
extern EVP_PKEY*
SSL_get_privatekey(SSL *ssl)
{
     int idx;
     if ((NULL == ssl) || (OSSL_PKEY_MAX == (idx = ssl->ssl_ctx->ossl_pkey_idx)))
       return NULL;
     else
       return ssl->ssl_ctx->privatekey[idx];
}

/*------------------------------------------------------------------*/

/* This can be called after SSL_connect, SSL_read, SSL_write.. */
extern int
SSL_get_error(const SSL *s, int ret_code)
{
    BIO* bio;
    int reason;
    unsigned long l;

    if (s == NULL)
        return -1;

    if (ret_code > 0)
        return SSL_ERROR_NONE;

#if !defined(__DISABLE_DIGICERT_OPENSSL_PEEK_ERROR__)
    /*
     * Make things return SSL_ERROR_SYSCALL when doing SSL_do_handshake etc,
     * where we do encode the error
     */
    if ((l = ERR_peek_error()) != 0) {
        if (ERR_GET_LIB(l) == ERR_LIB_SYS)
            return (SSL_ERROR_SYSCALL);
        else
            return (SSL_ERROR_SSL);
    }
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (OSSL_IN_READ == s->io_state)
#else
    if ((ret_code < 0) && (OSSL_IN_READ == s->io_state))
#endif
    {
        bio = SSL_get_rbio(s);
        if(BIO_should_read(bio))
        {
            return SSL_ERROR_WANT_READ;
        }
        else if(BIO_should_write(bio))
        {
            /*
             * This one doesn't make too much sense ... We never try to write
             * to the rbio, and an application program where rbio and wbio
             * are separate couldn't even know what it should wait for.
             * However if we ever set s->rwstate incorrectly (so that we have
             * SSL_want_read(s) instead of SSL_want_write(s)) and rbio and
             * wbio *are* the same, this test works around that bug; so it
             * might be safer to keep it.
             */
            return (SSL_ERROR_WANT_WRITE);
        }
        else if (BIO_should_io_special(bio))
        {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
            {
                return (SSL_ERROR_WANT_CONNECT);
            }
            else if (reason == BIO_RR_ACCEPT)
            {
                return (SSL_ERROR_WANT_ACCEPT);
            }
            else
            {
                return (SSL_ERROR_SYSCALL); /* unknown */
            }
        }
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (OSSL_IN_WRITE == s->io_state)
#else
    if ((ret_code < 0) && (OSSL_IN_WRITE == s->io_state))
#endif
    {
        bio = SSL_get_wbio(s);
        if (BIO_should_write(bio))
        {
            return (SSL_ERROR_WANT_WRITE);
        }
        else if (BIO_should_read(bio))
        {
            /*
             * See above (SSL_want_read(s) with BIO_should_write(bio))
             */
            return (SSL_ERROR_WANT_READ);
        }
        else if (BIO_should_io_special(bio))
        {
            reason = BIO_get_retry_reason(bio);
            if (reason == BIO_RR_CONNECT)
            {
                return (SSL_ERROR_WANT_CONNECT);
            }
            else if (reason == BIO_RR_ACCEPT)
            {
                return (SSL_ERROR_WANT_ACCEPT);
            }
            else
            {
                return (SSL_ERROR_SYSCALL);
            }
        }
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (OSSL_X509_LOOKUP == s->io_state)
#else
    if ((ret_code < 0) && (OSSL_X509_LOOKUP == s->io_state))
#endif
    {
        return (SSL_ERROR_WANT_X509_LOOKUP);
    }

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (s->orig_s.rwstate == SSL_CLIENT_HELLO_CB)
    {
        return (SSL_ERROR_WANT_CLIENT_HELLO_CB);
    }
#endif

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) && !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if (ret_code == 0)
#endif
    {
        if (s->orig_s.shutdown & SSL_RECEIVED_SHUTDOWN)
            return (SSL_ERROR_ZERO_RETURN);
    }

    return SSL_ERROR_SYSCALL;
}

/*------------------------------------------------------------------*/

extern const char*
SSL_get_cipher(SSL* ssl)
{
    ubyte4 i;
    ubyte2 cipherId;
    ubyte4 eccCurves;

    if (!ssl)
        return NULL;

     if (OK > NSSL_CHK_CALL(getCipherInfo,ssl->instance, &cipherId, &eccCurves))
        return NULL;

    for (i = 0; i < NUM_CIPHER_DESCS; i++)
    {
        if (gCipherDescs[i].cipherId == cipherId)
        return (const char*) gCipherDescs[i].cipherName;
    }

    return NULL;
}


extern const SSL_CIPHER *SSL_CIPHER_find(SSL *ssl, const unsigned char *ptr)
{
    unsigned long osslCipherId = 0;
    ubyte2        cipherId = 0;
    const SSL_CIPHER *pCipher = NULL;
    ubyte4 i = 0, j = 0;

    if ((NULL == ssl) || (NULL == ptr))
    {
        return NULL;
    }

    osslCipherId = 0x03000000L | ((unsigned long)ptr[0] << 8L) | (unsigned long)ptr[1];
    cipherId = (ubyte2)((unsigned long)ptr[0] << 8 | (unsigned long)ptr[1]);

    for (i = 0; i < NUM_CIPHER_DESCS; i++)
    {
        if (gCipherDescs[i].cipherId == cipherId)
        {
            for (j = 0; j < SSL3_NUM_CIPHERS; j++)
            {
                if (osslCipherId == ssl3_ciphers[j].id)
                {
                    pCipher = &(ssl3_ciphers[j]);
                    break;
                }
            }

            if (pCipher != NULL)
                break;
        }
    }
    return pCipher;
}

/*------------------------------------------------------------------*/

extern SSL *
SSL_new(SSL_CTX *ctx)
{
    SSL* ssl = NULL;
    sbyte4 status = 0;
    char *pminiVersion = NULL;
    char* pMaxVersion  = NULL;
    int minVersion = 0;
    int maxVersion = 0;

    if (!ctx) {
        SSLerr(SSL_F_SSL_NEW, SSL_R_NULL_SSL_CTX);
        return (NULL);
    }

    ssl = OSSL_MALLOC(sizeof(*ssl));
    if (!ssl) {
        SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }

    memset((ubyte*)ssl, 0, sizeof(*ssl));
    ssl->method     = ctx->ssl_method;
    ssl->version    = ctx->ssl_method->version;
    ssl->instance    = MOC_SSL_CONN_INSTANCE_UNASSIGNED;
    ssl->tempSocket    = -1;
    ssl->clientServerFlag = SSL_CLIENT_FLAG;
    ssl->orig_s.quiet_shutdown = ctx->orig_ssl_ctx.quiet_shutdown;

	if (OK > (status = moc_mutexWait(m_connectionCountMutex)))
    {
        PRINT("RTOS_mutexWait() failed : %d\n", status);
        OSSL_FREE(ssl);
        ssl = NULL;
        return NULL;
    }

       ssl->appId = gConnectionCount++;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ossl_statem_clear(ssl);
    ssl->orig_s.rlayer.read_ahead = ctx->orig_ssl_ctx.read_ahead;
#else
    ssl->orig_s.read_ahead = ctx->orig_ssl_ctx.read_ahead;
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Shallow copy of the ciphersuites stack */
    ssl->tls13_ciphersuites = sk_SSL_CIPHER_dup(ctx->tls13_ciphersuites);
    if (ssl->tls13_ciphersuites == NULL)
    {
        OSSL_FREE(ssl);
        ssl = NULL;
        return NULL;
    }

    ssl->orig_s.max_early_data                = ctx->orig_ssl_ctx.max_early_data;
    ssl->orig_s.recv_max_early_data           = ctx->orig_ssl_ctx.recv_max_early_data;
    ssl->orig_s.num_tickets                   = ctx->orig_ssl_ctx.num_tickets;
    ssl->orig_s.pha_enabled                   = ctx->orig_ssl_ctx.pha_enabled;
    ssl->orig_s.psk_find_session_cb           = ctx->orig_ssl_ctx.psk_find_session_cb;
    ssl->orig_s.psk_use_session_cb            = ctx->orig_ssl_ctx.psk_use_session_cb;
    ssl->orig_s.allow_early_data_cb           = ctx->orig_ssl_ctx.allow_early_data_cb;
    ssl->orig_s.allow_early_data_cb_data      = ctx->orig_ssl_ctx.allow_early_data_cb_data;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */

    /* if the OPENSSL_MIN_TLS_VERSION environment variable is set, load the version */
    if (NULL != (pminiVersion = getenv("OPENSSL_MIN_TLS_VERSION")))
    {
        OSSL_get_proto_version(pminiVersion,(ubyte4 *)&minVersion);
    }

    if (NULL != (pMaxVersion = getenv("OPENSSL_MAX_TLS_VERSION")))
    {
        OSSL_get_proto_version(pMaxVersion, (ubyte4*)&maxVersion);
    }

    if (0 == (setMinAndMaxVersion(maxVersion, minVersion)))
    {
        PRINT("OSSL version is either invalid or version is not supported\n");
        SSLerr(SSL_F_SSL3_CTX_CTRL, SSL_R_BAD_VALUE);
    }

    if (OK > (status = moc_mutexRelease(m_connectionCountMutex)))
    {
        PRINT("RTOS_mutexRelease() failed : %d\n", status);
        OSSL_FREE(ssl);
        ssl = NULL;
        return NULL;
    }

    /* Openssl does not initiliaze ssl->session here.
     * Allocate session and initialize session the structure.
     */
    if(0 == OSSL_getNewSession(ssl)) {
        SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
        OSSL_FREE(ssl);
        ssl = NULL;
        return NULL;
    }
    /* Reference is incremented as CTX is being assinged to SSL*/
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    SSL_CTX_up_ref(ctx);
#else
    (void) CRYPTO_add(&ctx->orig_ssl_ctx.references, 1, CRYPTO_LOCK_SSL_CTX);
#endif
    ssl->ssl_ctx = ctx;
    /* Get ALPN protocol list*/
    if (ssl->ssl_ctx->alpn_client_proto_list) {
        ssl->alpn_client_proto_list =
            OSSL_MALLOC(ssl->ssl_ctx->alpn_client_proto_list_len);
        if (ssl->alpn_client_proto_list == NULL) {
            SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
            OSSL_FREE(ssl);
            ssl = NULL;
            return (NULL);
        }
        memcpy(ssl->alpn_client_proto_list, ssl->ssl_ctx->alpn_client_proto_list,
               ssl->ssl_ctx->alpn_client_proto_list_len);
        ssl->alpn_client_proto_list_len = ssl->ssl_ctx->alpn_client_proto_list_len;
    }

    ssl->orig_s.param = X509_VERIFY_PARAM_new();
    if (NULL == ssl->orig_s.param)
    {
        SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
        OSSL_FREE(ssl);
        ssl = NULL;
        return (NULL);
    }
    X509_VERIFY_PARAM_inherit(ssl->orig_s.param, ctx->orig_ssl_ctx.param);

    ssl->s3 = OSSL_MALLOC(sizeof(struct ssl3_state_st));
    if (NULL == ssl->s3)
    {
        SSLerr(SSL_F_SSL_NEW, ERR_R_MALLOC_FAILURE);
        OSSL_FREE(ssl);
        ssl = NULL;
        return NULL;
    }
    memset(ssl->s3, 0x00, sizeof(struct ssl3_state_st));

    if(NULL == m_ssl_table)
        (void) NSSL_CHK_CALL(hashTableCreatePtrsTable, &m_ssl_table, 15, pHashCookie, allocSslTable, freeSslTable);

    /* Copy the verify mode from context */
    ssl->orig_s.verify_mode = ctx->verify_mode;

    ssl->orig_s.verify_callback = ctx->verify_callback;

    ssl->orig_s.mode = ctx->orig_ssl_ctx.mode;
    ssl->msg_callback = ctx->msg_callback;
    ssl->msg_callback_arg = ctx->msg_callback_arg;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
    ssl->orig_s.tlsext_status_type = ctx->orig_ssl_ctx.tlsext_status_type;
#elif defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl->tlsext_status_type = ctx->tlsext_status_type;
#else
    ssl->orig_s.tlsext_status_type = -1;
#endif
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl->tlsext_ocsp_resplen = -1;
#else
    ssl->orig_s.tlsext_ocsp_resplen = -1;
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl->orig_s.key_update = SSL_KEY_UPDATE_NONE;
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ssl->verified_chain = NULL;
#endif
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    ssl->hello_verify_done = 0;
#endif

    return ssl;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
static sbyte4 OSSL_rehandshake(sbyte4 connectionInstance)
{
    return NSSL_CHK_CALL(initiateRehandshake, connectionInstance);
}
#endif

static int OSSL_init(void)
{
  sbyte4 status;
  char* pKeySize = NULL;
  char* allowSha1SigAlgo = NULL;
  char* allowTlsPfsCiphersOnly = NULL;
#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
  char *pLogFile  = NULL;
  char *pAllowLog = NULL;
#endif
#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
  intBoolean isFIPSEnabled = 0;
#endif

  do
  {
    /* MOCANA Engine init also calls this but that should be a no-op */
    if (OK > (status = NSSL_CHK_CALL(libraryInit, 0)))
    {
        PRINT("Library Init failed with status = %d\n", (int)status);
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        ossl_assert(status >= OK);
#else
        OPENSSL_assert(status >= OK);
#endif
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__)
    if (OK > (status = NSSL_CHK_CALL(dtlsInit, 50, 50)))
        goto exit;
#else
    if (OK > (status = NSSL_CHK_CALL(sslInit, 50, 50)))
         goto exit;
#endif

  } while (0);

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
  if (OK > (status = NSSL_CHK_CALL(sslCheckFIPS, "")))
  {
    PRINT("sslCheckFIPS failed with status = %d\n", (int)status);
  }
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  ossl_assert(status >= OK);
#else
  OPENSSL_assert(status >= OK);
#endif
#endif

  allowTlsPfsCiphersOnly = getenv("TLS_PFS_CIPHERS_ONLY");

  if (NULL != allowTlsPfsCiphersOnly)
  {

    /* If the TLS 1.2 PFS environment variable is provided then it must be either 0  or 1.  */
    if ( (1 == DIGI_STRLEN(allowTlsPfsCiphersOnly)) &&
         (0 == DIGI_STRCMP(allowTlsPfsCiphersOnly, "0") ||
          0 == DIGI_STRCMP(allowTlsPfsCiphersOnly, "1")))
    {
        setTlsPfsCiphersOnly = atoi(allowTlsPfsCiphersOnly);
    }
  }

  pKeySize = getenv("MIN_SSL_RSA_SIZE");

  if (pKeySize != NULL)
  {
      if (OK > (status = NSSL_CHK_CALL(setMinRSAKeySize, atoi(pKeySize))))
      {
          goto exit;
      }
  }

  allowSha1SigAlgo = getenv("SSL_SHA1_SIG_ALG_SUPPORT");

  if (NULL != allowSha1SigAlgo)
  {

    /* If the SHA-1 environment variable is provided then it must be either 0
     * or 1.
     */
    if ( (1 == strlen(allowSha1SigAlgo)) &&
         (0 == strcmp(allowSha1SigAlgo, "0") || 0 == strcmp(allowSha1SigAlgo, "1")))
    {
        NSSL_CHK_CALL(setSha1SigAlg, atoi(allowSha1SigAlgo));
    }
  }

    /* Don't check return status (in case NanoSSL is built without OCSP).
     * Always attempt to set callback in NanoSSL. Even if the OpenSSL
     * application has not set the OCSP callback, we want to set this
     * callback to save the NanoSSL OCSP response in the SSL structure.
     * This is a global callback in NanoSSL, so set it in the init flow.
     */
    OSSL_setTLSExtStatusCallback();

#if defined(__ENABLE_DIGICERT_SSL_FIPS__)

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  /* returns 1 if the 'fips=yes' default property is set for the given
     libctx, otherwise it returns 0. */
  isFIPSEnabled = EVP_default_properties_is_fips_enabled(NULL);
#else
  isFIPSEnabled = FIPS_mode();
#endif

  /* Check the valid values */
  if ((1 == isFIPSEnabled) || (0 == isFIPSEnabled))
  {
    if (OK > (status = NSSL_CHK_CALL(setFIPSEnabled, isFIPSEnabled)))
    {
        goto exit;
    }
  }
#endif

#ifdef __ENABLE_DIGICERT_SSL_REHANDSHAKE__
  if (OK > (status = NSSL_CHK_CALL(
      rehandshakeInit, REHANDSHAKE_MAX_BYTE_COUNT, REHANDSHAKE_MAX_TIMER_COUNT,
      OSSL_rehandshake)))
  {
      goto exit;
  }
#endif

#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
    pAllowLog = getenv("OPENSSL_ENABLE_LOG");
    
    if ((pAllowLog != NULL) && (0 == strcmp(pAllowLog, "1")))
    {
        if ((NULL != (pLogFile = getenv("OPENSSL_LOG_FILE"))))
        {
            pLogBio = BIO_new(BIO_s_file());
            if (!BIO_append_filename(pLogBio, pLogFile))
            {
                BIO_free(pLogBio);
                pLogBio = NULL;
            }
        }
    }
#endif

exit:

  return (OK == status);
}

/*------------------------------------------------------------------*/

extern void
SSL_load_error_strings(void)
{
  ERR_load_crypto_strings();
  /* Nothing to do here */
}

/*------------------------------------------------------------------*/

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const unsigned char *sid_ctx,
                                   unsigned int sid_ctx_len)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT, SSL_R_NULL_SSL_CTX);
    return 0;
  }

  if (sid_ctx_len > sizeof ctx->sid_ctx)
  {
    SSLerr(SSL_F_SSL_CTX_SET_SESSION_ID_CONTEXT,
           SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }
  ctx->sid_ctx_length = sid_ctx_len;
  memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

/*------------------------------------------------------------------*/

int SSL_set_session_id_context(SSL *ssl, const unsigned char *sid_ctx,
                               unsigned int sid_ctx_len)
{
  if (ssl == NULL)
  {
    SSLerr(SSL_F_SSL_SET_SESSION_ID_CONTEXT,
           SSL_R_UNINITIALIZED);
    return 0;
  }

  if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH)
  {
    SSLerr(SSL_F_SSL_SET_SESSION_ID_CONTEXT,
           SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }
  ssl->sid_ctx_length = sid_ctx_len;
  memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

/*------------------------------------------------------------------*/


extern int
SSL_peek(SSL *s, void *buf, int num)
{
 sbyte4 status = 0;
 unsigned char *pReadPtr = NULL, *pFirstUnusedByte = NULL;
 ubyte4        bytesAvail = 0;
 int           retCount = 0, toCopy = 0, i = 0;
 ubyte4        bytesRemaining = 0, protocol;
 ubyte4    toKeep;
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
     int        mutexAcquired = 0;
#endif

  if (!s || !buf || (num == 0))
  {
    SSLerr(SSL_F_SSL_PEEK, SSL_R_UNINITIALIZED);
    return 0; /*  ERR_INVALID_ARG; */
  }
  if ((NULL == s->pHoldingBuf) || (NULL == s->pTxHoldingBuf)) {
    return -1;
  }
  if (s->rxDataBufLen > 0) { /* Data left over from before */
    toCopy = num <= (int)s->rxDataBufLen ? num : (int)s->rxDataBufLen;
    memcpy(buf, s->pRxDataBuf + s->rxDataBufOffset, toCopy);
    return toCopy;
  }
   do {
   if (0 == s->bytesRcvdRemaining) {
        s->io_state    = OSSL_IN_READ;
        s->orig_s.rwstate = SSL_READING;

        while( 0 >= ( i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf)))
        {
             if ((i<0)||(!BIO_should_retry(s->rbio) || (SSL_pending(s) <= 0)))
             {
               return i;
             }
        }
        /*
         i = BIO_read(s->rbio, s->pHoldingBuf, s->szHoldingBuf);
        if (i <= 0)
        {
            return i;
        }
        */
        s->io_state             = 0;
        s->orig_s.rwstate       = SSL_NOTHING;
        s->pFirstRcvdUnreadByte = s->pHoldingBuf;
        s->bytesRcvdRemaining   = i;
     }
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (0 == mutexAcquired)
    {
        status = OSSL_sessionAcquireMutex(s);
        if (OK == status)
            mutexAcquired = 1;
    }
#endif
    status = NSSL_CHK_CALL(parseSslBuf, s->instance, s->pFirstRcvdUnreadByte, s->bytesRcvdRemaining,
                &pFirstUnusedByte, &bytesRemaining);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
    if (1 == mutexAcquired)
    {
        (void) OSSL_sessionReleaseMutex(s);
        mutexAcquired = 0;
    }
#endif
    if (OK > status) {
      convertMocStatusToSslErr(s, status, SSL_F_SSL3_PEEK, ERR_R_INTERNAL_ERROR);
      return -1;
    }
    if (NULL != pFirstUnusedByte)
    { /* 1 full record was extracted and processed */
      if (0 == bytesRemaining) {
           s->pFirstRcvdUnreadByte     = s->pHoldingBuf;
           s->bytesRcvdRemaining     = 0;
           break;
      } else
      {
           s->pFirstRcvdUnreadByte    = pFirstUnusedByte;
           s->bytesRcvdRemaining    = bytesRemaining;
           status = 1;
      }
     } else { /* full rec not present and all bytes were consumed */
      s->bytesRcvdRemaining     = 0; /* necessary; recvMessage2 does not update this */
      }
     } while (0 == s->bytesRcvdRemaining);

     if (0 < status) {
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (0 == mutexAcquired)
        {
            status = OSSL_sessionAcquireMutex(s);
            if (OK == status)
                mutexAcquired = 1;
        }
#endif
        status = NSSL_CHK_CALL(readSslRec, s->instance, &pReadPtr, &bytesAvail, &protocol);
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
        if (1 == mutexAcquired)
        {
            (void) OSSL_sessionReleaseMutex(s);
            mutexAcquired = 0;
        }
#endif
      if ((pReadPtr != NULL) && (bytesAvail > 0))
      {
          toCopy = num > (int)bytesAvail ? (int)bytesAvail : num;
          memcpy((ubyte *)buf+retCount, pReadPtr, toCopy);
          retCount    += toCopy;

         /* SSL_peek leave the data for SSL_read */
          toKeep    = bytesAvail;
          (void) checkRxBuffer(s, toKeep); /* Sets rxDatabufOffset to 0 if it allocates */
          memcpy(s->pRxDataBuf + s->rxDataBufOffset + s->rxDataBufLen, pReadPtr, toKeep);
          s->rxDataBufLen      += toKeep;
       }
     }
     return retCount;
}

/*------------------------------------------------------------------*/

extern int
SSL_pending(const SSL *ssl)
{
    sbyte4 status = 0;
    sbyte4 numBytes = 0;

    if ( (NULL == ssl) || (MOC_SSL_CONN_INSTANCE_UNASSIGNED == ssl->instance) )
        goto exit;

    if ( (ssl->orig_s.shutdown & SSL_SENT_SHUTDOWN) ||
         (ssl->orig_s.shutdown & SSL_RECEIVED_SHUTDOWN) )
    {
        goto exit;
    }

    if (OK > NSSL_CHK_CALL(recvPending, ssl->instance, &numBytes))
        goto exit;

    if (numBytes > 0)
    {
       status = numBytes;
       goto exit;
    }

    if (ssl->rxDataBufLen > 0 )
    {
        status = ssl->rxDataBufLen;
        goto exit;
    }

    if (ssl->bytesRcvdRemaining > 0 )
    {
        /* Since the content is not deciphered yet - using length 1 */
        status = 1;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern SSL
*SSL_dup(SSL *s)
{
  STACK_OF(X509_NAME) * sk;
  X509_NAME * xn;
  SSL *ret;
  int i;
  char *t;
  ubyte4 dnsNameLen;

  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  if (NULL == (ret = SSL_new(SSL_get_SSL_CTX(s))))
    return (NULL);

  /* setup rbio, and wbio */
  if (NULL != s->rbio)
  {
    if (!BIO_dup_state(s->rbio, (char *) &ret->rbio))
      goto err;
  }

  if (NULL != s->wbio)
  {
    if (s->wbio != s->rbio)
    {
      if (!BIO_dup_state(s->wbio, (char *) &ret->wbio))
        goto err;
    } else
      ret->wbio = ret->rbio;
  }
  /* Dup the client_CA list */
  if (NULL != s->client_CA)
  {
    if (NULL == (sk = sk_X509_NAME_dup(s->client_CA)))
      goto err;
    ret->client_CA = sk;
    for (i = 0; i < sk_X509_NAME_num(sk); i++)
    {
      xn = sk_X509_NAME_value(sk, i);
      if (NULL == sk_X509_NAME_set(sk, i, X509_NAME_dup(xn)))
      {
        X509_NAME_free(xn);
        goto err;
      }
    }
  }

  ret->version = s->version;
  ret->method = s->method;
  ret->tempSocket = s->tempSocket;

  if (NULL != s->session)
  {
    SSL_copy_session_id(ret, s);
  } else
  {
    (void) SSL_set_session_id_context(ret, s->sid_ctx, s->sid_ctx_length);
  }

  /* Calculate the length of dnsName */
  t =s->tlsext_hostname;
  while (0 != *t)
    t++;
  dnsNameLen = (ubyte4) (t - s->tlsext_hostname);

  if (NULL == (ret->tlsext_hostname = (char *) OSSL_MALLOC(dnsNameLen + 1)))
    goto err;

  memcpy(ret->tlsext_hostname, s->tlsext_hostname, dnsNameLen + 1);
  ret->instance = s->instance;
  ret->clientServerFlag = s->clientServerFlag;
  ret->verify_result = s->verify_result;
  SSL_set_info_callback(ret, SSL_get_info_callback(s));

  if (!CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_SSL, &ret->ex_data, &s->ex_data))
    goto err;

  if (NULL == (ret->pHoldingBuf = (ubyte *) OSSL_MALLOC(s->szHoldingBuf)))
    goto err;

  memcpy(ret->pHoldingBuf, s->pHoldingBuf, s->szHoldingBuf);
  ret->szHoldingBuf = s->szHoldingBuf;

  if (NULL == (ret->pTxHoldingBuf = (ubyte *) OSSL_MALLOC(s->szTxHoldingBuf)))
    goto err;
  memcpy(ret->pTxHoldingBuf, s->pTxHoldingBuf, s->szTxHoldingBuf);
  ret->szTxHoldingBuf = s->szTxHoldingBuf;

  ret->bytesRcvdRemaining = s->bytesRcvdRemaining;
  if (NULL == (ret->pFirstRcvdUnreadByte =
                   (ubyte *) OSSL_MALLOC(s->bytesRcvdRemaining)))
    goto err;
  memcpy(ret->pFirstRcvdUnreadByte,
         s->pFirstRcvdUnreadByte,
         s->bytesRcvdRemaining);

  if (NULL == (ret->pRxDataBuf = (ubyte *) OSSL_MALLOC(s->rxDataBufSz)))
    goto err;
  memcpy(ret->pRxDataBuf, s->pRxDataBuf, s->rxDataBufSz);

  ret->rxDataBufSz = s->rxDataBufSz;
  ret->rxDataBufOffset = s->rxDataBufOffset;
  ret->rxDataBufLen = s->rxDataBufLen;
  ret->orig_s.shutdown = s->orig_s.shutdown;
  ret->state = s->state;
  ret->options = s->options;
  ret->io_state = s->io_state;
  ret->sent_client_hello = s->sent_client_hello;

  SSL_set_read_ahead(ret, SSL_get_read_ahead(s));
  /* @Note Assign the values of ssl3_state_st and compress */
  ret->s3 = (struct ssl3_state_st *) OSSL_MALLOC(sizeof(struct ssl3_state_st));
  ret->compress = (COMP_CTX *) OSSL_MALLOC(sizeof(COMP_CTX));
  ret->next_proto_negotiated =
      (unsigned char *) OSSL_MALLOC(s->next_proto_negotiated_len);
  if (NULL == ret->next_proto_negotiated || NULL == ret->s3 || NULL == ret->compress)
    goto err;

  memcpy(ret->next_proto_negotiated,
         s->next_proto_negotiated,
         s->next_proto_negotiated_len);

  if (NULL != s->cipher_list)
  {
    ret->cipher_list = sk_SSL_CIPHER_dup(s->cipher_list);
    if (NULL != ret->cipher_list)
      goto err;
  }

  return (ret);

  err:
  if (NULL != ret)
    SSL_free(ret);
  return NULL;
}

/*------------------------------------------------------------------*/

extern int
SSL_is_server(SSL *s)
{ /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return (s->clientServerFlag == SSL_SERVER_FLAG) ? 1 : 0;
}

/*------------------------------------------------------------------*/

extern void
SSL_set_info_callback(SSL *ssl, void (*cb)(const SSL *ssl, int type, int val))
{
    if (ssl)
        ssl->info_callback = cb;
}

/*------------------------------------------------------------------*/

extern void
(*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl, int type, int val)
{
    if (ssl == NULL) return NULL;
    return ssl->info_callback;
}

void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
    if (ctx == NULL) return;
   /* we parse the certificiates in this cert store and add to mocana cert store
      in OSSL_CTX_load_x509_store */
      if (ctx->cert_store != NULL)
        X509_STORE_free(ctx->cert_store);
    ctx->cert_store = store;
}

/*------------------------------------------------------------------*/
/* Functions related to certificate chain verification and cert. store
 * lookup are not been either called internally OR part of Openssl.
 */


/*------------------------------------------------------------------*/

#if 0
/*------------------------------------------------------------------*/

static sbyte4
certificateLeafTest(sbyte4 connectionInstance, ubyte *pCertificate,
               ubyte4 certificateLength)
{
    SSL* ssl = findSSLFromInstance(connectionInstance);
    X509* x509 = NULL;

    if (ssl)
    {
        x509 = X509_new_from_buffer(pCertificate, certificateLength);
        if (x509)
        {
            if (ssl->ssl_ctx.peerCert)
                X509_free(ssl->ssl_ctx.peerCert);
            ssl->ssl_ctx.peerCert = x509;
        }
    }

    return OK;
}

/*------------------------------------------------------------------*/

static sbyte4
do_verify(SSL* ssl, X509* subject, X509* issuer, int certNum,
      STACK_OF(X509)* chain, int *cert_ok)
{
    sbyte4 status=OK;
    X509_STORE_CTX store_ctx;

    if(ssl == NULL)
        return -1;

    status = X509_verify_sig(issuer, subject, certNum, (subject == issuer));
    if (status < OK)
    {
        ssl->verify_result = status;
    *cert_ok = 0;
    }

    /* Add this cert to the chain (if requested) and then call the callback */
    if (chain)
        (void)sk_X509_push(chain, subject);

    if (ssl->ssl_ctx.verify_callback)
    {
        store_ctx.current = subject;
    *cert_ok = ssl->ssl_ctx.verify_callback(*cert_ok, &store_ctx);
    }

    return status;
}

/*------------------------------------------------------------------*/

static sbyte4
certificateChainVerify(sbyte4 connectionInstance,
               struct certDescriptor* pCertChain,
               ubyte4 numCertsInChain)
{
    SSL* ssl = findSSLFromInstance(connectionInstance);
    X509* prevCert = NULL;
    int cert_ok = 1;
    int isSelfSigned = 0;
    ubyte status = OK;

    if (ssl)
    {
        STACK_OF(X509)* chain = sk_X509_new_null();
    ubyte4 count;

    ssl->verify_result = X509_V_OK;

    if (!chain)
    {
        ssl->verify_result = ERR_MEM_ALLOC_FAIL;
        return ERR_MEM_ALLOC_FAIL;
    }

    /* Reverse the order of the certificates */
    for (count = numCertsInChain - 1;  ; count--)
    {
        X509* x509 = X509_new_from_buffer(pCertChain[count].pCertificate,
                          pCertChain[count].certLength);

        if (!x509)
        {
            sk_X509_pop_free(chain, X509_free);
        ssl->verify_result = ERR_MEM_ALLOC_FAIL;
        return ERR_MEM_ALLOC_FAIL;
        }

        if (NULL == prevCert)
        {
            int certIsTrusted = 0;

            /*
         * NanoSSL may not provide the root certificate here.
         * If it is not provided we need to look it up
         * ourselves and then add it to the chain.  But first,
         * check to see if this is a self-signed certificate.
         * If it is and if numCertsInChain > 1 then look it up
         * as a potential root certificate.
         */

            status = X509_is_root(x509);
        if (status < OK && status != ERR_FALSE)
        {
            ssl->verify_result = status;
            break;
        }

        if (OK == status)
        {

            /* This is self-signed, so either it's a root
             * certificate or it is "not okay"
             */
            if (numCertsInChain > 1)
            {
                if (X509_STORE_in_store(ssl->ssl_ctx.cert_store, x509))
            {
                prevCert = x509;
                certIsTrusted = 1;
            }
            }
            else
            {
                prevCert = x509;
            isSelfSigned = 1;
            cert_ok = 0;
            }
        }
        else
        {
            /* Not self-signed, so look up the issuer */
            prevCert = X509_STORE_get_issuer(ssl->ssl_ctx.cert_store,
                             x509);
        }

        if (prevCert)
        {
            /* Add this cert to the chain and then call the callback */
            status = do_verify(ssl, prevCert, prevCert, count+1,
                       certIsTrusted ? NULL : chain, &cert_ok);

            /*  Self-signed is an error, so override any previous error */
            if (isSelfSigned)
            {
                status = ERR_SSL_NO_SELF_SIGNED_CERTIFICATES;
                ssl->verify_result = status;
            }

            /*  XXX ???  should be break here? */
            if (!cert_ok)
                break;
        }
        else
        {
            status = ERR_SSL_UNKNOWN_CERTIFICATE_AUTHORITY;
            ssl->verify_result = status;
            break;
        }
        }

        if (prevCert != x509)
        {
            /* Validate this cert against prevCert.  */
        status = do_verify(ssl, x509, prevCert, count, chain, &cert_ok);

        /* Save this cert for the next validation */
        prevCert = x509;
        }

        if (0 == count)
            break;
    }

    /* Done.  Save the chain (replacing any existing chain) */
    if (ssl->ssl_ctx.peerCertChain)
        sk_X509_pop_free(ssl->ssl_ctx.peerCertChain, X509_free);
    ssl->ssl_ctx.peerCertChain = chain;

    return SSL_VERIFY_NONE == ssl->ssl_ctx.verify_mode ? OK : status;
    }

    return ERR_SSL_NOT_OPEN;
}

/*------------------------------------------------------------------*/

static sbyte4
certificateStoreLookup(sbyte4 connectionInstance,
               ubyte* pDistinguishedName, ubyte4 distinguishedNameLen,
               struct certDescriptor* pReturnCert)
{
    SSL* ssl =NULL;
    ssl = (SSL*) findSSLFromInstance(connectionInstance);

    if (ssl)
    {
        X509* x509 = X509_STORE_find_by_DN(ssl->ssl_ctx.cert_store, pDistinguishedName, distinguishedNameLen);
        if (x509)
        {
            X509_to_certDescriptor(x509, pReturnCert);
        }
    }

    return OK;
}

#endif
/*------------------------------------------------------------------*/

/* The proper call to shutdown is made in SSL_free. This is no longer
 * used.
 */
static int
OSSL_shutdown(void)
{
    sbyte4 status = OK;

    if (OK > (status = moc_mutexWait(m_hashTableMutex)))
    {
        PRINT("RTOS_mutexWait() failed : %d\n", status);
        return -1;
    }

    NSSL_CHK_CALL(hashTableRemovePtrsTable, m_ssl_table, NULL);
    m_ssl_table = NULL;

    if (OK > (status = moc_mutexRelease(m_hashTableMutex)))
    {
        PRINT("RTOS_mutexRelease() failed : %d\n", status);
        return -1;
    }

#ifndef __DISABLE_DIGICERT_STACK_SHUTDOWN__
    status = NSSL_CHK_CALL(sslReleaseTables, NULL);
#if (defined(__ENABLE_DIGICERT_DTLS_SERVER__) || defined(__ENABLE_DIGICERT_DTLS_CLIENT__))
    status = NSSL_CHK_CALL(dtlsShutdown, NULL);
#else
    status = NSSL_CHK_CALL(sslShutdown, NULL);
#endif
#endif /* __DISABLE_DIGICERT_STACK_SHUTDOWN__ */


    status = NSSL_CHK_CALL(libraryUnInit, NULL);

#if defined(__ENABLE_DIGICERT_OSSL_LOGGING__)
    if (pLogBio != NULL)
    {
        BIO_free(pLogBio);
        pLogBio = NULL;
    }
#endif

    g_initialized = 0;
#if defined(__ENABLE_DIGICERT_SSL_FIPS__)
    g_FIPSInitialized = 0;
#endif

    if (OK == status)
        return 1;

    ERR_add_error_data(status);
    return status;
}

/*------------------------------------------------------------------*/

/*
RU: BEGIN SKELETON SSL FUNCTIONS.
    Move the function above this line once functionality is implemented.
*/

#ifndef __DISABLE_DIGICERT_UNSUPPORTED_OPENSSL_FN__

extern int
SSL_SRP_CTX_init(struct ssl_st *s)
{
  if (s == NULL)
  {
    SSLerr(SSL_F_SSL_SRP_CTX_INIT, SSL_R_UNINITIALIZED);
    return 0;
  }
  return 0; /*@Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_SRP_CTX_init(struct ssl_ctx_st *ctx)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_SRP_CTX_INIT, SSL_R_NULL_SSL_CTX);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_SRP_CTX_free(struct ssl_st *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_SRP_CTX_free(struct ssl_ctx_st *ctx)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_srp_server_param_with_username(SSL *s, int *ad)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SRP_generate_server_master_secret(SSL *s, unsigned char *master_key)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return -1;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SRP_Calc_A_param(SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return -1;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SRP_generate_client_master_secret(SSL *s, unsigned char *master_key)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return -1;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_set_client_cert_engine(SSL_CTX *ctx, ENGINE *e)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_SET_CLIENT_CERT_ENGINE,
           SSL_R_NULL_SSL_CTX);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx,
                               int (*cb)(SSL *ssl,
                                         unsigned char *cookie,
                                         unsigned int *cookie_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

void SSL_CTX_set_stateless_cookie_generate_cb(
    SSL_CTX *ctx,
    int (*cb) (SSL *ssl,
               unsigned char *cookie,
               size_t *cookie_len))
{
  /* @Note: unsupported */
}

#endif

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx,
                             int (*cb)(SSL *ssl, unsigned char *cookie,
                                       unsigned int cookie_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_psk_client_callback(SSL_CTX *ctx,
                                unsigned int (*cb)(SSL *ssl,
                                                   const char *hint,
                                                   char *identity,
                                                   unsigned int
                                                   max_identity_len,
                                                   unsigned char *psk,
                                                   unsigned int
                                                   max_psk_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_psk_client_callback(SSL *s,
                            unsigned int (*cb)(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int
                                               max_identity_len,
                                               unsigned char *psk,
                                               unsigned int
                                               max_psk_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_psk_server_callback(SSL_CTX *ctx,
                                unsigned int (*cb)(SSL *ssl,
                                                   const char *identity,
                                                   unsigned char *psk,
                                                   unsigned int
                                                   max_psk_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_psk_server_callback(SSL *s,
                            unsigned int (*cb)(SSL *ssl,
                                               const char *identity,
                                               unsigned char *psk,
                                               unsigned int
                                               max_psk_len))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_USE_PSK_IDENTITY_HINT,
           SSL_R_NULL_SSL_CTX);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_use_psk_identity_hint(SSL *s, const char *identity_hint)
{
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const char
*SSL_get_psk_identity_hint(const SSL *s)
{
  if (s == NULL || s->session == NULL)
    return NULL;

  return NULL; /* @Note : unsupported */
}

/*------------------------------------------------------------------*/

extern const char
*SSL_get_psk_identity(const SSL *s)
{
  if (s == NULL || s->session == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_add_client_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                              custom_ext_add_cb add_cb,
                              custom_ext_free_cb free_cb,
                              void *add_arg,
                              custom_ext_parse_cb parse_cb,
                              void *parse_arg)
{
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_add_server_custom_ext(SSL_CTX *ctx, unsigned int ext_type,
                              custom_ext_add_cb add_cb,
                              custom_ext_free_cb free_cb,
                              void *add_arg,
                              custom_ext_parse_cb parse_cb,
                              void *parse_arg)
{
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern int
SSL_extension_supported(unsigned int ext_type)
{
    switch (ext_type)
    {
        /* Internally supported extensions. */
    case TLSEXT_TYPE_application_layer_protocol_negotiation:
#ifndef OPENSSL_NO_EC
    case TLSEXT_TYPE_ec_point_formats:
    case TLSEXT_TYPE_supported_groups:
    case TLSEXT_TYPE_key_share:
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    case TLSEXT_TYPE_next_proto_neg:
#endif
    case TLSEXT_TYPE_padding:
    case TLSEXT_TYPE_renegotiate:
    case TLSEXT_TYPE_max_fragment_length:
    case TLSEXT_TYPE_server_name:
    case TLSEXT_TYPE_session_ticket:
    case TLSEXT_TYPE_signature_algorithms:
#ifndef OPENSSL_NO_SRP
    case TLSEXT_TYPE_srp:
#endif
#ifndef OPENSSL_NO_OCSP
    case TLSEXT_TYPE_status_request:
#endif
#ifndef OPENSSL_NO_CT
    case TLSEXT_TYPE_signed_certificate_timestamp:
#endif
#ifndef OPENSSL_NO_SRTP
    case TLSEXT_TYPE_use_srtp:
#endif
    case TLSEXT_TYPE_encrypt_then_mac:
    case TLSEXT_TYPE_supported_versions:
    case TLSEXT_TYPE_extended_master_secret:
    case TLSEXT_TYPE_psk_kex_modes:
    case TLSEXT_TYPE_cookie:
    case TLSEXT_TYPE_early_data:
    case TLSEXT_TYPE_certificate_authorities:
    case TLSEXT_TYPE_psk:
    case TLSEXT_TYPE_post_handshake_auth:
        return 1;
    default:
        return 0;
    }
}
#endif

/*------------------------------------------------------------------*/

extern EVP_PKEY
*SSL_CTX_get0_privatekey(const SSL_CTX *ctx)
{
  /* No Error Code in Openssl */
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode)
{
    if (NULL == ctx)
    {
        return;
    }

    ctx->orig_ssl_ctx.quiet_shutdown = mode;
}

/*------------------------------------------------------------------*/

extern int
SSL_want(const SSL *s)
{
  if (s == NULL)
    return -1;

  return s->orig_s.rwstate;
}

/*------------------------------------------------------------------*/

extern int
SSL_clear(SSL *s)
{
  if (s == NULL)
  {
    SSLerr(SSL_F_SSL_CLEAR, SSL_R_UNINITIALIZED);
    return 0;
  }

  if (s->method == NULL)
  {
    SSLerr(SSL_F_SSL_CLEAR, SSL_R_NO_METHOD_SPECIFIED);
    return 0;
  }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ossl_statem_clear(s);
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  /*
   * X509_VERIFY_PARAM_move_peername frees and sets the peername value to NULL;
   * If X509_VERIFY_PARAM_free is called later(NULL check is not performed
   * in this function before freeing peername), it may cause a crash.
   */
  X509_VERIFY_PARAM_move_peername(s->orig_s.param, NULL);
#endif
  s->orig_s.shutdown = 0;
  s->state = SSL_ST_BEFORE | ((s->clientServerFlag == SSL_CLIENT_FLAG) ? SSL_ST_CONNECT : SSL_ST_ACCEPT);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  s->orig_state = s->state;
#else
  s->orig_s.state = s->state;
#endif
  s->version = s->method->version;

  s->orig_s.rwstate = SSL_NOTHING;

  if (MOC_SSL_CONN_INSTANCE_UNASSIGNED != s->instance)
  {
      if (OK > OSSL_closeConnection(s))
      {
        return 0;
      }
  }
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  if (NULL != s->verify_store)
  {
    X509_STORE_free(s->verify_store);
    s->verify_store = NULL;
  }
#endif
  return 1;
}

/*------------------------------------------------------------------*/

/* Partial implementation
 *
 * Only handle the case where the time is passed in as 0.
 */
extern void
SSL_CTX_flush_sessions(SSL_CTX *s, long t)
{
    if ( (NULL != s) && (0 == t) )
    {
        NSSL_CHK_CALL(sslClearAllSessionCache, NULL);
    }

    return;
}

/*------------------------------------------------------------------*/

extern int
SSL_get_fd(const SSL *s)
{
  /* The operation failed, because the underlying BIO is not of the correct type */
  if (s == NULL)
    return -1;

  return BIO_get_fd(SSL_get_rbio(s), NULL);
}

/*------------------------------------------------------------------*/

extern int
SSL_get_rfd(const SSL *s)
{
  /* The operation failed, because the underlying BIO is not of the correct type */
  if (s == NULL)
    return -1;

  return s->rfd;
}

/*------------------------------------------------------------------*/

extern int
SSL_get_wfd(const SSL *s)
{
  /* The operation failed, because the underlying BIO is not of the correct type */
  if (s == NULL)
    return -1;

  return s->wfd;
}

/*------------------------------------------------------------------*/

/** The old interface to get the same thing as SSL_get_ciphers() */
const char *SSL_get_cipher_list(const SSL *s, int n)
{
    SSL_CIPHER *c;
    STACK_OF(SSL_CIPHER) *sk;

    if (s == NULL)
        return (NULL);
    sk = SSL_get_ciphers(s);
    if ((sk == NULL) || (sk_SSL_CIPHER_num(sk) <= n))
        return (NULL);
    c = (SSL_CIPHER *)sk_SSL_CIPHER_value(sk, n);
    if (c == NULL)
        return (NULL);
    return (c->name);
}

/*------------------------------------------------------------------*/

extern char
*SSL_get_shared_ciphers(const SSL *s, char *buf, int len)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_get_read_ahead(const SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
  return s->orig_s.rlayer.read_ahead;
#else
  return s->orig_s.read_ahead;
#endif
}

/*------------------------------------------------------------------*/

extern int (*SSL_get_verify_callback(const SSL *s))(int, X509_STORE_CTX *)
{
  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_verify_depth(SSL *s, int depth)
{
  if (s == NULL) return;
  X509_VERIFY_PARAM_set_depth(s->orig_s.param, depth);
}

/*------------------------------------------------------------------*/
static void ssl_cert_set_cert_cb(CERT *c, int (*cb) (SSL *ssl, void *arg), void *arg)
{
    if (NULL == c)
    {
        return;
    }

    c->cert_cb = cb;
    c->cert_cb_arg = arg;
}

extern void
SSL_set_cert_cb(SSL *s, int (*cb)(SSL *ssl, void *arg), void *arg)
{
    /*  @unsupported */
}

extern void
SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb)(SSL *ssl, void *arg), void *arg)
{
    if (NULL == c)
        return;

    ssl_cert_set_cert_cb(c->orig_ssl_ctx.cert, cb, arg);
}

/*------------------------------------------------------------------*/

extern int
SSL_use_RSAPrivateKey(SSL *ssl, RSA *pRsaKey)
{
    EVP_PKEY *pEvpKey;
    int ret;

    if ( (NULL == ssl) || (NULL == ssl->ssl_ctx) || (NULL == pRsaKey) )
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    pEvpKey = EVP_PKEY_new();
    if (NULL == pEvpKey)
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_EVP_LIB);
        return 0;
    }

    RSA_up_ref(pRsaKey);
    if (EVP_PKEY_assign_RSA(pEvpKey, pRsaKey) <= 0)
    {
        RSA_free(pRsaKey);
        return 0;
    }

    /* Load the key into the SSL_CTX.
     *
     * This implementation differs from the OpenSSL implementation. In the
     * OpenSSL implementation the key is stored in the SSL context itself.
     *
     * If a call to this function and SSL_CTX_use_PrivateKey is made by the
     * application then the latter call will have the key that is actually used.
     */
    ret = SSL_CTX_use_PrivateKey(ssl->ssl_ctx, pEvpKey);
    return ret;
}

/*------------------------------------------------------------------*/

extern int
SSL_use_RSAPrivateKey_ASN1(
    SSL *ssl, unsigned char *pKeyData, long keyDataLen)
{
    int ret;
    RSA *pRsaKey = NULL;

    if (NULL == ssl)
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    pRsaKey = d2i_RSAPrivateKey(
        NULL, (const unsigned char **) &pKeyData, keyDataLen);
    if (NULL == pRsaKey)
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    ret = SSL_use_RSAPrivateKey(ssl, pRsaKey);

    /* Coverity Issue: The following RSA_free() call has been flagged by Coverity as
     * a potential double free. However, this is a false positive. */
    RSA_free(pRsaKey); /* ref count is maintained; Freed only if ref count goes down to 0 */

    return ret;
}

/*------------------------------------------------------------------*/

extern int
SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey)
{
  if (ssl == NULL)
  {
    SSLerr(SSL_F_SSL_USE_PRIVATEKEY, SSL_R_UNINITIALIZED);
    return (0);
  }

  if (pkey == NULL)
  {
    SSLerr(SSL_F_SSL_USE_PRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
    return (0);
  }

    return SSL_CTX_use_PrivateKey(ssl->ssl_ctx, pkey);
}

/*------------------------------------------------------------------*/

extern int
SSL_use_PrivateKey_ASN1(
    int type, SSL *ssl, const unsigned char *pKeyData, long keyDataLen)
{
    int ret;
    EVP_PKEY *pEvpKey;

    if ( (NULL == ssl) || (NULL == ssl->ssl_ctx) )
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* Deserialize the key.
     */
    pEvpKey = d2i_PrivateKey(type, NULL, &pKeyData, keyDataLen);
    if (NULL == pEvpKey)
    {
        SSLerr(SSL_F_SSL_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return 0;
    }

    /* Load the key into the SSL_CTX.
     *
     * This implementation differs from the OpenSSL implementation. In the
     * OpenSSL implementation the key is stored in the SSL context itself.
     *
     * If a call to this function and SSL_CTX_use_PrivateKey is made by the
     * application then the latter call will have the key that is actually used.
     */
    ret = SSL_CTX_use_PrivateKey(ssl->ssl_ctx, pEvpKey);
    return ret;
}

/*------------------------------------------------------------------*/

extern int
SSL_use_certificate(SSL *ssl, X509 *x)
{
    if ( (NULL == ssl) || (NULL == ssl->ssl_ctx) || (NULL == x) )
    {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return SSL_CTX_use_certificate(ssl->ssl_ctx, x);
}

/*------------------------------------------------------------------*/

int SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_use_certificate(ssl, x);
    X509_free(x);
    return (ret);
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
extern int
SSL_use_certificate_chain_file(SSL *ssl, const char *file)
{
    if ((NULL == ssl) || (NULL == ssl->ssl_ctx))
    {
        SSLerr(SSL_F_SSL_USE_CERTIFICATE, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return SSL_CTX_use_certificate_chain_file(ssl->ssl_ctx, file);
}
#endif

/*------------------------------------------------------------------*/

extern int
SSL_CTX_use_serverinfo(SSL_CTX *ctx, const unsigned char *serverinfo,
                       size_t serverinfo_length)
{
  if (ctx == NULL || serverinfo == NULL || serverinfo_length == 0)
  {
    SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_use_serverinfo_file(SSL_CTX *ctx, const char *file)
{
  if (ctx == NULL || file == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_USE_SERVERINFO_FILE,
           ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type)
{
  if (ssl == NULL)
  {
    SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY_FILE, SSL_R_UNINITIALIZED);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type)
{
    if ( (NULL == ssl) || (NULL == ssl->ssl_ctx) || (NULL == file) )
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return SSL_CTX_use_PrivateKey_file(ssl->ssl_ctx, file, type);
}

/*------------------------------------------------------------------*/

extern int
SSL_use_certificate_file(SSL *ssl, const char *file, int type)
{
    if ( (NULL == ssl) || (NULL == ssl->ssl_ctx) || (NULL == file) )
    {
        SSLerr(SSL_F_SSL_USE_RSAPRIVATEKEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return SSL_CTX_use_certificate_file(ssl->ssl_ctx, file, type);
}

/*------------------------------------------------------------------*/

extern const char
*SSL_rstate_string(const SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const char
*SSL_rstate_string_long(const SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern long
SSL_SESSION_get_timeout(const SSL_SESSION *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return (0); /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_copy_session_id(SSL *t, const SSL *f)
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern X509
*SSL_SESSION_get0_peer(SSL_SESSION *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_SESSION_set1_id_context(SSL_SESSION *s, const unsigned char *sid_ctx,
                            unsigned int sid_ctx_len)
{
  if (s == NULL)
  {
    SSLerr(SSL_F_SSL_SESSION_SET1_ID_CONTEXT, SSL_R_UNINITIALIZED);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_SESSION_print_fp(FILE *fp, const SSL_SESSION *x)
{
  if (fp == NULL)
  {
    SSLerr(SSL_F_SSL_SESSION_PRINT_FP, SSL_R_BAD_VALUE);
    return 0;
  }
  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_generate_session_id(SSL_CTX *ctx, GEN_SESSION_CB cb)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_set_generate_session_id(SSL *ssl, GEN_SESSION_CB cb)
{
  /* No Error Code in Openssl */
  if (ssl == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_has_matching_session_id(const
                            SSL *ssl,
                            const
                            unsigned char *id,
                            unsigned int id_len)
{
  /* No Error Code in Openssl */
  if (ssl == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx)
{
    /* No Error Code in Openssl */
    if (ctx == NULL)
        return 0;

    return X509_VERIFY_PARAM_get_depth(ctx->orig_ssl_ctx.param);
}

/*------------------------------------------------------------------*/

void
SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth)
{
    if (ctx == NULL) return;
    X509_VERIFY_PARAM_set_depth(ctx->orig_ssl_ctx.param, depth);
}

/*------------------------------------------------------------------*/

int
SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_USE_RSAPRIVATEKEY_ASN1, SSL_R_NULL_SSL_CTX);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx,
                                const unsigned char *d, long len)
{
    int ret;
    const unsigned char *p;
    EVP_PKEY *pkey;

    p = d;
    if ((pkey = d2i_PrivateKey(type, NULL, &p, (long)len)) == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_PRIVATEKEY_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);
    return (ret);
}

/*------------------------------------------------------------------*/

int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len,
                                 const unsigned char *d)
{
    X509 *x;
    int ret;

    x = d2i_X509(NULL, &d, (long)len);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_ASN1, ERR_R_ASN1_LIB);
        return (0);
    }

    ret = SSL_CTX_use_certificate(ctx, x);
    X509_free(x);
    return (ret);
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_purpose(SSL_CTX *s, int purpose)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_set_purpose(SSL *s, int purpose)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_trust(SSL_CTX *s, int trust)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_set_trust(SSL *s, int trust)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return X509_VERIFY_PARAM_set1(ctx->orig_ssl_ctx.param, vpm);
}

/*------------------------------------------------------------------*/

int
SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm)
{
  /* No Error Code in Openssl */
  if (ssl == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

X509_VERIFY_PARAM
*SSL_CTX_get0_param(SSL_CTX *ctx)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return NULL;

  return ctx->orig_ssl_ctx.param;
}

/*------------------------------------------------------------------*/

X509_VERIFY_PARAM
*SSL_get0_param(SSL *ssl)
{
    /* No Error Code in Openssl */
    if (ssl == NULL)
        return NULL;

    return ssl->orig_s.param;
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_srp_username(SSL_CTX *ctx, char *name)
{
  /* No Error Code in Openssl. It does route to ssl3_ctx_ctrl.*/
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_srp_password(SSL_CTX *ctx, char *password)
{
  /* No Error Code in Openssl. It does route to ssl3_ctx_ctrl.*/
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_srp_strength(SSL_CTX *ctx, int strength)
{
  /* No Error Code in Openssl. It does route to ssl3_ctx_ctrl.*/
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_srp_client_pwd_callback(SSL_CTX *ctx, char *(*cb)(SSL *, void *))
{
  /* No Error Code in Openssl.*/
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_srp_verify_param_callback(SSL_CTX *ctx, int (*cb)(SSL *, void *))
{
  /* No Error Code in Openssl. It does route to ssl3_ctx_ctrl.*/
  if (ctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

int
SSL_set_srp_server_param_pw(SSL *s,
                            const
                            char *user,
                            const
                            char *pass,
                            const
                            char *grp)
{
  /* No Error Code in Openssl.*/
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

BIGNUM
*SSL_get_srp_g(SSL *s)
{
  /* No Error Code in Openssl.*/
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

BIGNUM
*SSL_get_srp_N(SSL *s)
{
  /* No Error Code in Openssl.*/
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

void
SSL_certs_clear(SSL *s)
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

long
SSL_callback_ctrl(SSL *s, int cmd, void (*fp)(void))
{
    if (s == NULL) return 0;
    switch (cmd) {
    case SSL_CTRL_SET_MSG_CALLBACK:
        if ( NULL == fp )
            return 0;
        s->msg_callback = (void (*)
                           (int write_p, int version, int content_type,
                            const void *buf, size_t len, SSL *ssl,
                            void *arg))(fp);
        OSSL_set_alert_cb(s);
        return 1;

    default:
        return 0;
    }
}

void SSL_set_msg_callback(SSL *ssl,
                          void (*cb) (int write_p, int version,
                                      int content_type, const void *buf,
                                      size_t len, SSL *ssl, void *arg))
{
    (void) SSL_callback_ctrl(ssl, SSL_CTRL_SET_MSG_CALLBACK, (void (*)(void))cb);
}

int SSL_export_keying_material(SSL *s, unsigned char *out, size_t olen,
                               const char *label, size_t llen,
                               const unsigned char *p, size_t plen,
                               int use_context)
{
    sbyte4 status = 0;

    if (s == NULL) return 0;
    status = NSSL_CHK_CALL(getExportKeyMaterial, s->instance, out, (ubyte2) olen, (ubyte *)label, (ubyte2) llen, (ubyte *)p, (ubyte2) plen, use_context);

    /* NanoSSL API returns 0 in case of success */
    if (0 == status)
    {
        status = 1;
    }

    if (0 == status)
    {
        SSLerr(SSL_F_SSL_UNDEFINED_FUNCTION,ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    }

    return status;
}

int SSL_check_private_key(const SSL *ssl)
{
    if ((NULL == ssl) || (NULL == ssl->ssl_ctx))
    {
        SSLerr(SSL_F_SSL_CHECK_PRIVATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return (0);
    }

    if (NULL == ssl->ssl_ctx->cert_x509)
    {
        SSLerr(SSL_F_SSL_CTX_CHECK_PRIVATE_KEY,
            SSL_R_NO_CERTIFICATE_ASSIGNED);
        return (0);
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    return 1;
#else
    return (X509_check_private_key(
        ssl->ssl_ctx->cert_x509,
        ssl->ssl_ctx->privatekey[ssl->ssl_ctx->ossl_pkey_idx]));
#endif
}

/*------------------------------------------------------------------*/

static int OSSL_SSL_serializePrivateKey(
    EVP_PKEY *pEvpKey, unsigned char **ppKey, int *pKeyLen)
{
    int rv = -1;
    unsigned char *pTemp;

    if ( (NULL == pEvpKey) || (NULL == ppKey) || (NULL == pKeyLen) )
    {
        goto exit;
    }

    *pKeyLen = 0;
    *pKeyLen = i2d_PrivateKey(pEvpKey, NULL);
    if (*pKeyLen <= 0)
    {
        goto exit;
    }

    *ppKey = OSSL_MALLOC(*pKeyLen);
    if (NULL == *ppKey)
        goto exit;

    pTemp = *ppKey;
    *pKeyLen = i2d_PrivateKey(pEvpKey, &pTemp);
    rv = 0;

exit:

    return rv;
}

/*------------------------------------------------------------------*/

static int OSSL_SSL_serializeCert(
    X509 *pCert, unsigned char **ppCert, int *pCertLen)
{
    int rv = -1;
    unsigned char *pTemp;

    if ( (NULL == pCert) || (NULL == ppCert) || (NULL == pCertLen) )
    {
        goto exit;
    }

    *pCertLen = i2d_X509(pCert, NULL);
    if (0 > *pCertLen)
    {
        goto exit;
    }

    *ppCert = OSSL_MALLOC(*pCertLen);
    if (NULL == *ppCert)
        goto exit;

    pTemp = *ppCert;
    *pCertLen = i2d_X509(pCert, &pTemp);
    rv = 0;

exit:

    return rv;
}

static int OSSL_SSL_serializeCertChain(
    STACK_OF(X509) *pChain, unsigned char **ppChain, int *pChainLen,
    int *pChainCount)
{
    int rv = -1, i, bufSize = 0, tempSize;
    unsigned char *pTemp;

    if ( (NULL == pChain) || (NULL == ppChain) || (NULL == pChainLen) ||
         (NULL == pChainCount) )
    {
        goto exit;
    }

    for (i = 0; i < sk_X509_num(pChain); i++)
    {
        bufSize += i2d_X509(sk_X509_value(pChain, i), NULL);
    }

    *ppChain = OSSL_MALLOC(bufSize + (i * sizeof(ubyte4)));
    if (i > 0 && NULL == *ppChain)
    {
        goto exit;
    }
    
    *pChainLen = bufSize + (i * sizeof(ubyte4));
    *pChainCount = i;
    pTemp = *ppChain;

    for (i = 0; i < sk_X509_num(pChain); i++)
    {
        tempSize = i2d_X509(sk_X509_value(pChain, i), NULL);
        *((ubyte4 *) pTemp) = (ubyte4) tempSize;
        pTemp += sizeof(ubyte4);
        i2d_X509(sk_X509_value(pChain, i), &pTemp);
    }

    rv = 0;

exit:

    return rv;
}

/*------------------------------------------------------------------*/

static int tls1_check_chain(
    SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain, int idx)
{
    int rv = 0, status;
    int keyLen = 0, certLen = 0, chainLen = 0, chainCount = 0;
    unsigned char *pKey = NULL, *pCert = NULL, *pChain = NULL;

    if (idx != -1)
    {
        goto exit;
    }

    if ( (NULL == x) || (NULL == pk) )
    {
        goto exit;
    }

    status = OSSL_SSL_serializePrivateKey(pk, &pKey, &keyLen);
    if (0 != status)
    {
        goto exit;
    }

    status = OSSL_SSL_serializeCert(x, &pCert, &certLen);
    if (0 != status)
    {
        goto exit;
    }

    if (NULL != chain)
    {
        status = OSSL_SSL_serializeCertChain(
            chain, &pChain, &chainLen, &chainCount);
        if (0 != status)
        {
            goto exit;
        }
    }

    status = NSSL_CHK_CALL(
        validateCertKeyChain, pKey, keyLen, pCert, certLen,
        pChain, chainLen, chainCount);
    if (0 != status)
    {
        goto exit;
    }

    rv = CERT_PKEY_VALID;

exit:

    if (NULL != pKey)
    {
        OSSL_FREE(pKey);
    }

    if (NULL != pCert)
    {
        OSSL_FREE(pCert);
    }
    
    if (NULL != pChain)
    {
        OSSL_FREE(pChain);
    }

    return rv;
}

/*------------------------------------------------------------------*/

int SSL_check_chain(SSL *s, X509 *x, EVP_PKEY *pk, STACK_OF(X509) *chain)
{
    if (NULL == s)
    {
        return 0;
    }
    
    return tls1_check_chain(s, x, pk, chain, -1);
}

/*------------------------------------------------------------------*/

int
SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth)
{
  if (ctx == NULL)
  {
    SSLerr(SSL_F_SSL_CTX_SET_SSL_VERSION, SSL_R_NULL_SSL_CTX);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*SSLv2_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*SSLv2_server_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*SSLv2_client_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLSv1_2_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLSv1_2_server_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLSv1_2_client_method(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*DTLS_method(void)
{
#if (defined(__ENABLE_DIGICERT_DTLS_CLIENT__) || defined(__ENABLE_DIGICERT_DTLS_SERVER__))
    return &dtls_method;
#else
    return NULL;
#endif
}

/*------------------------------------------------------------------*/

extern int
SSL_renegotiate_abbreviated(SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_renegotiate_pending(SSL *s)
{
    sbyte4 status = OK;
    ubyte4 connState = 0;

    if (s == NULL)
        return 0;

    if (OK > (status = NSSL_CHK_CALL(getSessionStatus, s->instance, &connState)))
    {
        return 0;
    }

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    if ((SSL_CONNECTION_RENEGOTIATE == connState) || (SSL_ST_RENEGOTIATE == s->orig_state))
#else
    if ((SSL_CONNECTION_RENEGOTIATE == connState) || (SSL_ST_RENEGOTIATE == s->orig_s.state))
#endif
    {
        return 1;
    }

    return 0;
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*SSL_CTX_get_ssl_method(SSL_CTX *ctx)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return NULL;

  return ctx->ssl_method;
}

/*------------------------------------------------------------------*/

extern const SSL_METHOD
*SSL_get_ssl_method(SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return s->method;
}

/*------------------------------------------------------------------*/

extern int
SSL_set_ssl_method(SSL *s, const SSL_METHOD *method)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  s->method = method;
  return 1;
}

/*------------------------------------------------------------------*/

extern const char
*SSL_alert_desc_string(int value)
{
  return "U"; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_add_client_CA(SSL *ssl, X509 *x)
{
  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s)
{
    if (s == NULL) return NULL;
     if (s->clientServerFlag == SSL_CLIENT_FLAG) { /* we are in the client */
        if (s->s3 != NULL)
            return (s->s3->tmp.ca_names);
        else
            return (NULL);
    } else {
        if (s->client_CA != NULL)
            return (s->client_CA);
        else
            return (s->ssl_ctx->client_CA);
    }
}

/*------------------------------------------------------------------*/

extern long
SSL_get_default_timeout(const SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

static const char *ssl_protocol_to_string(int version)
{
    switch(version)
    {
    case TLS1_3_VERSION:
        return "TLSv1.3";

    case TLS1_2_VERSION:
        return "TLSv1.2";

    case TLS1_1_VERSION:
        return "TLSv1.1";

    case TLS1_VERSION:
        return "TLSv1";

    case SSL3_VERSION:
        return "SSLv3";

    case DTLS1_BAD_VER:
        return "DTLSv0.9";

    case DTLS1_VERSION:
        return "DTLSv1";

    case DTLS1_2_VERSION:
        return "DTLSv1.2";

    default:
        return "unknown";
    }
}

extern char
*SSL_CIPHER_description(const SSL_CIPHER *cipher, char *buf, int len)
{
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    const char *kx, *au, *enc, *mac;
    const char *ver;
    uint32_t alg_mkey, alg_auth, alg_enc, alg_mac;
    static const char *format = "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s\n";

    if (buf == NULL) {
        len = 128;
        if ((buf = OPENSSL_malloc(len)) == NULL) {
            SSLerr(SSL_F_SSL_CIPHER_DESCRIPTION, ERR_R_MALLOC_FAILURE);
            return NULL;
        }
    } else if (len < 128) {
        return NULL;
    }

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;
    alg_enc = cipher->algorithm_enc;
    alg_mac = cipher->algorithm_mac;

    ver = ssl_protocol_to_string(cipher->min_tls);

    switch (alg_mkey) {
    case SSL_kRSA:
        kx = "RSA";
        break;
    case SSL_kDHE:
        kx = "DH";
        break;
    case SSL_kECDHE:
        kx = "ECDH";
        break;
    case SSL_kPSK:
        kx = "PSK";
        break;
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    case SSL_kRSAPSK:
        kx = "RSAPSK";
        break;
    case SSL_kECDHEPSK:
        kx = "ECDHEPSK";
        break;
    case SSL_kDHEPSK:
        kx = "DHEPSK";
        break;
#endif
    case SSL_kSRP:
        kx = "SRP";
        break;
    case SSL_kGOST:
        kx = "GOST";
        break;
    case SSL_kANY:
        kx = "any";
        break;
    default:
        kx = "unknown";
    }

    switch (alg_auth) {
    case SSL_aRSA:
        au = "RSA";
        break;
    case SSL_aDSS:
        au = "DSS";
        break;
    case SSL_aNULL:
        au = "None";
        break;
    case SSL_aECDSA:
        au = "ECDSA";
        break;
    case SSL_aPSK:
        au = "PSK";
        break;
    case SSL_aSRP:
        au = "SRP";
        break;
    case SSL_aGOST01:
        au = "GOST01";
        break;
    /* New GOST ciphersuites have both SSL_aGOST12 and SSL_aGOST01 bits */
    case (SSL_aGOST12 | SSL_aGOST01):
        au = "GOST12";
        break;
    case SSL_aANY:
        au = "any";
        break;
    default:
        au = "unknown";
        break;
    }

    switch (alg_enc) {
    case SSL_DES:
        enc = "DES(56)";
        break;
    case SSL_3DES:
        enc = "3DES(168)";
        break;
    case SSL_RC4:
        enc = "RC4(128)";
        break;
    case SSL_RC2:
        enc = "RC2(128)";
        break;
    case SSL_IDEA:
        enc = "IDEA(128)";
        break;
    case SSL_eNULL:
        enc = "None";
        break;
    case SSL_AES128:
        enc = "AES(128)";
        break;
    case SSL_AES256:
        enc = "AES(256)";
        break;
    case SSL_AES128GCM:
        enc = "AESGCM(128)";
        break;
    case SSL_AES256GCM:
        enc = "AESGCM(256)";
        break;
    case SSL_AES128CCM:
        enc = "AESCCM(128)";
        break;
    case SSL_AES256CCM:
        enc = "AESCCM(256)";
        break;
    case SSL_AES128CCM8:
        enc = "AESCCM8(128)";
        break;
    case SSL_AES256CCM8:
        enc = "AESCCM8(256)";
        break;
    case SSL_CAMELLIA128:
        enc = "Camellia(128)";
        break;
    case SSL_CAMELLIA256:
        enc = "Camellia(256)";
        break;
    case SSL_ARIA128GCM:
        enc = "ARIAGCM(128)";
        break;
    case SSL_ARIA256GCM:
        enc = "ARIAGCM(256)";
        break;
    case SSL_SEED:
        enc = "SEED(128)";
        break;
    case SSL_eGOST2814789CNT:
    case SSL_eGOST2814789CNT12:
        enc = "GOST89(256)";
        break;
    case SSL_CHACHA20POLY1305:
        enc = "CHACHA20/POLY1305(256)";
        break;
    default:
        enc = "unknown";
        break;
    }

    switch (alg_mac) {
    case SSL_MD5:
        mac = "MD5";
        break;
    case SSL_SHA1:
        mac = "SHA1";
        break;
    case SSL_SHA256:
        mac = "SHA256";
        break;
    case SSL_SHA384:
        mac = "SHA384";
        break;
    case SSL_AEAD:
        mac = "AEAD";
        break;
    case SSL_GOST89MAC:
    case SSL_GOST89MAC12:
        mac = "GOST89";
        break;
    case SSL_GOST94:
        mac = "GOST94";
        break;
    case SSL_GOST12_256:
    case SSL_GOST12_512:
        mac = "GOST2012";
        break;
    default:
        mac = "unknown";
        break;
    }

    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac);

    return buf;

#else

    int is_export, pkl, kl;
    const char *ver, *exp_str;
    const char *kx, *au, *enc, *mac;
    unsigned long alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl, alg2;
#ifdef KSSL_DEBUG
    static const char *format =
        "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s AL=%lx/%lx/%lx/%lx/%lx\n";
#else
    static const char *format =
        "%-23s %s Kx=%-8s Au=%-4s Enc=%-9s Mac=%-4s%s\n";
#endif                          /* KSSL_DEBUG */

    alg_mkey = cipher->algorithm_mkey;
    alg_auth = cipher->algorithm_auth;
    alg_enc = cipher->algorithm_enc;
    alg_mac = cipher->algorithm_mac;
    alg_ssl = cipher->algorithm_ssl;

    alg2 = cipher->algorithm2;

    is_export = SSL_C_IS_EXPORT(cipher);
    pkl = SSL_C_EXPORT_PKEYLENGTH(cipher);
    kl = SSL_C_EXPORT_KEYLENGTH(cipher);
    exp_str = is_export ? " export" : "";

    if (alg_ssl & SSL_SSLV2)
        ver = "SSLv2";
    else if (alg_ssl & SSL_SSLV3)
        ver = "SSLv3";
    else if (alg_ssl & SSL_TLSV1_2)
        ver = "TLSv1.2";
    else
        ver = "unknown";

    switch (alg_mkey) {
    case SSL_kRSA:
        kx = is_export ? (pkl == 512 ? "RSA(512)" : "RSA(1024)") : "RSA";
        break;
    case SSL_kDHr:
        kx = "DH/RSA";
        break;
    case SSL_kDHd:
        kx = "DH/DSS";
        break;
    case SSL_kKRB5:
        kx = "KRB5";
        break;
    case SSL_kEDH:
        kx = is_export ? (pkl == 512 ? "DH(512)" : "DH(1024)") : "DH";
        break;
    case SSL_kECDHr:
        kx = "ECDH/RSA";
        break;
    case SSL_kECDHe:
        kx = "ECDH/ECDSA";
        break;
    case SSL_kEECDH:
        kx = "ECDH";
        break;
    case SSL_kPSK:
        kx = "PSK";
        break;
    case SSL_kSRP:
        kx = "SRP";
        break;
    case SSL_kGOST:
        kx = "GOST";
        break;
    default:
        kx = "unknown";
    }

    switch (alg_auth) {
    case SSL_aRSA:
        au = "RSA";
        break;
    case SSL_aDSS:
        au = "DSS";
        break;
    case SSL_aDH:
        au = "DH";
        break;
    case SSL_aKRB5:
        au = "KRB5";
        break;
    case SSL_aECDH:
        au = "ECDH";
        break;
    case SSL_aNULL:
        au = "None";
        break;
    case SSL_aECDSA:
        au = "ECDSA";
        break;
    case SSL_aPSK:
        au = "PSK";
        break;
    case SSL_aSRP:
        au = "SRP";
        break;
    case SSL_aGOST94:
        au = "GOST94";
        break;
    case SSL_aGOST01:
        au = "GOST01";
        break;
    default:
        au = "unknown";
        break;
    }

    switch (alg_enc) {
    case SSL_DES:
        enc = (is_export && kl == 5) ? "DES(40)" : "DES(56)";
        break;
    case SSL_3DES:
        enc = "3DES(168)";
        break;
    case SSL_RC4:
        enc = is_export ? (kl == 5 ? "RC4(40)" : "RC4(56)")
            : ((alg2 & SSL2_CF_8_BYTE_ENC) ? "RC4(64)" : "RC4(128)");
        break;
    case SSL_RC2:
        enc = is_export ? (kl == 5 ? "RC2(40)" : "RC2(56)") : "RC2(128)";
        break;
    case SSL_IDEA:
        enc = "IDEA(128)";
        break;
    case SSL_eNULL:
        enc = "None";
        break;
    case SSL_AES128:
        enc = "AES(128)";
        break;
    case SSL_AES256:
        enc = "AES(256)";
        break;
    case SSL_AES128GCM:
        enc = "AESGCM(128)";
        break;
    case SSL_AES256GCM:
        enc = "AESGCM(256)";
        break;
    case SSL_CAMELLIA128:
        enc = "Camellia(128)";
        break;
    case SSL_CAMELLIA256:
        enc = "Camellia(256)";
        break;
    case SSL_SEED:
        enc = "SEED(128)";
        break;
    case SSL_eGOST2814789CNT:
        enc = "GOST89(256)";
        break;
    default:
        enc = "unknown";
        break;
    }

    switch (alg_mac) {
    case SSL_MD5:
        mac = "MD5";
        break;
    case SSL_SHA1:
        mac = "SHA1";
        break;
    case SSL_SHA256:
        mac = "SHA256";
        break;
    case SSL_SHA384:
        mac = "SHA384";
        break;
    case SSL_AEAD:
        mac = "AEAD";
        break;
    case SSL_GOST89MAC:
        mac = "GOST89";
        break;
    case SSL_GOST94:
        mac = "GOST94";
        break;
    default:
        mac = "unknown";
        break;
    }

    if (buf == NULL) {
        len = 128;
        buf = OPENSSL_malloc(len);
        if (buf == NULL)
            return ("OPENSSL_malloc Error");
    } else if (len < 128)
        return ("Buffer too small");

#ifdef KSSL_DEBUG
    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac,
                 exp_str, alg_mkey, alg_auth, alg_enc, alg_mac, alg_ssl);
#else
    BIO_snprintf(buf, len, format, cipher->name, ver, kx, au, enc, mac,
                 exp_str);
#endif                          /* KSSL_DEBUG */
    return (buf);
#endif
}

/*------------------------------------------------------------------*/

extern STACK_OF(X509_NAME)
*
SSL_dup_CA_list(STACK_OF(X509_NAME) *sk)
{
/* No Error Code in Openssl */
 return NULL; /* @Note: unsupported */
}



/*------------------------------------------------------------------*/

extern int
SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx)
{
  /* No Error Code in Openssl */
  if (ctx == NULL)
    return 0;

  return ctx->orig_ssl_ctx.quiet_shutdown;
}

/*------------------------------------------------------------------*/

extern void
SSL_set_quiet_shutdown(SSL *ssl, int mode)
{
    if (NULL == ssl)
        return;

    ssl->orig_s.quiet_shutdown = mode;
}

/*------------------------------------------------------------------*/

extern int
SSL_get_quiet_shutdown(const SSL *ssl)
{
  if (ssl == NULL)
    return 0;

  return ssl->orig_s.quiet_shutdown;
}

/*------------------------------------------------------------------*/

extern int
SSL_version(const SSL *ssl)
{
    int version = -1;
    if (NULL == ssl)
        return 0;

    version = NSSL_CHK_CALL(sslGetVersion, ssl->instance);

    if (version == TLS10_MINORVERSION)
    {
        return TLS1_VERSION;
    }
    else if (version == TLS11_MINORVERSION)
    {
        return TLS1_1_VERSION;
    }
    else if (version == TLS12_MINORVERSION)
    {
        return TLS1_2_VERSION;
    }
    else if (version == TLS13_MINORVERSION)
    {
        return TLS1_3_VERSION;
    }

    return 0;
}

/*------------------------------------------------------------------*/

extern int
SSL_SESSION_set_ex_data(SSL_SESSION *ss, int idx, void *data)
{
  /* No Error Code in Openssl */
  if (ss == NULL)
    return -1;

  return (CRYPTO_set_ex_data(&ss->ex_data, idx, data));
}

/*------------------------------------------------------------------*/

extern void
*SSL_SESSION_get_ex_data(const SSL_SESSION *ss, int idx)
{
  /* No Error Code in Openssl */
  if (ss == NULL)
    return NULL;

  return (CRYPTO_get_ex_data(&ss->ex_data, idx));
}

/*------------------------------------------------------------------*/

extern int
SSL_SESSION_get_ex_new_index(long argl, void *argp,
                             CRYPTO_EX_new *new_func,
                             CRYPTO_EX_dup *dup_func,
                             CRYPTO_EX_free *free_func)
{
  return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_SESSION, argl, argp,
                                   new_func, dup_func, free_func);
}

/*------------------------------------------------------------------*/

extern int
SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func)
{
  return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_SSL_CTX, argl, argp,
                                   new_func, dup_func, free_func);
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
                             RSA *(*cb)(SSL *ssl, int is_export, int keylength))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_tmp_rsa_callback(SSL *ssl,
                         RSA *(*cb)(SSL *ssl, int is_export, int keylength))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_tmp_dh_callback(SSL *ssl,
                        DH *(*dh)(SSL *ssl, int is_export, int keylength))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
                              EC_KEY *(*ecdh)(SSL *ssl,
                                              int is_export,
                                              int keylength))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_tmp_ecdh_callback(SSL *ssl,
                          EC_KEY *(*ecdh)(SSL *ssl,
                                          int is_export,
                                          int keylength))
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const COMP_METHOD
*SSL_get_current_expansion(SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const char
*SSL_COMP_get_name(const COMP_METHOD *comp)
{
  /* No Error Code in Openssl */
  if (comp == NULL)
    return NULL;

  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern STACK_OF(SSL_COMP)
*
SSL_COMP_get_compression_methods(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern STACK_OF(SSL_COMP)
*
SSL_COMP_set0_compression_methods(STACK_OF(SSL_COMP) *meths)
{
/* No Error Code in Openssl */
return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_COMP_free_compression_methods(void)
{
    if (g_initialized)
    {
        OSSL_shutdown();
        /* Mutex cleanup added assuming this call is associated with the destructor flow */
        if (m_hashTableMutex)
        {
            moc_mutexFree(&m_hashTableMutex);
            m_hashTableMutex = NULL;
        }
        if (m_connectionCountMutex)
        {
            moc_mutexFree(&m_connectionCountMutex);
            m_connectionCountMutex = NULL;
        }
    }
}

/*------------------------------------------------------------------*/

extern int
SSL_COMP_add_compression_method(int id, COMP_METHOD *cm)
{
  return 1; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len)
{
  if (s == NULL)
  {
    SSLerr(SSL_F_SSL_SET_SESSION_TICKET_EXT, SSL_R_UNINITIALIZED);
    return 0;
  }

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_set_session_ticket_ext_cb(SSL *s,
                              tls_session_ticket_ext_cb_fn cb,
                              void *arg)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_set_session_secret_cb(SSL *s,
                          tls_session_secret_cb_fn tls_session_secret_cb,
                          void *arg)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
SSL_set_debug(SSL *s, int debug)
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_cache_hit(SSL *s)
{
  /* No Error Code in Openssl */
  if (s == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

/* Create a new SSL configuration context.
 */
extern SSL_CONF_CTX *
SSL_CONF_CTX_new(void)
{
    return OSSL_CALLOC(1, sizeof(SSL_CONF_CTX));
}

/*------------------------------------------------------------------*/

/* Finialize the SSL configuration context.
 */
extern int
SSL_CONF_CTX_finish(SSL_CONF_CTX *pConfCtx)
{
    return 1;
}

/*------------------------------------------------------------------*/

 /* Free the SSL configuration context.
  */
extern void
SSL_CONF_CTX_free(SSL_CONF_CTX *pConfCtx)
{
    if (pConfCtx)
    {
        if (pConfCtx->prefix)
        {
            OSSL_FREE(pConfCtx->prefix);
        }
        OSSL_FREE(pConfCtx);
    }
}

/*------------------------------------------------------------------*/

/* Set the flags within the SSL configuration context.
 */
extern unsigned int
SSL_CONF_CTX_set_flags(SSL_CONF_CTX *pConfCtx, unsigned int flags)
{
    int retVal = 0;
    if (NULL == pConfCtx)
        goto exit;

    pConfCtx->flags |= flags;
    retVal = pConfCtx->flags;

exit:

    return retVal;
}

/*------------------------------------------------------------------*/

extern unsigned int
SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags)
{
  /* No Error Code in Openssl */
  if (cctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre)
{
  /* No Error Code in Openssl */
  if (cctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

/*------------------------------------------------------------------*/

/* Store a SSL object within the SSL configuration context. This will
 * NULL out the SSL context (SSL_CTX) object within the SSL configuration.
 */
extern void
SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *pConfCtx, SSL *pSSL)
{
    if (NULL == pConfCtx)
        return;

    /* Set the SSL variable and unset the SSL context variable within the
     * configuration context.
     */
    pConfCtx->ssl = pSSL;
    pConfCtx->ctx = NULL;
    if (pSSL)
    {
        pConfCtx->poptions = &pSSL->options;
    }
    else
    {
        pConfCtx->poptions = NULL;
    }

    /* The original OpenSSL implementation will get this variable from the
     * SSL struct. The OpenSSL shim/connector implementation does not store or
     * maintain this variable in the SSL struct, therefore we always set it to
     * NULL.
     */
    pConfCtx->pcert_flags = NULL;
}

/*------------------------------------------------------------------*/

/* Store a SSL context object (SSL_CTX) within the SSL configuration context. This will
 * NULL out the SSL object within the SSL configuration.
 */
extern void
SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *pConfCtx, SSL_CTX *pSSLCtx)
{
    if (NULL == pConfCtx)
        return;

    /* Unset the SSL variable and set the SSL context variable within the
     * configuration context.
     */
    pConfCtx->ssl = NULL;
    pConfCtx->ctx = pSSLCtx;
    if (pSSLCtx)
    {
        pConfCtx->poptions = &pSSLCtx->options;
    }
    else
    {
        pConfCtx->poptions = NULL;
    }

    /* The original OpenSSL implementation will get this variable from the
     * SSL_CTX struct. The OpenSSL shim/connector implementation does not store
     * or maintain this variable in the SSL_CTX struct, therefore we always set
     * it to NULL.
     */
    pConfCtx->pcert_flags = NULL;
}

/*------------------------------------------------------------------*/

static int cmd_CipherString(SSL_CONF_CTX *cctx, const char *value)
{
    int rv = 1;
    if (cctx->ctx)
        rv = SSL_CTX_set_cipher_list(cctx->ctx, value);
    if (cctx->ssl)
        rv = SSL_set_cipher_list(cctx->ssl, value);
    return rv > 0;
}

/*------------------------------------------------------------------*/

static int ssl_match_option(SSL_CONF_CTX *cctx, const ssl_flag_tbl *tbl,
                            const char *name, int namelen, int onoff)
{
    /* If name not relevant for context skip */
    if (!(cctx->flags & tbl->name_flags & SSL_TFLAG_BOTH))
        return 0;
    if (namelen == -1) {
        if (strcmp(tbl->name, name))
            return 0;
    } else if (tbl->namelen != namelen
               || STR_N_CASE_CMP(tbl->name, name, namelen))
        return 0;
    if (cctx->poptions) {
        if (tbl->name_flags & SSL_TFLAG_INV)
            onoff ^= 1;
        if (tbl->name_flags & SSL_TFLAG_CERT) {
            if (onoff)
                *cctx->pcert_flags |= tbl->option_value;
            else
                *cctx->pcert_flags &= ~tbl->option_value;
        } else {
            if (onoff)
                *cctx->poptions |= tbl->option_value;
            else
                *cctx->poptions &= ~tbl->option_value;
        }
    }
    return 1;
}

/*------------------------------------------------------------------*/

static int ssl_set_option_list(const char *elem, int len, void *usr)
{
    SSL_CONF_CTX *cctx = usr;
    size_t i;
    const ssl_flag_tbl *tbl;
    int onoff = 1;
    /*
     * len == -1 indicates not being called in list context, just for single
     * command line switches, so don't allow +, -.
     */
    if (elem == NULL)
        return 0;
    if (len != -1) {
        if (*elem == '+') {
            elem++;
            len--;
            onoff = 1;
        } else if (*elem == '-') {
            elem++;
            len--;
            onoff = 0;
        }
    }
    for (i = 0, tbl = cctx->tbl; i < cctx->ntbl; i++, tbl++) {
        if (ssl_match_option(cctx, tbl, elem, len, onoff))
            return 1;
    }
    return 0;
}


/*------------------------------------------------------------------*/

static int cmd_Protocol(SSL_CONF_CTX *cctx, const char *value)
{
    static const ssl_flag_tbl ssl_protocol_list[] = {
        SSL_FLAG_TBL_INV("ALL", SSL_OP_NO_SSL_MASK),
        /* SSL_FLAG_TBL_INV("SSLv2", SSL_OP_NO_SSLv2), Do not allow caller to set SSLv2 */
        SSL_FLAG_TBL_INV("SSLv3", SSL_OP_NO_SSLv3),
        SSL_FLAG_TBL_INV("TLSv1", SSL_OP_NO_TLSv1),
        SSL_FLAG_TBL_INV("TLSv1.1", SSL_OP_NO_TLSv1_1),
        SSL_FLAG_TBL_INV("TLSv1.2", SSL_OP_NO_TLSv1_2),
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        SSL_FLAG_TBL_INV("TLSv1.3", SSL_OP_NO_TLSv1_3),
#endif
    };
    int ret;
    int sslv2off;
    unsigned long versionOptions = 0;

    if (!(cctx->flags & SSL_CONF_FLAG_FILE))
        return -2;
    cctx->tbl = ssl_protocol_list;
    cctx->ntbl = sizeof(ssl_protocol_list) / sizeof(ssl_flag_tbl);

    sslv2off = *cctx->poptions & SSL_OP_NO_SSLv2;
    ret = CONF_parse_list(value, ',', 1, ssl_set_option_list, cctx);

    computeAndSetVersion(*cctx->poptions, &versionOptions);
    *cctx->poptions |= versionOptions;

    /* Never turn on SSLv2 through configuration */
    *cctx->poptions |= sslv2off;
    return ret;
}

/*------------------------------------------------------------------*/

/* This function will set the DH parameters within NanoSSL stack. This will only
 * set the DH parameters if the configuration has a SSL_CTX loaded in.
 */
#ifndef OPENSSL_NO_DH
static int
cmd_DHParameters(SSL_CONF_CTX *pConfCtx, const char *pValue)
{
    int retVal = 0;
    BIO *pBio = NULL;
    DH *pDH = NULL;

    /* The DH parameters can only be set if the certificate flag has been set
     * within the configuration context.
     */
    if (!(pConfCtx->flags & SSL_CONF_FLAG_CERTIFICATE))
        return -2;

    /* Only read in the DH parameters if the configuration context has a
     * SSL_CTX variable internally set.
     */
    if (pConfCtx->ctx)
    {
        pBio = BIO_new(BIO_s_file_internal());
        if (!pBio)
            goto exit;

        if (BIO_read_filename(pBio, pValue) <= 0)
            goto exit;

        pDH = PEM_read_bio_DHparams(pBio, NULL, NULL, NULL);
        if (!pDH)
            goto exit;
    }
    else
    {
        return 1;
    }

    if (pConfCtx->ctx)
        retVal = SSL_CTX_set_tmp_dh(pConfCtx->ctx, pDH);

exit:
    if (NULL != pBio)
    {
        BIO_free(pBio);
    }

    if (NULL != pDH)
    {
        DH_free(pDH);
    }

    return retVal > 0;
}
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
static int cmd_MinProtocol(SSL_CONF_CTX *pCtx, const char *pValue)
{
    int version = 0;
    sbyte4 status = OK;

    OSSL_conf_get_proto_version(pValue, &version);

    status = sslSetMinProtoVersion(version);
    if (status >= OK)
        return 1;
    else
        return -2;
}

static int cmd_MaxProtocol(SSL_CONF_CTX *pCtx, const char *pValue)
{
    int version = 0;
    sbyte4 status = OK;
    OSSL_conf_get_proto_version(pValue, &version);

    status = sslSetMaxProtoVersion(version);
    if (status >= OK)
        return 1;
    else
        return -2;
}

static int cmd_Groups(SSL_CONF_CTX *cctx, const char *value)
{
    int rv;
    if (cctx->ssl)
        rv = SSL_set1_groups_list(cctx->ssl, value);
    /* NB: ctx == NULL performs syntax checking only */
    else
        rv = SSL_CTX_set1_groups_list(cctx->ctx, value);
    return rv > 0;
}

static int cmd_emptyStub(SSL_CONF_CTX *pCtx, const char *pValue)
{
    return -4;
}

#endif
/*------------------------------------------------------------------*/

static int
ssl_conf_cmd_skip_prefix(SSL_CONF_CTX *pConfCtx, const char **ppCmd)
{
    /* Non-NULL command must be provided.
     */
    if (!ppCmd || !*ppCmd)
        return 0;

    /* If the SSL configuration context has a prefix then check if the command
     * has the appropriate prefix.
     */
    if (pConfCtx->prefix)
    {
        if (strlen(*ppCmd) <= pConfCtx->prefixlen)
            return 0;

        if ( (pConfCtx->flags & SSL_CONF_FLAG_CMDLINE) &&
             (strncmp(*ppCmd, pConfCtx->prefix, pConfCtx->prefixlen)) )
            return 0;

        if ( (pConfCtx->flags & SSL_CONF_FLAG_FILE) &&
             (STR_N_CASE_CMP(*ppCmd, pConfCtx->prefix, pConfCtx->prefixlen)) )
            return 0;

        *ppCmd += pConfCtx->prefixlen;
    }
    else if (pConfCtx->flags & SSL_CONF_FLAG_CMDLINE)
    {
        if ( (**ppCmd != '-') ||
             (!(*ppCmd)[1]) )
            return 0;

        *ppCmd += 1;
    }
    return 1;
}

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* Determine if a command is allowed according to pCtx flags */
static int ssl_conf_cmd_allowed(SSL_CONF_CTX *pCtx, const ssl_conf_cmd_tbl * t)
{
    unsigned int tfl = t->flags;
    unsigned int cfl = pCtx->flags;
    if ((tfl & SSL_CONF_FLAG_SERVER) && !(cfl & SSL_CONF_FLAG_SERVER))
        return 0;
    if ((tfl & SSL_CONF_FLAG_CLIENT) && !(cfl & SSL_CONF_FLAG_CLIENT))
        return 0;
    if ((tfl & SSL_CONF_FLAG_CERTIFICATE)
        && !(cfl & SSL_CONF_FLAG_CERTIFICATE))
        return 0;
    return 1;
}
#endif

/*------------------------------------------------------------------*/

/* Lookup the provided command in the command table. If the command is found
 * then a pointer to the struct will be retruned which will contain a function
 * pointer for performing the command. If the command is not found then NULL
 * will be returned.
 */
static const ssl_conf_cmd_tbl *
ssl_conf_cmd_lookup(SSL_CONF_CTX *pConfCtx, const char *pCmd)
{
    const ssl_conf_cmd_tbl *pRetCmd;
    size_t i;
    if (NULL == pCmd)
        return NULL;

    /* Check if the provided command is in the list of supported commands.
     */
    for (i = 0, pRetCmd = ssl_conf_cmds;
         i < sizeof(ssl_conf_cmds) / sizeof(ssl_conf_cmd_tbl); i++, pRetCmd++)
    {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        if (ssl_conf_cmd_allowed(pConfCtx, pRetCmd))
#endif
        {
            if (pConfCtx->flags & SSL_CONF_FLAG_CMDLINE)
            {
                if ( (pRetCmd->str_cmdline) && (!strcmp(pRetCmd->str_cmdline, pCmd)) )
                    return pRetCmd;
            }
            if (pConfCtx->flags & SSL_CONF_FLAG_FILE)
            {
                if ( (pRetCmd->str_file) && (!STR_CASE_CMP(pRetCmd->str_file, pCmd)) )
                    return pRetCmd;
            }
        }
    }

    return NULL;
}

/*------------------------------------------------------------------*/

extern int
SSL_CONF_cmd(SSL_CONF_CTX *pConfCtx, const char *pCmd, const char *pValue)
{
    const ssl_conf_cmd_tbl *pRunCmd;

    /* Non-NULL command must be provided.
     */
    if (NULL == pCmd)
    {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_INVALID_NULL_CMD_NAME);
        return 0;
    }

    /* Lookup the command in the command table.
     */
    pRunCmd = ssl_conf_cmd_lookup(pConfCtx, pCmd);
    if (pRunCmd)
    {
        int retVal;
        if (NULL == pValue)
            return -3;

        retVal = pRunCmd->cmd(pConfCtx, pValue);
        if (retVal > 0)
            return 2;
        if (retVal == -2)
            return -2;
        if (retVal == -4) /* -4 is returned by cmd_emptyStub; Unsupported, do NOT throw error */
            return 1;
        if (pConfCtx->flags & SSL_CONF_FLAG_SHOW_ERRORS)
        {
            SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_BAD_VALUE);
            ERR_add_error_data(4, "cmd=", pCmd, ", value=", pValue);
        }
        return 0;
    }

    if (pConfCtx->flags & SSL_CONF_FLAG_SHOW_ERRORS)
    {
        SSLerr(SSL_F_SSL_CONF_CMD, SSL_R_UNKNOWN_CMD_NAME);
        ERR_add_error_data(2, "cmd=", pCmd);
    }


    return -2;
}

/*------------------------------------------------------------------*/

extern int
SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv)
{
  /* Openssl does not define error for cctx*/
  if (cctx == NULL)
    return 0;

  return 0; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern int
SSL_CONF_cmd_value_type(SSL_CONF_CTX *pConfCtx, const char *pCmd)
{
    const ssl_conf_cmd_tbl *pRunCmd;
    if (ssl_conf_cmd_skip_prefix(pConfCtx, &pCmd))
    {
        pRunCmd = ssl_conf_cmd_lookup(pConfCtx, pCmd);
        if (pRunCmd)
            return pRunCmd->value_type;
    }

    return SSL_CONF_TYPE_UNKNOWN;
}

/*------------------------------------------------------------------*/

extern void
SSL_trace(int write_p, int version, int content_type,
          const void *buf, size_t len, SSL *ssl, void *arg)
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const char
*SSL_CIPHER_standard_name(const SSL_CIPHER *c)
{
  /* No Error Code in Openssl */
  /* if (c == NULL)
    return ("NONE");  */
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern const struct
    openssl_ssl_test_functions *SSL_test_functions(void)
{
  return NULL; /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
ERR_load_SSL_strings(void)
{
  /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

#if 0
/*
    Defined in the EVP package (c_all.c)
*/
extern void
OPENSSL_add_all_algorithms_noconf(void)
{
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
}

/*------------------------------------------------------------------*/

extern void
OpenSSL_add_all_ciphers(void)
{
    /* @Note: unsupported */
}

/*------------------------------------------------------------------*/

extern void
OpenSSL_add_all_digests(void)
{
    /* @Note: unsupported */
}

/*------------------------------------------------------------------*/
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
 void SSL_CTX_set_client_hello_cb(SSL_CTX *c, SSL_client_hello_cb_fn cb,
                                  void *arg)
{
    if (c == NULL) return;
    c->orig_ssl_ctx.client_hello_cb = cb;
    c->orig_ssl_ctx.client_hello_cb_arg = arg;
}

int SSL_add1_to_CA_list(SSL *ssl, const X509 *x)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_add1_to_CA_list(SSL_CTX *ctx, const X509 *x)
{
    /* @Note: unsupported */
    return 0;
}

const STACK_OF(X509_NAME) *SSL_get0_CA_list(const SSL *s)
{
    /* @Note: unsupported */
    return NULL;
}

void SSL_set0_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list)
{
    /* @Note: unsupported */
}

void SSL_CTX_set_security_level(SSL_CTX *ctx, int level)
{
    /* @Note: unsupported */
}

int SSL_is_dtls(const SSL *ssl)
{
    if (ssl == NULL) return 0; /* OpenSSL no error */
	return  ((ssl->version == DTLSV1_VERSION) || (ssl->version == DTLS_ANY_VERSION)) ? 1 : 0;
}

int SSL_has_pending(const SSL *s)
{
    return ((SSL_pending(s) > 0) ? 1 : 0);
}

int SSL_get_all_async_fds(SSL *s, OSSL_ASYNC_FD *fd, size_t *numfds)
{
    /* @Note: unsupported, just return empty list, but no error */
    *numfds = 0;
    return 1;
}

const STACK_OF(X509_NAME) *SSL_get0_peer_CA_list(const SSL *s)
{
    return SSL_get_client_CA_list(s);
}

const char *SSL_COMP_get0_name(const SSL_COMP *comp)
{
   #ifndef OPENSSL_NO_COMP
       return ((comp != NULL) ? comp->name : NULL);
   #else
       return NULL;
   #endif
}

int SSL_COMP_get_id(const SSL_COMP *comp)
{
    #ifndef OPENSSL_NO_COMP
       return ((comp != NULL) ? comp->id : -1);
    #else
       return -1;
    #endif
}


int SSL_CTX_get_security_level(const SSL_CTX *ctx)
{
    /*
        The functions SSL_CTX_get_security_level() and SSL_get_security_level() retrieve the current security level.

        The default security level can be configured when OpenSSL is
        compiled by setting -DOPENSSL_TLS_SECURITY_LEVEL=level. If not set then 1 is used.
    */
    /* @Note: unsupported */
    return 1;
}
#endif

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef unsigned int (*DTLS_timer_cb)(SSL *s, unsigned int timer_us);

void DTLS_set_timer_cb(SSL *s, DTLS_timer_cb cb)
{
    /* @Note: unsupported */
}

const char *OSSL_default_cipher_list(void)
{
    /* @Note: unsupported */
    /*
        OSSL_default_cipher_list() returns the default cipher string for
        TLSv1.2 (and earlier) ciphers. OSSL_default_ciphersuites() returns
        the default cipher string for TLSv1.3 ciphersuites.

        OSSL_default_cipher_list() and OSSL_default_ciphersuites() replace
        SSL_DEFAULT_CIPHER_LIST and TLS_DEFAULT_CIPHERSUITES, respectively.
        The cipher list defines are deprecated as of 3.0. 
    */
    return NULL;
}

const char *OSSL_default_ciphersuites(void)
{
    /* @Note: unsupported */
    /*
        OSSL_default_cipher_list() returns the default cipher string for
        TLSv1.2 (and earlier) ciphers. OSSL_default_ciphersuites() returns
        the default cipher string for TLSv1.3 ciphersuites.

        OSSL_default_cipher_list() and OSSL_default_ciphersuites() replace
        SSL_DEFAULT_CIPHER_LIST and TLS_DEFAULT_CIPHERSUITES, respectively.
        The cipher list defines are deprecated as of 3.0. 
    */
    return NULL;
}


 int SSL_CTX_config(SSL_CTX *ctx, const char *name)
 {
    /* @Note: unsupported */
    return 0;
 }

int SSL_CTX_ct_is_enabled(const SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_CTX_set0_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list)
{
    /* @Note: unsupported */
}

const CTLOG_STORE *SSL_CTX_get0_ctlog_store(const SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return NULL;
}

void *SSL_CTX_get0_security_ex_data(const SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return NULL;
}

void *SSL_CTX_get_record_padding_callback_arg(const SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return NULL;
}


int SSL_CTX_has_client_custom_ext(const SSL_CTX *ctx, unsigned int ext_type)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_load_verify_dir(SSL_CTX *ctx, const char *CApath)
{
    return SSL_CTX_load_verify_locations(ctx, NULL, CApath);
}

int SSL_CTX_load_verify_file(SSL_CTX *ctx, const char *CAfile)
{
    return SSL_CTX_load_verify_locations(ctx, CAfile, NULL);
}

int SSL_CTX_load_verify_store(SSL_CTX *ctx, const char *CAstore)
{
    /* @Note: unsupported */
    return 0;
}

SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
                        const SSL_METHOD *meth)
{
    /* @Note: unsupported */
    return NULL;
}

int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx)) (SSL *ssl, SSL_SESSION *sess)
{
    /* @Note: unsupported */
    return NULL;
}

void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx)) (SSL_CTX *ctx,
                                                  SSL_SESSION *sess)
{
    /* @Note: unsupported */
    return NULL;
}

LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return NULL;
}

void SSL_CTX_set0_ctlog_store(SSL_CTX *ctx, CTLOG_STORE * logs)
{
    /* @Note: unsupported */
}

void SSL_CTX_set0_security_ex_data(SSL_CTX *ctx, void *ex)
{
    /* @Note: unsupported */
}

int SSL_CTX_set0_tmp_dh_pkey(SSL_CTX *ctx, EVP_PKEY *dhpkey)
{
    DH *pKey = NULL;
    ubyte *pP = NULL;
    ubyte *pG = NULL;
    int pLen = 0;
    int gLen = 0;
    int rval = 0;

    if ((NULL == ctx) || (NULL == dhpkey))
    {
        SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
        return 0;
    }

    pKey = (DH*)(dhpkey->keydata);

    /* check parameters are present */
    if ((NULL == pKey->params.p) || (NULL == pKey->params.g))
    {
        SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
        return 0;
    }

    pLen = BN_num_bytes(pKey->params.p);
    pP = OSSL_MALLOC(pLen);
    if (NULL == pP)
    {
        return 0;
    }

    BN_bn2bin(pKey->params.p, pP);

    gLen = BN_num_bytes(pKey->params.g);
    pG = OSSL_MALLOC(gLen);
    if (NULL == pG)
    {
        OSSL_FREE(pP);
        return 0;
    }

    BN_bn2bin(pKey->params.g, pG);

    rval = NSSL_CHK_CALL(setDHParameters, pP, pLen, pG, gLen, 0);
    OSSL_FREE(pP);
    OSSL_FREE(pG);
    if (rval < 0)
    {
        SSLerr(SSL_F_SSL3_CTX_CTRL, ERR_R_DH_LIB);
        return 0;
    }

    EVP_PKEY_free(dhpkey);
    return 1;
}

void SSL_set0_rbio(SSL *s, BIO *rbio)
{
    if (NULL != s)
    {
        BIO_free_all(s->rbio);
        s->rbio = rbio;
        s->orig_s.rbio = s->rbio;
    }
}

void SSL_set0_wbio(SSL *s, BIO *wbio)
{
    if (NULL != s)
    {
        if (s->bbio != NULL) {
            if (s->wbio == s->bbio) {
                s->wbio = s->wbio->next_bio;
                s->bbio->next_bio = NULL;
            }
        }

        BIO_free_all(s->wbio);
        s->wbio = wbio;

        s->orig_s.wbio = s->wbio;
        s->orig_s.bbio = s->bbio;
    }
}

void SSL_CTX_set_allow_early_data_cb(SSL_CTX *ctx,
                                     SSL_allow_early_data_cb_fn cb,
                                     void *arg)
{
    /* @Note: unsupported */
}

int SSL_CTX_set_async_callback(SSL_CTX *ctx, SSL_async_callback_fn callback)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_async_callback_arg(SSL_CTX *ctx, void *arg)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_ct_validation_callback(SSL_CTX *ctx,
                                       ssl_ct_validation_cb callback,
                                       void *arg)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_ctlog_list_file(SSL_CTX *ctx, const char *path)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_default_ctlog_list_file(SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_CTX_set_default_read_buffer_len(SSL_CTX *ctx, size_t len)
{
    /* @Note: unsupported */
}

int SSL_CTX_set_default_verify_dir(SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_default_verify_file(SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_set_default_verify_store(SSL_CTX *ctx)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_CTX_set_not_resumable_session_callback(SSL_CTX *ctx,
                                                int (*cb) (SSL *ssl,
                                                           int
                                                           is_forward_secure))
{
    /* @Note: unsupported */
}


void SSL_CTX_set_record_padding_callback(SSL_CTX *ctx,
                                         size_t (*cb) (SSL *ssl, int type,
                                                       size_t len, void *arg))
{
    /* @Note: unsupported */
}

void SSL_CTX_set_record_padding_callback_arg(SSL_CTX *ctx, void *arg)
{
    /* @Note: unsupported */
}

void SSL_CTX_set_security_callback(SSL_CTX *ctx,
                                    int (*cb)(const SSL *s, const SSL_CTX *ctx, int op,
                                              int bits, int nid,
                                              void *other, void *ex))
{
    /* @Note: unsupported */
}

void SSL_CTX_set_stateless_cookie_verify_cb(
    SSL_CTX *ctx,
    int (*verify_stateless_cookie_cb) (SSL *ssl,
                                       const unsigned char *cookie,
                                       size_t cookie_len))
{
    /* @Note: unsupported */
}

int SSL_CTX_set_tlsext_ticket_key_evp_cb
    (SSL_CTX *ctx, int (*fp)(SSL *, unsigned char *, unsigned char *,
                             EVP_CIPHER_CTX *, EVP_MAC_CTX *, int))
{
    /* @Note: unsupported */
    return 0;
}

const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s)
{
    /* @Note: unsupported */
    return NULL;
}

const char *SSL_SESSION_get0_hostname(const SSL_SESSION *s)
{
    /* @Note: unsupported */
    return NULL;
}

const unsigned char *SSL_SESSION_get0_id_context(const SSL_SESSION *s,
                                                  unsigned int *len)
{
    /* @Note: unsupported */
    return NULL;
}

int SSL_SESSION_print_keylog(BIO *bp, const SSL_SESSION *x)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_add_ssl_module(void)
{
    /* @Note: unsupported */
    /* Do nothing. This will be added automatically by libcrypto */
}

int SSL_add_store_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs,
                                       const char *uri)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_client_version(const SSL *s)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_config(SSL *s, const char *name)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_ct_is_enabled(const SSL *s)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_enable_ct(SSL *s, int validation_mode)
{
    /* @Note: unsupported */
    return 0;
}

const STACK_OF(SCT) *SSL_get0_peer_scts(SSL *s)
{
    /* @Note: unsupported */
    return NULL;
}

void *SSL_get0_security_ex_data(const SSL *s)
{
    /* @Note: unsupported */
    return NULL;
}

STACK_OF(X509) *SSL_get0_verified_chain(const SSL *ssl)
{
    /* @Note: unsupported */
    return NULL;
}

STACK_OF(SSL_CIPHER) *SSL_get1_supported_ciphers(SSL *s)
{
    /* @Note: unsupported */
    return NULL;
}

int SSL_get_async_status(SSL *s, int *status)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_get_changed_async_fds(SSL *s, OSSL_ASYNC_FD *addfd, size_t *numaddfds,
                              OSSL_ASYNC_FD *delfd, size_t *numdelfds)
{
    /* @Note: unsupported */
    return 0;
}

STACK_OF(SSL_CIPHER) *SSL_get_client_ciphers(const SSL *ssl)
{
    /* @Note: unsupported */
    return 0;
}

pem_password_cb *SSL_get_default_passwd_cb(SSL *s)
{
    /* @Note: unsupported */
    /* These functions do not provide diagnostic information. */
    return NULL;
}

void *SSL_get_default_passwd_cb_userdata(SSL *s)
{
    /* @Note: unsupported */
    /* These functions do not provide diagnostic information. */
    return NULL;
}

void *SSL_get_record_padding_callback_arg(const SSL *ssl)
{
    /* @Note: unsupported */
    return NULL;
}

int (*SSL_get_security_callback(const SSL *s))(const SSL *s, const SSL_CTX *ctx, int op,
                                               int bits, int nid, void *other,
                                               void *ex)
{
    /* @Note: unsupported */
    return NULL;
}

int SSL_get_signature_type_nid(const SSL *s, int *pnid)
{
    /* @Note: unsupported */
    return 0;
}

const char *SSL_group_to_name(SSL *ssl, int id)
{
    /* @Note: unsupported */
    return NULL;
}


int SSL_in_before(const SSL *s)
{
    /* @Note: unsupported */
    return 0;
}

STACK_OF(X509_NAME) *SSL_load_client_CA_file_ex(const char *file,
                                                OSSL_LIB_CTX *libctx,
                                                const char *propq)
{
    /* @Note: unsupported */
    return NULL;
}

int SSL_new_session_ticket(SSL *s)
{
    /* @Note: unsupported */
    return 0;
}

ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size, int flags)
{
    /* @Note: unsupported */
    return -1;
}

void SSL_set0_security_ex_data(SSL *s, void *ex)
{
    /* @Note: unsupported */
}

int SSL_set0_tmp_dh_pkey(SSL *s, EVP_PKEY *dhpkey)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_set_allow_early_data_cb(SSL *s,
                                  SSL_allow_early_data_cb_fn cb,
                                  void *arg)
{
    /* @Note: unsupported */
}

int SSL_set_async_callback(SSL *s, SSL_async_callback_fn callback)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_set_async_callback_arg(SSL *s, void *arg)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_set_ct_validation_callback(SSL *s, ssl_ct_validation_cb callback,
                                    void *arg)
{
    /* @Note: unsupported */
    return 0;
}

void SSL_set_default_passwd_cb(SSL *s, pem_password_cb *cb)
{
    /* @Note: unsupported */
}

void SSL_set_default_passwd_cb_userdata(SSL *s, void *u)
{
    /* @Note: unsupported */
}

void SSL_set_default_read_buffer_len(SSL *s, size_t len)
{
    /* @Note: unsupported */
}

void SSL_set_not_resumable_session_callback(SSL *ssl,
                                            int (*cb) (SSL *ssl,
                                                       int is_forward_secure))
{
    /* @Note: unsupported */
}

int SSL_set_record_padding_callback(SSL *ssl, size_t (*cb)(SSL *ssl, int type, size_t len, void *arg))
{
    /* @Note: unsupported */
    return 0;
}

void SSL_set_record_padding_callback_arg(SSL *ssl, void *arg)
{
    /* @Note: unsupported */
}

void SSL_set_security_callback(SSL *s, int (*cb)(const SSL *s, const SSL_CTX *ctx, int op,
                                                 int bits, int nid,
                                                 void *other, void *ex))
{
    /* @Note: unsupported */
}

int SSL_up_ref(SSL *s)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_waiting_for_async(SSL *s)
{
    /* @Note: unsupported */
    return 0;
}
int (*SSL_CTX_get_security_callback(const SSL_CTX *ctx))(SSL *s, SSL_CTX *ctx, int op, int bits, int nid, void *other, void *ex)
{
    /* @Note: unsupported */
    return 0;
}

int SSL_CTX_enable_ct(SSL_CTX *ctx, int validation_mode)
{
    /* @Note: unsupported */
    return 0;
}
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
/*
RU: END SKELETON SSL FUNCTIONS.
*/

#endif /* __DISABLE_DIGICERT_UNSUPPORTED_OPENSSL_FN__ */

#endif /* defined(__ENABLE_DIGICERT_SSL_SERVER__) || defined(__ENABLE_DIGICERT_SSL_CLIENT__) */
