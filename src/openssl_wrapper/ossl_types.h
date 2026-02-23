/*
 * ossl_types.h
 *
 * OpenSSL types interface for DIGICERT
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

#ifndef OSSL_TYPES_HEADER
#define OSSL_TYPES_HEADER

#include <stdint.h>
#ifdef __RTOS_VXWORKS__
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ct.h>
#else /* !__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#include <bio.h>
#include <ec.h>
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
#include "ossl_typesv3.h"
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <openssl/comp.h>
#else
#include <comp.h>
#endif
#include <openssl/x509.h>
#else /* ! __RTOS_VXWORKS__ */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#include <include/openssl/bio.h>
#include <include/openssl/ec.h>
#include "ossl_typesv3.h"
#include "include/openssl/comp.h"
#include "include/openssl/x509.h"
#include "include/openssl/ct.h"
#else
#include <crypto/bio/bio.h>
#include <crypto/ec/ec.h>
#include "ossl_typesv3.h"
#include "crypto/comp/comp.h"
#include "crypto/x509/x509.h"
#endif
#endif

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
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
#include "ssl/statem/statem.h"
#include "internal/dane.h"
#endif

#define TABLE_SIZE_MASK 	31        /* must be 2^n-1 */
#define MAX_NUM_CIPHER_IDS 	256     /* arbitrary limit */

#define MAX_NUM_SRTP_PROFILE_IDS 16 /* arbitrary limit */

#define NUM_CIPHER_DESCS (sizeof(gCipherDescs)/sizeof(gCipherDescs[0]))
#define MAX_NUM_ECCCURVES   32 /* arbitrary */

/* SSL_METHOD related Definitions */
#define SSLV2_VERSION		254
#define SSL_SERVER_METHOD	1
#define SSL_CLIENT_METHOD	2

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define BIO_s_file_internal BIO_s_file
#define CRYPTO_LOCK_X509       3
#define CRYPTO_LOCK_EVP_PKEY  10
#define CRYPTO_LOCK_SSL_CTX   12
#define ERR_R_ECDH_LIB        ERR_LIB_ECDH  /* 43 */

#endif

typedef int pem_password_cb_moc(char *buf, int size, int rwflag, void *userdata);
#define pem_password_cb pem_password_cb_moc

void DIGI_PKEY_EX_DATA_free(void *pParent, void *pData, CRYPTO_EX_DATA *pAd,
                       int idx, long argl, void *pArgp);

typedef struct
{
    pem_password_cb *pCallback;
    void *pCallbackInfo;
} OSSL_PemPasswordCallback;

/* Already defined in ssl.h */
#define SSL_MAXSESSIONIDSIZE                (32)
#ifndef SSL_MASTERSECRETSIZE
#define SSL_MASTERSECRETSIZE                (48)
#endif

/* Already defined in sslsock.h */
#ifndef SSL_RANDOMSIZE
#define SSL_RANDOMSIZE                  (32)
#endif

#define TLSEXT_STATUSTYPE_nothing -1
#define TLSEXT_STATUSTYPE_ocsp     1
#define TLSEXT_NAMETYPE_host_name 0
#define TLSEXT_MAXLEN_host_name 255

#define OSSL_PKEY_RSA	0
#define OSSL_PKEY_DSA	1
#define OSSL_PKEY_EC	2
#define OSSL_EVP_PKEY_ED448   3
#define OSSL_EVP_PKEY_ED25519 4
#define OSSL_PKEY_MAX	5

#define SSL_MAX_SID_CTX_LENGTH	32
#define SSL3_SSL_SESSION_ID_LENGTH 32

/* Context when evaluating whether a Certificate Transparency policy is met */
struct ct_policy_eval_ctx_st {
    X509 *cert;
    X509 *issuer;
    void *log_store; /* Changed from CTLOG_STORE* to void* */
    /* milliseconds since epoch (to check that SCTs aren't from the future) */
    ubyte8 epoch_time_in_ms; /* uint64_t changed to ubyte8 */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    OSSL_LIB_CTX *libctx;
    char *propq;
#endif
};
typedef struct ct_policy_eval_ctx_st CT_POLICY_EVAL_CTX;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/*
 * A callback for verifying that the received SCTs are sufficient.
 * Expected to return 1 if they are sufficient, otherwise 0.
 * May return a negative integer if an error occurs.
 * A connection should be aborted if the SCTs are deemed insufficient.
 */
typedef int(*ssl_ct_validation_cb)(const CT_POLICY_EVAL_CTX *ctx,
                                   const STACK_OF(SCT) *scts, void *arg);

/*
 * A callback for logging out TLS key material. This callback should log out
 * |line| followed by a newline.
 */
typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

#endif

typedef struct srp_ctx_st {
    /* param for all the callbacks */
    void *SRP_cb_arg;
    /* set client Hello login callback */
    void *mem1;
    /* set SRP N/g param callback for verification */
    void *mem2;
    /* set SRP N/g param callback for verification */
    /* set SRP client passwd callback */
    void *mem3;
    /* set SRP N/g param callback for verification */
    char *login;
    BIGNUM *N, *g, *s, *B, *A;
    BIGNUM *a, *b, *v;
    char *info;
    int strength;
    unsigned long srp_Mask;
} SRP_CTX;

typedef void* m_GEN_SESSION_CB;

typedef int (*GEN_SESSION_CB) (const SSL *ssl, unsigned char *id,
                               unsigned int *id_len);

typedef struct ssl_cipher_st {
    int valid;
    const char *name;           /* text name */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    const char *stdname;        /* RFC name */
#endif
    unsigned long id;           /* id, 4 bytes, first is version */
    /*
     * changed in 0.9.9: these four used to be portions of a single value
     * 'algorithms'
     */
    unsigned long algorithm_mkey; /* key exchange algorithm */
    unsigned long algorithm_auth; /* server authentication */
    unsigned long algorithm_enc; /* symmetric encryption */
    unsigned long algorithm_mac; /* symmetric authentication */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    int min_tls;                /* minimum SSL/TLS protocol version */
    int max_tls;                /* maximum SSL/TLS protocol version */
    int min_dtls;               /* minimum DTLS protocol version */
    int max_dtls;               /* maximum DTLS protocol version */
#else
    unsigned long algorithm_ssl; /* (major) protocol version */
#endif
    unsigned long algo_strength; /* strength and export flags */
    unsigned long algorithm2;   /* Extra flags */
    int strength_bits;          /* Number of bits really used */
    int alg_bits;               /* Number of bits for algorithm */
} SSL_CIPHER;

STACK_OF(SSL_CIPHER);
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
DEFINE_STACK_OF_CONST(SSL_CIPHER)
#endif

typedef int (*tls_session_secret_cb_fn) (SSL *s, void *secret,
                                      int *secret_len,
                                      STACK_OF(SSL_CIPHER) *peer_ciphers,
                                      SSL_CIPHER **cipher, void *arg);

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef struct {
    uint32_t mask;
    int nid;
} ssl_cipher_table;
#endif

typedef struct sess_cert_st {
    STACK_OF(X509) *cert_chain; /* as received from peer (not for SSL2) */
    /* The 'peer_...' members are used only by clients. */
    int peer_cert_type;
} SESS_CERT;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef struct ssl_method_st {
    int version;
    unsigned flags;
    unsigned long mask;
    int (*ssl_new) (SSL *s);
    void (*ssl_clear) (SSL *s);
    void (*ssl_free) (SSL *s);
    int (*ssl_accept) (SSL *s);
    int (*ssl_connect) (SSL *s);
    int (*ssl_read) (SSL *s, void *buf, int len);
    int (*ssl_peek) (SSL *s, void *buf, int len);
    int (*ssl_write) (SSL *s, const void *buf, int len);
    int (*ssl_shutdown) (SSL *s);
    int (*ssl_renegotiate) (SSL *s);
    int (*ssl_renegotiate_check) (SSL *s);
    int (*ssl_read_bytes) (SSL *s, int type, int *recvd_type,
                           unsigned char *buf, int len, int peek);
    int (*ssl_write_bytes) (SSL *s, int type, const void *buf_, int len);
    int (*ssl_dispatch_alert) (SSL *s);
    long (*ssl_ctrl) (SSL *s, int cmd, long larg, void *parg);
    long (*ssl_ctx_ctrl) (SSL_CTX *ctx, int cmd, long larg, void *parg);
    const SSL_CIPHER *(*get_cipher_by_char) (const unsigned char *ptr);
    int (*put_cipher_by_char) (const SSL_CIPHER *cipher, unsigned char *ptr);
    int (*ssl_pending) (const SSL *s);
    int (*num_ciphers) (void);
    const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
    long (*get_timeout) (void);
    const struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
    int (*ssl_version) (void);
    long (*ssl_callback_ctrl) (SSL *s, int cb_id, void (*fp) (void));
    long (*ssl_ctx_callback_ctrl) (SSL_CTX *s, int cb_id, void (*fp) (void));
} SSL_METHOD;
#else
typedef struct ssl_method_st {
     int protocol;
     int version;
     int server_or_client;
     char *name;
     const SSL_CIPHER *(*get_cipher) (unsigned ncipher);
     int (*num_ciphers) (void);
     int (*ssl_accept) (SSL *s);
     int (*ssl_connect) (SSL *s);
     void (*ssl_free) (SSL *s);
} SSL_METHOD;
#endif


struct cert_pkey_st {
    X509 *x509;
    EVP_PKEY *privatekey;
    /* Chain for this certificate */
    STACK_OF(X509) *chain;
    /*-
     * serverinfo data for this certificate.  The data is in TLS Extension
     * wire format, specifically it's a series of records like:
     *   uint16_t extension_type; // (RFC 5246, 7.4.1.4, Extension)
     *   uint16_t length;
     *   uint8_t data[length];
     */
    unsigned char *serverinfo;
    size_t serverinfo_length;
};
typedef struct cert_pkey_st CERT_PKEY;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
#ifdef __RTOS_WIN32__
typedef volatile int CRYPTO_REF_COUNT;
#else
# if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L \
     && !defined(__STDC_NO_ATOMICS__) &&  (defined(ATOMIC_INT_LOCK_FREE) \
     && (ATOMIC_INT_LOCK_FREE > 0)))
typedef _Atomic int CRYPTO_REF_COUNT;
#else
typedef int CRYPTO_REF_COUNT;
#endif
#endif
#endif
#define SSL_PKEY_NUM            9

/*
 * Structure containing table entry of values associated with the signature
 * algorithms (signature scheme) extension
*/
typedef struct sigalg_lookup_st {
    /* TLS 1.3 signature scheme name */
    const char *name;
    /* Raw value used in extension */
    uint16_t sigalg;
    /* NID of hash algorithm or NID_undef if no hash */
    int hash;
    /* Index of hash algorithm or -1 if no hash algorithm */
    int hash_idx;
    /* NID of signature algorithm */
    int sig;
    /* Index of signature algorithm */
    int sig_idx;
    /* Combined hash and signature NID, if any */
    int sigandhash;
    /* Required public key curve (ECDSA only) */
    int curve;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Whether this signature algorithm is actually available for use */
    int enabled;
#endif
} SIGALG_LOOKUP;

typedef enum {
    ENDPOINT_CLIENT = 0,
    ENDPOINT_SERVER,
    ENDPOINT_BOTH
} ENDPOINT;

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

typedef struct {
    unsigned short ext_type;
    ENDPOINT role;
    /* The context which this extension applies to */
    unsigned int context;
    /*
     * Per-connection flags relating to this extension type: not used if
     * part of an SSL_CTX structure.
     */
    uint32_t ext_flags;
    SSL_custom_ext_add_cb_ex add_cb;
    SSL_custom_ext_free_cb_ex free_cb;
    void *add_arg;
    SSL_custom_ext_parse_cb_ex parse_cb;
    void *parse_arg;
} custom_ext_method;

/* ext_flags values */

/*
 * Indicates an extension has been received. Used to check for unsolicited or
 * duplicate extensions.
 */
#define SSL_EXT_FLAG_RECEIVED   0x1
/*
 * Indicates an extension has been sent: used to enable sending of
 * corresponding ServerHello extension.
 */
#define SSL_EXT_FLAG_SENT       0x2

/*
 * Extension type for Certificate Transparency
 * https://tools.ietf.org/html/rfc6962#section-3.3.1
 */
#define TLSEXT_TYPE_signed_certificate_timestamp    18

#define SSL_EXT_CLIENT_HELLO                    0x0080

/* ExtensionType value from RFC7301 */
#define TLSEXT_TYPE_application_layer_protocol_negotiation 16

/* ExtensionType values from RFC4492 */
/*
 * Prior to TLSv1.3 the supported_groups extension was known as
 * elliptic_curves
 */
# define TLSEXT_TYPE_supported_groups            10
# define TLSEXT_TYPE_ec_point_formats            11

/* As defined for TLS1.3 */
# define TLSEXT_TYPE_psk                         41
# define TLSEXT_TYPE_early_data                  42
# define TLSEXT_TYPE_supported_versions          43
# define TLSEXT_TYPE_cookie                      44
# define TLSEXT_TYPE_psk_kex_modes               45
# define TLSEXT_TYPE_certificate_authorities     47
# define TLSEXT_TYPE_post_handshake_auth         49
# define TLSEXT_TYPE_signature_algorithms_cert   50
# define TLSEXT_TYPE_key_share                   51

# ifndef OPENSSL_NO_NEXTPROTONEG
/* This is not an IANA defined extension number */
#  define TLSEXT_TYPE_next_proto_neg              13172
# endif

/*
 * ExtensionType value for TLS padding extension.
 * http://tools.ietf.org/html/draft-agl-tls-padding
 */
# define TLSEXT_TYPE_padding     21

/* Temporary extension type */
# define TLSEXT_TYPE_renegotiate                 0xff01

/* ExtensionType values from RFC3546 / RFC4366 / RFC6066 */
# define TLSEXT_TYPE_server_name                 0
# define TLSEXT_TYPE_max_fragment_length         1
# define TLSEXT_TYPE_status_request              5

/* ExtensionType value from RFC4507 */
# define TLSEXT_TYPE_session_ticket              35
/* ExtensionType values from RFC5246 */
# define TLSEXT_TYPE_signature_algorithms        13

/* ExtensionType values from RFC5246 */
# define TLSEXT_TYPE_signature_algorithms        13

/* ExtensionType value from RFC5054 */
# define TLSEXT_TYPE_srp                         12

/* ExtensionType value from RFC5764 */
# define TLSEXT_TYPE_use_srtp    14

/* ExtensionType value from RFC7366 */
# define TLSEXT_TYPE_encrypt_then_mac    22

/* ExtensionType value from RFC7627 */
# define TLSEXT_TYPE_extended_master_secret      23

typedef struct {
    custom_ext_method *meths;
    size_t meths_count;
} custom_ext_methods;

typedef struct cert_st {
    /* Current active set */
    /*
     * ALWAYS points to an element of the pkeys array
     * Probably it would make more sense to store
     * an index, not a pointer.
     */
    CERT_PKEY *key;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#ifndef OPENSSL_NO_DH
    EVP_PKEY *dh_tmp;
    DH *(*dh_tmp_cb) (SSL *ssl, int is_export, int keysize);
    int dh_tmp_auto;
# endif
#endif
    /* Flags related to certificates */
    uint32_t cert_flags;
    CERT_PKEY pkeys[SSL_PKEY_NUM];
    /* Custom certificate types sent in certificate request message. */
    uint8_t *ctype;
    size_t ctype_len;
    /*
     * supported signature algorithms. When set on a client this is sent in
     * the client hello as the supported signature algorithms extension. For
     * servers it represents the signature algorithms we are willing to use.
     */
    uint16_t *conf_sigalgs;
    /* Size of above array */
    size_t conf_sigalgslen;
    /*
     * Client authentication signature algorithms, if not set then uses
     * conf_sigalgs. On servers these will be the signature algorithms sent
     * to the client in a certificate request for TLS 1.2. On a client this
     * represents the signature algorithms we are willing to use for client
     * authentication.
     */
    uint16_t *client_sigalgs;
    /* Size of above array */
    size_t client_sigalgslen;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /*
     * Signature algorithms shared by client and server: cached because these
     * are used most often.
     */
    const SIGALG_LOOKUP **shared_sigalgs;
    size_t shared_sigalgslen;
#endif
    /*
     * Certificate setup callback: if set is called whenever a certificate
     * may be required (client or server). the callback can then examine any
     * appropriate parameters and setup any certificates required. This
     * allows advanced applications to select certificates on the fly: for
     * example based on supported signature algorithms or curves.
     */
    int (*cert_cb) (SSL *ssl, void *arg);
    void *cert_cb_arg;
    /*
     * Optional X509_STORE for chain building or certificate validation If
     * NULL the parent SSL_CTX store is used instead.
     */
    X509_STORE *chain_store;
    X509_STORE *verify_store;
    /* Custom extensions */
    custom_ext_methods custext;
    /* Security callback */
    int (*sec_cb) (const SSL *s, const SSL_CTX *ctx, int op, int bits, int nid,
                   void *other, void *ex);
    /* Security level */
    int sec_level;
    void *sec_ex;
# ifndef OPENSSL_NO_PSK
    /* If not NULL psk identity hint to use for servers */
    char *psk_identity_hint;
# endif
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
    CRYPTO_REF_COUNT references;             /* >1 only if SSL_copy_session_id is used */
    CRYPTO_RWLOCK *lock;
#endif
} CERT;


/*
 * Matches the length of PSK_MAX_PSK_LEN. We keep it the same value for
 * consistency, even in the event of OPENSSL_NO_PSK being defined.
 */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#define TLS13_MAX_RESUMPTION_PSK_LENGTH        512
#else
#define TLS13_MAX_RESUMPTION_PSK_LENGTH        256
#endif

#define SSL_MAX_SSL_SESSION_ID_LENGTH           32

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef struct ssl_session_st {
    int ssl_version;            /* what ssl version session info is being kept
                                 * in here? */
    size_t master_key_length;

    /* TLSv1.3 early_secret used for external PSKs */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    /*
     * For <=TLS1.2 this is the master_key. For TLS1.3 this is the resumption
     * PSK
     */
    unsigned char master_key[TLS13_MAX_RESUMPTION_PSK_LENGTH];
    /* session_id - valid? */
    size_t session_id_length;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    /*
     * this is used to determine whether the session is being reused in the
     * appropriate context. It is up to the application to set this, via
     * SSL_new
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

    char *psk_identity_hint;
    char *psk_identity;

    /*
     * Used to indicate that session resumption is not allowed. Applications
     * can also set this bit for a new session via not_resumable_session_cb
     * to disable session caching and tickets.
     */
    int not_resumable;
    /* This is the cert and type for the other end. */
    X509 *peer;
#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    int peer_type;
#endif
    /* Certificate chain peer sent. */
    STACK_OF(X509) *peer_chain;
    /*
     * when app_verify_callback accepts a session where the peer's
     * certificate is not ok, we must remember the error for session reuse:
     */
    long verify_result;         /* only for servers */
    int references;
    long timeout;
    long time;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    time_t calc_timeout;
    int timeout_ovf;
#endif
    unsigned int compress_meth; /* Need to lookup the method */
    const SSL_CIPHER *cipher;
    unsigned long cipher_id;    /* when ASN.1 loaded, this needs to be used to
                                 * load the 'cipher' structure */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    unsigned int kex_group;      /* TLS group from key exchange */
#endif
#if OPENSSL_VERSION_NUMBER < 0x0101010bf
    STACK_OF(SSL_CIPHER) *ciphers; /* ciphers offered by the client */
#endif
    CRYPTO_EX_DATA ex_data;     /* application specific data */
    /*
     * These are used to make removal of session-ids more efficient and to
     * implement a maximum cache size.
     */
    struct ssl_session_st *prev, *next;

    struct {
        char *hostname;

#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        size_t ecpointformats_len;
        unsigned char *ecpointformats; /* peer's list */

        size_t supportedgroups_len;
        uint16_t *supportedgroups; /* peer's list */
#endif
    /* RFC4507 info */
        unsigned char *tick; /* Session ticket */
        size_t ticklen;      /* Session ticket length */
        /* Session lifetime hint in seconds */
        unsigned long tick_lifetime_hint;
        uint32_t tick_age_add;
        /* Max number of bytes that can be sent as early data */
        uint32_t max_early_data;
        /* The ALPN protocol selected for this session */
        unsigned char *alpn_selected;
        size_t alpn_selected_len;
        /*
         * Maximum Fragment Length as per RFC 4366.
         * If this value does not contain RFC 4366 allowed values (1-4) then
         * either the Maximum Fragment Length Negotiation failed or was not
         * performed at all.
         */
        uint8_t max_fragment_len_mode;
    } ext;

    char *srp_username;

    unsigned char *ticket_appdata;
    size_t ticket_appdata_len;
    uint32_t flags;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    SSL_CTX *owner;
#endif
    void *lock;
} SSL_SESSION;
#else
# define SSL_MAX_KEY_ARG_LENGTH                  8
# define SSL_MAX_MASTER_KEY_LENGTH               48
typedef struct ssl_session_st {
    int ssl_version;            /* what ssl version session info is being
                                 * kept in here? */
    /* only really used in SSLv2 */
    unsigned int key_arg_length;
    unsigned char key_arg[SSL_MAX_KEY_ARG_LENGTH];
    int master_key_length;
    unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
    /* session_id - valid? */
    unsigned int session_id_length;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    /*
     * this is used to determine whether the session is being reused in the
     * appropriate context. It is up to the application to set this, via
     * SSL_new
     */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
#  ifndef OPENSSL_NO_KRB5
    unsigned int krb5_client_princ_len;
    unsigned char krb5_client_princ[SSL_MAX_KRB5_PRINCIPAL_LENGTH];
#  endif
    char *psk_identity_hint;
    char *psk_identity;
    /*
     * Used to indicate that session resumption is not allowed. Applications
     * can also set this bit for a new session via not_resumable_session_cb
     * to disable session caching and tickets.
     */
    int not_resumable;
    /* The cert is the certificate used to establish this connection */
    struct sess_cert_st /* SESS_CERT */ *sess_cert;
    /*
     * This is the cert for the other end. On clients, it will be the same as
     * sess_cert->peer_key->x509 (the latter is not enough as sess_cert is
     * not retained in the external representation of sessions, see
     * ssl_asn1.c).
     */
    X509 *peer;
    /*
     * when app_verify_callback accepts a session where the peer's
     * certificate is not ok, we must remember the error for session reuse:
     */
    long verify_result;         /* only for servers */
    int references;
    long timeout;
    long time;
    unsigned int compress_meth; /* Need to lookup the method */
    const SSL_CIPHER *cipher;
    unsigned long cipher_id;    /* when ASN.1 loaded, this needs to be used
                                 * to load the 'cipher' structure */
    STACK_OF(SSL_CIPHER) *ciphers; /* shared ciphers? */
    CRYPTO_EX_DATA ex_data;     /* application specific data */
    /*
     * These are used to make removal of session-ids more efficient and to
     * implement a maximum cache size.
     */
    struct ssl_session_st *prev, *next;
    char *tlsext_hostname;
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist; /* peer's list */
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist; /* peer's list */
    /* RFC4507 info */
    unsigned char *tlsext_tick; /* Session ticket */
    size_t tlsext_ticklen;      /* Session ticket length */
    long tlsext_tick_lifetime_hint; /* Session lifetime hint in seconds */
    char *srp_username;
} SSL_SESSION;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */

#define OSSL_MAX_CERT_CHAIN_COUNT	16
typedef struct ossl_x509_list {
     int	count;
     X509     * certs[OSSL_MAX_CERT_CHAIN_COUNT];
} OSSL_X509_LIST;

# define TLSEXT_KEYNAME_LENGTH 16

/* All hashes are SHA256 in v1 of Certificate Transparency */
#define CT_V1_HASHLEN SHA256_DIGEST_LENGTH
# define HMAC_MAX_MD_CBLOCK      128/* largest known is SHA512 */

typedef void CRYPTO_RWLOCK;
/*
 * Information about a CT log server.
 */
typedef struct ctlog_st {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    OSSL_LIB_CTX *libctx;
    char *propq;
#endif
    char *name;
    ubyte log_id[CT_V1_HASHLEN];
    EVP_PKEY *public_key;
}CTLOG;

/*
 * A store for multiple CTLOG instances.
 * It takes ownership of any CTLOG instances added to it.
 */
typedef struct ctlog_store_st {
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    OSSL_LIB_CTX *libctx;
    char *propq;
#endif
    STACK_OF(CTLOG) *logs;
}CTLOG_STORE;

typedef struct hmac_ctx_st {
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;
    EVP_MD_CTX *i_ctx;
    EVP_MD_CTX *o_ctx;
#if !defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    unsigned int key_length;
    unsigned char key[HMAC_MAX_MD_CBLOCK];
#endif
}HMAC_CTX;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
/* this structure holds data relevant to SSL_client_hello_* functions */
typedef struct ClientHelloData *ClientHelloDataPtr;

typedef int (*SSL_client_hello_cb_fn) (SSL *s, int *al, void *arg);

/*
 * A callback for logging out TLS key material. This callback should log out
 * |line| followed by a newline.
 */
typedef void (*SSL_CTX_keylog_cb_func)(const SSL *ssl, const char *line);

typedef int (*SSL_psk_find_session_cb_func)(SSL *ssl,
                                            const unsigned char *identity,
                                            size_t identity_len,
                                            SSL_SESSION **sess);

typedef int (*SSL_psk_use_session_cb_func)(SSL *ssl, const EVP_MD *md,
                                           const unsigned char **id,
                                           size_t *idlen,
                                           SSL_SESSION **sess);

typedef int (*SSL_CTX_generate_session_ticket_fn)(SSL *s, void *arg);

/* Status codes passed to the decrypt session ticket callback. Some of these
 * are for internal use only and are never passed to the callback. */
typedef int SSL_TICKET_STATUS;
/* Return codes for the decrypt session ticket callback */
typedef int SSL_TICKET_RETURN;

/* Post-Handshake Authentication state */
typedef enum {
    SSL_PHA_NONE = 0,
    SSL_PHA_EXT_SENT,        /* client-side only: extension sent */
    SSL_PHA_EXT_RECEIVED,    /* server-side only: extension received */
    SSL_PHA_REQUEST_PENDING, /* server-side only: request pending */
    SSL_PHA_REQUESTED        /* request received by client, or sent by server */
} SSL_PHA_STATE;

typedef SSL_TICKET_RETURN (*SSL_CTX_decrypt_session_ticket_fn)(SSL *s, SSL_SESSION *ss,
                                                               const unsigned char *keyname,
                                                               size_t keyname_length,
                                                               SSL_TICKET_STATUS status,
                                                               void *arg);

typedef int (*SSL_allow_early_data_cb_fn)(SSL *s, void *arg);

typedef int (*tls_session_ticket_ext_cb_fn) (SSL *s,
                                             const unsigned char *data,
                                             int len, void *arg);

/*
 * Extension index values NOTE: Any updates to these defines should be mirrored
 * with equivalent updates to ext_defs in extensions.c
 */
typedef enum tlsext_index_en {
    TLSEXT_IDX_renegotiate,
    TLSEXT_IDX_server_name,
    TLSEXT_IDX_max_fragment_length,
    TLSEXT_IDX_srp,
    TLSEXT_IDX_ec_point_formats,
    TLSEXT_IDX_supported_groups,
    TLSEXT_IDX_session_ticket,
    TLSEXT_IDX_status_request,
    TLSEXT_IDX_next_proto_neg,
    TLSEXT_IDX_application_layer_protocol_negotiation,
    TLSEXT_IDX_use_srtp,
    TLSEXT_IDX_encrypt_then_mac,
    TLSEXT_IDX_signed_certificate_timestamp,
    TLSEXT_IDX_extended_master_secret,
    TLSEXT_IDX_signature_algorithms_cert,
    TLSEXT_IDX_post_handshake_auth,
    TLSEXT_IDX_signature_algorithms,
    TLSEXT_IDX_supported_versions,
    TLSEXT_IDX_psk_kex_modes,
    TLSEXT_IDX_key_share,
    TLSEXT_IDX_cookie,
    TLSEXT_IDX_cryptopro_bug,
    TLSEXT_IDX_early_data,
    TLSEXT_IDX_certificate_authorities,
    TLSEXT_IDX_padding,
    TLSEXT_IDX_psk,
    /* Dummy index - must always be the last entry */
    TLSEXT_IDX_num_builtins
} TLSEXT_INDEX;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__  */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)

struct ssl_ctx_st_orig {
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    unsigned long session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept will cache SSL_SESSIONS.
     */
    ubyte4 session_cache_mode;  /* uint32_t changed to ubyte4 */
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    const unsigned char *data, int len,
                                    int *copy);
    struct {
        int sess_connect;       /* SSL new conn - started */
        int sess_connect_renegotiate; /* SSL reneg - requested */
        int sess_connect_good;  /* SSL new conne/reneg - finished */
        int sess_accept;        /* SSL new accept - started */
        int sess_accept_renegotiate; /* SSL reneg - requested */
        int sess_accept_good;   /* SSL accept/reneg - finished */
        int sess_miss;          /* session lookup misses */
        int sess_timeout;       /* reuse attempt on timeouted session */
        int sess_cache_full;    /* session removed due to full cache */
        int sess_hit;           /* session reuse actually done */
        int sess_cb_hit;        /* session-id that was not in the cache was
                                 * passed back via the callback.  This
                                 * indicates that the application is supplying
                                 * session-id's from other processes - spooky
                                 * :-) */
    } stats;

    int references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                 unsigned int cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /* what we put in client cert requests */
    STACK_OF(X509_NAME) *client_CA;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

    ubyte4 options;  /*  uint32_t changed to ubyte4 */
    unsigned long mode;
    int min_proto_version;
    int max_proto_version;
    long max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    ubyte4 verify_mode; /*  uint32_t changed to ubyte4 */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

    int quiet_shutdown;

# ifndef OPENSSL_NO_CT
    CTLOG_STORE *ctlog_store;   /* CT Log Store */
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    void *ct_validation_callback_arg;
# endif

    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    unsigned int split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    unsigned int max_send_fragment;

    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    unsigned int max_pipelines;

    /* The default read buffer length to use (0 means not set) */
    size_t default_read_buf_len;

# ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
# endif

    /* TLS extensions servername callback */
    int (*tlsext_servername_callback) (SSL *, int *, void *);
    void *tlsext_servername_arg;
    /* RFC 4507 session ticket keys */
    unsigned char tlsext_tick_key_name[TLSEXT_KEYNAME_LENGTH];
    unsigned char tlsext_tick_hmac_key[32];
    unsigned char tlsext_tick_aes_key[32];
    /* Callback to support customisation of ticket key setting */
    int (*tlsext_ticket_key_cb) (SSL *ssl,
                                 unsigned char *name, unsigned char *iv,
                                 EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);

    /* certificate status request info */
    /* Callback for status request */
    int (*tlsext_status_cb) (SSL *ssl, void *arg);
    void *tlsext_status_arg;

# ifndef OPENSSL_NO_PSK
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
# endif

# ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
# endif

# ifndef OPENSSL_NO_NEXTPROTONEG
    /* Next protocol negotiation information */

    /*
     * For a server, this contains a callback function by which the set of
     * advertised protocols can be provided.
     */
    int (*next_protos_advertised_cb) (SSL *s, const unsigned char **buf,
                                      unsigned int *len, void *arg);
    void *next_protos_advertised_cb_arg;
    /*
     * For a client, this contains a callback function that selects the next
     * protocol from the list provided by the server.
     */
    int (*next_proto_select_cb) (SSL *s, unsigned char **out,
                                 unsigned char *outlen,
                                 const unsigned char *in,
                                 unsigned int inlen, void *arg);
    void *next_proto_select_cb_arg;
# endif

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

        /*-
         * For a server, this contains a callback function that allows the
         * server to select the protocol for the connection.
         *   out: on successful return, this must point to the raw protocol
         *        name (without the length prefix).
         *   outlen: on successful return, this contains the length of |*out|.
         *   in: points to the client's list of supported protocols in
         *       wire-format.
         *   inlen: the length of |in|.
         */
    int (*alpn_select_cb) (SSL *s,
                           const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in,
                           unsigned int inlen, void *arg);
    void *alpn_select_cb_arg;

    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

    /* Shared DANE context */
    struct dane_ctx_st dane;

    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);
# ifndef OPENSSL_NO_EC
    /* EC extension values inherited by SSL structure */
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist;
# endif                         /* OPENSSL_NO_EC */

    /* ext status type used for CSR extension (OCSP Stapling) */
    int tlsext_status_type;

    CRYPTO_RWLOCK *lock;

    /* TODO: this shold be cleaned up */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* ClientHello callback.  Mostly for extensions, but not entirely. */
    SSL_client_hello_cb_fn client_hello_cb;
    void *client_hello_cb_arg;

    /*
     * Callback for logging key material for use with debugging tools like
     * Wireshark. The callback should log `line` followed by a newline.
     */
    SSL_CTX_keylog_cb_func keylog_callback;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    uint32_t max_early_data;

    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    uint32_t recv_max_early_data;

    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    /* Session ticket appdata */
    SSL_CTX_generate_session_ticket_fn generate_ticket_cb;
    SSL_CTX_decrypt_session_ticket_fn decrypt_ticket_cb;
    void *ticket_cb_data;

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;


    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;

    /* Do we advertise Post-handshake auth support? */
    int pha_enabled;

    /* TLS1.3 app-controlled cookie generate callback */
    int (*gen_stateless_cookie_cb) (SSL *ssl, unsigned char *cookie,
                                    size_t *cookie_len);

    /* TLS1.3 verify app-controlled cookie callback */
    int (*verify_stateless_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                       size_t cookie_len);

    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;

    /* TLS extensions. */
    struct {
        /* RFC 4366 Maximum Fragment Length Negotiation */
        uint8_t max_fragment_len_mode;

    } ext;
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ */
};
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)

#define TSAN_QUALIFIER

# define TLSEXT_KEYNAME_LENGTH  16
# define TLSEXT_TICK_KEY_LENGTH 32

typedef struct ssl_ctx_ext_secure_st {
    unsigned char tick_hmac_key[TLSEXT_TICK_KEY_LENGTH];
    unsigned char tick_aes_key[TLSEXT_TICK_KEY_LENGTH];
} SSL_CTX_EXT_SECURE;
typedef struct ssl_ctx_ext_secure_st SSL_CTX_EXT_SECURE;
typedef int (*SSL_CTX_npn_advertised_cb_func)(SSL *ssl,
                                              const unsigned char **out,
                                              unsigned int *outlen,
                                              void *arg);

typedef int (*SSL_CTX_npn_select_cb_func)(SSL *s,
                                          unsigned char **out,
                                          unsigned char *outlen,
                                          const unsigned char *in,
                                          unsigned int inlen,
                                          void *arg);

typedef unsigned int (*SSL_psk_client_cb_func)(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);

typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
                                               const char *identity,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);

/* Typedef for SSL async callback */
typedef int (*SSL_async_callback_fn)(SSL *s, void *arg);

typedef struct tls_group_info_st {
    char *tlsname;           /* Curve Name as in TLS specs */
    char *realname;          /* Curve Name according to provider */
    char *algorithm;         /* Algorithm name to fetch */
    unsigned int secbits;    /* Bits of security (from SP800-57) */
    uint16_t group_id;       /* Group ID */
    int mintls;              /* Minimum TLS version, -1 unsupported */
    int maxtls;              /* Maximum TLS version (or 0 for undefined) */
    int mindtls;             /* Minimum DTLS version, -1 unsupported */
    int maxdtls;             /* Maximum DTLS version (or 0 for undefined) */
    char is_kem;             /* Mode for this Group: 0 is KEX, 1 is KEM */
} TLS_GROUP_INFO;

struct ssl_ctx_st_orig {
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    OSSL_LIB_CTX *libctx;
#endif
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    size_t session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept will cache SSL_SESSIONS.
     */
    ubyte4 session_cache_mode;
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    const unsigned char *data, int len,
                                    int *copy);
    struct {
        TSAN_QUALIFIER int sess_connect;       /* SSL new conn - started */
        TSAN_QUALIFIER int sess_connect_renegotiate; /* SSL reneg - requested */
        TSAN_QUALIFIER int sess_connect_good;  /* SSL new conne/reneg - finished */
        TSAN_QUALIFIER int sess_accept;        /* SSL new accept - started */
        TSAN_QUALIFIER int sess_accept_renegotiate; /* SSL reneg - requested */
        TSAN_QUALIFIER int sess_accept_good;   /* SSL accept/reneg - finished */
        TSAN_QUALIFIER int sess_miss;          /* session lookup misses */
        TSAN_QUALIFIER int sess_timeout;       /* reuse attempt on timeouted session */
        TSAN_QUALIFIER int sess_cache_full;    /* session removed due to full cache */
        TSAN_QUALIFIER int sess_hit;           /* session reuse actually done */
        TSAN_QUALIFIER int sess_cb_hit;        /* session-id that was not in
                                                * the cache was passed back via
                                                * the callback. This indicates
                                                * that the application is
                                                * supplying session-id's from
                                                * other processes - spooky
                                                * :-) */
    } stats;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
#ifdef TSAN_REQUIRES_LOCKING
    CRYPTO_RWLOCK *tsan_lock;
#endif
#endif

    int references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                 unsigned int cookie_len);

    /* TLS1.3 app-controlled cookie generate callback */
    int (*gen_stateless_cookie_cb) (SSL *ssl, unsigned char *cookie,
                                    size_t *cookie_len);

    /* TLS1.3 verify app-controlled cookie callback */
    int (*verify_stateless_cookie_cb) (SSL *ssl, const unsigned char *cookie,
                                       size_t cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ubyte8 options;
#else
    ubyte4 options;
#endif
    ubyte4 mode;
    int min_proto_version;
    int max_proto_version;
    size_t max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    ubyte4 verify_mode;
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

    int quiet_shutdown;

# ifndef OPENSSL_NO_CT
    CTLOG_STORE *ctlog_store;   /* CT Log Store */
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    void *ct_validation_callback_arg;
# endif

    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    size_t split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    size_t max_send_fragment;

    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    size_t max_pipelines;

    /* The default read buffer length to use (0 means not set) */
    size_t default_read_buf_len;

# ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
# endif

    /* ClientHello callback.  Mostly for extensions, but not entirely. */
    SSL_client_hello_cb_fn client_hello_cb;
    void *client_hello_cb_arg;

    /* TLS extensions. */
    struct {
        /* TLS extensions servername callback */
        int (*servername_cb) (SSL *, int *, void *);
        void *servername_arg;
        /* RFC 4507 session ticket keys */
        unsigned char tick_key_name[TLSEXT_KEYNAME_LENGTH];
        SSL_CTX_EXT_SECURE *secure;
        /* Callback to support customisation of ticket key setting */
# ifndef OPENSSL_NO_DEPRECATED_3_0
        int (*ticket_key_cb) (SSL *ssl,
                              unsigned char *name, unsigned char *iv,
                              EVP_CIPHER_CTX *ectx, HMAC_CTX *hctx, int enc);
#endif


#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        int (*ticket_key_evp_cb) (SSL *ssl,
                                  unsigned char *name, unsigned char *iv,
                                  EVP_CIPHER_CTX *ectx, EVP_MAC_CTX *hctx,
                                  int enc);
#endif
        /* certificate status request info */
        /* Callback for status request */
        int (*status_cb) (SSL *ssl, void *arg);
        void *status_arg;
        /* ext status type used for CSR extension (OCSP Stapling) */
        int status_type;
        /* RFC 4366 Maximum Fragment Length Negotiation */
        ubyte max_fragment_len_mode;

# ifndef OPENSSL_NO_EC
        /* EC extension values inherited by SSL structure */
        size_t ecpointformats_len;
        unsigned char *ecpointformats;
        size_t supportedgroups_len;
        ubyte2 *supportedgroups;
# endif                         /* OPENSSL_NO_EC */

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
        ubyte2 *supported_groups_default;
        size_t supported_groups_default_len;
#endif
        /*
         * ALPN information (we are in the process of transitioning from NPN to
         * ALPN.)
         */

        /*-
         * For a server, this contains a callback function that allows the
         * server to select the protocol for the connection.
         *   out: on successful return, this must point to the raw protocol
         *        name (without the length prefix).
         *   outlen: on successful return, this contains the length of |*out|.
         *   in: points to the client's list of supported protocols in
         *       wire-format.
         *   inlen: the length of |in|.
         */
        int (*alpn_select_cb) (SSL *s,
                               const unsigned char **out,
                               unsigned char *outlen,
                               const unsigned char *in,
                               unsigned int inlen, void *arg);
        void *alpn_select_cb_arg;

        /*
         * For a client, this contains the list of supported protocols in wire
         * format.
         */
        unsigned char *alpn;
        size_t alpn_len;

# ifndef OPENSSL_NO_NEXTPROTONEG
        /* Next protocol negotiation information */

        /*
         * For a server, this contains a callback function by which the set of
         * advertised protocols can be provided.
         */
        SSL_CTX_npn_advertised_cb_func npn_advertised_cb;
        void *npn_advertised_cb_arg;
        /*
         * For a client, this contains a callback function that selects the next
         * protocol from the list provided by the server.
         */
        SSL_CTX_npn_select_cb_func npn_select_cb;
        void *npn_select_cb_arg;
# endif

        unsigned char cookie_hmac_key[SHA256_DIGEST_LENGTH];
    } ext;

# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

# ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
# endif

    /* Shared DANE context */
    struct dane_ctx_st dane;

# ifndef OPENSSL_NO_SRTP
    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
# endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);

    CRYPTO_RWLOCK *lock;

    /*
     * Callback for logging key material for use with debugging tools like
     * Wireshark. The callback should log `line` followed by a newline.
     */
    SSL_CTX_keylog_cb_func keylog_callback;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    ubyte4 max_early_data;

    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    ubyte4 recv_max_early_data;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    /* Session ticket appdata */
    SSL_CTX_generate_session_ticket_fn generate_ticket_cb;
    SSL_CTX_decrypt_session_ticket_fn decrypt_ticket_cb;
    void *ticket_cb_data;

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;

    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;

    /* Do we advertise Post-handshake auth support? */
    int pha_enabled;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* Callback for SSL async handling */
    SSL_async_callback_fn async_cb;
    void *async_cb_arg;

    char *propq;

    int ssl_mac_pkey_id[14]; /* SSL_MD_NUM_IDX defined in ossl_ssl.h */
    const EVP_CIPHER *ssl_cipher_methods[24]; /* SSL_ENC_NUM_IDX defined in ossl_ssl.h */
    const EVP_MD *ssl_digest_methods[14]; /* SSL_MD_NUM_IDX defined in ossl_ssl.h */
    size_t ssl_mac_secret_size[14]; /* SSL_MD_NUM_IDX defined in ossl_ssl.h */

    /* Cache of all sigalgs we know and whether they are available or not */
    struct sigalg_lookup_st *sigalg_lookup_cache;

    TLS_GROUP_INFO *group_list;
    size_t group_list_len;
    size_t group_list_max_len;

    /* masks of disabled algorithms */
    ubyte4 disabled_enc_mask;
    ubyte4 disabled_mac_mask;
    ubyte4 disabled_mkey_mask;
    ubyte4 disabled_auth_mask;
#endif
};

#else

struct ssl_ctx_st_orig {
    const SSL_METHOD *method;
    STACK_OF(SSL_CIPHER) *cipher_list;
    /* same as above but sorted for lookup */
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    struct x509_store_st /* X509_STORE */ *cert_store;
    LHASH_OF(SSL_SESSION) *sessions;
    /*
     * Most session-ids that will be cached, default is
     * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited.
     */
    unsigned long session_cache_size;
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    /*
     * This can have one of 2 values, ored together, SSL_SESS_CACHE_CLIENT,
     * SSL_SESS_CACHE_SERVER, Default is SSL_SESSION_CACHE_SERVER, which
     * means only SSL_accept which cache SSL_SESSIONS.
     */
    int session_cache_mode;
    /*
     * If timeout is not 0, it is the default timeout value set when
     * SSL_new() is called.  This has been put in to make life easier to set
     * things up
     */
    long session_timeout;
    /*
     * If this callback is not null, it will be called each time a session id
     * is added to the cache.  If this function returns 1, it means that the
     * callback will do a SSL_SESSION_free() when it has finished using it.
     * Otherwise, on 0, it means the callback has finished with it. If
     * remove_session_cb is not null, it will be called when a session-id is
     * removed from the cache.  After the call, OpenSSL will
     * SSL_SESSION_free() it.
     */
    int (*new_session_cb) (struct ssl_st *ssl, SSL_SESSION *sess);
    void (*remove_session_cb) (struct ssl_ctx_st *ctx, SSL_SESSION *sess);
    SSL_SESSION *(*get_session_cb) (struct ssl_st *ssl,
                                    unsigned char *data, int len, int *copy);
    struct {
        int sess_connect;       /* SSL new conn - started */
        int sess_connect_renegotiate; /* SSL reneg - requested */
        int sess_connect_good;  /* SSL new conne/reneg - finished */
        int sess_accept;        /* SSL new accept - started */
        int sess_accept_renegotiate; /* SSL reneg - requested */
        int sess_accept_good;   /* SSL accept/reneg - finished */
        int sess_miss;          /* session lookup misses */
        int sess_timeout;       /* reuse attempt on timeouted session */
        int sess_cache_full;    /* session removed due to full cache */
        int sess_hit;           /* session reuse actually done */
        int sess_cb_hit;        /* session-id that was not in the cache was
                                 * passed back via the callback.  This
                                 * indicates that the application is
                                 * supplying session-id's from other
                                 * processes - spooky :-) */
    } stats;

    int references;

    /* if defined, these override the X509_verify_cert() calls */
    int (*app_verify_callback) (X509_STORE_CTX *, void *);
    void *app_verify_arg;
    /*
     * before OpenSSL 0.9.7, 'app_verify_arg' was ignored
     * ('app_verify_callback' was called with just one argument)
     */

    /* Default password callback. */
    pem_password_cb *default_passwd_callback;

    /* Default password callback user data. */
    void *default_passwd_callback_userdata;

    /* get client cert callback */
    int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);

    /* cookie generate callback */
    int (*app_gen_cookie_cb) (SSL *ssl, unsigned char *cookie,
                              unsigned int *cookie_len);

    /* verify cookie callback */
    int (*app_verify_cookie_cb) (SSL *ssl, unsigned char *cookie,
                                 unsigned int cookie_len);

    CRYPTO_EX_DATA ex_data;

    const EVP_MD *rsa_md5;      /* For SSLv2 - name is 'ssl2-md5' */
    const EVP_MD *md5;          /* For SSLv3/TLSv1 'ssl3-md5' */
    const EVP_MD *sha1;         /* For SSLv3/TLSv1 'ssl3->sha1' */

    STACK_OF(X509) *extra_certs;
    STACK_OF(SSL_COMP) *comp_methods; /* stack of SSL_COMP, SSLv3/TLSv1 */

    /* Default values used when no per-SSL value is defined follow */

    /* used if SSL's info_callback is NULL */
    void (*info_callback) (const SSL *ssl, int type, int val);

    /* what we put in client cert requests */
    STACK_OF(X509_NAME) *client_CA;

    /*
     * Default values to use in SSL structures follow (these are copied by
     * SSL_new)
     */

    unsigned long options;
    unsigned long mode;
    long max_cert_list;

    struct cert_st /* CERT */ *cert;
    int read_ahead;

    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;

    int verify_mode;
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* called 'verify_callback' in the SSL */
    int (*default_verify_callback) (int ok, X509_STORE_CTX *ctx);

    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;

    X509_VERIFY_PARAM *param;

#  if 0
    int purpose;                /* Purpose setting */
    int trust;                  /* Trust setting */
#  endif

    int quiet_shutdown;

    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    unsigned int max_send_fragment;

#  ifndef OPENSSL_NO_ENGINE
    /*
     * Engine to pass requests for client certs to
     */
    ENGINE *client_cert_engine;
#  endif

#  ifndef OPENSSL_NO_TLSEXT
    /* TLS extensions servername callback */
    int (*tlsext_servername_callback) (SSL *, int *, void *);
    void *tlsext_servername_arg;
    /* RFC 4507 session ticket keys */
    unsigned char tlsext_tick_key_name[16];
    unsigned char tlsext_tick_hmac_key[16];
    unsigned char tlsext_tick_aes_key[16];
    /* Callback to support customisation of ticket key setting */
    int (*tlsext_ticket_key_cb) (SSL *ssl,
                                 unsigned char *name, unsigned char *iv,
                                 EVP_CIPHER_CTX *ectx,
                                 HMAC_CTX *hctx, int enc);

    /* certificate status request info */
    /* Callback for status request */
    int (*tlsext_status_cb) (SSL *ssl, void *arg);
    void *tlsext_status_arg;

    /* draft-rescorla-tls-opaque-prf-input-00.txt information */
    int (*tlsext_opaque_prf_input_callback) (SSL *, void *peerinput,
                                             size_t len, void *arg);
    void *tlsext_opaque_prf_input_callback_arg;
#  endif

#  ifndef OPENSSL_NO_PSK
    char *psk_identity_hint;
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif

#  ifndef OPENSSL_NO_BUF_FREELISTS
#   define SSL_MAX_BUF_FREELIST_LEN_DEFAULT 32
    unsigned int freelist_max_len;
    struct ssl3_buf_freelist_st *wbuf_freelist;
    struct ssl3_buf_freelist_st *rbuf_freelist;
#  endif
#  ifndef OPENSSL_NO_SRP
    SRP_CTX srp_ctx;            /* ctx for SRP authentication */
#  endif

#  ifndef OPENSSL_NO_TLSEXT

#   ifndef OPENSSL_NO_NEXTPROTONEG
    /* Next protocol negotiation information */
    /* (for experimental NPN extension). */

    /*
     * For a server, this contains a callback function by which the set of
     * advertised protocols can be provided.
     */
    int (*next_protos_advertised_cb) (SSL *s, const unsigned char **buf,
                                      unsigned int *len, void *arg);
    void *next_protos_advertised_cb_arg;
    /*
     * For a client, this contains a callback function that selects the next
     * protocol from the list provided by the server.
     */
    int (*next_proto_select_cb) (SSL *s, unsigned char **out,
                                 unsigned char *outlen,
                                 const unsigned char *in,
                                 unsigned int inlen, void *arg);
    void *next_proto_select_cb_arg;
#   endif
    /* SRTP profiles we are willing to do from RFC 5764 */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;

    /*
     * ALPN information (we are in the process of transitioning from NPN to
     * ALPN.)
     */

    /*-
     * For a server, this contains a callback function that allows the
     * server to select the protocol for the connection.
     *   out: on successful return, this must point to the raw protocol
     *        name (without the length prefix).
     *   outlen: on successful return, this contains the length of |*out|.
     *   in: points to the client's list of supported protocols in
     *       wire-format.
     *   inlen: the length of |in|.
     */
    int (*alpn_select_cb) (SSL *s,
                           const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in,
                           unsigned int inlen, void *arg);
    void *alpn_select_cb_arg;

    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

#   ifndef OPENSSL_NO_EC
    /* EC extension values inherited by SSL structure */
    size_t tlsext_ecpointformatlist_length;
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    unsigned char *tlsext_ellipticcurvelist;
#   endif                       /* OPENSSL_NO_EC */
#  endif
};

#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ || __ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__ */

struct ssl_ctx_st
{
     /* store the original structure */
     struct ssl_ctx_st_orig orig_ssl_ctx;

     const struct ssl_method_st * ssl_method;
     /* Mocana CERT_STORE. This holds the server identity keypair as well
      * as CA certs to authenticate peer certificates
      */
     void	      * pCertStore;
     int		verify_mode;
     /* This is verify_callback in struct SSL and default_verify_callback in CTX
      * in openssl.
      */
     int (*verify_callback)(int, X509_STORE_CTX *);
     int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey);
     X509	      * cert_x509; 	/* Server cert public */
     OSSL_X509_LIST     cert_x509_list; /* Server cert chain */
     /* Used by client to store CA certs and CRLs. Used to verify server cert */
     X509_STORE	      * cert_store;
     /* Above certs are parsed and list of CA names are put in client_CA list. I guess
      * only MOD_SSL does this; Most simple clients won't need it
      */
     STACK_OF(X509_NAME) *client_CA;
    /* X509_STORE for certificate validation, stored
     * to hold reference only */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    X509_STORE *verify_store;
#endif
     /* array below indexed based on public key type in cert_x509 */
     int		ossl_pkey_idx;
     EVP_PKEY	      *privatekey[OSSL_PKEY_MAX + 1]; /* server priv key corr to pubkey above */
     ubyte            *pKeyAlias; /* This is the alias for this key, cert (and cert chain) entry in NanoSSL Cert Store */
     ubyte4           keyAliasLength;
     int              privateKeyPending; /* Flag to maintain the status if key is loaded before certificate */
     int		cert_valid;
     X509             * peerCert;
     STACK_OF(X509)   * peerCertChain;
     ubyte2		cipherIds[MAX_NUM_CIPHER_IDS];
     ubyte4             numCipherIds;
     ubyte2             srtpProfileIds[MAX_NUM_SRTP_PROFILE_IDS];
     ubyte4             numSrtpProfileIds;
     /* NOTE: extra_certs is directly accessed by MOD_SSL ! */
     STACK_OF(X509)    * extra_certs;
     CRYPTO_EX_DATA 	 ex_data;
     int (*new_session_cb) (SSL *ssl, SSL_SESSION *sess);
     void (*remove_session_cb) (SSL_CTX *ctx, SSL_SESSION *sess);
     SSL_SESSION *(*get_session_cb) (SSL *ssl,
				     unsigned char *data, int len, int *copy);
     void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
     void *msg_callback_arg;

     RSA *rsa_tmp;
     RSA *(*rsa_tmp_cb) (SSL *ssl, int is_export, int keysize);

     DH *dh_tmp;
     DH *(*dh_tmp_cb) (SSL *ssl, int is_export, int keysize);
     EC_KEY *ecdh_tmp;
     /* Callback for generating ephemeral ECDH keys */
     EC_KEY *(*ecdh_tmp_cb) (SSL *ssl, int is_export, int keysize);
     ubyte2 *pEccCurves;
     ubyte4 numEccCurves;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /* ext status type used for CSR extension (OCSP Stapling) */
    int tlsext_status_type;
#endif

     int (*tlsext_servername_callback) (SSL *, int *, void *);
     void *tlsext_servername_arg;
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);

     /* Callback for status request */
     int (*tlsext_status_cb) (SSL *ssl, void *arg);
     void *tlsext_status_arg;
     long session_timeout;
     unsigned long options;
     unsigned int sid_ctx_length;
     unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /*-
     * For a server, this contains a callback function that allows the
     * server to select the protocol for the connection.
     *   out: on successful return, this must point to the raw protocol
     *        name (without the length prefix).
     *   outlen: on successful return, this contains the length of |*out|.
     *   in: points to the client's list of supported protocols in
     *       wire-format.
     *   inlen: the length of |in|.
     */
    int (*alpn_select_cb) (SSL *s,
                           const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in,
                           unsigned int inlen, void *arg);
    void *alpn_select_cb_arg;
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;

     /* Default password callback. */
     pem_password_cb *default_passwd_callback;

     int references;

     /* Default password callback user data. */
     void *default_passwd_callback_userdata;
     int (*app_verify_callback) (X509_STORE_CTX *, void *arg);
     void *app_verify_arg;
     int (*next_protos_advertised_cb) (SSL *s, const unsigned char **buf,
                                      unsigned int *len, void *arg);
     void *next_protos_advertised_cb_arg;

     int (*next_proto_select_cb) (SSL *s, unsigned char **out,
                                 unsigned char *outlen,
                                 const unsigned char *in,
                                 unsigned int inlen, void *arg);
     void *next_proto_select_cb_arg;
     STACK_OF(SSL_CIPHER) *cipher_list;
     STACK_OF(SSL_CIPHER) *cipher_list_by_id;
     int isCertInitialized;

#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    /*
     * Callback for logging key material for use with debugging tools like
     * Wireshark. The callback should log `line` followed by a newline.
     */
    SSL_CTX_keylog_cb_func keylog_callback;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
#endif
};

enum
{
  SSL_CLIENT_FLAG               = 1 << 0,
  SSL_SERVER_FLAG               = 1 << 1
};

#define OSSL_IN_READ      1
#define OSSL_IN_WRITE     2
#define OSSL_X509_LOOKUP  3

typedef void* m_tls_session_ticket_ext_cb_fn;
typedef void* m_tls_session_secret_cb_fn;

typedef struct srtp_protection_profile_st {
    const char *name;
    unsigned long id;
} SRTP_PROTECTION_PROFILE;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
DEFINE_STACK_OF(SRTP_PROTECTION_PROFILE)
#endif

typedef struct {
    unsigned short length;
    void *data;
}TLS_SESSION_TICKET_EXT;

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
typedef struct {
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Number of bytes remaining */
    size_t remaining;
} PACKET;

typedef struct raw_extension_st {
    /* Raw packet data for the extension */
    PACKET data;
    /* Set to 1 if the extension is present or 0 otherwise */
    int present;
    /* Set to 1 if we have already parsed the extension or 0 otherwise */
    int parsed;
    /* The type of this extension, i.e. a TLSEXT_TYPE_* value */
    unsigned int type;
    /* Track what order extensions are received in (0-based). */
    size_t received_order;
} RAW_EXTENSION;

# define SSL_MAX_SSL_SESSION_ID_LENGTH           32

/* lengths of messages */
/*
 * Actually the max cookie length in DTLS is 255. But we can't change this now
 * due to compatibility concerns.
 */
# define DTLS1_COOKIE_LENGTH                     256

#define MAX_COMPRESSIONS_SIZE   255

typedef struct {
    unsigned int isv2;
    unsigned int legacy_version;
    unsigned char random[SSL3_RANDOM_SIZE];
    size_t session_id_len;
    unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t dtls_cookie_len;
    unsigned char dtls_cookie[DTLS1_COOKIE_LENGTH];
    PACKET ciphersuites;
    size_t compressions_len;
    unsigned char compressions[MAX_COMPRESSIONS_SIZE];
    PACKET extensions;
    size_t pre_proc_exts_len;
    RAW_EXTENSION *pre_proc_exts;
} CLIENTHELLO_MSG;

# define SSL3_RANDOM_SIZE                        32

# define SSL_EARLY_DATA_NOT_SENT    0
# define SSL_EARLY_DATA_REJECTED    1
# define SSL_EARLY_DATA_ACCEPTED    2

/* TLSv1.3 KeyUpdate message types */
/* -1 used so that this is an invalid value for the on-the-wire protocol */
#define SSL_KEY_UPDATE_NONE             -1
/* Values as defined for the on-the-wire protocol */
#define SSL_KEY_UPDATE_NOT_REQUESTED     0
#define SSL_KEY_UPDATE_REQUESTED         1

# define SSL_CHACHA20POLY1305    0x00080000U
# define SSL_AES128CCM           0x00004000U
# define SSL_AES128CCM8          0x00010000U



/* Bits 0-7 are handshake MAC */
# define SSL_HANDSHAKE_MAC_MASK  0xFF

# define SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH       232
# define SSL_F_SSL_SET_TLSEXT_MAX_FRAGMENT_LENGTH         550
# define SSL_F_SSL_CTX_SET_TLSEXT_MAX_FRAGMENT_LENGTH     551

/* OpenSSL value to disable maximum fragment length extension */
# define TLSEXT_max_fragment_length_DISABLED    0
/* Allowed values for max fragment length extension */
# define TLSEXT_max_fragment_length_512         1
# define TLSEXT_max_fragment_length_1024        2
# define TLSEXT_max_fragment_length_2048        3
# define TLSEXT_max_fragment_length_4096        4

# define IS_MAX_FRAGMENT_LENGTH_EXT_VALID(value) \
    (((value) >= TLSEXT_max_fragment_length_512) && \
     ((value) <= TLSEXT_max_fragment_length_4096))

typedef enum {
    SSL_EARLY_DATA_NONE = 0,
    SSL_EARLY_DATA_CONNECT_RETRY,
    SSL_EARLY_DATA_CONNECTING,
    SSL_EARLY_DATA_WRITE_RETRY,
    SSL_EARLY_DATA_WRITING,
    SSL_EARLY_DATA_WRITE_FLUSH,
    SSL_EARLY_DATA_UNAUTH_WRITING,
    SSL_EARLY_DATA_FINISHED_WRITING,
    SSL_EARLY_DATA_ACCEPT_RETRY,
    SSL_EARLY_DATA_ACCEPTING,
    SSL_EARLY_DATA_READ_RETRY,
    SSL_EARLY_DATA_READING,
    SSL_EARLY_DATA_FINISHED_READING
} SSL_EARLY_DATA_STATE;

#define TLS1_FLAGS_STATELESS                    0x0800

#define SEQ_NUM_SIZE                            8
# define SSL_MAX_PIPELINES  32

typedef struct dtls1_bitmap_st {
    /* Track 32 packets on 32-bit systems and 64 - on 64-bit systems */
    unsigned long map;
    /* Max record number seen so far, 64-bit value in big-endian encoding */
    unsigned char max_seq_num[SEQ_NUM_SIZE];
} DTLS1_BITMAP;

typedef struct record_pqueue_st {
    unsigned short epoch;
    struct pqueue_st *q;
} record_pqueue;

typedef struct dtls1_record_data_st {
    unsigned char *packet;
    size_t packet_length;
    SSL3_BUFFER rbuf;
    SSL3_RECORD rrec;
#ifndef OPENSSL_NO_SCTP
    struct bio_dgram_sctp_rcvinfo recordinfo;
#endif
} DTLS1_RECORD_DATA;

typedef struct dtls_record_layer_st {
    /*
     * The current data and handshake epoch.  This is initially
     * undefined, and starts at zero once the initial handshake is
     * completed
     */
    unsigned short r_epoch;
    unsigned short w_epoch;
    /* records being received in the current epoch */
    DTLS1_BITMAP bitmap;
    /* renegotiation starts a new set of sequence numbers */
    DTLS1_BITMAP next_bitmap;
    /* Received handshake records (processed and unprocessed) */
    record_pqueue unprocessed_rcds;
    record_pqueue processed_rcds;
    /*
     * Buffered application records. Only for records between CCS and
     * Finished to prevent either protocol violation or unnecessary message
     * loss.
     */
    record_pqueue buffered_app_data;
    /* save last and current sequence numbers for retransmissions */
    unsigned char last_write_sequence[8];
    unsigned char curr_write_sequence[8];
} DTLS_RECORD_LAYER;

typedef struct record_layer_st {
    /* The parent SSL structure */
    SSL *s;
    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     */
    int read_ahead;
    /* where we are when reading */
    int rstate;
    /* How many pipelines can be used to read data */
    size_t numrpipes;
    /* How many pipelines can be used to write data */
    size_t numwpipes;
    /* read IO goes into here */
    SSL3_BUFFER rbuf;
    /* write IO goes into here */
    SSL3_BUFFER wbuf[SSL_MAX_PIPELINES];
    /* each decoded record goes in here */
    SSL3_RECORD rrec[SSL_MAX_PIPELINES];
    /* used internally to point at a raw packet */
    unsigned char *packet;
    size_t packet_length;
    /* number of bytes sent so far */
    size_t wnum;
    unsigned char handshake_fragment[4];
    size_t handshake_fragment_len;
    /* The number of consecutive empty records we have received */
    size_t empty_record_count;
    /* partial write - check the numbers match */
    /* number bytes written */
    size_t wpend_tot;
    int wpend_type;
    /* number of bytes submitted */
    size_t wpend_ret;
    const unsigned char *wpend_buf;
    unsigned char read_sequence[SEQ_NUM_SIZE];
    unsigned char write_sequence[SEQ_NUM_SIZE];
    /* Set to true if this is the first record in a connection */
    unsigned int is_first_record;
    /* Count of the number of consecutive warning alerts received */
    unsigned int alert_count;
    DTLS_RECORD_LAYER *d;
} RECORD_LAYER;

typedef int (*tls_session_secret_cb_fn_ex)(SSL *s, void *secret, int *secret_len,
                                        STACK_OF(SSL_CIPHER) *peer_ciphers,
                                        const SSL_CIPHER **cipher, void *arg);


typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;
typedef struct async_job_st ASYNC_JOB;
#endif  /* __ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__ || __ENABLE_DIGICERT_OPENSSL_LIB_3_0__  */

/* Start of OpenSSL ssl_st structure */
#if defined(__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
struct ssl_st_orig {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    OSSL_STATEM statem;
    SSL_EARLY_DATA_STATE early_data_state;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    size_t init_num;               /* amount read/written */
    size_t init_off;               /* amount read/written */

    struct {
        long flags;
        size_t read_mac_secret_size;
        unsigned char read_mac_secret[EVP_MAX_MD_SIZE];
        size_t write_mac_secret_size;
        unsigned char write_mac_secret[EVP_MAX_MD_SIZE];
        unsigned char server_random[SSL3_RANDOM_SIZE];
        unsigned char client_random[SSL3_RANDOM_SIZE];
        /* flags for countermeasure against known-IV weakness */
        int need_empty_fragments;
        int empty_fragment_done;
        /* used during startup, digest all incoming/outgoing packets */
        BIO *handshake_buffer;
        /*
         * When handshake digest is determined, buffer is hashed and
         * freed and MD_CTX for the required digest is stored here.
         */
        EVP_MD_CTX *handshake_dgst;
        /*
         * Set whenever an expected ChangeCipherSpec message is processed.
         * Unset when the peer's Finished message is received.
         * Unexpected ChangeCipherSpec messages trigger a fatal alert.
         */
        int change_cipher_spec;
        int warn_alert;
        int fatal_alert;
        /*
         * we allow one fatal and one warning alert to be outstanding, send close
         * alert via the warning alert
         */
        int alert_dispatch;
        unsigned char send_alert[2];
        /*
         * This flag is set when we should renegotiate ASAP, basically when there
         * is no more data in the read or write buffers
         */
        int renegotiate;
        int total_renegotiations;
        int num_renegotiations;
        int in_read_app_data;
        struct {
            /* actually only need to be 16+20 for SSLv3 and 12 for TLS */
            unsigned char finish_md[EVP_MAX_MD_SIZE * 2];
            size_t finish_md_len;
            unsigned char peer_finish_md[EVP_MAX_MD_SIZE * 2];
            size_t peer_finish_md_len;
            size_t message_size;
            int message_type;
            /* used to hold the new cipher we are going to use */
            const SSL_CIPHER *new_cipher;
            EVP_PKEY *pkey;         /* holds short lived key exchange key */
            /* used for certificate requests */
            int cert_req;
            /* Certificate types in certificate request message. */
            uint8_t *ctype;
            size_t ctype_len;
            /* Certificate authorities list peer sent */
            STACK_OF(X509_NAME) *peer_ca_names;
            size_t key_block_length;
            unsigned char *key_block;
            const EVP_CIPHER *new_sym_enc;
            const EVP_MD *new_hash;
            int new_mac_pkey_type;
            size_t new_mac_secret_size;
# ifndef OPENSSL_NO_COMP
            const SSL_COMP *new_compression;
# else
            char *new_compression;
# endif
            int cert_request;
            /* Raw values of the cipher list from a client */
            unsigned char *ciphers_raw;
            size_t ciphers_rawlen;
            /* Temporary storage for premaster secret */
            unsigned char *pms;
            size_t pmslen;
# ifndef OPENSSL_NO_PSK
            /* Temporary storage for PSK key */
            unsigned char *psk;
            size_t psklen;
# endif
            /* Signature algorithm we actually use */
            const struct sigalg_lookup_st *sigalg;
            /* Pointer to certificate we use */
            CERT_PKEY *cert;
            /*
             * signature algorithms peer reports: e.g. supported signature
             * algorithms extension for server or as part of a certificate
             * request for client.
             * Keep track of the algorithms for TLS and X.509 usage separately.
             */
            uint16_t *peer_sigalgs;
            uint16_t *peer_cert_sigalgs;
            /* Size of above arrays */
            size_t peer_sigalgslen;
            size_t peer_cert_sigalgslen;
            /* Sigalg peer actually uses */
            const struct sigalg_lookup_st *peer_sigalg;
            /*
             * Set if corresponding CERT_PKEY can be used with current
             * SSL session: e.g. appropriate curve, signature algorithms etc.
             * If zero it can't be used at all.
             */
            uint32_t valid_flags[SSL_PKEY_NUM];
            /*
             * For servers the following masks are for the key and auth algorithms
             * that are supported by the certs below. For clients they are masks of
             * *disabled* algorithms based on the current session.
             */
            uint32_t mask_k;
            uint32_t mask_a;
            /*
             * The following are used by the client to see if a cipher is allowed or
             * not.  It contains the minimum and maximum version the client's using
             * based on what it knows so far.
             */
            int min_ver;
            int max_ver;
        } tmp;

        /* Connection binding to prevent renegotiation attacks */
        unsigned char previous_client_finished[EVP_MAX_MD_SIZE];
        size_t previous_client_finished_len;
        unsigned char previous_server_finished[EVP_MAX_MD_SIZE];
        size_t previous_server_finished_len;
        int send_connection_binding;

# ifndef OPENSSL_NO_NEXTPROTONEG
        /*
         * Set if we saw the Next Protocol Negotiation extension from our peer.
         */
        int npn_seen;
# endif

        /*
         * ALPN information (we are in the process of transitioning from NPN to
         * ALPN.)
         */

        /*
         * In a server these point to the selected ALPN protocol after the
         * ClientHello has been processed. In a client these contain the protocol
         * that the server selected once the ServerHello has been processed.
         */
        unsigned char *alpn_selected;
        size_t alpn_selected_len;
        /* used by the server to know what options were proposed */
        unsigned char *alpn_proposed;
        size_t alpn_proposed_len;
        /* used by the client to know if it actually sent alpn */
        int alpn_sent;

        /*
         * This is set to true if we believe that this is a version of Safari
         * running on OS X 10.6 or newer. We wish to know this because Safari on
         * 10.8 .. 10.8.3 has broken ECDHE-ECDSA support.
         */
        char is_probably_safari;

        /*
         * Track whether we did a key exchange this handshake or not, so
         * SSL_get_negotiated_group() knows whether to fall back to the
         * value in the SSL_SESSION.
         */
        char did_kex;
        /* For clients: peer temporary key */
        /* The group_id for the key exchange key */
        uint16_t group_id;
        EVP_PKEY *peer_tmp;

    } s3;

    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
    /* Per connection DANE state */
    SSL_DANE dane;
    /* crypto */
    STACK_OF(SSL_CIPHER) *peer_ciphers;
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    uint32_t mac_flags;
    /*
     * The TLS1.3 secrets.
     */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char handshake_secret[EVP_MAX_MD_SIZE];
    unsigned char master_secret[EVP_MAX_MD_SIZE];
    unsigned char resumption_master_secret[EVP_MAX_MD_SIZE];
    unsigned char client_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_hash[EVP_MAX_MD_SIZE];
    unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE];
    unsigned char client_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char server_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char exporter_master_secret[EVP_MAX_MD_SIZE];
    unsigned char early_exporter_master_secret[EVP_MAX_MD_SIZE];
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    unsigned char read_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static read IV */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
    COMP_CTX *compress;         /* compression */
    COMP_CTX *expand;           /* uncompress */
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    unsigned char write_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static write IV */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;

    /*
     * The hash of all messages prior to the CertificateVerify, and the length
     * of that hash.
     */
    unsigned char cert_verify_hash[EVP_MAX_MD_SIZE];
    size_t cert_verify_hash_len;

    /* Flag to indicate whether we should send a HelloRetryRequest or not */
    enum {SSL_HRR_NONE = 0, SSL_HRR_PENDING, SSL_HRR_COMPLETE}
        hello_retry_request;

    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* TLSv1.3 PSK session */
    SSL_SESSION *psksession;
    unsigned char *psksession_id;
    size_t psksession_id_len;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /*
     * The temporary TLSv1.3 session id. This isn't really a session id at all
     * but is a random value sent in the legacy session id field.
     */
    unsigned char tmp_session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t tmp_session_id_len;
    /* Used in SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    uint32_t verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

    SSL_CTX *ctx;
    /* Verified chain of peer */
    STACK_OF(X509) *verified_chain;
    long verify_result;
    /* extra application data */
    CRYPTO_EX_DATA ex_data;
    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;
    int references;
    /* protocol behaviour */
    uint64_t options;
    /* API behaviour */
    uint32_t mode;
    int min_proto_version;
    int max_proto_version;
    size_t max_cert_list;
    int first_packet;
    /*
     * What was passed in ClientHello.legacy_version. Used for RSA pre-master
     * secret and SSLv3/TLS (<=1.2) rollback check
     */
    int client_version;
    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    size_t split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    size_t max_send_fragment;
    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    size_t max_pipelines;

    struct {
        /* Built-in extension flags */
        uint8_t extflags[TLSEXT_IDX_num_builtins];
        /* TLS extension debug callback */
        void (*debug_cb)(SSL *s, int client_server, int type,
                         const unsigned char *data, int len, void *arg);
        void *debug_arg;
        char *hostname;
        /* certificate status request info */
        /* Status type or -1 if no status type */
        int status_type;
        /* Raw extension data, if seen */
        unsigned char *scts;
        /* Length of raw extension data, if seen */
        uint16_t scts_len;
        /* Expect OCSP CertificateStatus message */
        int status_expected;

        struct {
            /* OCSP status request only */
            STACK_OF(OCSP_RESPID) *ids;
            X509_EXTENSIONS *exts;
            /* OCSP response received or to be sent */
            unsigned char *resp;
            size_t resp_len;
        } ocsp;

        /* RFC4507 session ticket expected to be received or sent */
        int ticket_expected;
        /* TLS 1.3 tickets requested by the application. */
        int extra_tickets_expected;
        size_t ecpointformats_len;
        /* our list */
        unsigned char *ecpointformats;

        size_t peer_ecpointformats_len;
        /* peer's list */
        unsigned char *peer_ecpointformats;
        size_t supportedgroups_len;
        /* our list */
        uint16_t *supportedgroups;

        size_t peer_supportedgroups_len;
         /* peer's list */
        uint16_t *peer_supportedgroups;

        /* TLS Session Ticket extension override */
        TLS_SESSION_TICKET_EXT *session_ticket;
        /* TLS Session Ticket extension callback */
        tls_session_ticket_ext_cb_fn session_ticket_cb;
        void *session_ticket_cb_arg;
        /* TLS pre-shared secret session resumption */
        tls_session_secret_cb_fn_ex session_secret_cb;
        void *session_secret_cb_arg;
        /*
         * For a client, this contains the list of supported protocols in wire
         * format.
         */
        unsigned char *alpn;
        size_t alpn_len;
        /*
         * Next protocol negotiation. For the client, this is the protocol that
         * we sent in NextProtocol and is set when handling ServerHello
         * extensions. For a server, this is the client's selected_protocol from
         * NextProtocol and is set when handling the NextProtocol message, before
         * the Finished message.
         */
        unsigned char *npn;
        size_t npn_len;

        /* The available PSK key exchange modes */
        int psk_kex_mode;

        /* Set to one if we have negotiated ETM */
        int use_etm;

        /* Are we expecting to receive early data? */
        int early_data;
        /* Is the session suitable for early data? */
        int early_data_ok;

        /* May be sent by a server in HRR. Must be echoed back in ClientHello */
        unsigned char *tls13_cookie;
        size_t tls13_cookie_len;
        /* Have we received a cookie from the client? */
        int cookieok;

        /*
         * Maximum Fragment Length as per RFC 4366.
         * If this member contains one of the allowed values (1-4)
         * then we should include Maximum Fragment Length Negotiation
         * extension in Client Hello.
         * Please note that value of this member does not have direct
         * effect. The actual (binding) value is stored in SSL_SESSION,
         * as this extension is optional on server side.
         */
        uint8_t max_fragment_len_mode;

        /*
         * On the client side the number of ticket identities we sent in the
         * ClientHello. On the server side the identity of the ticket we
         * selected.
         */
        int tick_identity;
    } ext;

    /*
     * Parsed form of the ClientHello, kept around across client_hello_cb
     * calls.
     */
    CLIENTHELLO_MSG *clienthello;

    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
# ifndef OPENSSL_NO_CT
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    /* User-supplied argument that is passed to the ct_validation_callback */
    void *ct_validation_callback_arg;
    /*
     * Consolidated stack of SCTs from all sources.
     * Lazily populated by CT_get_peer_scts(SSL*)
     */
    STACK_OF(SCT) *scts;
    /* Have we attempted to find/parse SCTs yet? */
    int scts_parsed;
# endif
    SSL_CTX *session_ctx;       /* initial ctx, used to store sessions */
# ifndef OPENSSL_NO_SRTP
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
# endif
    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
    /* If sending a KeyUpdate is pending */
    int key_update;
    /* Post-handshake authentication state */
    SSL_PHA_STATE post_handshake_auth;
    int pha_enabled;
    uint8_t* pha_context;
    size_t pha_context_len;
    int certreqs_sent;
    EVP_MD_CTX *pha_dgst; /* this is just the digest through ClientFinished */

# ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
# endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);
    RECORD_LAYER rlayer;
    /* Default password callback. */
    pem_password_cb *default_passwd_callback;
    /* Default password callback user data. */
    void *default_passwd_callback_userdata;
    /* Async Job info */
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    size_t asyncrw;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    uint32_t max_early_data;
    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    uint32_t recv_max_early_data;

    /*
     * The number of bytes of early data received so far. If we accepted early
     * data then this is a count of the plaintext bytes. If we rejected it then
     * this is a count of the ciphertext bytes.
     */
    uint32_t early_data_count;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    CRYPTO_RWLOCK *lock;

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;
    /* The number of TLS1.3 tickets actually sent so far */
    size_t sent_tickets;
    /* The next nonce value to use when we send a ticket on this connection */
    uint64_t next_ticket_nonce;

    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;

    /* Callback for SSL async handling */
    SSL_async_callback_fn async_cb;
    void *async_cb_arg;

    /*
     * Signature algorithms shared by client and server: cached because these
     * are used most often.
     */
    const struct sigalg_lookup_st **shared_sigalgs;
    size_t shared_sigalgslen;
};
#elif defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
struct ssl_st_orig {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    OSSL_STATEM statem;
    SSL_EARLY_DATA_STATE early_data_state;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    size_t init_num;               /* amount read/written */
    size_t init_off;               /* amount read/written */
    struct ssl3_state_st *s3;   /* SSLv3 variables */
    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
    /* Per connection DANE state */
    SSL_DANE dane;
    /* crypto */
#if OPENSSL_VERSION_NUMBER >= 0x1010106fL /* greater or equal to OpenSSL 1.1.1f */
    STACK_OF(SSL_CIPHER) *peer_ciphers;
#endif
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /* TLSv1.3 specific ciphersuites */
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    uint32_t mac_flags;
    /*
     * The TLS1.3 secrets.
     */
    unsigned char early_secret[EVP_MAX_MD_SIZE];
    unsigned char handshake_secret[EVP_MAX_MD_SIZE];
    unsigned char master_secret[EVP_MAX_MD_SIZE];
    unsigned char resumption_master_secret[EVP_MAX_MD_SIZE];
    unsigned char client_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_secret[EVP_MAX_MD_SIZE];
    unsigned char server_finished_hash[EVP_MAX_MD_SIZE];
    unsigned char handshake_traffic_hash[EVP_MAX_MD_SIZE];
    unsigned char client_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char server_app_traffic_secret[EVP_MAX_MD_SIZE];
    unsigned char exporter_master_secret[EVP_MAX_MD_SIZE];
    unsigned char early_exporter_master_secret[EVP_MAX_MD_SIZE];
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    unsigned char read_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static read IV */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
    COMP_CTX *compress;         /* compression */
    COMP_CTX *expand;           /* uncompress */
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    unsigned char write_iv[EVP_MAX_IV_LENGTH]; /* TLSv1.3 static write IV */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;

    /*
     * The hash of all messages prior to the CertificateVerify, and the length
     * of that hash.
     */
    unsigned char cert_verify_hash[EVP_MAX_MD_SIZE];
    size_t cert_verify_hash_len;

    /* Flag to indicate whether we should send a HelloRetryRequest or not */
    enum {SSL_HRR_NONE = 0, SSL_HRR_PENDING, SSL_HRR_COMPLETE}
        hello_retry_request;

    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    size_t sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* TLSv1.3 PSK session */
    SSL_SESSION *psksession;
    unsigned char *psksession_id;
    size_t psksession_id_len;
    /* Default generate session ID callback. */
    GEN_SESSION_CB generate_session_id;
    /*
     * The temporary TLSv1.3 session id. This isn't really a session id at all
     * but is a random value sent in the legacy session id field.
     */
    unsigned char tmp_session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
    size_t tmp_session_id_len;
    /* Used in SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    uint32_t verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
# ifndef OPENSSL_NO_PSK
    SSL_psk_client_cb_func psk_client_callback;
    SSL_psk_server_cb_func psk_server_callback;
# endif
    SSL_psk_find_session_cb_func psk_find_session_cb;
    SSL_psk_use_session_cb_func psk_use_session_cb;

    SSL_CTX *ctx;
    /* Verified chain of peer */
    STACK_OF(X509) *verified_chain;
    long verify_result;
    /* extra application data */
    CRYPTO_EX_DATA ex_data;
    /*
     * What we put in certificate_authorities extension for TLS 1.3
     * (ClientHello and CertificateRequest) or just client cert requests for
     * earlier versions. If client_ca_names is populated then it is only used
     * for client cert requests, and in preference to ca_names.
     */
    STACK_OF(X509_NAME) *ca_names;
    STACK_OF(X509_NAME) *client_ca_names;
    CRYPTO_REF_COUNT references;
    /* protocol behaviour */
    uint32_t options;
    /* API behaviour */
    uint32_t mode;
    int min_proto_version;
    int max_proto_version;
    size_t max_cert_list;
    int first_packet;
    /*
     * What was passed in ClientHello.legacy_version. Used for RSA pre-master
     * secret and SSLv3/TLS (<=1.2) rollback check
     */
    int client_version;
    /*
     * If we're using more than one pipeline how should we divide the data
     * up between the pipes?
     */
    size_t split_send_fragment;
    /*
     * Maximum amount of data to send in one fragment. actual record size can
     * be more than this due to padding and MAC overheads.
     */
    size_t max_send_fragment;
    /* Up to how many pipelines should we use? If 0 then 1 is assumed */
    size_t max_pipelines;

    struct {
        /* Built-in extension flags */
        uint8_t extflags[TLSEXT_IDX_num_builtins];
        /* TLS extension debug callback */
        void (*debug_cb)(SSL *s, int client_server, int type,
                         const unsigned char *data, int len, void *arg);
        void *debug_arg;
        char *hostname;
        /* certificate status request info */
        /* Status type or -1 if no status type */
        int status_type;
        /* Raw extension data, if seen */
        unsigned char *scts;
        /* Length of raw extension data, if seen */
        uint16_t scts_len;
        /* Expect OCSP CertificateStatus message */
        int status_expected;

        struct {
            /* OCSP status request only */
            STACK_OF(OCSP_RESPID) *ids;
            X509_EXTENSIONS *exts;
            /* OCSP response received or to be sent */
            unsigned char *resp;
            size_t resp_len;
        } ocsp;

        /* RFC4507 session ticket expected to be received or sent */
        int ticket_expected;
# ifndef OPENSSL_NO_EC
        size_t ecpointformats_len;
        /* our list */
        unsigned char *ecpointformats;
#if OPENSSL_VERSION_NUMBER >= 0x1010106fL /* greater or equal to OpenSSL 1.1.1f */
        size_t peer_ecpointformats_len;
        /* peer's list */
        unsigned char *peer_ecpointformats;
#endif
# endif                         /* OPENSSL_NO_EC */
        size_t supportedgroups_len;
        /* our list */
        uint16_t *supportedgroups;
#if OPENSSL_VERSION_NUMBER >= 0x1010106fL /* greater or equal to OpenSSL 1.1.1f */
        size_t peer_supportedgroups_len;
         /* peer's list */
        uint16_t *peer_supportedgroups;
#endif
        /* TLS Session Ticket extension override */
        TLS_SESSION_TICKET_EXT *session_ticket;
        /* TLS Session Ticket extension callback */
        tls_session_ticket_ext_cb_fn session_ticket_cb;
        void *session_ticket_cb_arg;
        /* TLS pre-shared secret session resumption */
        tls_session_secret_cb_fn session_secret_cb;
        void *session_secret_cb_arg;
        /*
         * For a client, this contains the list of supported protocols in wire
         * format.
         */
        unsigned char *alpn;
        size_t alpn_len;
        /*
         * Next protocol negotiation. For the client, this is the protocol that
         * we sent in NextProtocol and is set when handling ServerHello
         * extensions. For a server, this is the client's selected_protocol from
         * NextProtocol and is set when handling the NextProtocol message, before
         * the Finished message.
         */
        unsigned char *npn;
        size_t npn_len;

        /* The available PSK key exchange modes */
        int psk_kex_mode;

        /* Set to one if we have negotiated ETM */
        int use_etm;

        /* Are we expecting to receive early data? */
        int early_data;
        /* Is the session suitable for early data? */
        int early_data_ok;

        /* May be sent by a server in HRR. Must be echoed back in ClientHello */
        unsigned char *tls13_cookie;
        size_t tls13_cookie_len;
        /* Have we received a cookie from the client? */
        int cookieok;

        /*
         * Maximum Fragment Length as per RFC 4366.
         * If this member contains one of the allowed values (1-4)
         * then we should include Maximum Fragment Length Negotiation
         * extension in Client Hello.
         * Please note that value of this member does not have direct
         * effect. The actual (binding) value is stored in SSL_SESSION,
         * as this extension is optional on server side.
         */
        uint8_t max_fragment_len_mode;

        /*
         * On the client side the number of ticket identities we sent in the
         * ClientHello. On the server side the identity of the ticket we
         * selected.
         */
        int tick_identity;
    } ext;

    /*
     * Parsed form of the ClientHello, kept around across client_hello_cb
     * calls.
     */
    CLIENTHELLO_MSG *clienthello;

    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
# ifndef OPENSSL_NO_CT
    /*
     * Validates that the SCTs (Signed Certificate Timestamps) are sufficient.
     * If they are not, the connection should be aborted.
     */
    ssl_ct_validation_cb ct_validation_callback;
    /* User-supplied argument that is passed to the ct_validation_callback */
    void *ct_validation_callback_arg;
    /*
     * Consolidated stack of SCTs from all sources.
     * Lazily populated by CT_get_peer_scts(SSL*)
     */
    STACK_OF(SCT) *scts;
    /* Have we attempted to find/parse SCTs yet? */
    int scts_parsed;
# endif
    SSL_CTX *session_ctx;       /* initial ctx, used to store sessions */
# ifndef OPENSSL_NO_SRTP
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
# endif
    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
    /* If sending a KeyUpdate is pending */
    int key_update;
    /* Post-handshake authentication state */
    SSL_PHA_STATE post_handshake_auth;
    int pha_enabled;
    uint8_t* pha_context;
    size_t pha_context_len;
    int certreqs_sent;
    EVP_MD_CTX *pha_dgst; /* this is just the digest through ClientFinished */

# ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
# endif
    /*
     * Callback for disabling session caching and ticket support on a session
     * basis, depending on the chosen cipher.
     */
    int (*not_resumable_session_cb) (SSL *ssl, int is_forward_secure);
    RECORD_LAYER rlayer;
    /* Default password callback. */
    pem_password_cb *default_passwd_callback;
    /* Default password callback user data. */
    void *default_passwd_callback_userdata;
    /* Async Job info */
    ASYNC_JOB *job;
    ASYNC_WAIT_CTX *waitctx;
    size_t asyncrw;

    /*
     * The maximum number of bytes advertised in session tickets that can be
     * sent as early data.
     */
    uint32_t max_early_data;
    /*
     * The maximum number of bytes of early data that a server will tolerate
     * (which should be at least as much as max_early_data).
     */
    uint32_t recv_max_early_data;

    /*
     * The number of bytes of early data received so far. If we accepted early
     * data then this is a count of the plaintext bytes. If we rejected it then
     * this is a count of the ciphertext bytes.
     */
    uint32_t early_data_count;

    /* TLS1.3 padding callback */
    size_t (*record_padding_cb)(SSL *s, int type, size_t len, void *arg);
    void *record_padding_arg;
    size_t block_padding;

    CRYPTO_RWLOCK *lock;
#if OPENSSL_VERSION_NUMBER == 0x1010103fL /* OpenSSL 1.1.1c only */
    RAND_DRBG *drbg;
#endif

    /* The number of TLS1.3 tickets to automatically send */
    size_t num_tickets;
    /* The number of TLS1.3 tickets actually sent so far */
    size_t sent_tickets;
    /* The next nonce value to use when we send a ticket on this connection */
    uint64_t next_ticket_nonce;

    /* Callback to determine if early_data is acceptable or not */
    SSL_allow_early_data_cb_fn allow_early_data_cb;
    void *allow_early_data_cb_data;
#if OPENSSL_VERSION_NUMBER >= 0x1010106fL /* greater or equal to OpenSSL 1.1.1f */
    /*
     * Signature algorithms shared by client and server: cached because these
     * are used most often.
     */
    const struct sigalg_lookup_st **shared_sigalgs;
    size_t shared_sigalgslen;
#endif
};
#else
struct ssl_st_orig {
    /*
     * protocol version (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
     * DTLS1_VERSION)
     */
    int version;
    /* SSL_ST_CONNECT or SSL_ST_ACCEPT */
    int type;
    /* SSLv3 */
    const SSL_METHOD *method;
    /*
     * There are 2 BIO's even though they are normally both the same.  This
     * is so data can be read and written to different handlers
     */
#  ifndef OPENSSL_NO_BIO
    /* used by SSL_read */
    BIO *rbio;
    /* used by SSL_write */
    BIO *wbio;
    /* used during session-id reuse to concatenate messages */
    BIO *bbio;
#  else
    /* used by SSL_read */
    char *rbio;
    /* used by SSL_write */
    char *wbio;
    char *bbio;
#  endif
    /*
     * This holds a variable that indicates what we were doing when a 0 or -1
     * is returned.  This is needed for non-blocking IO so we know what
     * request needs re-doing when in SSL_accept or SSL_connect
     */
    int rwstate;
    /* true when we are actually in SSL_accept() or SSL_connect() */
    int in_handshake;
    int (*handshake_func) (SSL *);
    /*
     * Imagine that here's a boolean member "init" that is switched as soon
     * as SSL_set_{accept/connect}_state is called for the first time, so
     * that "state" and "handshake_func" are properly initialized.  But as
     * handshake_func is == 0 until then, we use this test instead of an
     * "init" member.
     */
    /* are we the server side? - mostly used by SSL_clear */
    int server;
    /*
     * Generate a new session or reuse an old one.
     * NB: For servers, the 'new' session may actually be a previously
     * cached session or even the previous session unless
     * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set
     */
    int new_session;
    /* don't send shutdown packets */
    int quiet_shutdown;
    /* we have shut things down, 0x01 sent, 0x02 for received */
    int shutdown;
    /* where we are */
    int state;
    /* where we are when reading */
    int rstate;
    BUF_MEM *init_buf;          /* buffer used during init */
    void *init_msg;             /* pointer to handshake message body, set by
                                 * ssl3_get_message() */
    int init_num;               /* amount read/written */
    int init_off;               /* amount read/written */
    /* used internally to point at a raw packet */
    unsigned char *packet;
    unsigned int packet_length;
    struct ssl2_state_st *s2;   /* SSLv2 variables */
    struct ssl3_state_st *s3;   /* SSLv3 variables */
    struct dtls1_state_st *d1;  /* DTLSv1 variables */
    int read_ahead;             /* Read as many input bytes as possible (for
                                 * non-blocking reads) */
    /* callback that allows applications to peek at protocol messages */
    void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
    void *msg_callback_arg;
    int hit;                    /* reusing a previous session */
    X509_VERIFY_PARAM *param;
#  if 0
    int purpose;                /* Purpose setting */
    int trust;                  /* Trust setting */
#  endif
    /* crypto */
    STACK_OF(SSL_CIPHER) *cipher_list;
    STACK_OF(SSL_CIPHER) *cipher_list_by_id;
    /*
     * These are the ones being used, the ones in SSL_SESSION are the ones to
     * be 'copied' into these ones
     */
    int mac_flags;
    EVP_CIPHER_CTX *enc_read_ctx; /* cryptographic state */
    EVP_MD_CTX *read_hash;      /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
    COMP_CTX *expand;           /* uncompress */
#  else
    char *expand;
#  endif
    EVP_CIPHER_CTX *enc_write_ctx; /* cryptographic state */
    EVP_MD_CTX *write_hash;     /* used for mac generation */
#  ifndef OPENSSL_NO_COMP
    COMP_CTX *compress;         /* compression */
#  else
    char *compress;
#  endif
    /* session info */
    /* client cert? */
    /* This is used to hold the server certificate used */
    struct cert_st /* CERT */ *cert;
    /*
     * the session_id_context is used to ensure sessions are only reused in
     * the appropriate context
     */
    unsigned int sid_ctx_length;
    unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
    /* This can also be in the session once a session is established */
    SSL_SESSION *session;
    /* Default generate session ID callback. */
    m_GEN_SESSION_CB generate_session_id;
    /* Used in SSL2 and SSL3 */
    /*
     * 0 don't care about verify failure.
     * 1 fail if verify fails
     */
    int verify_mode;
    /* fail if callback returns 0 */
    int (*verify_callback) (int ok, X509_STORE_CTX *ctx);
    /* optional informational callback */
    void (*info_callback) (const SSL *ssl, int type, int val);
    /* error bytes to be written */
    int error;
    /* actual code */
    int error_code;
#if !defined(__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__)
#  ifndef OPENSSL_NO_KRB5
    /* Kerberos 5 context */
    KSSL_CTX *kssl_ctx;
#  endif                        /* OPENSSL_NO_KRB5 */
#endif
#  ifndef OPENSSL_NO_PSK
    unsigned int (*psk_client_callback) (SSL *ssl, const char *hint,
                                         char *identity,
                                         unsigned int max_identity_len,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
    unsigned int (*psk_server_callback) (SSL *ssl, const char *identity,
                                         unsigned char *psk,
                                         unsigned int max_psk_len);
#  endif
    SSL_CTX *ctx;
    /*
     * set this flag to 1 and a sleep(1) is put into all SSL_read() and
     * SSL_write() calls, good for nbio debuging :-)
     */
    int debug;
    /* extra application data */
    long verify_result;
    CRYPTO_EX_DATA ex_data;
    /* for server side, keep the list of CA_dn we can use */
    STACK_OF(X509_NAME) *client_CA;
    int references;
    /* protocol behaviour */
    unsigned long options;
    /* API behaviour */
    unsigned long mode;
    long max_cert_list;
    int first_packet;
    /* what was passed, used for SSLv3/TLS rollback check */
    int client_version;
    unsigned int max_send_fragment;
#  ifndef OPENSSL_NO_TLSEXT
    /* TLS extension debug callback */
    void (*tlsext_debug_cb) (SSL *s, int client_server, int type,
                             unsigned char *data, int len, void *arg);
    void *tlsext_debug_arg;
    char *tlsext_hostname;
    /*-
     * no further mod of servername
     * 0 : call the servername extension callback.
     * 1 : prepare 2, allow last ack just after in server callback.
     * 2 : don't call servername callback, no ack in server hello
     */
    int servername_done;
    /* certificate status request info */
    /* Status type or -1 if no status type */
    int tlsext_status_type;
    /* Expect OCSP CertificateStatus message */
    int tlsext_status_expected;
    /* OCSP status request only */
    STACK_OF(OCSP_RESPID) *tlsext_ocsp_ids;
    X509_EXTENSIONS *tlsext_ocsp_exts;
    /* OCSP response received or to be sent */
    unsigned char *tlsext_ocsp_resp;
    int tlsext_ocsp_resplen;
    /* RFC4507 session ticket expected to be received or sent */
    int tlsext_ticket_expected;
#   ifndef OPENSSL_NO_EC
    size_t tlsext_ecpointformatlist_length;
    /* our list */
    unsigned char *tlsext_ecpointformatlist;
    size_t tlsext_ellipticcurvelist_length;
    /* our list */
    unsigned char *tlsext_ellipticcurvelist;
#   endif                       /* OPENSSL_NO_EC */
    /*
     * draft-rescorla-tls-opaque-prf-input-00.txt information to be used for
     * handshakes
     */
    void *tlsext_opaque_prf_input;
    size_t tlsext_opaque_prf_input_len;
    /* TLS Session Ticket extension override */
    TLS_SESSION_TICKET_EXT *tlsext_session_ticket;
    /* TLS Session Ticket extension callback */
    m_tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
    void *tls_session_ticket_ext_cb_arg;
    /* TLS pre-shared secret session resumption */
    m_tls_session_secret_cb_fn tls_session_secret_cb;
    void *tls_session_secret_cb_arg;
    SSL_CTX *initial_ctx;       /* initial ctx, used to store sessions */
#   ifndef OPENSSL_NO_NEXTPROTONEG
    /*
     * Next protocol negotiation. For the client, this is the protocol that
     * we sent in NextProtocol and is set when handling ServerHello
     * extensions. For a server, this is the client's selected_protocol from
     * NextProtocol and is set when handling the NextProtocol message, before
     * the Finished message.
     */
    unsigned char *next_proto_negotiated;
    unsigned char next_proto_negotiated_len;
#   endif
#   define session_ctx initial_ctx
    /* What we'll do */
    STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
    /* What's been chosen */
    SRTP_PROTECTION_PROFILE *srtp_profile;
        /*-
         * Is use of the Heartbeat extension negotiated?
         * 0: disabled
         * 1: enabled
         * 2: enabled, but not allowed to send Requests
         */
    unsigned int tlsext_heartbeat;
    /* Indicates if a HeartbeatRequest is in flight */
    unsigned int tlsext_hb_pending;
    /* HeartbeatRequest sequence number */
    unsigned int tlsext_hb_seq;
#  else
#   define session_ctx ctx
#  endif                        /* OPENSSL_NO_TLSEXT */
    /*-
     * 1 if we are renegotiating.
     * 2 if we are a server and are inside a handshake
     * (i.e. not just sending a HelloRequest)
     */
    int renegotiate;
#  ifndef OPENSSL_NO_SRP
    /* ctx for SRP authentication */
    SRP_CTX srp_ctx;
#  endif
#  ifndef OPENSSL_NO_TLSEXT
    /*
     * For a client, this contains the list of supported protocols in wire
     * format.
     */
    unsigned char *alpn_client_proto_list;
    unsigned alpn_client_proto_list_len;
#  endif                        /* OPENSSL_NO_TLSEXT */
};
#endif /* __ENABLE_DIGICERT_OPENSSL_LIB_3_0__ */
/* End of OpenSSL ssl_st structure */

struct ssl_st {
     struct ssl_st_orig orig_s;
     SSL_CTX  * ssl_ctx;
     BIO      * rbio;
     /* used by SSL_write */
     BIO      * wbio;
     /* used during session-id reuse to concatenate messages */
     BIO      * bbio;
     /* see comment in SSL_CTX */
     STACK_OF(X509_NAME) *client_CA;
     int 	version;
     const SSL_METHOD *method;
     int (*handshake_func) (SSL *);
     sbyte4 	tempSocket;
     SSL_SESSION* session;
     unsigned int sid_ctx_length;
     unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
     sbyte4 	instance;
     ubyte2     appId;
     int        fd;
     int        rfd;
     int        wfd;
     int 	clientServerFlag;
     long 	verify_result;
     int    registerRetrievePSK;     
     void (*info_callback) (const SSL *ssl, int type, int val);
     CRYPTO_EX_DATA 	 ex_data;
     ubyte    * pHoldingBuf;
     sbyte4	szHoldingBuf;
     sbyte4 bytesSentRemaining; /* BIO_write could result in partial write */
     sbyte4 applBytesEncoded; /* Number of bytes encrypted/consumed by SSL_write */
     sbyte4 txHoldingBufOffset; /* offset in the send buffer */
     ubyte    * pTxHoldingBuf;
     sbyte4	szTxHoldingBuf;
     sbyte4	bytesRcvdRemaining;
     ubyte    * pFirstRcvdUnreadByte;
     ubyte    * pRxDataBuf;
     sbyte4	rxDataBufSz;	/* size of above buf */
     ubyte4	rxDataBufOffset;/* offset of next un-read byte */
     ubyte4	rxDataBufLen;	/* bytes remaining to be read */
     unsigned long state;
     unsigned long options;
     unsigned long io_state; /* Needed to emulate SSL_get_error() */
     unsigned int sent_client_hello;
     struct ssl3_state_st *s3;   /* SSLv3 variables */

    int hello_verify_done; /* set to 1 if cookie is verified in dtls connection */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
     /* ext status type used for CSR extension (OCSP Stapling) */
     int tlsext_status_type;

    int orig_state;
    /* OCSP response received or to be sent */
    unsigned char *tlsext_ocsp_resp;
    int tlsext_ocsp_resplen;
#endif

    /* X509_STORE for certificate validation, stored
     * to hold reference only */
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    X509_STORE *verify_store;
#endif
     char *tlsext_hostname;
     COMP_CTX *compress;
     unsigned char *alpn_client_proto_list;
     unsigned alpn_client_proto_list_len;
     ubyte*   mocAlpnList;
     unsigned char *next_proto_negotiated;
     unsigned char next_proto_negotiated_len;
     STACK_OF(SSL_CIPHER) *cipher_list;
     STACK_OF(SSL_CIPHER) *cipher_list_by_id;
     ubyte2	cipherIds[MAX_NUM_CIPHER_IDS];
     ubyte4 numCipherIds;
     ubyte2 srtpProfileIds[MAX_NUM_SRTP_PROFILE_IDS];
     ubyte4 numSrtpProfileIds;
     ubyte2 selectedSrtpId;
     ubyte2 *pEccCurves;
     ubyte4 numEccCurves;
     ubyte *pPendingBuffer;
     X509     *pClientCert;
     EVP_PKEY *pClientPrivateKey;
     void (*msg_callback) (int write_p, int version, int content_type,
                          const void *buf, size_t len, SSL *ssl, void *arg);
     void *msg_callback_arg;
#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_3_0__)
    ClientHelloDataPtr client_hello_data;
     /*
      * Callback for logging key material for use with debugging tools like
      * Wireshark. The callback should log `line` followed by a newline.
      */
     SSL_CTX_keylog_cb_func keylog_callback;
     /* TLSv1.3 specific ciphersuites */
     STACK_OF(SSL_CIPHER) *tls13_ciphersuites;
     /* Verified chain of peer */
     STACK_OF(X509) *verified_chain;
#endif
#if defined(__ENABLE_DIGICERT_OSSL_CLIENT_THREAD_SAFE__)
     void     * session_mutex;
#endif
};


/* Original structure from OpenSSL.
 */
typedef struct {
    const char *name;
    int namelen;
    unsigned int name_flags;
    unsigned long option_value;
} ssl_flag_tbl;

/* Original structure from OpenSSL.
 */
struct ssl_conf_ctx_st {
    /*
     * Various flags indicating (among other things) which options we will
     * recognise.
     */
    unsigned int flags;
    /* Prefix and length of commands */
    char *prefix;
    size_t prefixlen;
    /* SSL_CTX or SSL structure to perform operations on */
    SSL_CTX *ctx;
    SSL *ssl;
    /* Pointer to SSL or SSL_CTX options field or NULL if none */
    unsigned long *poptions;
    /* Pointer to SSL or SSL_CTX cert_flags or NULL if none */
    unsigned int *pcert_flags;
    /* Current flag table being worked on */
    const ssl_flag_tbl *tbl;
    /* Size of table */
    size_t ntbl;
};

#if defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_0__) || defined (__ENABLE_DIGICERT_OPENSSL_LIB_1_1_1C__)
struct ossl_init_settings_st {
    char *filename;
    char *appname;
    unsigned long flags;
};

typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;

#endif
#endif /* OSSL_TYPES_HEADER */
