/*
 * sslsock.h
 *
 * SSL implementation
 *
 * Copyright Mocana Corp 2003-2007. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SSLSOCK_H__
#define __SSLSOCK_H__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_MOCANA_SSL_DUAL_MODE_API__)
#define IS_SSL_ASYNC(X)         ((X)->internalFlags & SSL_INT_FLAG_ASYNC_MODE)
#define IS_SSL_SYNC(X)          ((X)->internalFlags & SSL_INT_FLAG_SYNC_MODE)

#elif defined(__ENABLE_MOCANA_SSL_ASYNC_SERVER_API__) || defined(__ENABLE_MOCANA_SSL_ASYNC_CLIENT_API__)
#define IS_SSL_ASYNC(X)         (1)
#define IS_SSL_SYNC(X)          (0)

#else
#define IS_SSL_ASYNC(X)         (0)
#define IS_SSL_SYNC(X)          (1)
#endif

#define CONNECT_DISABLED        0
#define CONNECT_CLOSED          1
#define CONNECT_NEGOTIATE       2
#define CONNECT_OPEN            3

#define MAX_OCSP_TRUSTED_RESPONDERS 5

/* Post Handshake message mask */
#define NEW_SESSION_TICKET      0
#define CERTIFICATE_REQUEST     1
#define KEY_UPDATE              2

#define TICKET_LIFETIME_ONE_WEEK  604800
#define TICKET_LIFETIME_TWO_HOURS 7200
#define TICKET_RESEND_TIME_30_SECONDS 30 /* If the ticket is expiring in 30s, send a new session ticket */
#define KEY_UPDATE_REQUEST_TIMEOUT 15000 /* 15 seconds */

#ifdef __ENABLE_MOCANA_OPENSSL_SHIM__
#include "../openssl_wrapper/openssl_shim.h"
#endif

#ifdef __ENABLE_MOCANA_MBEDTLS_SHIM__
#include "../mbedtls_wrapper/mbedtls_shim.h"
#endif

/*------------------------------------------------------------------*/

enum sslAsyncStates
{
    SSL_ASYNC_RECEIVE_RECORD_1,
    SSL_ASYNC_RECEIVE_RECORD_2,
    SSL_ASYNC_RECEIVE_RECORD_COMPLETED
};

enum sslHandshakeStates
{
    kSslReceiveHelloInitState0, /* used by DTLS for sending server HelloVerifyRequest */
    kSslReceiveHelloInitState,
    kSslReceiveHelloState,
    kSslReceiveHelloState1,
    kSslReceiveHelloState2,
    kSslReceiveUntil,
    kSslReceiveUntil1,
    kSslReceiveUntil2,
    kSslReceiveUntil3,
    kSslReceiveUntilResume,
    kSslReceiveUntilResume1,
    kSslReceiveUntilResume2,
    kSslReceiveUntilResume3,
    kSslOpenState
};

enum sslOpenStates
{
    kSslSecureSessionNotEstablished = 0,
    kSslSecureSessionJustEstablished,
    kSslSecureSessionEstablished
};

enum sslSyncRecordStates
{
    kRecordStateReceiveFrameWait = 0,
    kRecordStateReceiveFrameComplete
};

enum sslASN1EncodeTypes
{
    sslASN1EncodePSK = 1,
    sslASN1EncodeTicket
};

#define SSL_RANDOMSIZE                  (32)
#define SSL_RSAPRESECRETSIZE            (48)

#define SSL_MAXMACSECRETSIZE            (SHA384_RESULT_SIZE)
#define SSL_MAXKEYSIZE                  (32)
#define SSL_MAXIVSIZE                   (20)   /* FORTEZZA */

#define SSL_HELLO_COOKIE_MAX_SIZE       (255)

#ifdef __ENABLE_MOCANA_EAP_FAST__
#define PACKEY_SIZE                     (32)
#define SKS_SIZE                        (40)
#define FAST_MSCHAP_CHAL_SIZE           (32)
#define SSL_MAXMATERIALS                (2 * (SSL_MAXMACSECRETSIZE + SSL_MAXKEYSIZE) + SKS_SIZE + FAST_MSCHAP_CHAL_SIZE)
#else
#define SSL_MAXMATERIALS                (2 * (SSL_MAXMACSECRETSIZE + SSL_MAXKEYSIZE + SSL_MAXIVSIZE))
#endif

#ifdef __ENABLE_MOCANA_INNER_APP__
#define SSL_INNER_SECRET_SIZE           (48)
#endif

#define SSL_MAXROUNDS                   (1 + (SSL_MAXMATERIALS / MD5_DIGESTSIZE ))
/*    key material size  this is the maximum space occupied for the
    encryption material, it includes 2 write MAC secrets  */

#define SSL_SHA1_PADDINGSIZE            (40)
#define SSL_MD5_PADDINGSIZE             (48)
#define SSL_MAX_PADDINGSIZE             (SSL_MD5_PADDINGSIZE)
#define SSL_FINISHEDSIZE                (SHA_HASH_RESULT_SIZE + MD5_DIGESTSIZE)
#define SSL_MAXDIGESTSIZE               (SHA384_RESULT_SIZE)
#define MAX_EXTENSIONS_SENT             (15)
#define CERTIFICATE_REQ_CONTEXT_LEN (32)

/*
 *  o  "client_verify_data": The verify_data from the finished message sent by
 *     the client on the immediately previous handshake. For currently defined
 *     TLS versions and cipher suites, this will be a 36-byte value for SSLv3,
 *     12 bytes for anything from TLSv1 to TLSv1_2, and variable length for
 *     TLSv1_3.
 *
 *  o  "server_verify_data": The verify_data from the finished message
 *     sent by the server on the immediately previous handshake.
 */
#define SSL_VERIFY_DATA                 (SSL_FINISHEDSIZE)
#define SSL_VERIFY_DATA_MAX             (64)

#define SSL_RX_RECORD_STATE(X)          (X)->asyncState
#define SSL_RX_RECORD_BUFFER(X)         (X)->pAsyncBuffer
#define SSL_RX_RECORD_BYTES_READ(X)     (X)->asyncBytesRead
#define SSL_RX_RECORD_BYTES_REQUIRED(X) (X)->asyncBytesRequired
#define SSL_RX_RECORD_STATE_INIT(X)     (X)->asyncStateInit

#define SSL_SYNC_RECORD_STATE(X)        (X)->recordState

#define SSL_HANDSHAKE_STATE(X)          (X)->sslHandshakeState
#define SSL_REMOTE_HANDSHAKE_STATE(X)   (X)->theirHandshakeState

#define SSL_OPEN_STATE(X)               (X)->openState

#define SSL_TIMER_START_TIME(X)         (X)->timerStartTime
#define SSL_TIMER_MS_EXPIRE(X)          (X)->timerMsExpire

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
#define DTLS_TIMER_STATE(X)             (X)->dtlsTimerState
#define DTLS_PEEREPOCH(X)               ((X)->peerSeqnumHigh >> 16)
#define DTLS_OWNEPOCH(X)                ((X)->ownSeqnumHigh >> 16)
#endif

#if defined(__ENABLE_MOCANA_TLS13__)
#if defined(__ENABLE_MOCANA_SSL_SERVER__)
/* Supported Groups Extension */
#define TLS13_SET_SUPPORTED_GROUPS_EXT_RX(X)    MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 1, 0)
#define TLS13_GET_SUPPORTED_GROUPS_EXT_RX(X)    MOC_BIT_GET((X)->roleSpecificInfo.server.receivedExtensions, 0)

/* Key Share Extension */
#define TLS13_SET_KEY_SHARE_EXT_RX(X)           MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 1, 1)
#define TLS13_GET_KEY_SHARE_EXT_RX(X)           MOC_BIT_GET((X)->roleSpecificInfo.server.receivedExtensions, 1)

/* Pre-Shared Key */
#define TLS13_SET_PRE_SHARED_KEY_EXT_RX(X)      MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 1, 2)
#define TLS13_RESET_PRE_SHARED_KEY_EXT_RX(X)    MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 0, 2)
#define TLS13_GET_PRE_SHARED_KEY_EXT_RX(X)      MOC_BIT_GET((X)->roleSpecificInfo.server.receivedExtensions, 2)

/* Signature Algo */
#define TLS13_SET_SIGNATURE_ALGO_EXT_RX(X)      MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 1, 3)
#define TLS13_GET_SIGNATURE_ALGO_EXT_RX(X)      MOC_BIT_GET((X)->roleSpecificInfo.server.receivedExtensions, 3)

/* Signature Algo Certificate */
#define TLS13_SET_SIGNATURE_ALGO_CERT_EXT_RX(X) MOC_BIT_SET((X)->roleSpecificInfo.server.receivedExtensions, 1, 4)
#define TLS13_GET_SIGNATURE_ALGO_CERT_EXT_RX(X) MOC_BIT_GET((X)->roleSpecificInfo.server.receivedExtensions, 4)

#if defined(__ENABLE_MOCANA_TLS13_0RTT__)
#define TLS13_0RTT_SET_EARLY_DATA_RX(X)         MOC_BIT_SET((X)->roleSpecificInfo.server.zeroRTT, 1, 0)
#define TLS13_0RTT_GET_EARLY_DATA_RX(X)         MOC_BIT_GET((X)->roleSpecificInfo.server.zeroRTT, 0)

#define TLS13_0RTT_SET_END_OF_EARLY_DATA_RX(X)  MOC_BIT_SET((X)->roleSpecificInfo.server.zeroRTT, 1, 1)
#define TLS13_0RTT_GET_END_OF_EARLY_DATA_RX(X)  MOC_BIT_GET((X)->roleSpecificInfo.server.zeroRTT, 1)

/* 0RTT failed; fallback to using PSK or Certificate */
#define TLS13_0RTT_SET_FALLBACK(X)              MOC_BIT_SET((X)->roleSpecificInfo.server.zeroRTT, 1, 2)
#define TLS13_0RTT_RESET_FALLBACK(X)            MOC_BIT_SET((X)->roleSpecificInfo.server.zeroRTT, 0, 2)
#define TLS13_0RTT_GET_FALLBACK(X)              MOC_BIT_GET((X)->roleSpecificInfo.server.zeroRTT, 2)
#endif /* __ENABLE_MOCANA_TLS13_0RTT__ */
#endif /* __ENABLE_MOCANA_SSL_SERVER__ */

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
/* Received a HRR */
#define TLS13_HRR_SET_RX(X)                     MOC_BIT_SET((X)->roleSpecificInfo.client.hrr, 1, 0)
#define TLS13_HRR_RESET_RX(X)                   MOC_BIT_SET((X)->roleSpecificInfo.client.hrr, 0, 0)
#define TLS13_HRR_GET_RX(X)                     MOC_BIT_GET((X)->roleSpecificInfo.client.hrr, 0)

/* Client Hello in response to HRR sent */
#define TLS13_HRR_SET_REPLY_TX(X)               MOC_BIT_SET((X)->roleSpecificInfo.client.hrr, 1, 1)
#define TLS13_HRR_GET_REPLY_TX(X)               MOC_BIT_GET((X)->roleSpecificInfo.client.hrr, 1)

/* Processed Server Hello after responding to HRR */
#define TLS13_HRR_SET_SERVER_HELLO_RX(X)        MOC_BIT_SET((X)->roleSpecificInfo.client.hrr, 1, 2)
#define TLS13_HRR_GET_SERVER_HELLO_RX(X)        MOC_BIT_GET((X)->roleSpecificInfo.client.hrr, 2)

/* Client sent key share extension */
#define TLS13_CLIENT_SET_KEY_SHARE_TX(X)        MOC_BIT_SET((X)->roleSpecificInfo.client.extensions, 1, 0)
#define TLS13_CLIENT_GET_KEY_SHARE_TX(X)        MOC_BIT_GET((X)->roleSpecificInfo.client.extensions, 0)

/* Client received key share extension */
#define TLS13_CLIENT_SET_KEY_SHARE_RX(X)        MOC_BIT_SET((X)->roleSpecificInfo.client.extensions, 1, 1)
#define TLS13_CLIENT_GET_KEY_SHARE_RX(X)        MOC_BIT_GET((X)->roleSpecificInfo.client.extensions, 1)

#define TLS13_CLIENT_SET_PSK_RX(X)              MOC_BIT_SET((X)->roleSpecificInfo.client.extensions, 1, 2)
#define TLS13_CLIENT_GET_PSK_RX(X)              MOC_BIT_GET((X)->roleSpecificInfo.client.extensions, 2)

#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
#endif /*  __ENABLE_MOCANA_TLS13__*/

#define SSL_KEYEX_RSA_BIT               (0x001)
#define SSL_KEYEX_DHE_BIT               (0x002)
#define SSL_KEYEX_ECDH_BIT              (0x004)
#define SSL_KEYEX_ECDHE_BIT             (0x008)

#define SSL_AUTH_RSA_BIT                (0x010)
#define SSL_AUTH_ANON_BIT               (0x020)
#define SSL_AUTH_ECDSA_BIT              (0x040)
#define SSL_AUTH_DSA_BIT                (0x080)

#define SSL_PSK_BIT                     (0x100)
#define SSL_SRP_BIT                     (0x200)
#define SSL_NO_MUTUAL_AUTH_BIT          (0x400)
#define SSL_HYBRID_BIT                  (0x800)

#define SSL_RSA                         (SSL_KEYEX_RSA_BIT  | SSL_AUTH_RSA_BIT )
#define SSL_ECDH_RSA                    (SSL_KEYEX_ECDH_BIT | SSL_AUTH_RSA_BIT)
#define SSL_ECDH_ECDSA                  (SSL_KEYEX_ECDH_BIT | SSL_AUTH_ECDSA_BIT)
#define SSL_ECDHE_RSA                   (SSL_KEYEX_ECDHE_BIT| SSL_AUTH_RSA_BIT)
#define SSL_ECDHE_ECDSA                 (SSL_KEYEX_ECDHE_BIT| SSL_AUTH_ECDSA_BIT)
#define SSL_ECDH_ANON                   (SSL_KEYEX_ECDHE_BIT| SSL_AUTH_ANON_BIT | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_ECDH_PSK                    (SSL_KEYEX_ECDHE_BIT| SSL_AUTH_ANON_BIT | SSL_PSK_BIT | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_RSA_PSK                     (SSL_RSA            | SSL_PSK_BIT       | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_DHE_RSA                     (SSL_KEYEX_DHE_BIT  | SSL_AUTH_RSA_BIT)
#define SSL_DHE_DSA                     (SSL_KEYEX_DHE_BIT  | SSL_AUTH_DSA_BIT)
#define SSL_DH_ANON                     (SSL_KEYEX_DHE_BIT  | SSL_AUTH_ANON_BIT | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_DH_PSK                      (SSL_KEYEX_DHE_BIT  | SSL_AUTH_ANON_BIT | SSL_PSK_BIT        | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_PSK                         (SSL_PSK_BIT        | SSL_AUTH_ANON_BIT | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_SRP                         (SSL_AUTH_ANON_BIT  | SSL_SRP_BIT       | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_RSA_SRP                     (SSL_AUTH_RSA_BIT   | SSL_SRP_BIT       | SSL_NO_MUTUAL_AUTH_BIT)
#define SSL_ECDHE_ALL                   (SSL_ECDHE_RSA      | SSL_ECDHE_ECDSA)
/* hybrid is always combined with ecdhe and ecdsa */
#define SSL_HYBRID                      (SSL_HYBRID_BIT     | SSL_KEYEX_ECDHE_BIT | SSL_AUTH_ECDSA_BIT)

/* "signature_algorithms" and "signature_algorithms_cert" extension flags
 */
#define SSL_RSA_PKCS1_SHA256         0x0401
#define SSL_RSA_PKCS1_SHA384         0x0501
#define SSL_RSA_PKCS1_SHA512         0x0601
#define SSL_ECDSA_SECP256R1_SHA256   0x0403
#define SSL_ECDSA_SECP384R1_SHA384   0x0503
#define SSL_ECDSA_SECP521R1_SHA521   0x0603
#define SSL_RSA_PSS_RSAE_SHA256      0x0804
#define SSL_RSA_PSS_RSAE_SHA384      0x0805
#define SSL_RSA_PSS_RSAE_SHA512      0x0806
#define SSL_ED25519                  0x0807
#define SSL_ED448                    0x0808
#define SSL_RSA_PSS_PSS_SHA256       0x0809
#define SSL_RSA_PSS_PSS_SHA384       0x080A
#define SSL_RSA_PSS_PSS_SHA512       0x080B
#define SSL_RSA_PKCS1_SHA1           0x0201
#define SSL_ECDSA_SHA1               0x0203

/* PQC signing algs */
#define SSL_MLDSA_44                       0x0904
#define SSL_MLDSA_65                       0x0905
#define SSL_MLDSA_87                       0x0906
#define SSL_MLDSA_44_ECDSA_P256_SHA256     0x0907
#define SSL_MLDSA_65_ECDSA_P384_SHA384     0x0908
#define SSL_MLDSA_87_ECDSA_P384_SHA384     0x0909
#define SSL_MLDSA_44_ED25519               0x090A
#define SSL_MLDSA_65_ED25519               0x090B
#define SSL_MLDSA_44_RSA2048_PKCS15_SHA256 0x090C
#define SSL_MLDSA_65_RSA3072_PKCS15_SHA256 0x090D
#define SSL_MLDSA_65_RSA4096_PKCS15_SHA384 0x090E
#define SSL_MLDSA_44_RSA2048_PSS_SHA256    0x090F
#define SSL_MLDSA_65_RSA3072_PSS_SHA256    0x0910
#define SSL_MLDSA_65_RSA4096_PSS_SHA384    0x0911
#define SSL_MLDSA_87_ED448                 0x0912

/* Mocana SSL Internal Flags */
#define SSL_INT_FLAG_SYNC_MODE          (0x00000001)
#define SSL_INT_FLAG_ASYNC_MODE         (0x00000002)

typedef ubyte4 SESSIONID;

typedef enum
{
    E_NoSessionResume = 0,
    E_SessionIDResume = 1,
    E_SessionTicketResume = 2,
    E_SessionEAPFASTResume = 3
} E_SessionResumeType;

/* SSL Session Ticket macros based on RFC 5077 */

/* Key name size */
#define SSL_SESSION_TICKET_KEY_NAME_SIZE    (16)
/* AES-CBC encryption key size */
#define SSL_SESSION_TICKET_ENC_KEY_SIZE     (16)
/* HMAC-SHA-256 mac key size and output size */
#define SSL_SESSION_TICKET_MAC_KEY_SIZE     (32)
#define SSL_SESSION_TICKET_MAC_SIZE         (32)
/* IV size */
#define SSL_SESSION_TICKET_IV_SIZE          (16)

/* ClientAuthenticationType - anonymous */
#define SSL_SESSION_TICKET_CLIENT_AUTH_TYPE_ANON        (0)
/* ClientAuthenticationType - certificate */
#define SSL_SESSION_TICKET_CLIENT_AUTH_TYPE_CERT        (1)

#define SSL_SESSION_TICKET_VERSION          (2)

/* forward declare */
struct CipherSuiteInfo;
struct diffieHellmanContext;

struct certChain;
struct certStore;

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
enum dtlsTimerStates
{
    kDtlsPreparing,
    kDtlsSending,
    kDtlsWaiting,
    kDtlsFinished,
    kDtlsUnknown
};

#ifdef __ENABLE_MOCANA_TLS13__
enum postHandshakeType
{
    kNewSessionTicket = 0,
    kCertificateRequest = 1,
    kKeyUpdate = 2,
    kMainHandshake = 3 /* this indicates the message is not post-handshake */
};

typedef struct _RecordListNode * RecordListNodePtr;

typedef struct PostHandshakeState
{
    enum postHandshakeType type;
    enum dtlsTimerStates state;
    RecordListNodePtr pSentRecords;
    ubyte4 sentRecordsLen;
    RecordListNodePtr pRecvRecords;
    ubyte4 recvRecordsLen;
    ubyte *msgTimer;
    ubyte4 msgTimeout;
} PostHandshakeState;
#endif /* __ENABLE_MOCANA_TLS13__ */

typedef struct msgBufferDescr
{
    ubyte *ptr;
    ubyte4 recordSize;
    ubyte2 firstHoleOffset;
#if defined(__ENABLE_MOCANA_TLS13__)
    RecordListNodePtr pRecordNodeList;
#endif
} msgBufferDescr;

typedef struct retransBufferDescr
{
    ubyte   recordType;
    ubyte*  pData;
    ubyte4  length;
#if defined(__ENABLE_MOCANA_TLS13__)
    enum postHandshakeType handshakeType;
    RecordListNodePtr pRecordNodeList;
    ubyte2 epoch;
#endif
} retransBufferDescr;

#endif
#define MAX_HANDSHAKE_MESG_IN_FLIGHT  (8)
#define DTLS_HANDSHAKE_HEADER_SISE    (12)
#define DTLS_MAX_REPLAY_WINDOW_SIZE   (64)

typedef struct sharedKey
{
    ubyte4  type;
    ubyte4  namedGroup;
    void*  pKey;
} sharedKey;

/* This is the maximum number of possible supported named groups,
 * which is based on RFC 8446 4.2.7 NamedGroup list. */
#define MAX_SUPPORTED_NAMED_GROUPS 11

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
#if defined(__ENABLE_MOCANA_DTLS_SRTP__) && defined(__ENABLE_MOCANA_SRTP_PROFILES_SELECT__)
#define SRTP_MAX_NUM_PROFILES (16)
#endif
#endif

#if defined(__ENABLE_MOCANA_SSL_HEARTBEAT_RFC_6520__)
#define HEARTBEAT_PAYLOAD_LENGTH 32 /* RFC requirement is max of 2^16 - 1*/
#define HEARTBEAT_PADDING_LENGTH 32 /* RFC requirement is minimum of 16 bytes */

#define HEARTBEAT_MESSAGE_REQUEST  1
#define HEARTBEAT_MESSAGE_RESPONSE 2
#endif

typedef struct SSL_Transport_Handler 
{
    TCP_SOCKET sslSocket;
    sbyte4 sslId;
    SSLTransportSend funcPtrTransportSend;
    SSLTransportRecv funcPtrTransportRecv;

} SSL_Transport_Handler;

/* arrange the structure so that number of hash operations is limited */
typedef struct SSLSocket
{

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
    peerDescr                       peerDescr;
    ubyte*                          dtlsHandshakeTimer;
    ubyte4                          dtlsHandshakeTimeout; /* in millisecond */
    ubyte4                          dtlsPMTU;
#endif
    TCP_SOCKET                      tcpSock;
    void			  * pSslConnectDescr; /* cache this; avoid hash lookup */
    /* timer support */
    moctime_t                       timerStartTime;
    ubyte4                          timerMsExpire;

    /* used for receiving data asynchronously */
    enum sslOpenStates              openState;
    enum sslAsyncStates             asyncState;
    enum sslSyncRecordStates        recordState;
    ubyte*                          pAsyncBuffer;
    ubyte4                          asyncBytesRead;
    ubyte4                          asyncBytesRequired;
    intBoolean                      asyncStateInit;
    ubyte*                          pSharedInBuffer;
#if defined(__ENABLE_MOCANA_TLS13__) && ((defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__)))
    ubyte2                          sharedInBufferLen;                          
#endif

    /* send buffered data out */
    ubyte*                          pOutputBufferBase;      /* malloc'd base */
    ubyte*                          pOutputBuffer;          /* current position */
    ubyte4                          outputBufferSize;       /* size of output buffer */
    ubyte4                          numBytesToSend;         /* number of bytes pending inside of buffer */

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
    intBoolean                      isRetransmit;
    retransBufferDescr              retransBuffers[MAX_HANDSHAKE_MESG_IN_FLIGHT];   /* remember for retransmission */
#endif

    /* used for handshake only */
    ubyte4                          handshakeCount;
    RNGFun                          rngFun;
    void*                           rngFunArg;
    enum sslHandshakeStates         sslHandshakeState;      /* my handshake state */
    sbyte4                          theirHandshakeState;    /* peer's handshake state */
    intBoolean                      receivedServerKeyEx;
#ifdef __ENABLE_MOCANA_SSL_REHANDSHAKE__
    /* Timer count for rehandshake */
    moctime_t    sslRehandshakeTimerCount;
#endif

    /* Count of bytes sent */
    sbyte4       sslByteSendCount;
    struct certStore               *pCertStore;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__)
    struct certStore               *pMutualAuthCertStore;
#endif
    struct certChain               *pCertChain;
#ifdef __ENABLE_MOCANA_TLS13__
    certDistinguishedName          *pSupportedCADn;
#if (defined(__ENABLE_MOCANA_TLS13_PSK__) && defined(__ENABLE_MOCANA_TLS13_0RTT__))
    ubyte4                          maxEarlyDataSize;/* The max Early data Size, a server can receive per session;
                                                      * This value should always be lower than or equal to recvEarlyDataSize
                                                      * in sslsettings
                                                      */
    ubyte                           earlyDataExtAccepted;
    intBoolean                      sendEarlyData; /* Maintaining a separate variable since
                                                    * early Data can be retrieved just before sending;
                                                    * State transitions are done on the basis of this flag
                                                    */
    ubyte*                          pEarlyData; /* Shallow copy; Memory is owned by the application */
    ubyte4                          earlyDataSize;
#endif
    ubyte                           encryptThenMac;
    ubyte                           helloRetryRequest;
    ubyte2                          tls13EncryptedExtensionsLength;
    ubyte                           isPSKSelected;
#endif

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__) || defined(__ENABLE_MOCANA_TLS13__))
    /* This cookie variable is used in both TLS 1.3 and DTLS */
    ubyte2                          helloCookieLen;
    ubyte                           helloCookie[SSL_HELLO_COOKIE_MAX_SIZE];
#endif

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
    enum dtlsTimerStates            dtlsTimerState;
    ubyte2                          nextSendSeq; /* next sending handshake message sequence counter */
    ubyte2                          nextRecvSeq; /* next receive handshake message sequence counter */
    msgBufferDescr                  msgBufferDescrs[MAX_HANDSHAKE_MESG_IN_FLIGHT]; /* max outstanding messages in a flight */
    ubyte4                          msgBase;     /* base sequence number of handshake message flight */
    ubyte                           HSHBytes[DTLS_HANDSHAKE_HEADER_SISE]; /* sizeof(SSLHandShakeHeader) */
    byteBoolean                     shouldChangeCipherSpec; /* true if epoch increases by 1 */
    ubyte2                          currentPeerEpoch;       /* the current peer epoch in effect */
    intBoolean                      receivedFinished;
#ifdef __ENABLE_MOCANA_TLS13__
    PostHandshakeState              postHandshakeState[3]; /* 3 post handshake message types */

    intBoolean                      sendKeyUpdateResponse; /* respond to peer request for rekey */
    intBoolean                      keyUpdateMessageSent; /* initiate rekey */
    intBoolean                      keyUpdateMessageReceived; /* peer sending key update message */
#endif
#endif
    intBoolean                      sentFinished;

    SizedBuffer                     buffers[10];
    sbyte4                          bufIndex;
    sbyte4                          numBuffers;

    SHA1_CTX*                       pShaCtx;
    MD5_CTX*                        pMd5Ctx;
    BulkCtx                         pHashCtx;
#if defined(__ENABLE_MOCANA_TLS13__)
    BulkCtx                         pHandshakeHashCtx;
#endif
    BulkCtx*                        pHashCtxList;

    intBoolean                      isDTLS; /* whether we are doing dtls */

    ubyte                           advertisedMinorVersion;  /* set by ioctl */
    ubyte                           clientHelloMinorVersion; /* sent/receive in client hello.
                                                                For TLS v1.3 and later, this is
                                                                the version selected by the server.*/
    ubyte                           minFallbackMinorVersion; /* set by ioctl */

    ubyte                           sslMaxVersion;
    ubyte                           sslMinorVersion;         /* negotiated, current */

#if defined(__ENABLE_MOCANA_TLS13__)
    ubyte                           legacySSLMinorVersion; /* For TLS 1.3, this is the minorVersion
                                                              sent in header; */
#endif

    poolHeaderDescr                 shaPool;
    poolHeaderDescr                 md5Pool;
    poolHeaderDescr                 hashPool; /* used for TLS1.2 and up */
    poolHeaderDescr                 smallPool;


    /* extensions */
    sbyte*                          serverNameIndication;

    ubyte2                          alpnProtocolsLen;
    ubyte*                          alpnProtocols;
    const ubyte*                    selectedALPN; /* point inside alpnProtocols,
                                                   first byte is length */

    ubyte4                          signatureAlgoListLength;
    ubyte*                          signatureAlgoList;
#if defined(__ENABLE_MOCANA_TLS13__)
    ubyte4                          signatureAlgoCertListLength;
    ubyte*                          signatureAlgoCertList;
#endif

    ubyte2                          signatureAlgo;

#if defined(__ENABLE_MOCANA_SSL_HEARTBEAT_RFC_6520__)
    E_HeartbeatExtension            sendHeartbeatMessage;
    E_HeartbeatExtension            rxHeartbeatExtension;
    ubyte                           heartbeatPayload[HEARTBEAT_PAYLOAD_LENGTH];
    intBoolean                      heartbeatMessageInFlight;
#endif

#if defined( __ENABLE_MOCANA_OCSP_CLIENT__)
    /* certificate status request */
    /* Track whether or not a status request must be sent */
    intBoolean                     certStatusReqExt;
    /* Track whether the peer provided an OCSP response */
    intBoolean                     didRecvCertStatusExt;
    /* Track whether a status request was recieved */
    intBoolean                     recvStatusReqExt;

    /* Client: Input parameter to be used while create certificate status request */
    /* Server: Extensions to be attached while generating OCSP Request */
    extensions*                     pExts;
    ubyte4                          numOfExtension;
    void*                           pOcspContext; /* typecast of ocspContext */
    sbyte*                          pResponderUrl;          /* allocated */
    /* certificate status request extension data */
    ubyte4                          certStatusReqExtLen;
    ubyte*                          certStatusReqExtData;
    ubyte4                          ocspResponseLen;
    ubyte*                          pOcspResponse;
#endif


#ifdef __ENABLE_MOCANA_EAP_FAST__
    ubyte                           pacKey[PACKEY_SIZE];
#endif

#ifdef __ENABLE_MOCANA_INNER_APP__
    intBoolean                      receivedInnerApp;
    ubyte2                          receivedInnerAppValue;
    ubyte                           innerSecret[SSL_INNER_SECRET_SIZE];
#endif

    /* session resumption */
    E_SessionResumeType             sessionResume;
    /* rehandshake flag */
    intBoolean                      rehandshake;


    /** encryption ***********/
    const struct CipherSuiteInfo*   pActiveOwnCipherSuite;  /* cipher suite used for encrypting data */
    const struct CipherSuiteInfo*   pActivePeerCipherSuite; /* cipher suite used for decrypting data */
    const struct CipherSuiteInfo*   pHandshakeCipherSuite;  /* cipher suite used connection handshake */

    AsymmetricKey                   handshakeKey;

    /* bulk encryption contexts */
    BulkCtx                         clientBulkCtx;
    BulkCtx                         serverBulkCtx;

    /* MAC secrets -> points to materials below */
    ubyte*                          clientMACSecret;
    ubyte*                          serverMACSecret;

    /* IV for block encryption -> points to materials below */
    ubyte*                          clientIV;
    ubyte*                          serverIV;

#ifdef __ENABLE_MOCANA_EAP_FAST__
    /* session key seed -> points to materials below */
    ubyte*                          sessionKeySeed;
    ubyte*                          fastChapChallenge;
#endif

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
    /* handshake message retransmission */
    struct retransCipherInfo {
        intBoolean                      deleteOldBulkCtx;    /* TRUE if we should call deleteCtxFunc */
        BulkCtx                         oldBulkCtx;
        ubyte                           oldMACSecret[SSL_MAXMACSECRETSIZE];
        const struct CipherSuiteInfo*   pOldCipherSuite;     /* cipher suite used for encrypting retransmitted data */
    } retransCipherInfo;
#endif
#if defined(__ENABLE_MOCANA_TLS13__) && defined(__ENABLE_MOCANA_DTLS_SERVER__) && \
    defined(__ENABLE_MOCANA_TLS13_PSK__) && defined(__ENABLE_MOCANA_TLS13_0RTT__)
    struct earlyDataEpochKeys {
        ubyte4                          currentPeerEpoch;
        ubyte4                          peerSeqnumHigh;
        ubyte4                          peerSeqnum;
        intBoolean                      isSet;
        BulkCtx                         pBulkCtx;
        ubyte                           pIv[16];
        ubyte4                          ivLen;
        intBoolean                      needToRevert;
        intBoolean                      disableEpoch;
    } earlyDataEpochKeys;
#endif

    /* sequence numbers */
    ubyte4                          ownSeqnum;
    ubyte4                          ownSeqnumHigh;  /* if DTLS, first two octets are epoch */
    ubyte4                          peerSeqnum;
    ubyte4                          peerSeqnumHigh;

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
    ubyte4                          oldSeqnum;      /* remember for retransmission */
    ubyte4                          oldSeqnumHigh;  /* remember for retransmission */

    /* anti-replay */
    ubyte                           replayWindow[DTLS_MAX_REPLAY_WINDOW_SIZE/8];
    ubyte4                          windowStartSeqnum;
    ubyte4                          windowStartSeqnumHigh;
#endif

    /* SSL 3.0 this will contain the master secret
     followed by the client random and server random
        TLS 1.0 this will contain "master secret" followed by the client
     random and the server random. "master secret" is at position
     SSL_RSAPRESECRETSIZE - TLS_MASTERSECRETLEN
    */
    ubyte*                          pSecretAndRand;
    ubyte*                          pClientRandHello;
    ubyte*                          pServerRandHello;
    /* contains the key materials */
    ubyte*                          pMaterials;
    ubyte*                          pActiveMaterials;   /* active materials is a clone of pMaterials --- allows for key reuse */

#ifdef __ENABLE_MOCANA_SSL_CIPHER_SUITES_SELECT__
    /* ability to chose at run-time cipher suites to support */
    byteBoolean                     isCipherTableInit;
    byteBoolean                     isCipherEnabled[SSL_MAX_NUM_CIPHERS];
#endif

    ubyte4                          supportedGroups;
    ubyte2*                         pSupportedGroupList;
    ubyte4                          supportedGroupListLength;
    ubyte2*                         pSupportedSignatureAlgoList;
    ubyte4                          supportedSignatureAlgoListLength;
#if defined(__ENABLE_MOCANA_TLS13__)
    ubyte2*                         pConfiguredSignatureCertAlgoList;
    ubyte4                          configuredSignatureCertAlgoListLength;
#endif

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__)) && defined(__ENABLE_MOCANA_DTLS_SRTP__)
    byteBoolean                     useSrtp; /* is use_srtp enabled? */
    ubyte*                          srtpMki; /* opaque srtp_mki<0..255> */
    const struct SrtpProfileInfo*   pHandshakeSrtpProfile;  /* protection profile used connection handshake */
    ubyte*                          pSrtpMaterials; /* contains the key materials */

#ifdef __ENABLE_MOCANA_SRTP_PROFILES_SELECT__
    /* ability to chose at run-time srtp protection profiles to support */
    byteBoolean                     isSrtpProfileTableInit;
    byteBoolean                     isSrtpProfileEnabled[SRTP_MAX_NUM_PROFILES]; /* TODO: should change to a smaller value */
#endif

#endif

    /* enough space to receive any SSL record */
    sbyte*                          pReceiveBuffer;
    sbyte*                          pReceiveBufferBase;
    sbyte4                          receiveBufferSize;
    sbyte4                          offset;                 /* points inside receive buffer ( used by SSL_Receive) */
    sbyte4                          recordSize;             /* size of record in receiveBuffer */
    ubyte4                          protocol;               /* current SSL message type (i.e. application, alert, inner, etc) */
    ubyte4                          timeOutReceive;         /* Receive timeout */

#if (defined(__ENABLE_MOCANA_SSL_DHE_SUPPORT__) || \
    defined(__ENABLE_MOCANA_SSL_DH_ANON_SUPPORT__))
    struct diffieHellmanContext*    pDHcontext;
    ubyte                           *pDHP;
    ubyte4                           pLen;
    ubyte                           *pDHG;
    ubyte4                           gLen;
    ubyte4                          lengthY;

    /* when crypto interface is enabled we want to hold on to the public key remote context,
     * we also need to keep a hold of the shared secret until it is used. */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    ubyte*                          pRemotePublicKey;
    ubyte4                          remotePublicKeyLength; 

    ubyte*                          pSharedSecret;
    ubyte4                          sharedSecretLength;
#endif
#endif

#if (defined(__ENABLE_MOCANA_SSL_ECDHE_SUPPORT__) || \
    defined( __ENABLE_MOCANA_SSL_ECDH_ANON_SUPPORT__))
    AsymmetricKey                   ecdheKey;
#endif

#if defined(__ENABLE_MOCANA_PQC__)
    ubyte                           *pQsSharedSecret;
    ubyte4                          qsSharedSecretLen;
#endif

    /* these two are used by both client and server */
    intBoolean                      isMutualAuthNegotiated;
    intBoolean                      generateEmptyCert;

#ifdef __ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__
    AsymmetricKey                   mutualAuthKey;
#endif

#ifdef __ENABLE_MOCANA_SSL_SRP__
    ubyte*                          srpIdentity; /* first byte is length */
    sbyte4                          srpNumBits; /* identify the "group" */

#endif

    hwAccelDescr                    hwAccelCookie;          /* hardware accelerator cookie */

    ubyte4                          runtimeFlags;
    ubyte4                          internalFlags;
    intBoolean                      alertCloseConnection; /* Flag to check if connection should be closed
                                                           *  because of a fatal alert */
    intBoolean                      sendCloseNotifyAlert; /* Flag to check if close notify should be sent */

#if (defined(__ENABLE_MOCANA_SSL_REHANDSHAKE__))
    intBoolean                      isRehandshakeExtPresent;
    intBoolean                      isRehandshakeAllowed;
#endif
    ubyte                           client_verify_data[SSL_VERIFY_DATA_MAX];
    ubyte4                          client_verify_data_len;
    ubyte                           server_verify_data[SSL_VERIFY_DATA_MAX];
    ubyte4                          server_verify_data_len;

    /* engineer defined cookie */
    void*                           cookie;

#if defined(__ENABLE_MOCANA_TLS13__)
    ubyte*                          certificateRequestContext;
    ubyte                           certificateRequestContextLength; /* 0..2^8-1 */
    ubyte                           postHandshakeAuth;
    ubyte                           postHandshakeMessages;
#if defined(__ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__)
    ubyte                           filterCertExtensions;
    ubyte2                          certReqTotalExtensionsLength;
#endif
    intBoolean                      isPartialHandshakeRecord;
    ubyte*                          pPartialHandshakeRecordBuffer;
    ubyte4                          partialHandshakeRecordBufferLen;

    /* Keys generated */
    ubyte*                          pPskSecret;
    ubyte*                          pClientEarlyTrafficSecret;
    ubyte*                          pClientHandshakeTrafficSecret;
    ubyte*                          pServerHandshakeTrafficSecret;
    ubyte*                          pClientApplicationTrafficSecret;
    ubyte*                          pServerApplicationTrafficSecret;
    ubyte*                          pEarlySecret;
    ubyte*                          pBinderKey;
    ubyte*                          pEarlyExporterMasterSecret;
    ubyte*                          pHandshakeSecret;
    ubyte*                          pMasterSecret;
    ubyte*                          pExporterMasterSecret;
    ubyte*                          pResumptionMasterSecret;
    ubyte2                          sentExtensions[MAX_EXTENSIONS_SENT];
    ubyte4                          numExtensions;
    ubyte4                          keyUpdateRequested;
    moctime_t                       keyUpdateTimerCount;
#if defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__)
    RecordListNodePtr               pRecvRecords;
    ubyte4                          recvRecordsLen;
#endif
#endif /* __ENABLE_MOCANA_TLS13__ */

#if defined(__ENABLE_MOCANA_EXTENDED_MASTERSECRET_RFC7627__)
    intBoolean                      supportExtendedMasterSecret;
    intBoolean                      useExtendedMasterSecret;/* If the connection is using extended Master Secret computation */
    intBoolean                      receivedExtendedMasterSecret; /* Flag to mark if extended_master_secret extension is received */
#endif
    sbyte4                          lastErrorStatus;
    sbyte4                          server;                 /* are we a server or a client */
    union
    {
#ifdef __ENABLE_MOCANA_SSL_SERVER__
        struct ServerInfo
        {
            ubyte4                  numCertificates;
            const SizedBuffer*      certificates;           /* points to cert store managed buffers */
            SESSIONID               sessionId;              /* our own session ID is 4 bytes long */
#if defined(__ENABLE_MOCANA_SSL_SESSION_TICKET_RFC_5077__)
            ubyte2                  ticketCipherSuiteId;
            ubyte                   ticketUseExtendedMasterSecret;
#endif
            ubyte4                  certECCurves;           /* bit is set if curve is used in certchain */
            ubyte4                  clientECCurves;         /* bit is set if curve can be used by client */
            byteBoolean             sendSessionTicket;
            ubyte4                  numOfSessionTickets;    /* This indicates the number of session tickets to send;
                                                               Configured by application; Default value is 1; */
            /* Keys used in generating a session ticket */
            ubyte*                  aesKey;
            ubyte*                  hmacKey;

#ifdef __ENABLE_MOCANA_SSL_SRP__
            vlong*                  srpb;                   /* random value b */
            vlong*                  srpVerifier;            /* SRP verifier */
            ubyte*                  srpB;                   /* B value kv + g^b %N */
            ubyte2                  srpBLen;                /* length of sprB */
#endif
#if defined(__ENABLE_MOCANA_INNER_APP__)
            intBoolean              innerApp;
            ubyte2                  innerAppValue;
#endif
            sbyte4                  keyExchangeMode;        /* Content of PSK Key Exchange Mode extension */
#if defined(__ENABLE_MOCANA_TLS13__) || defined(__ENABLE_MOCANA_SSL_SESSION_TICKET_RFC_5077__)
            ubyte                   sessionIdEchoLen;
            ubyte                   sessionIdEcho[SSL_MAXSESSIONIDSIZE];
#endif
#ifdef __ENABLE_MOCANA_TLS13__
            /* RFC 8446, section 4.1.3. legacy_session_id_echo
             * TLS 1.3, the session ID received in Client Hello should be echoed back in Server Hello
             */
            ubyte*                  pSessionTicket;
            ubyte                   sessionTicketLen;
            ubyte                   sessionTicketNonceLen;

            ubyte                   enableTls13SessionTickets;
            /* Received Extensions :
             * 0x01 - Supported Groups
             * 0x02 - Key Share
             * 0x04 - Pre Shared Key
             * 0x08 - Signature Algo
             * 0x10 - Signature Algo Cert
             */
            ubyte                   receivedExtensions;
            enum tlsExtNamedCurves  clientSupportedGroups[MAX_SUPPORTED_NAMED_GROUPS];
            ubyte                   hrrClientHello; /* Is the client hello received in response to Hello Retry Request sent */
            /* Server side keys generated in KDF */
            ubyte*                  pServerHandshakeTrafficSecret;
            ubyte*                  pServerApplicationTrafficSecret0;
            ubyte2                  numSupportedGroupReceived;
            ubyte*                  pKeyShareExt;
            ubyte2                  keyShareExtLength;
            ubyte*                  receivedPubKey;
            ubyte2                  receivedPubKeyLen;
            enum tlsExtNamedCurves  selectedGroup;
            tls13PSK                *pSelectedPSK;
            ubyte2                  selectedPskIdentityIndex;
            ubyte4                  selectedPskAge;
#ifdef __ENABLE_MOCANA_TLS13_0RTT__
            ubyte                   zeroRTT; /* 0x01 - earlyApplicationDataReceived
                                              * 0x02 - endOfEarlyData Message received
                                              * 0x04 - 0RTT Fallback;
                                              *        0RTT failed and handshake fallback to PSK or Certificate
                                              */
#endif
            ubyte4                  selectedCurveLength;
            ubyte2                  bindersLength;
            ubyte                   PSKExt;
#endif /* __ENABLE_MOCANA_TLS13__ */
        } server;
#endif

#ifdef __ENABLE_MOCANA_SSL_CLIENT__
        struct ClientInfo
        {
            /* this part is set by the client specific extra initialization routine */
            ubyte                   sessionIdLen;
            ubyte                   sessionId[SSL_MAXSESSIONIDSIZE];
                                                            /* this contains a copy of the buffer passed
                                                               in the client specific extra initialization
                                                               routine originally and then the session id
                                                               sent by the server */
            ubyte*                  pMasterSecret;          /* points to some external buffer */
            const sbyte*            pDNSName;               /* points to some external buffer */
#if defined(__ENABLE_MOCANA_MULTIPLE_COMMON_NAMES__)
            const CNMatchInfo*      pCNMatchInfos;          /* points to some external buffer */
#endif

#ifdef __ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__
            ubyte2                  mutualAuthSignAlgo;     /* TLS 1.2 signature Algo */
            /* This alias is for the key/cert loaded by SSL client in mutual auth case;
             * This enables the application to direct the client
             * to use a specific key and certificate when authenticating itself */
            ubyte *pCertAuthAlias;
            ubyte4 certAuthAliasLen;

#endif

#ifdef __ENABLE_MOCANA_SSL_SRP__
            /* the SRP parameters */
            ubyte                   ipHash[SHA1_RESULT_SIZE]; /* SHA (I|':'|P) */
            ubyte*                  srpSB; /* salt and B value -- copy of part of
                                            the Server Key Exchange */
            sbyte4                  srpSBLen;
#endif

#ifdef __ENABLE_MOCANA_SSL_PSK_SUPPORT__
            ubyte                   psk[SSL_PSK_MAX_LENGTH];
            ubyte4                  pskLength;
            ubyte                   pskIdentity[SSL_PSK_SERVER_IDENTITY_LENGTH];
            ubyte4                  pskIdentityLength;
#endif

            ubyte4                  numMutualAuthCert;
            const SizedBuffer*      sslMutualAuthCerts;    /* points to cert store managed buffers */
            ubyte2                  certExtensionSize;
#ifdef __ENABLE_MOCANA_SSL_SESSION_TICKET_RFC_5077__
            sessionTicket*          pTicketTls;
#endif
#ifdef __ENABLE_MOCANA_EAP_FAST__
            ubyte4                  ticketLength;
            ubyte*                  ticket;
#endif
#ifdef __ENABLE_MOCANA_INNER_APP__
            intBoolean              innerApp;
            ubyte2                  innerAppValue;
#endif
            ubyte*                  helloBuffer; /* for saving the client hello for hash calculation */
            ubyte4                  helloBufferLen; /* for saving the client hello for hash calculation */

#if (defined(__ENABLE_MOCANA_OCSP_CLIENT__))
            /* We will extract responder Ids from this; and use it for parsing
                          the received response */
            ubyte4                  trustedResponderCount;
            certDescriptor*         pOcspTrustedResponderCerts;
#endif

            ubyte                   requestSessionTicket;
#ifdef __ENABLE_MOCANA_TLS13__
            ubyte*                  pSessionTicket;
            ubyte                   sessionTicketLen;
            ubyte                   numOfSharedVersions;
            ubyte2*                 pSharedVersions;  /* Check hard coded value 5 */
            ubyte                   isSupportedVersionPresent;
            ubyte                   clientHelloHash[32];
            ubyte2                  clientHelloHashSize;
            ubyte                   serverHelloHash[32];
            ubyte                   pskKeyExchangeMode;
            sharedKey*              ppSharedKeys;
            ubyte4                  sharedKeyCount;
            ubyte                   sharedKeyIndex;
            ubyte                   sharedSupportedVersion;

            /* Client side keys generated in KDF */
            ubyte*                  pClientEarlyTrafficSecret;
            ubyte*                  pClientApplicationTrafficSecret0;
            ubyte2                  serverSelectedVersion;
            ubyte2                  selectedGroup;
            ubyte2                  selectedIdentityIndex;

            /* Client keyshare:
             * 0x01 - Client sent Keyshare extension
             * 0x02 - Client received Keyshare extension
             * 0x04 - Client received PSK extension
             */
            ubyte                   extensions;

            ubyte                   hrrServerSSLMinorVersion;
            /* 0x01 - received hrr
             * 0x02 - hrrReplySent
             * 0x04 - ServerHello Received after responding to HRR
             */
            ubyte                   hrr;
            const struct CipherSuiteInfo* hrrCipherSuiteInfo;
            ubyte*                  hrrBuffer; /* for saving the HRR for hash calculation */
            ubyte4                  hrrBufferLen; /* for saving the HRR for hash calculation */
            ubyte2                  numOfTLS13PSK;
            tls13PSKList*           pTLS13PSKList;
            ubyte2                  serverSelectedIdentityIndex;
            ubyte*                  receivedPubKey;
            ubyte2                  receivedPubKeyLen;
#endif
#if defined(__ENABLE_MOCANA_EXTENDED_MASTERSECRET_RFC7627__)
            ubyte                   sentExtendedMasterSecret;
#endif
            MSTATUS (*funcPtrClientCertCallback)(sbyte4 connInstance,
                                                 SizedBuffer **ppRetCert, ubyte4 *pRetNumCerts,
                                                 ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLen,
                                                 ubyte **pRetCACert, ubyte4 *pRetNumCACerts);
        } client;
#endif
    } roleSpecificInfo;
#ifdef __ENABLE_MOCANA_OPENSSL_SHIM__
    /* Variables have been replaced by funcPtrGetCertAndStatusCallback
     */
#if 0
     osslVrfyCertChainCB	appVerifyCertChainCB;
     void			* appVerifyCertChainArg;
#endif
    ClientHelloCallback clientHelloCallback;
    void *clientHelloCallbackArg;
#endif
 
#ifndef __DISABLE_MOCANA_ALPN_CALLBACK__
    sbyte4 (*funcPtrAlpnCallback)(sbyte4 connectionInstance,
                                  ubyte** out[],
                                  sbyte4* outlen,
                                  ubyte* in,
                                  sbyte4 inlen);
#endif

#ifndef __DISABLE_MOCANA_SSL_CERTIFICATE_CALLBACK__
    MSTATUS (*funcPtrGetCertAndStatusCallback)(sbyte4 connectionInstance,
                                               struct certChain* pCertChain,
                                               MSTATUS status );
    void (*funcPtrGetOriginalCertChainCallback)(sbyte4 connectionInstance,
                                               struct certChain* pCertChain);
    MSTATUS (*funcPtrClientCertAuthorityCallback) (sbyte4 connectionInstance,
                                             SizedBuffer *pCertAuthorities,
                                             ubyte4 certAuthorityCount);
#endif

#ifdef __ENABLE_MOCANA_SSL_INVALID_CERTIFICATE_CALLBACK__
    MSTATUS (*funcPtrInvalidCertCallback)(sbyte4 connectionInstance, MSTATUS status);
#endif

   MSTATUS (*funcPtrVersionCallback)(ubyte4 serverVersion, ubyte4 clientVersion, MSTATUS sslStatus);

#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_SSL_SESSION_TICKET_RFC_5077__)
    sbyte4 (*funcPtrSSLClientSaveTicketCallback)(sbyte4 connectionInstance, sbyte *serverInfo, ubyte4 serverInfoLen,
                                                 void *userData, ubyte *pTicket, ubyte4 ticketLen);

    sbyte4 (*funcPtrSSLClientRetrieveTicketCallback)(sbyte4 connectionInstance, sbyte *serverInfo, ubyte4 serverinfoLen,
                                                      void *userData, ubyte **ppTicket, ubyte4 *pTicketLen,
                                                      intBoolean *pFreeMemory);
#endif

#if (defined(__ENABLE_MOCANA_TLS13__) && defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_TLS13_PSK__))
    /* Call back to handover the RX'ed PSK to Application*/
    sbyte4 (*funcPtrSSLClientSavePSKCallback)(sbyte4 connectionInstance, sbyte* ServerInfo,
                                              ubyte4 serverInfoLen, void *userData, ubyte *pPsk, ubyte4 pskLen);

    /* Call back to get the PSK from Application */
    sbyte4 (*funcPtrSSLClientRetrievePSKCallback)(sbyte4 connectionInstance, sbyte* ServerInfo, ubyte4 serverInfoLen,
                                             void *userData, void **ppPSKs, ubyte2 *pNumPSKs,ubyte *selectedIndex,
                                             intBoolean *pFreeMemory);
#endif

#if (defined(__ENABLE_MOCANA_TLS13__) && defined(__ENABLE_MOCANA_TLS13_APPLICATION_DATA_CALLBACK__))
    /* Stack invokes this callback to get the data from application to send out
     * The parameters are connectionInstance, Data to send and length of data and an additional state */
    sbyte4 (*funcPtrSSLSendApplicationDataCallback(sbyte4 connectoinInstance,
                                                     ubyte **pData, ubyte4 *pDataLen,
                                                     dataState state));
#endif /*__ENABLE_MOCANA_TLS13__ && __ENABLE_MOCANA_TLS13_APPLICATION_DATA_CALLBACK__ */

#if defined(__ENABLE_MOCANA_SSL_HEARTBEAT_RFC_6520__)
    sbyte4 (*funcPtrHeatbeatMessageCallback)(sbyte4 connectionInstance, sbyte4 status, ubyte heartbeatType);
#endif
#ifdef __ENABLE_MOCANA_SSL_PROXY_CONNECT__
    SSL_Transport_Handler *pTransportHandler;
#endif

} SSLSocket;

/* Initialize SSL server engine */
MOC_EXTERN MSTATUS    SSL_SOCK_initServerEngine(RNGFun rngFun, void* rngFunArg);

/* Initialization /Deinitialization */
MOC_EXTERN MSTATUS SSL_SOCK_init(SSLSocket* pSSLSock, intBoolean isDTLS, TCP_SOCKET tcpSock, peerDescr *pPeerDescr, RNGFun rngFun, void* rngFunArg);
MOC_EXTERN MSTATUS SSL_SOCK_initHashPool(SSLSocket *pSSLSock );

#ifdef __ENABLE_MOCANA_SSL_CLIENT__
MOC_EXTERN MSTATUS SSL_SOCK_initSocketExtraClient(SSLSocket* pSSLSock,
                                                  ubyte sessionIdLen,
                                                  ubyte* sessionId,
                                                  ubyte* masterSecret,
                                                  const sbyte* dnsName,
                                                  certStorePtr certStore);
#endif

#if (defined(__ENABLE_MOCANA_EAP_FAST__) && defined(__ENABLE_MOCANA_SSL_CLIENT__))
MOC_EXTERN MSTATUS    SSL_SOCK_setEAPFASTParams(SSLSocket* pSSLSock, ubyte* pPacOpaque, ubyte4 pacOpaqueLen, ubyte pacKey[PACKEY_SIZE]);
#endif

#ifdef __ENABLE_MOCANA_EAP_FAST__
MOC_EXTERN MSTATUS    SSL_SOCK_generateEAPFASTIntermediateCompoundKey(SSLSocket *pSSLSock, ubyte *s_imk, ubyte *msk, ubyte mskLen, ubyte *imk);
MOC_EXTERN MSTATUS    SSL_SOCK_generateEAPFASTSessionKeys(SSLSocket *pSSLSock, ubyte* S_IMCK, sbyte4 s_imckLen, ubyte* MSK, sbyte4 mskLen, ubyte* EMSK, sbyte4 emskLen/*64 Len */);
#endif

#if (defined(__ENABLE_MOCANA_EAP_PEER__) || defined(__ENABLE_MOCANA_EAP_AUTH__))
MOC_EXTERN MSTATUS    SSL_SOCK_generatePEAPIntermediateKeys(SSLSocket *pSSLSock, ubyte* IPMK, sbyte4 ipmkLen, ubyte* ISK, sbyte4 iskLen, ubyte* result, sbyte4 resultLen/*32 Len */);
MOC_EXTERN MSTATUS    SSL_SOCK_generatePEAPServerCompoundMacKeys(SSLSocket *pSSLSock, ubyte* IPMK , sbyte4 ipmkLen, ubyte* S_NONCE, sbyte4 s_nonceLen, ubyte* result, sbyte4 resultLen/*20 bytes*/);
MOC_EXTERN MSTATUS    SSL_SOCK_generatePEAPClientCompoundMacKeys(SSLSocket *pSSLSock, ubyte* IPMK , sbyte4 ipmkLen, ubyte* S_NONCE, sbyte4 s_nonceLen, ubyte* C_NONCE, sbyte4 c_nonceLen, ubyte* result, sbyte4 resultLen/*20 bytes*/);
MOC_EXTERN MSTATUS    SSL_SOCK_generatePEAPCompoundSessionKey(SSLSocket *pSSLSock, ubyte* IPMK , sbyte4 ipmkLen, ubyte* S_NONCE, sbyte4 s_nonceLen, ubyte* C_NONCE, sbyte4 c_nonceLen, ubyte* result, sbyte4 resultLen);
#endif

#ifdef __ENABLE_MOCANA_SSL_SERVER__
MOC_EXTERN MSTATUS    SSL_SOCK_initSocketExtraServer(SSLSocket* pSSLSock);
MOC_EXTERN MSTATUS    SSL_SOCK_setServerCert(SSLSocket* pSSLSock);
#endif

MOC_EXTERN void       SSL_SOCK_uninit(SSLSocket* pSSLSock);

/* Handshake */
#ifdef __ENABLE_MOCANA_SSL_SERVER__
MOC_EXTERN MSTATUS    SSL_SOCK_serverHandshake(SSLSocket* pSSLSock, intBoolean isWriter);
MOC_EXTERN MSTATUS    constructTLSExtCertificateAuthorities(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte4 distNameLen);
#endif

#ifdef __ENABLE_MOCANA_SSL_CLIENT__
MOC_EXTERN MSTATUS    SSL_SOCK_clientHandshake(SSLSocket* pSSLSock, intBoolean isWriter);
#ifdef __ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__
MOC_EXTERN MSTATUS    SSLSOCK_populateMutualAuthCertStore(SSLSocket* pSSLSock, const SizedBuffer *pCerts, ubyte4 numCerts, ubyte *pKey, ubyte4 keyLen, const ubyte *pCACert, ubyte4 caCertLength);
#endif
#endif
/* Send/Receive */
MOC_EXTERN MSTATUS    SSL_SOCK_send(SSLSocket* pSSLSock, const sbyte* data, sbyte4 dataSize);
MOC_EXTERN MSTATUS    SSL_SOCK_sendPendingBytes(SSLSocket* pSSLSock);
MOC_EXTERN MSTATUS    SSL_SOCK_receive(SSLSocket* pSSLSock, sbyte* buffer, sbyte4 bufferSize, ubyte **ppPacketPayload, ubyte4 *pPacketLength, sbyte4 *pRetNumBytesReceived);
MOC_EXTERN MSTATUS    SSLSOCK_sendEncryptedHandshakeBuffer(SSLSocket* pSSLSock);

/* SSL Alerts */
MOC_EXTERN intBoolean SSLSOCK_parseAlert(SSLSocket* pSSLSock, sbyte4 alertId, sbyte4 alertClass, sbyte4 *pRetErrorCode);
MOC_EXTERN intBoolean SSLSOCK_lookupAlert(SSLSocket* pSSLSock, sbyte4 lookupError, sbyte4 *pRetAlertId, sbyte4 *pAlertClass);
MOC_EXTERN MSTATUS    SSLSOCK_sendAlert(SSLSocket* pSSLSock, intBoolean encryptBool, sbyte4 alertId, sbyte4 alertClass);
MOC_EXTERN MSTATUS    SSLSOCK_clearServerSessionCache(SSLSocket* pSSLSock);
MOC_EXTERN MSTATUS    SSLSOCK_clearAllServerSessionCache();

/* cipher manipulation/information */
#ifdef __ENABLE_MOCANA_SSL_CIPHER_SUITES_SELECT__
MOC_EXTERN sbyte4     SSL_SOCK_numCiphersAvailable(void);
MOC_EXTERN sbyte4     SSL_SOCK_disableCipherHashAlgorithm(SSLSocket *pSSLSock, TLS_HashAlgorithm hashId);
MOC_EXTERN sbyte4     SSLSOCK_setDSACiphers(SSLSocket *pSSLSock, intBoolean value);
MOC_EXTERN sbyte4     SSL_SOCK_getCipherList(SSLSocket *pSSLSock, ubyte2 **ppCipherIdList, ubyte4 *pCount);
#endif

#if defined ( __ENABLE_MOCANA_SSL_CIPHER_SUITES_SELECT__) || (defined(__ENABLE_MOCANA_EAP_FAST__) && defined(__ENABLE_MOCANA_SSL_SERVER__))
MOC_EXTERN sbyte4     SSL_SOCK_getCipherTableIndex(SSLSocket* pSSLSock, ubyte2 cipherId);
#endif

#if (defined(__ENABLE_MOCANA_DTLS_CLIENT__) || defined(__ENABLE_MOCANA_DTLS_SERVER__))
#if (defined(__ENABLE_MOCANA_DTLS_SRTP__) && defined(__ENABLE_MOCANA_SRTP_PROFILES_SELECT__))
MOC_EXTERN sbyte4     SSL_SOCK_numSrtpProfilesAvailable(void);
MOC_EXTERN sbyte4     SSL_SOCK_getSrtpProfileIndex(SSLSocket* pSSLSock, ubyte2 profileId);
#endif
#endif

#if defined(__ENABLE_MOCANA_INNER_APP__)
MOC_EXTERN MSTATUS    SSLSOCK_sendInnerApp(SSLSocket* pSSLSock, InnerAppType innerApp, ubyte* pMsg, ubyte4 msgLen, ubyte4 *retMsgLen, sbyte4 isClient);
MOC_EXTERN MSTATUS    SSLSOCK_updateInnerAppSecret(SSLSocket* pSSLSock, ubyte* session_key, ubyte4 sessionKeyLen);
MOC_EXTERN MSTATUS    SSLSOCK_verifyInnerAppVerifyData(SSLSocket *pSSLSock, ubyte *data, InnerAppType innerAppType, sbyte4 isClient);
#endif

/* EAP-TTLS */
#ifdef __ENABLE_MOCANA_SSL_KEY_EXPANSION__
MOC_EXTERN MSTATUS    SSL_SOCK_generateKeyExpansionMaterial(SSLSocket *pSSLSock,ubyte *pKey, ubyte2 keySize, ubyte *keyPhrase, ubyte2 keyPhraseLen);
MOC_EXTERN MSTATUS    SSL_SOCK_generateTLSKeyExpansionMaterial(SSLSocket *pSSLSock,ubyte *pKey, ubyte2 keySize, ubyte *keyPhrase, ubyte2 keyPhraseLen);
MOC_EXTERN MSTATUS    SSL_SOCK_generateTLSKeyExpansionMaterialWithContext(SSLSocket *pSSLSock,
                                                    ubyte *pKey, ubyte2 keySize,
                                                    ubyte *keyPhrase, ubyte2 keyPhraseLen,
                                                    ubyte *pContext, ubyte2 contextLen);
MOC_EXTERN MSTATUS
SSLSOCK_generateHmacKdfExporterKey(
    SSLSocket *pSSLSock, ubyte *pSecret, ubyte *pLabel, ubyte2 labelLen,
    ubyte *pContext, ubyte2 contextLen, ubyte *pKey, ubyte2 keyLen);
#endif

MOC_EXTERN MSTATUS    SSL_SOCK_getCipherId(SSLSocket* pSSLSock, ubyte2* pCipherId);
MOC_EXTERN MSTATUS    SSL_SOCK_sendServerHelloRequest(SSLSocket* pSSLSock);
#if !defined(__ENABLE_MOCANA_TLS13__)
MOC_EXTERN MSTATUS SSL_SOCK_setSupportedAlgorithm(SSLSocket *pSSLSock, ubyte2 *pList, ubyte4 listLength);
#endif

MOC_EXTERN MSTATUS SSL_SOCK_filterSupportedSignatureAlgorithm(SSLSocket *pSSLSock, intBoolean isVersionNegotiated);
MOC_EXTERN MSTATUS SSL_SOCK_getSharedSignatureAlgorithm(SSLSocket *pSSLSock, ubyte4 index, ubyte2 *pSigAlgo, ubyte isPeer);
MOC_EXTERN MSTATUS    SSL_SOCK_setSessionResumeTimeout(ubyte4 timeout);
MOC_EXTERN MSTATUS constructTLSExtPreSharedKey(SSLSocket *pSSLSock, ubyte **ppPacket,ubyte hrrReply, ubyte selectedIndex);
MOC_EXTERN MSTATUS constructTLSExtKeyShare(SSLSocket *pSSLSock, ubyte **ppPacket, ubyte2 *pPointLen);
MOC_EXTERN MSTATUS constructTLSExtSupportedAlgorithms(SSLSocket *pSSLSock, ubyte **ppPacket,ubyte2 numECCurves,ubyte4 eccCurves);

MOC_EXTERN MSTATUS SSL_SOCK_getSharedSignatureAlgorithm(SSLSocket *pSSLSock, ubyte4 index, ubyte2 *pSigAlgo, ubyte isPeer);
MOC_EXTERN sbyte4 SSL_SOCK_enableECCCurves(SSLSocket *pSSLSock, enum tlsExtNamedCurves *pECCCurvesList, ubyte4 listLength);

#if defined(__ENABLE_MOCANA_TLS13__)

MOC_EXTERN MSTATUS SSLSOCK_sendKeyUpdateRequest(SSLSocket *pSSLSock,ubyte updateRequest);
MOC_EXTERN MSTATUS SSLSOCK_processCertificateExtensions(SSLSocket *pSSLSock, ubyte4 index, ValidationConfig *pConfig);
MOC_EXTERN MSTATUS SSL_SOCK_setCipherAlgorithm(SSLSocket *pSSLSock, ubyte2 *pList, ubyte4 listLength, ubyte4 listType);
MOC_EXTERN MSTATUS SSL_SOCK_enforcePQCAlgorithm(SSLSocket *pSSLSock);
#if defined(__ENABLE_MOCANA_TLS13_PSK__)

MOC_EXTERN MSTATUS SSLSOCK_tls13SerializePsk(tls13PSK *pPsk, ubyte **ppRetPsk, ubyte4 *pRetPskLen);
MOC_EXTERN MSTATUS SSLSOCK_tls13DeserializePsk(ubyte *pPsk, ubyte4 pskLen, tls13PSK **ppRetPsk);
MOC_EXTERN MSTATUS SSLSOCK_clearPSKList(tls13PSKList **ppPskList, ubyte2 *pPskListLen);
MOC_EXTERN MSTATUS SSLSOCK_freePSK(tls13PSK **ppPsk);

#if defined(__ENABLE_MOCANA_TLS13_0RTT__)

MOC_EXTERN MSTATUS SSL_SOCK_sendEarlyData(SSLSocket *pSSLSock);

#endif /* __ENABLE_MOCANA_TLS13_0RTT__ */

#endif /* __ENABLE_MOCANA_TLS13_PSK__ */

#ifdef __ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__

MOC_EXTERN MSTATUS SSL_SERVER_sendPostHandshakeAuthCertificateRequest(SSLSocket* pSSLSock);

#endif /* __ENABLE_MOCANA_SSL_MUTUAL_AUTH_SUPPORT__ */

#endif /* __ENABLE_MOCANA_TLS13__ */
MOC_EXTERN MSTATUS SSLSOCK_initiateRehandshake(SSLSocket *pSSLSock);
MOC_EXTERN MSTATUS getSSLSocketFromConnectionInstance(sbyte4 connectionInstance, SSLSocket **ppSSLSock);

/* Internal APIs */
MOC_EXTERN sbyte4 processServerHelloVerifyRequest(SSLSocket *pSSLSock, ubyte* pHelloVerifyRequest, ubyte4 length);

#if defined(__ENABLE_MOCANA_TAP__) && defined(__ENABLE_MOCANA_TAP_DEFER_UNLOADKEY__)
MOC_EXTERN MSTATUS SSLSOCK_clearTAPKeyAndToken();
MOC_EXTERN MSTATUS SSLSOCK_setKeyAndTokenHandle(SSLSocket *pSSLSock, intBoolean isServer);
#endif

#if defined(__ENABLE_MOCANA_TAP__) && defined(__ENABLE_MOCANA_OPENSSL_LIB_3_0__)
MOC_EXTERN MSTATUS SSLSOCK_tapUnloadKey(AsymmetricKey *pAsymKey);
#endif /* __ENABLE_MOCANA_TAP__ */

#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_SSL_SESSION_TICKET_RFC_5077__)
MOC_EXTERN MSTATUS SSLSOCK_serializeSessionTicket(sessionTicket *pTicket,
                                              ubyte **ppRetTicket,
                                              ubyte4 *pRetTicketLen);
MOC_EXTERN MSTATUS SSLSOCK_deserializeSessionTicket(
    ubyte *pTicket, ubyte4 ticketLen, sessionTicket **ppRetTicket);
#endif

#if defined(__ENABLE_MOCANA_SSL_HEARTBEAT_RFC_6520__)
MOC_EXTERN MSTATUS SSL_SOCK_sendHeartbeatMessage(SSLSocket *pSSLSock,
                                                 ubyte *pPayload, ubyte2 payloadLen,
                                                 intBoolean isRequest);
MOC_EXTERN MSTATUS SSL_SOCK_processHeartbeatMessage(SSLSocket *pSSLSock,
                                                    ubyte *pMsg, ubyte2 msgLen);
#endif
#ifdef __cplusplus
}
#endif

#endif
