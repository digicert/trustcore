/*
 * ssh_context.h
 *
 * SSH Context Header
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


/*------------------------------------------------------------------*/

#ifndef __SSH_CONTEXT_HEADER__
#define __SSH_CONTEXT_HEADER__


/*------------------------------------------------------------------*/

#define SESSION_OPEN                    1
#define SESSION_CLOSING                 2
#define SESSION_CLOSED                  3

#define KEX_ALGO                        0
#define HOST_KEY_ALGO                   1
#define CIPHER_C2S_ALGO                 2
#define CIPHER_S2C_ALGO                 3
#define MAC_C2S_ALGO                    4
#define MAC_S2C_ALGO                    5
#define NUM_KEY_EXCHANGE_OPTIONS        16

#define SOCKET(X)                       (X)->socket
#define CONNECTION_INSTANCE(X)          (X)->connectionInstance
#define SSH_SESSION_ID(X)               (X)->pSessionId
#define SSH_OPTIONS_SELECTED(X)         (X)->optionsSelected

/* read only */
#define INBOUND_SEQUENCE_NUM(X)         ((const ubyte4)((X)->sequenceNumIn))
#define OUTBOUND_SEQUENCE_NUM(X)        ((const ubyte4)((X)->sequenceNumOut))

/* read / write */
#define CLIENT_KEX_INIT_PAYLOAD(X)      (X)->pPayloadClientKexInit
#define CLIENT_KEX_INIT_PAYLOAD_LEN(X)  (X)->payloadClientKexInitLen
#define SERVER_KEX_INIT_PAYLOAD(X)      (X)->pPayloadServerKexInit
#define SERVER_KEX_INIT_PAYLOAD_LEN(X)  (X)->payloadServerKexInitLen

#define SSH_UPPER_STATE(X)              (X)->upperStateIn
#define SSH_TIMER_START_TIME(X)         (X)->timerStartTime
#define SSH_TIMER_MS_EXPIRE(X)          (X)->timerMsExpire

/* open state sessions: distinguish between normal shell and sftp/scp */
#define SSH_SESSION_STATE(X)            (X)->sessionState.sessionState

/* sftp/scp state information */
#ifdef __ENABLE_DIGICERT_SSH_FTP_SERVER__
#define SSH_FTP_VERSION(X)              (X)->sessionState.sftpVersion
#define SSH_FTP_FILE_HANDLE_TABLE(X)    ((X)->sessionState.fileHandles)
#define SFTP_NUM_HANDLES                10
#endif

/* hello comment fields */
#define SERVER_HELLO_COMMENT(X)         (X)->pServerHelloComment
#define SERVER_HELLO_COMMENT_LEN(X)     (X)->serverHelloCommentLength
#define CLIENT_HELLO_COMMENT(X)         (X)->pClientHelloComment
#define CLIENT_HELLO_COMMENT_LEN(X)     (X)->clientHelloCommentLength

#define SSH_DIFFIEHELLMAN_CONTEXT(X)    (X)->sshKeyExCtx.p_dhContext
#define SSH_HASH_H(X)                   (X)->pHashH
#define SSH_K(X)                        (X)->sshKeyExCtx.pSharedSecret


/*------------------------------------------------------------------*/

/* This enum is used to identify which ciphers are selected
 * for inbound and outbound ciphers, they match the index of
 * mCipherSuites in ssh_trans.c */
enum mCiphers {
#if (defined(__ENABLE_DIGICERT_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES128_CIPHER__))
    AES_128_GCM,
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    AES_128_GCM_OPENSSH,
#endif
#endif
#if (defined(__ENABLE_DIGICERT_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES256_CIPHER__))
    AES_256_GCM,
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    AES_256_GCM_OPENSSH,
#endif
#endif
#if defined(__ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    CHACHA20_POLY1305_OPENSSH,
#endif
#endif
#if (!defined(__DISABLE_AES_CIPHERS__))
#if (!defined(__DISABLE_AES128_CIPHER__))
    AES128_CTR,
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    AES128_CBC,
    RIJNDAEL128_CBC,
#endif
#endif
#if (!defined(__DISABLE_AES256_CIPHER__))
    AES256_CTR,
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    AES256_CBC,
    RIJNDAEL256_CBC,
#endif
#endif
#ifndef __DISABLE_AES192_CIPHER__
    AES192_CTR,
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    AES192_CBC,
    RIJNDAEL192_CBC,
#endif
#endif
#endif /* __DISABLE_AES_CIPHERS__ */
#ifdef __ENABLE_BLOWFISH_CIPHERS__
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    BLOWFISH_CBC,
#endif
#endif
#ifndef __DISABLE_3DES_CIPHERS__
#ifdef __ENABLE_DIGICERT_SSH_WEAK_CIPHERS__
    THREE_DES_CBC,
#endif
#endif
    IGNORE
};


/*------------------------------------------------------------------*/

enum upperLayerStates
{
    kTransAlgorithmExchange = 0,
    kTransReceiveDiffieHellmanClassic,
    kTransReceiveDiffieHellmanGroup1,
    kTransReceiveDiffieHellmanGroup2,
    kTransReceiveECDH,
    kTransReceiveHybrid,
    kTransReceiveRSA,
    kTransNewKeys,

    kAuthServiceRequest,
    kAuthReceiveMessage,

    kOpenState,

    kReduxTransAlgorithmExchange,
    kReduxTransReceiveDiffieHellmanClassic,
    kReduxTransReceiveDiffieHellmanGroup1,
    kReduxTransReceiveDiffieHellmanGroup2,
    kReduxTransReceiveECDH,
    kReduxTransReceiveHybrid,
    kReduxTransReceiveRSA,
    kReduxTransNewKeys
};


/*------------------------------------------------------------------*/

enum sshSessionStates
{
    kOpenShellState,
    kSftpReceiveHello,
    kSftpOpenState
};


/*------------------------------------------------------------------*/

enum sshChannelTypes
{
    kShell,
    kSftp,
    kPortForwarding,
    kExec
};


/*------------------------------------------------------------------*/

typedef struct
{
    ubyte*                  pMacBuffer;

} macContext;

typedef struct
{
      sshStringBuffer*      user;
      struct keyIntInfoReq* pInfoRequest;

} keyIntAuthContext;

typedef struct
{
    ubyte*                  pAuthFailueBuffer;
    keyIntAuthContext       kbdInteractiveAuthContext;
    sbyte4                  authMethod;

} authDescr;

struct sshContext;

typedef struct sshKeyExMethods
{
    MSTATUS (*allocCtx)(struct sshContext *pContextSSH);
    MSTATUS (*freeCtx) (struct sshContext *pContextSSH);
    MSTATUS (*sendResp)(struct sshContext *pContextSSH);

} sshKeyExCtxMethods;

typedef struct sshKeyExDescr
{
    diffieHellmanContext*       p_dhContext;
    AsymmetricKey               transientKey;

    BulkCtx                     pKeyExHash;
    vlong*                      pSharedSecret;
    ubyte*                      pBytesSharedSecret;
    ubyte4                      bytesSharedSecretLen;

} sshKeyExDescr;

typedef struct sshHashHandshake
{
    BulkCtxAllocFunc        pAllocFunc;
    BulkCtxFreeFunc         pFreeFunc;
    BulkCtxInitFunc         pInitFunc;
    BulkCtxUpdateFunc       pUpdateFunc;
    BulkCtxFinalFunc        pFinalFunc;

    ubyte4                  hashResultSize;

} sshHashHandshake;

typedef struct
{
    sbyte*                  pDebugString;

    sbyte*                  pKeyExName;
    ubyte4                  keyExNameLength;

    ubyte4                  keyExHint;
    ubyte4                  qsKeyExHint;

    sshKeyExCtxMethods*     pKeyExMethods;
    sshHashHandshake*       pHashHandshakeAlgo;
    const ubyte*            pCurveOID;

    /* more extensible, use these to deal with new types of exchange mechanisms */
    enum upperLayerStates   nextStateFirstExchange;
    enum upperLayerStates   nextStateReKeyExchange;

} SSH_keyExSuiteInfo;

typedef struct SSH_hostKeySuiteInfo
{
    sbyte*                  pHostKeyName;
    ubyte4                  hostKeyNameLength;
    sbyte*                  pSignatureName;
    ubyte4                  signatureNameLength;
    ubyte4                  authType;
    ubyte4                  hashLen;
    ubyte4                  minAlgoDetail;      /* this could be a curve or key size; if curve, the min and max should match however only the min is used */
    ubyte4                  maxAlgoDetail;      /* to force a certain key size have min and max match */
    ubyte4                  identityType;
    MSTATUS (*pFuncBuildCert)     (struct sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength);
    MSTATUS (*pFuncBuildSig)      (struct sshContext *pContextSSH, ubyte *pDigestData, ubyte4 digestLen, ubyte **ppSignature, ubyte4 *pSignatureLength, AsymmetricKey *pKey);
    MSTATUS (*pFuncBuildCertChain)(struct sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates);

} SSH_hostKeySuiteInfo;

/* generic algorithm definition for both combination algo, ie. encryption+hash, and AEAD algos */
typedef MSTATUS (*sshAeadCipher)   (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* nonce, ubyte4 nlen, ubyte* adata, ubyte4 alen, ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt);

typedef struct sshAeadAlgo
{
    ubyte4              nonceFixedLength;
    ubyte4              nonceInvocationCounter;
    ubyte4              authenticationTagLength;

    sshAeadCipher       funcCipher;

} sshAeadAlgo;

typedef struct SSH_CipherSuiteInfo
{
    sbyte*                  pCipherName;        /* cipher identification */
    ubyte4                  cipherNameLength;   /* number of bytes for name */
    sbyte4                  keySize;            /* size of key */
    sbyte4                  ivSize;             /* size of IV or block for block encryption */
    BulkEncryptionAlgo*     pBEAlgo;            /* the encryption functions */
    sshAeadAlgo*            pAeadSuiteInfo;     /* AEAD algorithm data */

} SSH_CipherSuiteInfo;

typedef struct
{
    sbyte*                  pHmacName;
    ubyte4                  hmacNameLength;
    sbyte4                  hmacKeyLength;
    sbyte4                  hmacDigestLength;
    MSTATUS                 (*hmacFunc)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte* key, sbyte4 keyLen, const ubyte* text, sbyte4 textLen,
                                        const ubyte* textOpt, sbyte4 textOptLen, ubyte result[]);
    sshAeadAlgo*            pAeadSuiteInfo;     /* AEAD algorithm data */
    byteBoolean             isEtm;

} SSH_hmacSuiteInfo;

#ifdef __ENABLE_DIGICERT_SSH_FTP_SERVER__
typedef struct
{
    intBoolean              isFileHandleInUse;
    intBoolean              isDirectoryHandle;
    sshStringBuffer*        pFullPath;
    void*                   pHandleName;
    void*                   fileObjectIndex;
    void*                   cookie;                     /* not used for directories */

    void*                   directoryReadCookie;        /* used for short-term directory state */
    sbyte4                  directoryReadState;         /* open, reading, closed */

    sbyte4                  readLocation;
    sbyte*                  pReadBuffer;
    sbyte4                  readBufferSize;
    sbyte4                  numBytesRead;

    sbyte4                  writeLocation;
    sbyte*                  pWriteBuffer;
    sbyte4                  writeBufferSize;

} sftpFileHandleDescr;
#endif /* __ENABLE_DIGICERT_SSH_FTP_SERVER__ */

typedef struct
{
    intBoolean              isChannelActive;
    intBoolean              isShellActive;
    intBoolean              isExecActive;
    ubyte4                  channelState;           /* open, closing, closed */
    ubyte4                  recipientChannel;
    ubyte4                  maxWindowSize;
    ubyte4                  maxPacketSize;
    ubyte4                  windowSize;
    ubyte4                  serverWindowSize;       /* keep the client honest */
    ubyte4                  ackRecvdData;
    ubyte4                  unAckRecvdData;
    moctime_t               timeOfLastAck;
    intBoolean              isEof;

    enum sshSessionStates sessionState;

    /* sftp/scp state information */
#ifdef __ENABLE_DIGICERT_SSH_FTP_SERVER__
    ubyte4                  sftpVersion;

    sshStringBuffer*        pCurrentPath;           /* set by user application code */

    ubyte4                  sftpGroupAccessPermissions;
    sftpFileHandleDescr     fileHandles[SFTP_NUM_HANDLES];

    streamDescr*            pSftpOutStreamDescr;

#endif /* __ENABLE_DIGICERT_SSH_FTP_SERVER__ */

} sshSession;

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
typedef struct pfSession
{
    sshSession              pfSessionData;
    ubyte4                  ownChannel;
    struct pfSession*       pNextSession;

} sshPfSession;
#endif /* #ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */

enum sftpInternalStates
{
    SFTP_NOTHING,
    SFTP_RECEIVE_MESSAGE_LENGTH,
    SFTP_RECEIVE_MESSAGE_BODY,
    SFTP_RECEIVE_MESSAGE_COMPLETED
};

typedef struct sshContext
{
    TCP_SOCKET              socket;
#ifdef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
    streamDescr*            pSocketOutStreamDescr;
#endif
    sbyte4                  connectionInstance;

#ifdef __ENABLE_DIGICERT_SSH_ASYNC_SERVER_API__
    sbyte4                  waitEvent;              /* 0 == none, 1 == auth, 2 == hw offload */
    ubyte*                  pAsyncCacheMessage;
    ubyte*                  pAsyncCacheTemp;
    ubyte4                  asyncCacheMessageLength;
#endif

#ifdef __ENABLE_DIGICERT_SSH_FTP_SERVER__
    ubyte*                  p_sftpIncomingBuffer;
    ubyte4                  sftpIncomingBufferSize;
    ubyte4                  sftpNumBytesInBuffer;
    ubyte4                  sftpNumBytesRequired;
    ubyte4                  sftpState;
    ubyte                   sftpLengthBuffer[4];
#endif /* __ENABLE_DIGICERT_SSH_FTP_SERVER__ */

    /* Authentication Context */
    authDescr               authContext;
    sshStringBuffer         authAdvertised;
    sbyte4                  advertisedMethods;
    ubyte4                  authAttempts;

    /* Inbound Context */
    ubyte*                  pReceiveBuffer;
    ubyte4                  maxBufferSizeIn;
    ubyte4                  receiveState;
    ubyte4                  bytesRead;
    ubyte4                  bytesToRead;
    ubyte4                  packetLengthIn;
    ubyte4                  paddingLengthIn;
    ubyte4                  payloadLengthIn;
    ubyte4                  sequenceNumIn;

    moctime_t               timerStartTime;
    ubyte4                  timerMsExpire;

    /* Outbound Context */
    ubyte*                  pTransmitBuffer;
    ubyte4                  maxBufferSizeOut;
    ubyte4                  sequenceNumOut;

    /* INBOUND data structures */
    enum upperLayerStates   upperStateIn;
    ubyte4                  maxMessageSizeIn;       /* MUST be a multiple of cipherBlockSize */
    macContext              macDescrIn;
    enum mCiphers           cryptTypeIn;
    void*                   cryptDescrIn;
    void*                   cryptDescrIn2;
    SSH_CipherSuiteInfo*    pDecryptSuiteInfoIn;
    SSH_hmacSuiteInfo*      pHmacSuiteInfoIn;
    ubyte*                  decryptIV;

    /* OUTBOUND data structures */
    ubyte4                  maxMessageSizeOut;      /* MUST be a multiple of cipherBlockSize */
    macContext              macDescrOut;
    enum mCiphers           cryptTypeOut;
    void*                   cryptDescrOut;
    void*                   cryptDescrOut2;

    SSH_CipherSuiteInfo*    pEncryptSuiteInfoOut;
    SSH_hmacSuiteInfo*      pHmacSuiteInfoOut;
    ubyte*                  encryptIV;

    /* integrity key data */
    ubyte*                  pIntegrityKeyIn;
    ubyte4                  integrityKeyLengthIn;
    ubyte*                  pIntegrityKeyOut;
    ubyte4                  integrityKeyLengthOut;

    /* misc */
    sshStringBuffer         useThisList[10];
    void*                   pRandomContext;

    ubyte*                  pServerHelloComment;
    ubyte4                  serverHelloCommentLength;
    ubyte*                  pClientHelloComment;
    ubyte4                  clientHelloCommentLength;

    ubyte*                  pPayloadClientKexInit;
    ubyte4                  payloadClientKexInitLen;
    ubyte*                  pPayloadServerKexInit;
    ubyte4                  payloadServerKexInitLen;

    ubyte                   optionsSelected[NUM_KEY_EXCHANGE_OPTIONS];

    /* re-key exchange */
    ubyte4                  prevMesgType;
    intBoolean              isReKeyOccuring;        /* are we rekey-ing? */
    intBoolean              isReKeyInitiatedByMe;   /* did I initiate the key exchange? */
    intBoolean              isReKeyStrict;          /* do I strictly enforce re-keys?  */
    moctime_t               timeOfReKey;            /* if so, when did I request the re-key */
    ubyte4                  numMilliSecForReKey;    /* and how many milliseconds do they have to respond */
    ubyte8                  bytesTransmitted;       /* in & out bytes */

    intBoolean              msgExtInfoEnabled;

    /* key exchange computed values */
    SSH_keyExSuiteInfo*     pKeyExSuiteInfo;
    sshKeyExDescr           sshKeyExCtx;
    ubyte*                  pHashH;
    intBoolean              kexGuessMismatch;
    intBoolean              keyExInitReceived;

    /* key exchange hash */
    ubyte*                  pSessionId;
    ubyte4                  sessionIdLength;        /* we need to keep track of original length for rekey */

    /* our host key / signature data */
    SSH_hostKeySuiteInfo*   pHostKeySuites;
    AsymmetricKey           hostKey;
    ubyte*                  pHostBlob;              /* K_S */
    ubyte4                  hostBlobLength;         /* length of K_S */

    certStorePtr            pCertStore;

    /* session related */
    sshSession              sessionState;
    void*                   pTerminal;
    ubyte4                  maxSessionTimeLimit;
    moctime_t               sessionStartTime;       /* only used, if max session enabled */

    /* developer programmable cookie */
    hwAccelDescr            hwAccelCookie;          /* hardware accelerator cookie */
    sbyte4                  cookie;

#ifdef __ENABLE_DIGICERT_SSH_PORT_FORWARDING__
    /* port forwarding state information */
    ubyte4                  portForwardingPermissions;
    sshSession              portForwardingSessionState;
    sshPfSession*           pPfSessionHead;
#endif /* __ENABLE_DIGICERT_SSH_PORT_FORWARDING__ */

    sbyte4                  errorCode;
#if 1
    /* for harness support */
    poolHeaderDescr         smallPool;
    poolHeaderDescr         mediumPool;
#endif

} sshContext;


/*------------------------------------------------------------------*/

/**
 *  @brief Allocates and initializes all structures required for an SSH context.
 * 
 *  @param ppContextSSH Pointer to receive the allocated SSH context
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CONTEXT_allocStructures(sshContext **ppContextSSH);

/**
 *  @brief Deallocates all structures used by the SSH context.
 * 
 *  @param ppContextSSH Pointer to the SSH context to deallocate
 * 
 *  @return \c OK (0) if successful; otherwise a negative number error code
 *         definition from merrors.h. To retrieve a string containing an
 *         English text error identifier corresponding to the function's
 *         returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS SSH_CONTEXT_deallocStructures(sshContext **ppContextSSH);

#endif /* __SSH_CONTEXT_HEADER__ */
