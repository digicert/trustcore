/*
 * sshc_context.h
 *
 * SSHC Context Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __SSHC_CONTEXT_HEADER__
#define __SSHC_CONTEXT_HEADER__


/*------------------------------------------------------------------*/

#define SESSION_OPEN                    1
#define SESSION_CLOSING                 2
#define SESSION_CLOSED                  3

#define NUM_KEY_EXCHANGE_OPTIONS        16

#define SOCKET(X)                       (X)->socket
#define CONNECTION_INSTANCE(X)          (X)->connectionInstance
#define SSH_SESSION_ID(X)               (X)->pSessionId
#define SSH_OPTIONS_SELECTED(X)         (X)->optionsSelected

/* read only */
#define INBOUND_SEQUENCE_NUM(X)         ((ubyte4)((X)->sequenceNumIn))
#define OUTBOUND_SEQUENCE_NUM(X)        ((ubyte4)((X)->sequenceNumOut))

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
#define SSH_FTP_VERSION(X)              (X)->sessionState.sftpVersion
#define SSH_FTP_FILE_HANDLE_TABLE(X)    ((X)->sessionState.fileHandles)
#define SFTP_NUM_HANDLES                10

/* hello comment fields */
#define SERVER_HELLO_COMMENT(X)         (X)->pServerHelloComment
#define SERVER_HELLO_COMMENT_LEN(X)     (X)->serverHelloCommentLength
#define CLIENT_HELLO_COMMENT(X)         (X)->pClientHelloComment
#define CLIENT_HELLO_COMMENT_LEN(X)     (X)->clientHelloCommentLength

#define SSH_DH_CTX(X)                   (X)->sshKeyExCtx.p_dhContext
#define SSH_HASH_H(X)                   (X)->sshKeyExCtx.pHashH
#define SSH_K(X)                        (X)->sshKeyExCtx.pSharedSecret


/*------------------------------------------------------------------*/

/* This enum is used to identify which ciphers are selected
 * for inbound and outbound ciphers, they match the index of
 * mCipherSuites in ssh_trans.c */
enum mCiphers {
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES128_CIPHER__))
    AES_128_GCM,
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    AES_128_GCM_OPENSSH,
#endif
#endif
#if (defined(__ENABLE_MOCANA_GCM__) && !defined(__DISABLE_AES_CIPHERS__) && !defined(__DISABLE_AES256_CIPHER__))
    AES_256_GCM,
#ifndef __DISABLE_OPEN_SSH_AES_GCM__
    AES_256_GCM_OPENSSH,
#endif
#endif

#if defined(__ENABLE_MOCANA_CHACHA20__) && defined(__ENABLE_MOCANA_POLY1305__)
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    CHACHA20_POLY1305_OPENSSH,
#endif
#endif

#if (!defined(__DISABLE_AES_CIPHERS__))
#if (!defined(__DISABLE_AES128_CIPHER__))
    AES128_CTR,
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    AES128_CBC,
    RIJNDAEL128_CBC,
#endif
#endif
#if (!defined(__DISABLE_AES256_CIPHER__))
    AES256_CTR,
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    AES256_CBC,
    RIJNDAEL256_CBC,
#endif
#endif
#ifndef __DISABLE_AES192_CIPHER__
    AES192_CTR,
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    AES192_CBC,
    RIJNDAEL192_CBC,
#endif
#endif
#endif /* __DISABLE_AES_CIPHERS__ */
#ifdef __ENABLE_BLOWFISH_CIPHERS__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
    BLOWFISH_CBC,
#endif
#endif
#ifndef __DISABLE_3DES_CIPHERS__
#ifdef __ENABLE_MOCANA_SSH_WEAK_CIPHERS__
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
    kTransReceiveRSA,
    kTransReceiveRSADone,
    kTransReceiveECDH,
    kTransReceiveHybrid,
    kTransNewKeys,
    kAuthServiceRequest,
    kAuthReceiveMessage,

    kOpenState,

    kReduxTransAlgorithmExchange,
    kReduxTransReceiveDiffieHellmanClassic,
    kReduxTransReceiveDiffieHellmanGroup1,
    kReduxTransReceiveDiffieHellmanGroup2,
    kReduxTransReceiveRSA,
    kReduxTransReceiveRSADone,
    kReduxTransReceiveECDH,
    kReduxTransReceiveHybrid,
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

enum sshcChannelReqType
{
    kChannelRequestNothing,
    kChannelRequestSubsystem,
    kChannelRequestPty,
    kChannelRequestShell
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
    ubyte4                  authNumAttempts;

    /* public key iteration context */
    void*                   pFoundHint;
    ubyte4                  authTableIndex;     /* { (chain cert) or (leaf/naked key) } */
    ubyte4                  authPubKeyIndex;    /* index into auth key type table */

} authDescr;

struct sshClientContext;

typedef struct sshcKeyExMethods
{
    MSTATUS (*allocCtx)(struct sshClientContext *pContextSSH);
    MSTATUS (*freeCtx) (struct sshClientContext *pContextSSH);
    MSTATUS (*sendResp)(struct sshClientContext *pContextSSH);

} sshcKeyExMethods;

typedef struct sshcKeyExDescr
{
    diffieHellmanContext*       p_dhContext;
    AsymmetricKey               transientKey;

    BulkCtx                     pKeyExHash;
    ubyte*                      pHashH;
    vlong*                      pSharedSecret;

    ubyte*                      pBytesSharedSecret;
    ubyte4                      bytesSharedSecretLen;

    ubyte*                      pTempBuffer;
    ubyte4                      tempBufferLen;

} sshcKeyExDescr;

typedef struct sshcHashHandshake
{
    BulkCtxAllocFunc        pAllocFunc;
    BulkCtxFreeFunc         pFreeFunc;
    BulkCtxInitFunc         pInitFunc;
    BulkCtxUpdateFunc       pUpdateFunc;
    BulkCtxFinalFunc        pFinalFunc;

    ubyte4                  hashResultSize;

} sshcHashHandshake;

typedef struct
{
    sbyte*                  pDebugString;

    sbyte*                  pKeyExName;
    ubyte4                  keyExNameLength;

    ubyte4                  keyExHint;
    ubyte4                  qsKeyExHint;
    sshcKeyExMethods*       pKeyExMethods;
    sshcHashHandshake*      pHashHandshakeAlgo;

    const ubyte*            pCurveOID;

    /* more extensible, use these to deal with new types of exchange mechanisms */
    enum upperLayerStates   nextStateFirstExchange;
    enum upperLayerStates   nextStateReKeyExchange;

} SSHC_keyExSuiteInfo;

typedef struct SSHC_hostKeySuiteInfo
{
    sbyte*                  pHostKeyName;
    ubyte4                  hostKeyNameLength;
    sbyte*                  pSignatureName;
    ubyte4                  signatureNameLength;
    ubyte4                  authType;
    ubyte4                  hashLen;
    ubyte4                  identityType;
    MSTATUS (*pFuncParseCert)(struct sshClientContext *pContextSSH, const sshStringBuffer *pCertificate, AsymmetricKey *pPublicKey, vlong **ppVlongQueue);
    MSTATUS (*pFuncVerifySig)(struct sshClientContext *pContextSSH, AsymmetricKey *pKey, sshStringBuffer *pSignature, ubyte *pDigestData, ubyte4 digestLen, intBoolean *pRetIsGoodSignature, vlong **ppVlongQueue);

} SSHC_hostKeySuiteInfo;

/* generic algorithm definition for both combination algo, ie. encryption+hash, and AEAD algos */
typedef MSTATUS (*sshAeadCipher)   (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* nonce, ubyte4 nlen, ubyte* adata, ubyte4 alen, ubyte* data, ubyte4 dlen, ubyte4 verifyLen, sbyte4 encrypt);

typedef struct sshAeadAlgo
{
    ubyte4              nonceFixedLength;
    ubyte4              nonceInvocationCounter;
    ubyte4              authenticationTagLength;

    sshAeadCipher       funcCipher;

} sshAeadAlgo;

typedef struct SSH_CipherSuiteInfoTag
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
                                        const ubyte* textOpt, sbyte4 textOptLen, ubyte result[]); /* AB
 */
    sshAeadAlgo*            pAeadSuiteInfo;     /* AEAD algorithm data */

} SSH_hmacSuiteInfo;

typedef struct
{
    intBoolean              isChannelActive;
    intBoolean              isShellActive;
    ubyte4                  channelState;           /* open, closing, closed */
    ubyte4                  recipientChannel;       /* Server side channel number */
    ubyte4                  maxWindowSize;
    ubyte4                  maxPacketSize;
    ubyte4                  windowSize;
    ubyte4                  serverWindowSize;       /* keep the client honest */

    ubyte4                  ackRecvdData;
    ubyte4                  unAckRecvdData;
    moctime_t               timeOfLastAck;

    intBoolean              isEof;
#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
    ubyte4                  clientWindowSize;
#endif /* __ENABLE_MOCANA_SSH_FTP_CLIENT__ */
    intBoolean              rxdClosed;              /* true if other side sent closed */

    enum sshSessionStates sessionState;

    /* sftp/scp state information */
#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
    ubyte4                  sftpVersion;

    sshStringBuffer*        pCurrentPath;           /* set by user application code */

    sftpcFileHandleDescr    fileHandles[SFTP_NUM_HANDLES];

#endif /* __ENABLE_MOCANA_SSH_FTP_CLIENT__ */

#ifdef __ENABLE_MOCANA_SSH_CLIENT__
    ubyte4                  clientChannel;       /* Own/client side channel number */
    enum sshcChannelReqType channelRqstType;
#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */

} sshClientSession;

enum sftpClientInternalStates
{
    SFTP_NOTHING,
    SFTP_RECEIVE_MESSAGE_LENGTH,
    SFTP_RECEIVE_MESSAGE_BODY,
    SFTP_RECEIVE_MESSAGE_COMPLETED
};

#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
typedef struct lpfSession
{
    sshClientSession        lpfSessionData;
    struct lpfSession*      pNextSession;

} sshcPfSession;

typedef struct rpfContext
{
    intBoolean      isConfirmed;
    intBoolean      inUse;
    sshcPfSession*  pRpfSessionHead;
    ubyte4          bindPort;
    ubyte*          pBindAddr;
    ubyte4          hostPort;
    ubyte*          pHostAddr;
    ubyte4          assignedBindPort;
    ubyte4          channelList[SSH_MAX_REMOTE_PORT_FWD_CHANNEL];
}rpfContextData;
#endif /* #ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */

typedef struct sshClientContext
{
    TCP_SOCKET              socket;
    sbyte4                  connectionInstance;

#ifdef __ENABLE_MOCANA_SSH_ASYNC_CLIENT_API__
    sbyte4                  waitEvent;          /* 0 == none, 1 == auth, 2 == hw offload */
    ubyte*                  pAsyncCacheMessage;
    ubyte*                  pAsyncCacheTemp;
    ubyte4                  asyncCacheMessageLength;
#endif

#ifdef __ENABLE_MOCANA_SSH_FTP_CLIENT__
/*!!!! move to sshClientSession or create sftpSession structure */
    ubyte*                  p_sftpIncomingBuffer;
    ubyte4                  sftpIncomingBufferSize;
    ubyte4                  sftpNumBytesInBuffer;
    ubyte4                  sftpNumBytesRequired;
    ubyte4                  sftpState;
    ubyte                   sftpLengthBuffer[4];
#endif /* __ENABLE_MOCANA_SSH_FTP_CLIENT__ */

    /* Authentication Context */
    authDescr               authContext;

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

    sshStringBuffer         sshc_algorithmMethods[10];
/*
                            sshc_kexMethods,
                            sshc_hostKeyMethods,
                            sshc_encC2SMethods,
                            sshc_encS2CMethods,
                            sshc_macC2SMethods,
                            sshc_macS2CMethods,
                            sshc_compC2SMethods,
                            sshc_compS2CMethods,
                            sshc_langC2SMethods,
                            sshc_langS2CMethods
*/

    /* integrity key data */
    ubyte*                  pIntegrityKeyIn;
    ubyte4                  integrityKeyLengthIn;
    ubyte*                  pIntegrityKeyOut;
    ubyte4                  integrityKeyLengthOut;

    /* misc */
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

    /* key exchange computed values */
    SSHC_keyExSuiteInfo*    pKeyExSuiteInfo;
    sshcKeyExDescr          sshKeyExCtx;

    /* key exchange hash */
    ubyte*                  pSessionId;
    ubyte4                  sessionIdLength;        /* we need to keep track of original length for rekey */

    /* host key algo negotiated */
    SSHC_hostKeySuiteInfo*  pHostKeySuites;
    sshStringBuffer*        pCertificate;

    /* authentication */
    ubyte4                  authType;

    /* session related */
    sshClientSession        sessionState;
    void*                   pTerminal;

    ubyte4                  requestCounter;

    /* re-key exchange */
    intBoolean              isReKeyOccuring;        /* are we rekey-ing? */
    intBoolean              isReKeyInitiatedByMe;   /* did I initiate the key exchange? */
    intBoolean              isReKeyStrict;          /* do I strictly enforce re-keys?  */
    moctime_t               timeOfReKey;            /* if so, when did I request the re-key */
    ubyte4                  numMilliSecForReKey;    /* and how many milliseconds do they have to respond */
    ubyte8                  bytesTransmitted;       /* in & out bytes */

    /* developer programmable cookie */
    hwAccelDescr            hwAccelCookie;          /* hardware accelerator cookie */
    sbyte4                  cookie;
#ifdef __ENABLE_MOCANA_SSH_PORT_FORWARDING__
    sshcPfSession*          pLpfHead;
    rpfContextData          rpfTable[SSH_MAX_RPF_HOSTS];
#endif /* __ENABLE_MOCANA_SSH_PORT_FORWARDING__ */
#if 1
    /* for harness support */
    poolHeaderDescr         smallPool;
    poolHeaderDescr         mediumPool;
#endif

#ifdef __ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__
    sbyte*                  pCommonName;         /* NOT MALLOC'd */
    struct certStore*       pCertStore;
#endif

} sshClientContext;


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_CONTEXT_allocStructures(sshClientContext **ppContextSSH);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSHC_CONTEXT_deallocStructures(sshClientContext **ppContextSSH);


#endif /* __SSHC_CONTEXT_HEADER__ */
