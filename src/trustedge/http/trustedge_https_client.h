/*
 * um_https_client.h
 *
 * UM HTTPS Client header
 *
 * Copyright Mocana Corp 2009. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */


/*------------------------------------------------------------------*/

#ifndef __UMHTTPSCLIENT_HEADER__
#define __UMHTTPSCLIENT_HEADER__

#include "../../common/mjson.h"
#include "../../crypto/cert_store.h"

#include "../../http/http_context.h"

// #include "um_decl.h"
// #include "um_client_daemon_priv.h"
// #include "um_client_daemon.h"
// #include "um_state_manager.h"
// #include "um_utils.h"

#define NO_UPDATES_NEEDED           (20)
#define UPDATES_NEEDED              (21)

#define REQUEST_ID_FILE             "um_client_request_id"
#define DEVICE_ID_FILE              "um_client_device_id"

#define BASIC_AUTH                  "basicAuth"
#define API_KEY_AUTH                "ApiKeyAuth"

#define AUTH_FILE                   "um_auth.json"
#define DEFAULT_AUTH_FILE           "tpuc_default_auth.json"

#define DEFAULT_TRANSACTION_TIMEOUT     (10)
#define DEFAULT_DOWNLOAD_TIMEOUT        (5 * 60)

#define DEFAULT_SERVER_RETRY_MAX_CNT    (2)
#define DEFAULT_SERVER_RETRY_DELAY_SECS (1 * 60)

#define HTTP_ERROR_CODE_202                     (-12018)
#define HTTP_ERROR_CODE_202_TIMEOUT             (30 * 60)   /* 30 Minutes */

#define HTTP_ERROR_CODE_401_REVOKED               (-6019)
#define HTTP_ERROR_CODE_406_DUPLICATE_REQUEST_ID  (-6033)

typedef enum
{
    TRUSTEDGE_MSG_REGISTER = 0,
    TRUSTEDGE_MSG_SYNC,
    TRUSTEDGE_MSG_GET_PACKAGE_LIST,
    TRUSTEDGE_MSG_GET_PACKAGE,
    TRUSTEDGE_MSG_GET_SIGNING_CERTS,
    TRUSTEDGE_MSG_GET_TRUST_CERTS,
    TRUSTEDGE_MSG_UPDATE_CERT,
    TRUSTEDGE_MSG_SIGNING_REQUEST,
    TRUSTEDGE_MSG_EVENT_ACK,
    TRUSTEDGE_MSG_CUSTOM,
    TRUSTEDGE_MSG_CONFIGURATION_EVENT,
    TRUSTEDGE_MSG_UNKNOWN
} TRUSTEDGE_RequestMsgType;

typedef enum
{
    TRUSTEDGE_HTTP_RX_UPDATE = 0,
    TRUSTEDGE_HTTP_RX_API_KEY,
    TRUSTEDGE_HTTP_RX_PKG_LIST,
    TRUSTEDGE_HTTP_RX_FINISH,
    TRUSTEDGE_HTTP_RX_ERROR,
} TRUSTEDGE_HTTPResultType;

typedef enum
{
    TEST_PackageList1 = 0,
    TEST_PackageList2,
    TEST_PackageList3,
    TEST_PackageList4,
    TEST_PackageList5,
    TEST_PackageList6,
    TEST_PackageList7,
    TEST_PackageList8,
    TEST_PackageList9,
    TEST_PackageNum
} TRUSTEDGE_HttpPkgTestIdType;

typedef enum
{
    TRUSTEDGE_IDENTITY_CERTIFICATE =           (1 << 0),
    TRUSTEDGE_IDENTITY_CERTIFICATE_SUBJECT =   (1 << 1),
    TRUSTEDGE_IDENTITY_CERTIFICATE_ISSUER =    (1 << 2),
    TRUSTEDGE_IDENTITY_ROOT_OF_TRUST_CERT =    (1 << 3),
    TRUSTEDGE_IDENTITY_ROOT_OF_TRUST_KEYBLOB = (1 << 4)
} TRUSTEDGE_Identity;

#define MAX_HTTPS_THREADS            (4)

typedef struct HttpsClientCtx HttpsClientCtx;

typedef MSTATUS (*TRUSTEDGE_requestPrepareHeader)(
        HttpsClientCtx *pCtx, httpContext *pHttpContext);
typedef MSTATUS (*TRUSTEDGE_responseParse)(
        HttpsClientCtx *pCtx);

typedef struct HttpsClientCtx
{
//     TRUSTEDGE_HttpPkgTestIdType        pkgListTestId;
//     TRUSTEDGE_DaemonCtx*               daemonCtx;
//     intBoolean                  singleUpdateMode;
//     intBoolean                  registrationComplete;
//     sbyte *                     deviceID;
//     sbyte *                     deviceCreds;
    sbyte *                     serverAddress;
    sbyte *                     serverIPAddress;
    ubyte4                      serverPort;
    sbyte *                     serverRestPrefix;
    certStorePtr                pTrustStore;
    /* */
    intBoolean                  requireOSCPEnable;
    intBoolean                  mutualAuthEnable;
    sbyte *                     sslServerCertFileName;
    sbyte *                     sslClientCertFileName;
    sbyte *                     sslClientKeyFileName;
    sbyte *                     sslClientAlias;
    /* */
    sbyte *                     nonce;
    sbyte *                     signatureAlgoId;
    byteBoolean                 excludeChain;
    sbyte *                     serverURI;
    sbyte *                     signatureCertFileName;
    sbyte *                     signatureKeyFileName;
    sbyte *                     authType;
    sbyte *                     authValue;
    RTOS_THREAD                 threadHandle;
//     TRUSTEDGE_WaitCtx*                 waiterCtx;
    MSTATUS                     workerStatus;
    ubyte4                      httpsTransactionTimeout;
    ubyte4                      httpsDownloadTimeout;
    void *                      pUserData;
    TRUSTEDGE_RequestMsgType           requestMsgType;
    TRUSTEDGE_requestPrepareHeader     requestPrepareHeader;
    sbyte *                     requestMsg;
    ubyte4                      requestMsgLen;
    ubyte4                      requestId;
    ubyte4                      responseStatus;
    TRUSTEDGE_responseParse            responseParse;
    sbyte *                     responseMsg;
    ubyte4                      responseMsgLen;
    sbyte *                     responseMsgFileName;
    sbyte *                     responseBodyTempFileName;
    ubyte4                      responseBodyTempFD;
    ubyte4                      httpThreadRunning;
    RTOS_MUTEX                  httpThreadRunningLock;
    httpContext *               pCurrHttpContext;
    sbyte4                      connectionSSLInstance;
    intBoolean                  httpKillClient;
    sbyte *                     redirectURI;
    ubyte                       redirectURILen;
    intBoolean                  acceptOctetStream;
    sbyte *                     serverDownloadAddress;
    ubyte4                      serverDownloadPort;
    sbyte *                     serverDownloadURI;
    ubyte4                      serverRetryMaxCount;
    ubyte4                      serverRetryDelaySeconds;
    TCP_SOCKET                  serverSocket;
    TRUSTEDGE_Identity                 identity;
} HttpsClientCtx;

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsReleaseContext : de-initialize the context struct used
 *   for HTTPS operations in UM.
 *
 *   Parameters :
 *     HttpsClientCtx **ppContext :: The HTTPS context struct
 *       that is released by this call.
 *     MSTATUS *umStatus :: The supplemental status returned.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsReleaseContext(
        HttpsClientCtx **ppContext,
        MSTATUS *umStatus);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsRegisterProcess : Build the device registration
 *   message and send it to the server register URI.
 *
 *   Parameters :
 *     HttpsClientCtx pHttpsClientCtxt :: The HTTPS context struct
 *     MSTATUS *umStatus :: The supplemental status returned
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsRegisterProcess(
        HttpsClientCtx *pHttpsClientCtx,
        MSTATUS *umStatus);

/* TRUSTEDGE_clientHttpsEventAckProcess : Build the device event ack
 *   message and send it to the server event ack URI.
 *
 *   Parameters :
 *     HttpsClientCtx pHttpsClientCtxt :: The HTTPS context struct
 *     ubyte *pMsg :: Event acknowledgement message
 *     ubyte4 msgLen :: Event acknowledgement message length
 *     MSTATUS *umStatus :: The supplemental status returned
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsEventAckProcess(
        HttpsClientCtx *pHttpsClientCtx,
        ubyte *pMsg,
        ubyte4 msgLen,
        MSTATUS *umStatus);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalAcquireContext : Initialize the context struct used
 *   for local HTTPS operations
 *
 *   Parameters :
 *     sbyte *pRspDir :: Directory where HTTPS response is stored
 *     HttpsClientCtx **pNewContext :: The returned HTTPS
 *     context struct that is created by this call.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalAcquireContext(
        sbyte *pRspDir,
        HttpsClientCtx **ppNewContext);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalReleaseContext : de-initialize the context struct used
 *   for local HTTPS operations
 *
 *   Parameters :
 *     HttpsClientCtx **ppContext :: The HTTPS context struct
 *       that is released by this call.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalReleaseContext(
        HttpsClientCtx **ppContext);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalApplyServerConfig : apply server configuration to the
 *    local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     sbyte *pHostName :: Host name to connect to
 *     ubyte4 port :: Port number to connect to
 *     certStorePtr pStore :: Certificate store used for SSL connection
 *     sbyte *pMutualAuthAlias :: Mutual authenticaion alias to pick up from the
 *       certificate store. If NULL, no mutual authentication is done.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalApplyServerConfig(
        HttpsClientCtx *pCtx,
        sbyte *pHostName,
        ubyte4 port,
        certStorePtr pStore,
        sbyte *pMutualAuthAlias);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalSetCustomMsg : set custom message and data/handlers for
 *    custom message in the local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     ubyte *pMsg :: Message buffer
 *     ubyte4 msgLen :: Length of message in bytes
 *     void *pUserData :: User data provided to HTTP client callbacks
 *     TRUSTEDGE_requestPrepareHeader requestPrepareHeader :: HTTP header callback
 *     TRUSTEDGE_responseParse responseParse :: HTTP response callback
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalSetCustomMsg(
        HttpsClientCtx *pCtx,
        ubyte *pMsg,
        ubyte4 msgLen,
        void *pUserData,
        TRUSTEDGE_requestPrepareHeader requestPrepareHeader,
        TRUSTEDGE_responseParse responseParse);

/*------------------------------------------------------------------*/

/* TRUSTEDGE_clientHttpsLocalGetUserData : get user data in the local HTTPS context
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS context struct
 *     void **ppUserData :: Location where user data is stored
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalGetUserData(
        HttpsClientCtx *pCtx,
        void **ppUserData);

/* TRUSTEDGE_clientHttpsAcquireContext : Initialize the context struct used
 *   for HTTPS operations in UM
 *
 *   Parameters :
 *     UM_DaemonCtx *ctx :: The context created for the UM daemon.
 *     JSON_ContextType *pConfigJson :: The context created for
 *       parsing the config.json file.
 *     UM_HttpsClientCtx **pNewContext :: The returned HTTPS
 *     context struct that is created by this call.
 *     MSTATUS *umStatus :: The supplemental status returned.
 */
MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsAcquireContext(
        HttpsClientCtx **ppNewContext,
        MSTATUS *umStatus);

/*------------------------------------------------------------------*/

#endif /* __UMHTTPSCLIENT_HEADER__ */
