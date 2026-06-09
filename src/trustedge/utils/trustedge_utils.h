/*
 * trustedge_utils.h
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#ifndef __TRUSTEDGE_UTILS_HEADER__
#define __TRUSTEDGE_UTILS_HEADER__

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mtcp.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_chain.h"
#include "../../crypto/pkcs10.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/certificate/trustedge_certificate.h"
#include "../../trustedge/agent/trustedge_agent_policy_data_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCEP_JSTR                   "scep"
#define EST_JSTR                    "est"
#define JSON_EXT                    ".json"
#define SIG_EXT                     ".sig"

#define TRUSTEDGE_SUFFIX_TXT            ".txt"
#define TRUSTEDGE_SUFFIX_CRL            ".crl"
#define TRUSTEDGE_SUFFIX_PEM            ".pem"
#define TRUSTEDGE_SUFFIX_DER            ".der"
#define TRUSTEDGE_SUFFIX_OLD            ".old"
#define TRUSTEDGE_SUFFIX_PEM_OLD        ".pem" TRUSTEDGE_SUFFIX_OLD
#define TRUSTEDGE_SUFFIX_DER_OLD        ".der" TRUSTEDGE_SUFFIX_OLD
#define TRUSTEDGE_SUFFIX_PUB_TAPKEY     "-pub.tapkey"
#define TRUSTEDGE_SUFFIX_PRIV_TAPKEY    "-priv.tapkey"

#define TRUSTEDGE_METRICS_FILE              "metrics.pb"
#define TRUSTEDGE_DESIRED_ATTRIBUTE_FILE    "desired_attributes.pb"
#define TRUSTEDGE_ATTRIBUTES_FILE           "attributes.json"
#define TRUSTEDGE_BOOTSTRAP_FILE            "bootstrap_config.json"
#define TRUSTEDGE_BOOTSTRAP_SIG_FILE        "bootstrap_config.sig"
#define TRUSTEDGE_POLICY_AUTH_FILE          "policy_authorization.jwt"

#define SERVICE_REQUEST_DIR         "request"
#define SERVICE_PROCESSING_DIR      "processing"
#define SERVICE_COMPLETED_DIR       "completed"
#define SERVICE_FAILED_DIR          "failed"

#define BOOTSTRAP_KEYALIAS_JSTR     "key_alias"
#define BOOTSTRAP_CERTALIAS_JSTR    "cert_alias"

#ifndef TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS
#define TRUSTEDGE_AGENT_MAX_SLEEP_PERIOD_MS     (5000)
#endif

typedef struct
{
    sbyte *pBinDir;
    sbyte *pLibDir;
    sbyte *pRootDir;
    sbyte *pConfDir;
    sbyte *pDebugDir;
    sbyte *pKeystoreDir;
    sbyte *pKeystoreCADir;
    sbyte *pKeystoreCertsDir;
    sbyte *pKeystoreKeysDir;
    sbyte *pKeystoreReqDir;
    sbyte *pServiceDir;
    sbyte *pServiceRequestDir;
    sbyte *pServiceProcessingDir;
    sbyte *pServiceCompletedDir;
    sbyte *pServiceFailedDir;
    sbyte *pProxyUrl;
    sbyte *pBootstrapConfig;
    sbyte *pBootstrapSig;
    byteBoolean verifyBootstrapSig;
    sbyte *pWorkspaceDir;
    sbyte *pLogLevel;
    sbyte *pTrustEdgeMode;
    byteBoolean isCertFieldMissing;
    sbyte *pCertificateMode;
#ifndef __DISABLE_TRUSTEDGE_REST_API__
    sbyte *pRequestType;
    ubyte4 numProcess;
    ubyte4 numResource;
    ubyte4 port;
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
    sbyte *pServerKeyCert;
    sbyte *pServerFQDN;
#endif
#endif
    sbyte4 pollingInterval;
    sbyte4 renewalHours;
    sbyte4 connUptimeInterval;
    sbyte4 keepAliveInterval;
    sbyte4 recvPollingInterval;
    sbyte4 policyRequestTimeout;
    sbyte4 sleepInterval;
    sbyte4 refreshHours;
    sbyte4 actionHandlerTimeout;
    sbyte4 maxRetryCount;
    sbyte4 maxRetryCountCertEnroll;
    sbyte4 timestampWindow;
    sbyte4 maxErrorResponses;
    intBoolean enforceToken;
    intBoolean logPayload;
    intBoolean persistArtifact;
    ubyte4 protocolBufferSize;
    sbyte4 agentRenewalHours;
    intBoolean chunkSupported;
    ubyte4 chunkSize;
    ubyte4 chunkWindowSize;
    intBoolean requirePQC;
    sbyte *pProviderCredsDir;
    intBoolean exitClient;
} TrustEdgeConfig;

#define KEY_SOURCE_SW                "SW"
#define KEY_SOURCE_SW_LEN            (2)
#define KEY_SOURCE_SW_SERVER         "SW_SERVER"
#define KEY_SOURCE_SW_SERVER_LEN     (9)
#define KEY_SOURCE_TPM2              "TPM2"
#define KEY_SOURCE_TPM2_LEN          (4)
#define KEY_SOURCE_PKCS11            "PKCS11"
#define KEY_SOURCE_PKCS11_LEN        (6)
#define KEY_SOURCE_TEE               "TEE"
#define KEY_SOURCE_TEE_LEN           (3)
#define KEY_SOURCE_NANOROOT          "NANOROOT"
#define KEY_SOURCE_NANOROOT_LEN      (8)

typedef enum
{
    TRUSTEDGE_KEY_SOURCE_UNDEFINED = 0,
    TRUSTEDGE_KEY_SOURCE_SW,
    TRUSTEDGE_KEY_SOURCE_SW_SERVER,
    TRUSTEDGE_KEY_SOURCE_TPM2,
    TRUSTEDGE_KEY_SOURCE_PKCS11,
    TRUSTEDGE_KEY_SOURCE_TEE,
    TRUSTEDGE_KEY_SOURCE_NANOROOT
} TrustEdgeAgentKeySource;

typedef enum
{
    KEY_FORMAT_TAP_PUBLIC_BLOB    = 1 << 0,
    KEY_FORMAT_TAP_PRIVATE_BLOB   = 1 << 1,
} KeyFormat;

typedef MSTATUS (*TrustEdgeFuncPtrFileMatch)(
    void *pArg,
    sbyte *pFile,
    ubyte4 fileLen,
    byteBoolean *pMatch);

/**
 * Get TrustEdge configuration path
 *
 * @param ppPath        Location where configuration path is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetConfigPath(sbyte **ppPath);

/**
 * Read JSON string value, will return NULL if JSON field is null
 *
 * @param pJCtx         JSON context
 * @param ndx           Index of JSON object
 * @param pName         Name of JSON string
 * @param ppString      Location where JSON string is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsReadJsonStrAllowNull(
    JSON_ContextType *pJCtx,
    ubyte4 ndx,
    sbyte *pName,
    sbyte **ppString);

/**
 * Read TrustEdge configuration
 *
 * @param ppConfig      Location where TrustEdge configuration is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *               code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsReadConfig(
    TrustEdgeConfig **ppConfig);

/**
 * Clone TrustEdge configuration
 *
 * @param pConfig       TrustEdge configuration to clone
 * @param ppConfig      Location where cloned TrustEdge configuration is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *               code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsCloneConfig(
    TrustEdgeConfig *pConfig,
    TrustEdgeConfig **ppConfig);

/**
 * Delete TrustEdge configuration
 *
 * @param ppConfig      TrustEdge configuration to delete
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsDeleteConfig(
    TrustEdgeConfig **ppConfig);

/**
 * Get time elapsed since epoch time
 *
 * @param pElapsedTime      Location where elapsed time is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *             code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetElapsedTime(
    ubyte4 *pElapsedTime);

/**
 * Function takes an ISO 8601 encoded date string and checks that it is within
 * the given time windwow
 *
 * @param pTimeStr      ISO 8601 encoded date string
 * @param timeWindow    Window, in seconds, that pTimeStr needs to be within
 *
 * @return         TRUE if time is within window, otherwise FALSE
 */
intBoolean TRUSTEDGE_utilsInValidTimeWindow(
    sbyte *pTimeStr,
    sbyte4 timeWindow);

intBoolean TRUSTEDGE_utilsInValidTimeWindowStr(
    sbyte *pTimeStr1,
    sbyte *pTimeStr2);

/**
 * Compares pTimeStr in the format YYYYMMDDHHMMSSZ to the timeout specified in
 * seconds. If the current time + timeout >= pTimeStr then this function returns
 * TRUE, otherwise it returns FALSE.
 *
 * @param pTimeStr          String in format YYYYMMDDHHMMSSZ
 * @param timeWindowSeconds Window, in seconds, that pTimeStr needs to be within
 *
 * @return         TRUE if time is beyond window, otherwise FALSE
 */
intBoolean TRUSTEDGE_utilsIsExpired(
    sbyte *pTimeStr,
    sbyte4 timeWindow);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsValidateCert(
    certStorePtr pCertStore,
    ubyte *pCert,
    ubyte4 certLen,
    byteBoolean validateTime);

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)
MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetCertInfo(
    TrustEdgeServiceCtx *pSrvCtx,
    ubyte *pCert,
    ubyte4 certLen);
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_utilsWriteSMPBlob(
    sbyte *pDirPath,
    sbyte *pBaseName,
    AsymmetricKey *pKey,
    KeyFormat formats);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsWriteKeyAndCert(
    TrustEdgeConfig *pConfig,
    sbyte *pBaseName,
    AsymmetricKey *pKey,
    ubyte *pCert,
    ubyte4 certLen
#if defined(__ENABLE_DIGICERT_TAP__)
    , CertEnrollTAPAttributes *pTapAttributes
#endif
    );

MOC_EXTERN MSTATUS TRUSTEDGE_utilsWriteTrustedCert(
    TrustEdgeConfig *pConfig,
    ubyte *pCert,
    ubyte4 certLen);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetTime(
    sbyte **ppCurrentTime,
    int whichformat);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsDeletePersisted(
    TrustEdgeConfig *pConfig);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsClearDir(
    sbyte *pDirPath,
    TrustEdgeFuncPtrFileMatch pMatch,
    void *pArg);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsFindPrivateKey(
    sbyte *pPath,
    ubyte *pDerCert,
    ubyte4 derCertLen,
    ubyte **ppKey,
    ubyte4 *pKeyLen,
    sbyte **ppBootstrapFile);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsLoadKey(
    sbyte *pKeyPath,
    AsymmetricKey **ppKey);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsExtractZip(
    sbyte *pZ,
    sbyte *pDst);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsExtractInlineZip(
    sbyte *pZ,
    ubyte4 offset,
    ubyte4 length,
    sbyte *pDst);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsComputeRawDigest(
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashAlgo,
    sbyte **ppDigest,
    sbyte4 *pDigestLen);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsComputeAsciiDigest(
    ubyte *pData,
    ubyte4 dataLen,
    ubyte hashAlgo,
    sbyte **ppDigestStr);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsBinToString(
    sbyte *pData,
    sbyte4 dataLen,
    sbyte **ppDataStr);

MOC_EXTERN sbyte* TRUSTEDGE_generateFileDigest(
    sbyte *pPath,
    ubyte hashAlgo,
    sbyte4 *pOutLen);

MOC_EXTERN sbyte4 TRUSTEDGE_utilsRemoveLineBreak(
    sbyte *pString,
    sbyte4 stringLen);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsDetermineKeyParams(
    AsymmetricKey *pKey,
    CertEnrollAlg *pCertEnrollAlg,
    TrustEdgeAgentKeySource *pKeySource);

typedef enum MsgLogLevel MsgLogLevel;
MOC_EXTERN intBoolean TRUSTEDGE_utilsGetConfigLogLevel(
    MsgLogLevel *pLogLevel);

MOC_EXTERN sbyte* TRUSTEDGE_utilsCloneString(
    const sbyte *pS);

MOC_EXTERN intBoolean TRUSTEDGE_utilsTokenValid(
    sbyte *pPolicyId,
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pToken);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsParseJWT(
    sbyte *pToken,
    sbyte4 tokenLen,
    sbyte **ppHeader,
    sbyte4 *pHeaderLen,
    sbyte **ppPayload,
    sbyte4 *pPayloadLen,
    sbyte **ppSignature,
    sbyte4 *pSignatureLen
);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsParseJWTHeader(
    sbyte *pHeader,
    sbyte4 headerLen,
    JWSAlg *pAlgId,
    certChainPtr *ppCertChain,
    certStorePtr pCertStore,
    byteBoolean isBootstrapVerifyFlow
);

MOC_EXTERN intBoolean TRUSTEDGE_utilsValidatePayload(
    sbyte *pPolicyId,
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pDeviceName,
    sbyte *pDeviceGroupId,
    sbyte *pPayload,
    sbyte4 payloadLen,
    byteBoolean isBootstrapVerifyFlow
);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsVerifyJWTSignature(
    JWSAlg alg,
    sbyte *pPlainText,
    sbyte4 plainTextLen,
    certChainPtr pCertChain,
    sbyte *pSig,
    sbyte4 sigLen,
    byteBoolean isBootstrapVerifyFlow
);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsProcessJWT(
    sbyte *pAccountId,
    sbyte *pDeviceId,
    sbyte *pDivisionId,
    sbyte *pToken,
    sbyte4 tokenLen,
    certStorePtr pCertStore
);

MOC_EXTERN ubyte4 TRUSTEDGE_utilsGetJWTSigAlg(
    sbyte *pAlgId);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetSigAlgStr(
    ubyte4 sigAlg,
    sbyte **ppSigAlgStr);

/**
 * Parses CMC response data. CMC response is expected to be PKCS7 signed data.
 * The PKCS7 signed data is validated against the certificate store provided.
 * An array of issued certificates is returned.
 *
 * @param pCMCData          CMC response data
 * @param cmcDataLen        Length of CMC response data
 * @param pCertStore        Certificate store to validate CMC response
 * @param ppCertDesc        Location where array of issued certificates is stored
 * @param pCertDescArrayLen Location where number of issued certificates is stored
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *               code from merrors.h
 */
MOC_EXTERN MSTATUS TRUSTEDGE_utilsParseCMCResponse(
    ubyte *pCMCData,
    ubyte4 cmcDataLen,
    AsymmetricKey *pAsymKey,
    certDescriptor **ppCertDesc,
    ubyte4 *pCertDescArrayLen);


MOC_EXTERN MSTATUS TRUSTEDGE_utilsProxyConnect(
    sbyte *pHostname,
    sbyte2 port,
    TCP_SOCKET *pSocket,
    TCP_SOCKET *pSocketProxy,
    sbyte4 *pTransportProxy,
    certStorePtr pStore);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsOneLineCert(
    sbyte *pCert,
    ubyte4 certLen,
    ubyte **ppOneLineCert,
    ubyte4 *pOneLineCertLen);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsOneLineCSR(
    sbyte *pCsr,
    ubyte4 csrLen,
    ubyte **ppOneLineCert,
    ubyte4 *pOneLineCertLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentGetKeyHashAlgorithm(
    CertEnrollAlg keyAlgorithm,
    ubyte4 *pHashId);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsGetHostByName(
    sbyte *pName,
    sbyte *pIpStr);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsUpdateBootstrapConfig(
    sbyte *pBootstrapConfig,
    sbyte *pBootstrapKeyFile,
    byteBoolean overwriteExistingKeyFile);

MOC_EXTERN MSTATUS TRUSTEDGE_agentAttributesCPUId(
    ubyte **ppVal,
    ubyte4 *pValLen);

MOC_EXTERN MSTATUS TRUSTEDGE_utilsEval(
    void *pEvalFunctionArg,
    byteBoolean *pUseDefault,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen);

MOC_EXTERN intBoolean TRUSTEDGE_sleepCheckStatusMS(
    ubyte4 sleepMS);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_UTILS_HEADER__ */
