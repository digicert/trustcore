/*
 * trustedge_agent_priv.h
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

#ifndef __TRUSTEDGE_AGENT_PRIV_HEADER__
#define __TRUSTEDGE_AGENT_PRIV_HEADER__

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/mjson.h"
#include "../../common/mtcp.h"
#include "../../common/uri.h"
#include "../../common/mrtos.h"
#include "../../common/mfmgmt.h"
#include "../../common/datetime.h"
#include "../../common/hash_table.h"
#include "../../common/protobuf.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/pkcs10.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../tap/tap_smp.h"
#endif
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/agent/trustedge_agent_policy_data_types.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent.h"
#include "../../trustedge/agent/trustedge_agent_artifact.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_PATH_LENGTH
#define MAX_PATH_LENGTH 1024
#endif

#define SERVICE_RENEWAL_HOURS               24
#define SERVICE_POLLING_INTERVAL            60
#define SERVICE_UPTIME_INTERVAL             60*60
#define SERVICE_SLEEP_INTERVAL              5*60*60
#define DEFAULT_MAX_RETRY_COUNT             5
#define DEFAULT_MAX_RETRY_COUNT_CERT_ENROLL 3
#define DEFAULT_KEEP_ALIVE_INTERVAL         600
#define DEFAULT_RECV_POLLING_INTERVAL       2000 /* ms */
#define DEFAULT_POLICY_REQUEST_TIMEOUT      100
#define ACTION_HANDLER_TIMEOUT              3*60
#define DEFAULT_TIMESTAMP_WINDOW            300
#define DEFAULT_MAX_ERROR_RESP              5
#define DEFAULT_PROTOCOL_BUFFER_SIZE        2048
#define DEFAULT_REFRESH_HOURS               24
#define DEFAULT_AGENT_RENEWAL_HOURS         24
#define DEFAULT_CHUNK_SIZE                  131072
#define DEFAULT_CHUNK_WINDOW_SIZE           4
#ifndef __DISABLE_TRUSTEDGE_REST_API__
#define DEFAULT_REQUEST_TYPE                "http"
#define DEFAULT_SERVER_FQDN                 "localhost"
#ifndef __DISABLE_TRUSTEDGE_HTTPS_REST_API__
#define DEFAULT_SERVER_KEYCERT_ALIAS        "trustedge-server"
#endif
#endif
#define CONFIGURATION_JSTR                  "configuration"
#define DEVICE_ID_JSTR                      "device_id"
#define DEVICE_NAME_JSTR                    "device_name"
#define ACCOUNT_ID_JSTR                     "account_id"
#define DIVISION_ID_JSTR                    "division_id"
#define DEVICE_GROUP_ID_JSTR                "device_group_id"
#define RENDEZVOUS_CONFIGURATION_JSTR       "rendezvous_configuration"
#define MQTT_ENDPOINT_JSTR                  "mqtt_endpoint"
#define PRIMARY_JSTR                        "primary"
#define SECONDARY_JSTR                      "secondary"
#define AUTHENTICATION_JSTR                 "authentication"
#define METHOD_JSTR                         "method"
#define X509_JSTR                           "x509"
#define KEY_ALIAS_JSTR                      "key_alias"
#define CERT_ALIAS_JSTR                     "cert_alias"
#define PEM_KEY_JSTR                        "pem_key"
#define PEM_CERT_JSTR                       "pem_cert"
#define PERSIST_CONNECTION_JSTR             "persist_connection"
#define DEVICE_ATTRIBUTES_JSTR              "device_attributes" /* Added as desired attributes */
#define KEY_JSTR                            "key"
#define VALUE_JSTR                          "value"

#define ISSUED_CERT_DIR                     "issued"

#define CONF_DIR_PLACEHOLDER                "$TRUSTEDGE_CONF_DIR"

#define JWS_AUTH_HEADER_ALG_RS256       "RS256"
#define JWS_AUTH_HEADER_ALG_RS384       "RS384"
#define JWS_AUTH_HEADER_ALG_RS512       "RS512"
#define JWS_AUTH_HEADER_ALG_ES256       "ES256"
#define JWS_AUTH_HEADER_ALG_ES384       "ES384"
#define JWS_AUTH_HEADER_ALG_ES512       "ES512"
#define JWS_AUTH_HEADER_ALG_PS256       "PS256"
#define JWS_AUTH_HEADER_ALG_PS384       "PS384"
#define JWS_AUTH_HEADER_ALG_PS512       "PS512"
#define JWS_AUTH_HEADER_ALG_MLDSA44     "ML-DSA-44"
#define JWS_AUTH_HEADER_ALG_MLDSA65     "ML-DSA-65"
#define JWS_AUTH_HEADER_ALG_MLDSA87     "ML-DSA-87"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128F  "SLH-DSA-SHA2-128F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_128S  "SLH-DSA-SHA2-128S"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192F  "SLH-DSA-SHA2-192F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_192S  "SLH-DSA-SHA2-192S"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256F  "SLH-DSA-SHA2-256F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHA2_256S  "SLH-DSA-SHA2-256S"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128F "SLH-DSA-SHAKE-128F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_128S "SLH-DSA-SHAKE-128S"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192F "SLH-DSA-SHAKE-192F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_192S "SLH-DSA-SHAKE-192S"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256F "SLH-DSA-SHAKE-256F"
#define JWS_AUTH_HEADER_ALG_SLHDSA_SHAKE_256S "SLH-DSA-SHAKE-256S"

/*----------------------------------------------------------------------------*/

typedef struct
{
    sbyte *pPolicyType;
    sbyte *pPolicyId;
} TrustEdgeAgentPolicyDependencyFields;

typedef struct
{
    ubyte4 count;
    TrustEdgeAgentPolicyDependencyFields *pPolicies;
}TrustEdgeAgentPolicyDependency;

typedef enum
{
    TE_METRICS_FILE = 1,
    TE_DESIRED_ATTRIBUTES_FILE
} FileChoice;

typedef struct
{
    ubyte *pAuthKey;
    ubyte4 authKeyLen;
    ubyte *pAuthCert;
    ubyte4 authCertLen;
    sbyte *pDeviceId;
    sbyte *pDeviceName;
    sbyte *pAccountId;
    sbyte *pDivisionId;
    sbyte *pDeviceGroupId;
} TrustEdgeAgentConfig;

typedef struct
{
    URI **ppEndpoints;
    ubyte4 totalEndpoints;
    ubyte4 connEPIdx;
    TCP_SOCKET socket;
    sbyte4 sslConnInst;
    TCP_SOCKET socketProxy;
    sbyte4 transportProxy;
    byteBoolean persistConnection;
    MSTATUS status;
} TrustEdgeAgentMqtt;

typedef struct
{
    sbyte *pName;
    ubyte4 nameLen;
    sbyte *pValue;
    ubyte4 valueLen;
} TrustEdgeAgentMetric;

typedef enum
{
    TE_TOPIC_FIRST = 0,
    TE_TOPIC_NCMD = TE_TOPIC_FIRST,
    TE_TOPIC_NBIRTH = 1,
    TE_TOPIC_NDATA = 2,
    TE_TOPIC_GCMD = 3,
    TE_TOPIC_NDEATH = 4,
    TE_TOPIC_LAST
} TrustEdgeAgentTopic;

enum
{
    TE_TOPIC_CMD_SUB = 1
};

typedef struct
{
    ubyte4 attributes;
    sbyte *pTopic;
} TrustEdgeAgentTopicEntry;

typedef enum
{
    TE_MSG_TYPE_UNKNOWN,
    TE_MSG_TYPE_PENDING_POLICIES,
    TE_MSG_TYPE_CERTIFICATE_SPECIFICATION,
    TE_MSG_TYPE_ISSUED_CERTIFICATE,
    TE_MSG_TYPE_CERTIFICATE_RENEW,
    TE_MSG_TYPE_RELEASE_ARTIFACT_LIST,
    TE_MSG_TYPE_ARTIFACT_DOWNLOAD,
    TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK,
    TE_MSG_TYPE_CLOUDPLATFORM,
    TE_MSG_TYPE_ERROR_RESPONSE
} TrustEdgeAgentMessageType;

typedef enum
{
    TE_MODE_TYPE_UNKNOWN,
    TE_MODE_TYPE_POLICY_REQUEST,
    TE_MODE_TYPE_UPDATE_ARTIFACT_REQUEST,
    TE_MODE_TYPE_UPDATE_ARTIFACT_CHUNK_REQUEST,
    TE_MODE_TYPE_UPDATE_DEPLOY_PROGRESS,
    TE_MODE_TYPE_UPDATE_DEPLOY_COMPLETE,
    TE_MODE_TYPE_UPDATE_DEPLOY_FAILED,
    TE_MODE_TYPE_CERTIFICATE_SPECIFICATION,
    TE_MODE_TYPE_CERTIFICATE_ISSUE,
    TE_MODE_TYPE_CLOUDPLATFORM_REQUEST
} TrustEdgeAgentMode;

typedef enum
{
    TE_POLICY_TYPE_CERTIFICATE,
    TE_POLICY_TYPE_UPDATE,
    TE_POLICY_TYPE_CLOUDPLATFORM
} TrustEdgeAgentPolicyType;

typedef enum
{
    TE_POLICY_STATUS_PENDING,
    TE_POLICY_STATUS_SUCCESS,
    TE_POLICY_STATUS_FAILURE,
    TE_POLICY_STATUS_UNKNOWN,
    TE_POLICY_STATUS_ROLLBACK
} TrustEdgeAgentPolicyStatus;

typedef struct TrustEdgeAgentPolicyNode
{
    TrustEdgeAgentPolicyType type;
    sbyte *pId;
    sbyte *pDeviceGroupId;
    sbyte *pDeploymentId;
    sbyte4 priority;
    sbyte *pCreationTimestamp;
    TrustEdgeAgentPolicyStatus status;
    TrustEdgeAgentMessageType lastMsgSentType;
    sbyte *pProccessingTimestamp;
    sbyte *pCompletionTimestamp;
    sbyte *pAlias;
    ubyte *pCertSpecJson;
    ubyte4 certSpecJsonLen;
    intBoolean hasFailed;
    sbyte4 errorResponseCount;
    TrustEdgeAgentArtifactNode *pArtifactList;
    TrustEdgeAgentPolicyDependency *pDependency;
    sbyte *pServerErrorMsg;
    struct TrustEdgeAgentPolicyNode *pNext;
} TrustEdgeAgentPolicyNode;

typedef enum
{
    TE_CERT_SPEC_SOURCE_NONE        = 0,
    TE_CERT_SPEC_SOURCE_SW          = 1
} TrustEdgeAgentCertSpecSource;

typedef enum
{
    TE_REQ_FORMAT_NONE      = 0,
    TE_REQ_FORMAT_PKCS10    = 1
} TrustEdgeAgentCertSpecFormat;

typedef struct
{
    /* key attributes */
    CertKeyCtx keyCtx;

    /* csr attributes */
    CertCsrCtx csrCtx;

} TrustEdgeAgentCertSpec;

typedef struct
{
    AsymmetricKey *pNewKey;
    TrustEdgeAgentCertSpec *pCertSpec;
    ubyte *pCSR;
    ubyte4 csrLen;
#if defined(__ENABLE_DIGICERT_TAP__)
    byteBoolean primary;
    ubyte8 certHandle;
#endif
} TrustEdgeAgentPolicyDataCPS;

typedef struct
{
    TrustEdgeAgentArtifactNode *pArtifactHead;
    TrustEdgeAgentArtifactNode *pArtifact;
} TrustEdgeAgentPolicyDataUPS;

typedef struct
{
    ubyte **ppX5t256;
    ubyte4 count;
} TrustEdgeAgentPolicyDataCPPS;

typedef enum
{
    TE_POLICY_STAGE_UNKNOWN,
    TE_POLICY_STAGE_CPS_CERT_SPEC_REQ_CREATE,
    TE_POLICY_STAGE_CPS_CERT_SPEC_RSP_PARSE,
    TE_POLICY_STAGE_CPS_CERT_SPEC_KEY_GEN,
    TE_POLICY_STAGE_CPS_CERT_SPEC_CSR_GEN,
    TE_POLICY_STAGE_CPS_ISSUED_CERT_REQ_CREATE,
    TE_POLICY_STAGE_CPS_ISSUED_CERT_RSP_PARSE,
    TE_POLICY_STAGE_CPS_ISSUED_CERT_TRUSTBUNDLE,
    TE_POLICY_STAGE_CPS_ISSUED_CERT_KEY_AND_CERT_PAIR
} TrustEdgeAgentPolicyStage;

typedef struct ErrorResponseMsg
{
    intBoolean isSet;
    TrustEdgeAgentPolicyType type;
    sbyte *pPolicyId;
    sbyte *pDeploymentId;
    sbyte *pArtifactId;
    sbyte *pDeviceId;
    sbyte *pAccountId;
    TrustEdgeAgentMode mode;
    sbyte *pTimestamp;
    sbyte *pErrorCode;
    sbyte *pErrorString;
    intBoolean fatal;
} ErrorResponseMsg;


typedef struct
{
    /* Reference to policy */
    TrustEdgeAgentPolicyNode *pPolicy;
    TrustEdgeAgentMessageType lastPolicyMsgType;
    TrustEdgeAgentPolicyStage stage;
    MSTATUS policyErrorStatus;
    ErrorResponseMsg errorMsg;
    union
    {
        TrustEdgeAgentPolicyDataCPS cps;
        TrustEdgeAgentPolicyDataUPS ups;
        TrustEdgeAgentPolicyDataCPPS cpps;
    } data;
} TrustEdgeAgentPolicyState;

typedef struct
{
    sbyte *pUUID;
    TrustEdgeAgentMessageType msgType;
    sbyte **ppNames;
    sbyte **ppValues;
    ubyte4 metricCount;
    ubyte *pBody;
    ubyte4 bodyLen;
    FileDescriptor pArtifactFile;
} TrustEdgeAgentPBMsg;

typedef struct TrustedgeGlobalFuncTable
{
    funcPtrSafeToExitCallback pFuncOnSafeToExit;
    funcPtrDNSLookupCallback pFuncDNSLookup;
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
    funcPtrActionHandlerCallback pFuncActionHandler;
#endif
} TrustedgeGlobalFuncTable;

typedef struct
{
    sbyte *pBootstrapConfigFile;
    sbyte *pBootstrapSigFile;
    sbyte *pIssuedCertDir;
    sbyte *pWorkspaceDir;
    sbyte *pDebugDir;
    TrustEdgeAgentConfig configOptions;
    TrustEdgeAgentMqtt mqttConfig;
    ubyte4 totalMetrics;
    hashTableOfPtrs *pMetrics;
    hashTableOfPtrs *pDesiredAttributes;
    TrustEdgeConfig *pConfig;
    TrustEdgeAgentTopicEntry pAllTopics[TE_TOPIC_LAST];
    TrustEdgeAgentPolicyNode *pPendingPolicies;
    TrustEdgeAgentPolicyNode *pAppliedPolicies;
    TrustEdgeAgentPolicyNode *pErrorPolicies;
    TrustEdgeAgentPolicyState curPolicy;
    sbyte4 connInst;
    certStorePtr pTrustedStore;
    sbyte *pMetricFile;
    sbyte *pDesiredAttributeFile;
    sbyte *pPatFile; /* Policy Authorization Token */
    sbyte *pPatData; /* Policy Authorization Token */
    byteBoolean recievedPendingPolicies;
    byteBoolean needToProcessResponse;
    TrustEdgeAgentTopic curTopic;
    sbyte4 actionHandlerTimeout;
    sbyte4 connectionUptimeInterval;
    sbyte4 keepAliveInterval;
    sbyte4 sleepInterval;
    sbyte4 recvPollingInterval;
    sbyte4 refreshHours;
    sbyte4 maxRetryCount;
    byteBoolean exitClient;
    byteBoolean enforceToken;
    byteBoolean refreshToken;
    byteBoolean isPAT;
    sbyte4 timeoutWindow;
    sbyte4 maxErrorResponses;
    byteBoolean persistArtifact;
    byteBoolean service;
    ubyte4 protocolBufferSize;
    ProtobufContext *pPBCtx;
    TrustEdgeAgentPBMsg pbMsg;
    MSTATUS consumerStatus;
    ubyte8 lastAttrScanTime;
    TrustedgeGlobalFuncTable *pTable;
    ubyte *pChunkBuffer;
    ubyte4 chunkBufferSize;
    ubyte4 chunkBufferOffset;
    byteBoolean timeoutExpired;
    ubyte4 policyRequestTimeout;
    byteBoolean policyReqTimeoutExit;
    moctime_t policyReqTimer;
} TrustEdgeAgentCtx;

typedef MSTATUS (*funcPtrProcessMessage)(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType msgType,
    ubyte *pBody,
    ubyte4 bodyLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentIsMetricPresent(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pName,
    ubyte4 nameLen,
    intBoolean *present);

MOC_EXTERN MSTATUS TRUSTEDGE_agentAddMetric(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice,
    ubyte *pName,
    ubyte4 nameLen,
    ubyte *pVal,
    ubyte4 valLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentWriteMetrics(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCertSpecCreateRequest(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentCertSpec *pCertSpec,
    ubyte **ppReq,
    ubyte4 *pReqLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPublishMessage(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentTopic topic,
    ubyte *pMsg,
    ubyte4 msgLen);

MOC_EXTERN MSTATUS TRUSTEDGE_validateCurrentPolicy(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pDeploymentId,
    TrustEdgeAgentPolicyType type);

MOC_EXTERN MSTATUS TRUSTEDGE_agentGetAttribute(
    void *pArg,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentGetMetric(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pName,
    ubyte4 nameLen,
    ubyte **ppVal,
    ubyte4 *pValLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentProcessBody(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType msgType,
    ubyte *pBody,
    ubyte4 bodyLen);

MOC_EXTERN MSTATUS TRUSTEDGE_addDesiredAttributes(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pKey,
    ubyte4 keyLen,
    sbyte *pValue,
    ubyte4 valueLen
);

MOC_EXTERN intBoolean TRUSTEDGE_isLogPayloadEnabled();

MOC_EXTERN TrustedgeGlobalFuncTable *TRUSTEDGE_getFunctionTable(void);
MOC_EXTERN void TRUSTEDGE_freeDependentPolicies(
    TrustEdgeAgentPolicyDependency *pDependentPolicy);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_PRIV_HEADER__ */
