/*
 * trustedge_agent_policy.c
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

#include <stdio.h>
#ifdef __RTOS_LINUX__
#include <unistd.h>
#endif

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/base64.h"
#include "../../common/mrtos.h"
#include "../../common/datetime.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/cert_store.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../tap/tap.h"
#include "../../tap/tap_api.h"
#include "../../tap/tap_utils.h"
#endif
#include "../../crypto/sha256.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../mqtt/mqtt_client.h"
#if defined(__ENABLE_DIGICERT_TAP__)
#include "../../trustedge/utils/trustedge_tap.h"
#endif
#include "../../trustedge/agent/trustedge_agent_attributes.h"
#include "../../trustedge/agent/trustedge_agent_policy.h"
#include "../../trustedge/agent/trustedge_agent_protobuf.h"
#include "../../trustedge/agent/trustedge_agent_persist.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../est/est_cert_utils.h"
#include "../../est/est_client_api.h"
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
#include "../../trustedge/agent/trustedge_agent_debug.h"
#endif

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
#include "../../trustedge/agent/trustedge_state.h"
#endif

/* DeviceTM_Certificate_Specification_Request */
#define MQTT_CERTIFICATE_SPECIFICATION_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_specification\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_SPECIFICATION_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_specification\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"pkcs10\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"pkcs7\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"pkcs10\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"pkcs7\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_SKG_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"pkcs10\",\n" \
    "    \"generatedKeyAlgorithm\":\"%.*s\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"pkcs7\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_SKG_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"pkcs10\",\n" \
    "    \"generatedKeyAlgorithm\":\"%.*s\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"pkcs7\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_CMC_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"cmc\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"cmc\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_CMC_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"cmc\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"cmc\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_CMC_SKG_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"cmc\",\n" \
    "    \"generatedKeyAlgorithm\":\"%.*s\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"cmc\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_CERTIFICATE_REQUEST_CMC_SKG_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"csr\":\"%.*s\",\n" \
    "    \"csrFormat\":\"cmc\",\n" \
    "    \"generatedKeyAlgorithm\":\"%.*s\",\n" \
    "    \"trustbundleIncluded\":true,\n" \
    "    \"trustbundleFormat\":\"cmc\"\n" \
    "}\n"

/* DeviceTM_Certificate_Policy_Completed */
#define MQTT_CERTIFICATE_POLICY_COMPLETED_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_policy_completed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Certificate_Policy_Completed */
#define MQTT_CERTIFICATE_POLICY_COMPLETED_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_policy_completed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Certificate_Policy_Failed */
#define MQTT_CERTIFICATE_POLICY_FAILED_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_policy_failed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"deploymentFailure\":\n" \
    "    {\n" \
    "        \"errorCode\":\"%s\",\n" \
    "        \"errorDescription\":\"%s\",\n" \
    "        \"clientErrorCode\":%d,\n" \
    "        \"clientErrorDescription\":\"%s\"\n" \
    "    },\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Certificate_Policy_Failed */
#define MQTT_CERTIFICATE_POLICY_FAILED_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"CertificatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"certificate_policy_failed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"certificatePolicyId\":\"%s\",\n" \
    "    \"deploymentFailure\":\n" \
    "    {\n" \
    "        \"errorCode\":\"%s\",\n" \
    "        \"errorDescription\":\"%s\",\n" \
    "        \"clientErrorCode\":%d,\n" \
    "        \"clientErrorDescription\":\"%s\"\n" \
    "    }\n" \
    "}\n"

/* DeviceTM_Update_Policy_Request */
#define MQTT_UPDATE_POLICY_REQUEST_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_UPDATE_POLICY_REQUEST_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Progress */
#define MQTT_UPDATE_POLICY_PROGRESS_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_progress\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"progressState\":\"%s\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Progress */
#define MQTT_UPDATE_POLICY_PROGRESS_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_progress\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"progressState\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Artifact_Request */
#define MQTT_ARTIFACT_DOWNLOAD_REQ_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_artifact_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"downloadProtocolPreference\":[ \"mqtts\" ],\n" \
    "    \"chunkSupported\": true,\n" \
    "    \"maxChunkSize\": %lu,\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

#define MQTT_ARTIFACT_DOWNLOAD_REQ_MSG_NO_CHUNKING \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_artifact_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"downloadProtocolPreference\":[ \"mqtts\" ],\n" \
    "    \"chunkSupported\": false,\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Artifact_Request */
#define MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_artifact_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"downloadProtocolPreference\":[ \"mqtts\" ],\n" \
    "    \"chunkSupported\": true,\n" \
    "    \"maxChunkSize\": %lu\n" \
    "}\n"

#define MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG_NO_CHUNKING \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_artifact_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"artifactId\":\"%s\",\n" \
    "    \"downloadProtocolPreference\":[ \"mqtts\" ],\n" \
    "    \"chunkSupported\": false\n" \
    "}\n"

/* DeviceTM_Artifact_Chunk_Request */
#define MQTT_ARTIFACT_CHUNK_REQ_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\": \"UpdatePolicy\",\n" \
    "    \"deviceId\": \"%s\",\n" \
    "    \"accountId\": \"%s\",\n" \
    "    \"timestamp\": \"%s\",\n" \
    "    \"updatePolicyId\": \"%s\",\n" \
    "    \"deploymentId\": \"%s\",\n" \
    "    \"mode\": \"update_artifact_chunk_request\",\n" \
    "    \"artifactId\": \"%s\",\n" \
    "    \"artifactChunkOffset\": %lu,\n" \
    "    \"startSeqNum\": %lu,\n" \
    "    \"receiverWindowSize\": %lu,\n" \
    "    \"chunkSize\": %lu\n" \
    "}\n"

#define MQTT_ARTIFACT_CHUNK_REQ_MSG \
    "{\n" \
    "    \"policyService\": \"UpdatePolicy\",\n" \
    "    \"deviceId\": \"%s\",\n" \
    "    \"accountId\": \"%s\",\n" \
    "    \"timestamp\": \"%s\",\n" \
    "    \"updatePolicyId\": \"%s\",\n" \
    "    \"deploymentId\": \"%s\",\n" \
    "    \"mode\": \"update_artifact_chunk_request\",\n" \
    "    \"artifactId\": \"%s\",\n" \
    "    \"artifactChunkOffset\": %lu,\n" \
    "    \"startSeqNum\": %lu,\n" \
    "    \"receiverWindowSize\": %lu,\n" \
    "    \"chunkSize\": %lu,\n" \
    "    \"authorizationToken\": \"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Completed */
#define MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_completed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Completed */
#define MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_completed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Failed */
#define MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_failed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"deploymentFailure\":\n" \
    "    {\n" \
    "        \"errorCode\":\"%s\",\n" \
    "        \"errorDescription\":\"%s\"\n" \
    "    },\n" \
    "    \"authorizationToken\":\"%s\"\n" \
    "}\n"

/* DeviceTM_Update_Policy_Deployment_Failed */
#define MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_NO_AUTH_MSG \
    "{\n" \
    "    \"policyService\":\"UpdatePolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"update_policy_deployment_failed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"updatePolicyId\":\"%s\",\n" \
    "    \"deploymentId\":\"%s\",\n" \
    "    \"deploymentFailure\":\n" \
    "    {\n" \
    "        \"errorCode\":\"%s\",\n" \
    "        \"errorDescription\":\"%s\"\n" \
    "    }\n" \
    "}\n"

#define MQTT_POLICY_REFRESH \
    "{\n" \
    "    \"policyService\":\"rendezvousService\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"pending_policies_refresh\",\n" \
    "    \"deviceGroupId\":\"%s\"\n" \
    "}\n"

#define MQTT_CLOUDPLATFORM_POLICY_REQUEST_MSG \
    "{\n" \
    "    \"policyService\":\"CloudPlatformPolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"cloudplatform_policy_request\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"cloudPlatformPolicyId\":\"%s\",\n" \
    "    \"cloudPlatformCredentials\": [%s]\n" \
    "}\n"

#define MQTT_CLOUDPLATFORM_POLICY_COMPLETED_MSG \
    "{\n" \
    "    \"policyService\":\"CloudPlatformPolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"cloudplatform_policy_completed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"cloudPlatformPolicyId\":\"%s\"\n" \
    "}\n"

#define MQTT_CLOUDPLATFORM_POLICY_FAILED_MSG \
    "{\n" \
    "    \"policyService\":\"CloudPlatformPolicy\",\n" \
    "    \"deviceId\":\"%s\",\n" \
    "    \"accountId\":\"%s\",\n" \
    "    \"timestamp\":\"%s\",\n" \
    "    \"mode\":\"cloudplatform_policy_failed\",\n" \
    "    \"deviceGroupId\":\"%s\",\n" \
    "    \"cloudPlatformPolicyId\":\"%s\",\n" \
    "    \"cloudPlatformFailure\":\n" \
    "    {\n" \
    "        \"errorCode\":\"%s\",\n" \
    "        \"errorDescription\":\"%s\"\n" \
    "    }\n" \
    "}\n"

static MSTATUS TRUSTEDGE_agentConstructPolicyRefresh(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    ubyte **ppMsg,
    ubyte4 *pMsgLen)
{
    MSTATUS status;
    sbyte *pMsg = NULL;
    sbyte4 ret;
    sbyte *pTimeStamp = NULL;

    if (NULL == ppMsg || NULL == pMsgLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    ret = snprintf(NULL, 0, MQTT_POLICY_REFRESH,
                    pDeviceId,
                    pAccountId,
                    pTimeStamp,
                    pDeviceGroupId);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    ret = snprintf(pMsg, ret + 1, MQTT_POLICY_REFRESH,
                    pDeviceId,
                    pAccountId,
                    pTimeStamp,
                    pDeviceGroupId);
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    *ppMsg = pMsg; pMsg = NULL;
    *pMsgLen = ret;

exit:
    if (NULL != pMsg)
        DIGI_FREE((void **) &pMsg);

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

extern MSTATUS TRUSTEDGE_agentSendPolicyRefresh(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId)
{
    MSTATUS status;
    ubyte *pUUID = "DeviceTM_Pending_Policies_Refresh";
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    ubyte *pPublishMsg = NULL;
    ubyte4 publishMsgLen;

    status = TRUSTEDGE_agentConstructPolicyRefresh(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        &pReq,
        &reqLen);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
    DIGI_FREE((void **) &pReq);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
    DIGI_FREE((void **) &pPublishMsg);
    if (OK != status)
    {
        goto exit;
    }
exit:

    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pPublishMsg);
    return status;
}

static MSTATUS TRUSTEDGE_agentConstructUpdatePolicyDeploymentProgress(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pArtifactId,
    sbyte *pAuthorizationToken,
    enum TrustEdgeArtifactProgress progressState,
    ubyte **ppMsg,
    ubyte4 *pMsgLen)
{
    MSTATUS status;
    sbyte *pMsg = NULL;
    sbyte4 ret;
    sbyte *pTimeStamp = NULL;
    sbyte *pProgressState = NULL;

    if (NULL == ppMsg || NULL == pMsgLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    pProgressState = TRUSTEDGE_getArtifactProgressToString(progressState);

    if (pAuthorizationToken)
    {
        ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_PROGRESS_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pUpdatePolicyId,
                        pDeploymentId,
                        pArtifactId,
                        pProgressState,
                        pAuthorizationToken);
    }
    else
    {
        ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_PROGRESS_NO_AUTH_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pUpdatePolicyId,
                        pDeploymentId,
                        pArtifactId,
                        pProgressState);

    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    if (pAuthorizationToken)
    {
        ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_PROGRESS_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pUpdatePolicyId,
                        pDeploymentId,
                        pArtifactId,
                        pProgressState,
                        pAuthorizationToken);
    }
    else
    {
        ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_PROGRESS_NO_AUTH_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pUpdatePolicyId,
                        pDeploymentId,
                        pArtifactId,
                        pProgressState);

    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    *ppMsg = pMsg; pMsg = NULL;
    *pMsgLen = ret;

exit:
    if (NULL != pMsg)
        DIGI_FREE((void **) &pMsg);

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

#define ACK_CHUNK_MSG \
    "{\n" \
    "    \"policyService\": \"UpdatePolicy\",\n" \
    "    \"deviceId\": \"%s\",\n" \
    "    \"accountId\": \"%s\",\n" \
    "    \"timestamp\": \"%s\",\n" \
    "    \"updatePolicyId\": \"%s\",\n" \
    "    \"deploymentId\": \"%s\",\n" \
    "    \"mode\": \"update_artifact_chunk_request\",\n" \
    "    \"artifactId\": \"%s\",\n" \
    "    \"artifactChunkOffset\": %lu,\n" \
    "    \"ackSeqNum\": %lu,\n" \
    "    \"receiverWindowSize\": %lu,\n" \
    "    \"chunkSize\": %lu\n" \
    "}\n"

#define ACK_CHUNK_MSG_WITH_AUTH \
    "{\n" \
    "    \"policyService\": \"UpdatePolicy\",\n" \
    "    \"deviceId\": \"%s\",\n" \
    "    \"accountId\": \"%s\",\n" \
    "    \"timestamp\": \"%s\",\n" \
    "    \"updatePolicyId\": \"%s\",\n" \
    "    \"deploymentId\": \"%s\",\n" \
    "    \"mode\": \"update_artifact_chunk_request\",\n" \
    "    \"artifactId\": \"%s\",\n" \
    "    \"artifactChunkOffset\": %lu,\n" \
    "    \"ackSeqNum\": %lu,\n" \
    "    \"receiverWindowSize\": %lu,\n" \
    "    \"chunkSize\": %lu,\n" \
    "    \"authorizationToken\": \"%s\"\n" \
    "}\n"

extern MSTATUS TRUSTEDGE_agentSendDeploymentProgress(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pArtifactId,
    sbyte *pAuthorizationToken,
    enum TrustEdgeArtifactProgress progressState)
{
    MSTATUS status;
    ubyte *pUUID = "DeviceTM_Update_Policy_Deployment_Progress";
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    ubyte *pPublishMsg = NULL;
    ubyte4 publishMsgLen;

    MSG_LOG_print(MSG_LOG_INFO, "Sending deployment progress message (%s) for %s\n",
        TRUSTEDGE_getArtifactProgressToString(progressState), pArtifactId);
    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentProgress(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        pUpdatePolicyId,
        pDeploymentId,
        pArtifactId,
        pAuthorizationToken,
        progressState,
        &pReq,
        &reqLen);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
    DIGI_FREE((void **) &pReq);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
    DIGI_FREE((void **) &pPublishMsg);
    if (OK != status)
    {
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pPublishMsg);
    return status;

}

static MSTATUS TRUSTEDGE_agentConstructAritfactDownloadRequest(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pReleaseId,
    sbyte *pDeploymentId,
    sbyte *pArtifactId,
    intBoolean chunkSupported,
    ubyte4 chunkSize,
    sbyte *pAuthorizationToken,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status;

    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte4 ret;

    if (NULL == ppReq || NULL == pReqLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (pAuthorizationToken)
    {
        if (TRUE == chunkSupported)
        {
            ret = snprintf(NULL, 0, MQTT_ARTIFACT_DOWNLOAD_REQ_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            (unsigned long)chunkSize,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_ARTIFACT_DOWNLOAD_REQ_MSG_NO_CHUNKING,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            pAuthorizationToken);
        }
    }
    else
    {
        if (TRUE == chunkSupported)
        {
            ret = snprintf(NULL, 0, MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            (unsigned long)chunkSize);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG_NO_CHUNKING,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId);
        }

    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    if (pAuthorizationToken)
    {
        if (TRUE == chunkSupported)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_DOWNLOAD_REQ_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            (unsigned long)chunkSize,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_DOWNLOAD_REQ_MSG_NO_CHUNKING,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            pAuthorizationToken);
        }
    }
    else
    {
        if (TRUE == chunkSupported)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId,
                            (unsigned long)chunkSize);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_DOWNLOAD_REQ_NO_AUTH_MSG_NO_CHUNKING,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pReleaseId,
                            pDeploymentId,
                            pArtifactId);
        }

    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    *ppReq = (ubyte *) pMsg; pMsg = NULL;
    *pReqLen = ret;

exit:

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pAuthorizationToken,
    intBoolean isComplete,
    sbyte *pErrorCode,
    sbyte *pErrorDesc,
    ubyte **ppMsg,
    ubyte4 *pMsgLen)
{
    MSTATUS status;
    sbyte *pMsg = NULL;
    sbyte4 ret;
    sbyte *pTimeStamp = NULL;

    if (NULL == ppMsg || NULL == pMsgLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (TRUE == isComplete)
    {
        if (pAuthorizationToken)
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        if (pAuthorizationToken)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_DEPLOYMENT_COMPLETE_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }
    }
    else
    {
        if (pAuthorizationToken)
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pErrorCode,
                            pErrorDesc,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pErrorCode,
                            pErrorDesc);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        if (pAuthorizationToken)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pErrorCode,
                            pErrorDesc,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_DEPLOYMENT_FAILURE_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pUpdatePolicyId,
                            pDeploymentId,
                            pErrorCode,
                            pErrorDesc);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }
    }

    *ppMsg = pMsg; pMsg = NULL;
    *pMsgLen = ret;

exit:
    if (NULL != pMsg)
    {
        DIGI_FREE((void **) &pMsg);
    }

    if (NULL != pTimeStamp)
    {
        DIGI_FREE((void **) &pTimeStamp);
    }

    return status;
}

extern void TRUSTEDGE_agentPolicyPrintNodes(
    TrustEdgeAgentPolicyNode *pNode)
{
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", ">>> PRINTING POLICY NODE(S) START\n");

    while (NULL != pNode)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "NODE %p\n", pNode);

        MSG_LOG_print(MSG_LOG_VERBOSE, "> DEVICE GROUP ID: %s\n", pNode->pDeviceGroupId);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> TYPE: %d\n", pNode->type);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> ID: %s\n", pNode->pId);
        if (NULL != pNode->pDeploymentId)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "> DEPLOYMENT ID: %s\n", pNode->pDeploymentId);
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "> PRIORITY: %d\n", pNode->priority);

        pNode = pNode->pNext;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "<<< PRINTING POLICY NODE(S) END\n");
}

extern MSTATUS TRUSTEDGE_agentPolicyAddNode(
    TrustEdgeAgentPolicyType type,
    sbyte **ppDeviceGroupId,
    sbyte **ppPolicyId,
    sbyte **ppDeploymentId,
    sbyte4 priority,
    sbyte **ppCreationTimestamp,
    sbyte **ppProcessingTimeStamp,
    TrustEdgeAgentArtifactNode **ppArtifactList,
    TrustEdgeAgentPolicyDependency **ppDependency,
    intBoolean hasFailed,
    sbyte4 errorResponseCount,
    TrustEdgeAgentPolicyNode **ppNode)
{
    MSTATUS status;
    TrustEdgeAgentPolicyNode *pNode = NULL, *pPrevious = NULL;
    TrustEdgeAgentPolicyNode **ppCurrent = ppNode;
    TrustEdgeAgentPolicyNode *pFound = NULL;
    sbyte *pTimestamp = NULL;

    status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
        *ppNode, *ppPolicyId, type, &pFound);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pFound)
    {
        /* Do not add the node and exit with OK */
        MSG_LOG_print(MSG_LOG_WARNING,
                "Policy ID %s already exists in pending policies\n", *ppPolicyId);
        goto exit;
    }

    if (NULL == ppCreationTimestamp)
    {
        status = TRUSTEDGE_utilsGetTime(&pTimestamp, 0);
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        pTimestamp = *ppCreationTimestamp;
        *ppCreationTimestamp = NULL;
    }

    status = DIGI_CALLOC(
        (void **) &pNode, sizeof(TrustEdgeAgentPolicyNode), 1);
    if (OK != status)
    {
        goto exit;
    }

    pNode->pDeviceGroupId = *ppDeviceGroupId; *ppDeviceGroupId = NULL;
    pNode->type = type;
    pNode->pId = *ppPolicyId; *ppPolicyId = NULL;
    pNode->pDeploymentId = *ppDeploymentId; *ppDeploymentId = NULL;
    pNode->priority = priority;
    pNode->pCreationTimestamp = pTimestamp; pTimestamp = NULL;
    pNode->hasFailed = hasFailed;
    pNode->errorResponseCount = errorResponseCount;
    if (NULL != ppProcessingTimeStamp && NULL != *ppProcessingTimeStamp)
    {
        pNode->pProccessingTimestamp = *ppProcessingTimeStamp;
        *ppProcessingTimeStamp = NULL;
    }
    else
    {
        pNode->pProccessingTimestamp = NULL;
    }

    if (NULL != ppArtifactList && NULL != *ppArtifactList)
    {
        pNode->pArtifactList = *ppArtifactList; *ppArtifactList = NULL;
    }
    else
    {
        pNode->pArtifactList = NULL;
    }

    if (NULL != ppDependency && NULL != *ppDependency)
    {
        pNode->pDependency = *ppDependency; *ppDependency = NULL;
    }
    else
    {
        pNode->pDependency = NULL;
    }
    pNode->status = TE_POLICY_STATUS_PENDING;

    /* If the node priority is 0 then insert at head, otherwise find location in
     * list where node should be added */
    if (0 != pNode->priority)
    {
        while (NULL != *ppCurrent)
        {
            if (pNode->priority < (*ppCurrent)->priority)
            {
                break;
            }
            pPrevious = *ppCurrent;
            ppCurrent = &((*ppCurrent)->pNext);
        }
    }

    pNode->pNext = *ppCurrent;
    *ppCurrent = pNode;
    if (NULL != pPrevious)
    {
        pPrevious->pNext = pNode;
    }


exit:

    if (NULL != pTimestamp)
    {
        DIGI_FREE((void **) &pTimestamp);
    }
    return status;
}

/* take an existing policy node, and add it to a list */
static MSTATUS TRUSTEDGE_agentPolicyAddNodeEx(
    TrustEdgeAgentPolicyNode *pNode,
    TrustEdgeAgentPolicyNode **ppNode)
{
    MSTATUS status = OK;
    TrustEdgeAgentPolicyNode *pPrevious = NULL;
    TrustEdgeAgentPolicyNode **ppCurrent = ppNode;

    if (NULL == pNode)
    {
        /* we can return status OK  */
        goto exit;
    }

    /* If the node priority is 0 then insert at head, otherwise find location in
     * list where node should be added */
    if (0 != pNode->priority)
    {
        while (NULL != *ppCurrent)
        {
            if (pNode->priority < (*ppCurrent)->priority)
            {
                break;
            }
            pPrevious = *ppCurrent;
            ppCurrent = &((*ppCurrent)->pNext);
        }
    }

    pNode->pNext = *ppCurrent;
    *ppCurrent = pNode;
    if (NULL != pPrevious)
    {
        pPrevious->pNext = pNode;
    }

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyAddNodeFinal(
    TrustEdgeAgentPolicyType type,
    sbyte **ppDeviceGroupId,
    sbyte **ppPolicyId,
    sbyte **ppDeploymentId,
    sbyte4 priority,
    sbyte **ppCreationTimestamp,
    sbyte **ppProcessingTimestamp,
    sbyte **ppCompletionTimestamp,
    TrustEdgeAgentPolicyStatus nodeStatus,
    TrustEdgeAgentMessageType policyState,
    sbyte **ppAlias,
    TrustEdgeAgentArtifactNode **ppArtifactList,
    TrustEdgeAgentPolicyDependency **ppDependency,
    intBoolean hasFailed,
    sbyte4 errorResponseCount,
    TrustEdgeAgentPolicyNode **ppNode)
{
    MSTATUS status;
    sbyte *pPolicyId = NULL;
    TrustEdgeAgentPolicyNode *pFound = NULL;

    if (NULL == ppNode || NULL == ppPolicyId)
        return ERR_NULL_POINTER;

    status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
        *ppNode, *ppPolicyId, type, &pFound);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pFound)
    {
        /* Do not add the node and exit with OK */
        MSG_LOG_print(MSG_LOG_WARNING,
                "Policy ID %s already exists in policy list\n", *ppPolicyId);
        goto exit;
    }

    if (NULL != *ppPolicyId)
    {
        status = DIGI_MALLOC_MEMCPY((void **) &pPolicyId, DIGI_STRLEN(*ppPolicyId) + 1, *ppPolicyId, DIGI_STRLEN(*ppPolicyId));
        if (OK != status)
            goto exit;

        pPolicyId[DIGI_STRLEN(*ppPolicyId)] = '\0';
    }

    status = TRUSTEDGE_agentPolicyAddNode(
        type, ppDeviceGroupId, ppPolicyId, ppDeploymentId,
        priority, ppCreationTimestamp, ppProcessingTimestamp,
        ppArtifactList, ppDependency, hasFailed, errorResponseCount, ppNode);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
        *ppNode, pPolicyId, type, &pFound);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pFound)
    {
        /* Do not add the node and exit with OK */
        pFound->pCompletionTimestamp = *ppCompletionTimestamp; *ppCompletionTimestamp = NULL;
        pFound->status = nodeStatus;
        pFound->pAlias = *ppAlias; *ppAlias = NULL;
        pFound->lastMsgSentType = policyState;
        goto exit;
    }
exit:

    DIGI_FREE((void **) &pPolicyId);

    return status;
}

static MSTATUS TRUSTEDGE_agentPolicyAddFinishedNode(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentPolicyNode *pNode,
    TrustEdgeAgentPolicyNode **ppNode)
{
    MOC_UNUSED(pCtx);
    MSTATUS status;
    TrustEdgeAgentPolicyNode *pCurrent;

    pNode->status = TE_POLICY_STATUS_SUCCESS;

    status = TRUSTEDGE_utilsGetTime(&pNode->pCompletionTimestamp, 0);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL == *ppNode)
    {
        *ppNode = pNode;
    }
    else
    {
        pCurrent = *ppNode;
        while (NULL != pCurrent->pNext)
        {
            pCurrent = pCurrent->pNext;
        }
        pCurrent->pNext = pNode;
    }

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyDeleteNode(
    TrustEdgeAgentPolicyNode **ppNode)
{
    MSTATUS status = OK, fstatus;
    ubyte4 i = 0;

    if (NULL != ppNode && NULL != *ppNode)
    {
        if (NULL != (*ppNode)->pArtifactList)
        {
            TRUSTEDGE_agentFreeAgentArtifactList(&((*ppNode)->pArtifactList));
        }

        fstatus = DIGI_FREE((void **) &((*ppNode)->pDeviceGroupId));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &((*ppNode)->pId));
        if (OK == status)
            status = fstatus;

        if (NULL != (*ppNode)->pDeploymentId)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pDeploymentId));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pCreationTimestamp)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pCreationTimestamp));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pProccessingTimestamp)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pProccessingTimestamp));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pCompletionTimestamp)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pCompletionTimestamp));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pCertSpecJson)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pCertSpecJson));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pAlias)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pAlias));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pDependency)
        {
            for (i = 0; i < (*ppNode)->pDependency->count; i++)
            {
                if (NULL != (*ppNode)->pDependency->pPolicies[i].pPolicyId)
                {
                    fstatus = DIGI_FREE((void **) &((*ppNode)->pDependency->pPolicies[i].pPolicyId));
                    if (OK == status)
                        status = fstatus;
                }

               if (NULL != (*ppNode)->pDependency->pPolicies[i].pPolicyType)
               {
                    fstatus = DIGI_FREE((void **) &((*ppNode)->pDependency->pPolicies[i].pPolicyType));
                    if (OK == status)
                        status = fstatus;
               }
            }

            fstatus = DIGI_FREE((void **) &((*ppNode)->pDependency->pPolicies));
            if (OK == status)
                status = fstatus;

            fstatus = DIGI_FREE((void **) &((*ppNode)->pDependency));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != (*ppNode)->pServerErrorMsg)
        {
            fstatus = DIGI_FREE((void **) &((*ppNode)->pServerErrorMsg));
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) ppNode);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyDeleteNodes(
    TrustEdgeAgentPolicyNode **ppNode)
{
    MSTATUS status = OK, fstatus;
    TrustEdgeAgentPolicyNode *pNode, *pDelete;

    if (NULL != ppNode)
    {
        pNode = *ppNode;

        while (NULL != pNode)
        {
            pDelete = pNode;
            pNode = pNode->pNext;
            fstatus = TRUSTEDGE_agentPolicyDeleteNode(&pDelete);
            if (OK == status)
                status = fstatus;
        }

        *ppNode = NULL;
    }

    return status;
}

extern sbyte4 TRUSTEDGE_agentCountPolicies(
    TrustEdgeAgentPolicyNode *pPolicy)
{
    sbyte4 count = 0;

    if (NULL == pPolicy)
        return 0;

    while (pPolicy)
    {
        count++;
        pPolicy = pPolicy->pNext;
    }

    return count;
}

extern MSTATUS TRUSTEDGE_agentPolicyUnlinkNode(
    TrustEdgeAgentPolicyNode *pPolicy,
    TrustEdgeAgentPolicyNode **ppList)
{
    MSTATUS status = OK;
    TrustEdgeAgentPolicyNode *pPrev = NULL;
    TrustEdgeAgentPolicyNode *pCurr = *ppList;

    while (NULL != pCurr)
    {
        if (pPolicy == pCurr)
        {
            if (NULL == pPrev)
            {
                *ppList = pCurr->pNext;
            }
            else
            {
                pPrev->pNext = pCurr->pNext;
            }
            pCurr->pNext = NULL;

            break;
        }

        pPrev = pCurr;
        pCurr = pCurr->pNext;
    }

    return status;
}

static void TRUSTEDGE_agentPolicyFreeCloudPlatformCreds(
    TrustEdgeAgentPolicyDataCPPS *pData)
{
    ubyte4 i = 0;
    if (NULL != pData->ppX5t256)
    {
        for (i = 0; i < pData->count; i++)
        {
            if (NULL != pData->ppX5t256[i])
            {
                DIGI_FREE((void **) &(pData->ppX5t256[i]));
            }
        }
        DIGI_FREE((void **) &(pData->ppX5t256));
    }

}

extern MSTATUS TRUSTEDGE_agentPolicyClearCurrent(
    TrustEdgeAgentPolicyState *pState)
{
    MSTATUS status = OK, fstatus;

    if (NULL != pState)
    {
        if (NULL != pState->pPolicy)
        {
            if (TE_POLICY_TYPE_CERTIFICATE == pState->pPolicy->type)
            {
                if (NULL != pState->data.cps.pNewKey)
                {
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
                    TAP_KeyHandle keyHandle = 0;
                    TAP_TokenHandle tokenHandle = 0;

                    /* key was marked for deferred unload, unload it before deleting the outer AsymmetricKey structure */
                    fstatus = CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(pState->data.cps.pNewKey, MOC_ASYM_KEY_TYPE_PRIVATE, &tokenHandle, &keyHandle);
                    if (OK == status)
                        status = fstatus;

                    if (0 != keyHandle)
                    {
                        fstatus = CRYPTO_INTERFACE_unloadTapKey(NULL, tokenHandle, keyHandle);
                        if (OK == status)
                            status = fstatus;
                    }
#endif
                    fstatus = CRYPTO_uninitAsymmetricKey(pState->data.cps.pNewKey, NULL);
                    if (OK == status)
                        status = fstatus;

                    fstatus = DIGI_FREE((void **) &pState->data.cps.pNewKey);
                    if (OK == status)
                        status = fstatus;
                }

                if (NULL != pState->data.cps.pCSR)
                {
                    DIGI_FREE((void **) &pState->data.cps.pCSR);
                }

                if (NULL != pState->data.cps.pCertSpec)
                {
                    CERT_ENROLL_cleanupCsrCtx(&(pState->data.cps.pCertSpec->csrCtx));
                    CERT_ENROLL_cleanupKeyCtx(&(pState->data.cps.pCertSpec->keyCtx));
                    DIGI_FREE((void **) &pState->data.cps.pCertSpec);
                }
            }
            else if (TE_POLICY_TYPE_UPDATE == pState->pPolicy->type)
            {
                if (NULL != pState->data.ups.pArtifactHead)
                {
                    TRUSTEDGE_agentFreeAgentArtifactList(&pState->data.ups.pArtifactHead);
                }
            }
            else if (TE_POLICY_TYPE_CLOUDPLATFORM == pState->pPolicy->type)
            {
                TRUSTEDGE_agentPolicyFreeCloudPlatformCreds(&pState->data.cpps);
            }

            fstatus = DIGI_MEMSET((ubyte *)&(pState->data), 0x00, sizeof(pState->data));
            if (OK == status)
                status = fstatus;

            pState->pPolicy = NULL;
        }

        pState->stage = TE_POLICY_STAGE_UNKNOWN;
        pState->lastPolicyMsgType = TE_MSG_TYPE_PENDING_POLICIES;
        pState->policyErrorStatus = OK;
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyDetermineNext(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType msgType)
{
    MSTATUS status = OK;
    byteBoolean advancePolicy = FALSE;
    sbyte *pProcessingTimestamp;
    TrustEdgeAgentPolicyNode *pPolicy = NULL;

    switch (msgType)
    {
        /* Case only advances to the next policy if there is no policy
         * currently in progress */
        case TE_MSG_TYPE_PENDING_POLICIES:
            if (NULL == pCtx->curPolicy.pPolicy)
            {
                advancePolicy = TRUE;
                pCtx->needToProcessResponse = TRUE;
            }

            if (TRUE == pCtx->refreshToken &&
                TRUE == FMGMT_pathExists(pCtx->pPatFile, NULL))
            {
                pCtx->refreshToken          = FALSE;
                pCtx->needToProcessResponse = TRUE;
            }
            break;
        case TE_MSG_TYPE_ARTIFACT_DOWNLOAD:
            pCtx->needToProcessResponse = TRUE;
            if (NULL != pCtx->curPolicy.pPolicy &&
                TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type &&
                NULL != pCtx->curPolicy.data.ups.pArtifact &&
                TRUE == pCtx->curPolicy.data.ups.pArtifact->isAsync)
            {
                pCtx->needToProcessResponse = FALSE;
            }
            break;
        case TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK:
            break;
        /* Default is to not advance to the next policy */
        case TE_MSG_TYPE_ERROR_RESPONSE:
            pCtx->needToProcessResponse = TRUE;
            pPolicy = pCtx->curPolicy.pPolicy;
            if (NULL == pPolicy) /* jic */
            {
                pCtx->needToProcessResponse = FALSE; /* nothing to send */
                break;
            }

            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
            {
                /* rollback will be handled in TRUSTEDGE_agentProcessCurrentPolicyNodes */
                break;
            }

            if (1 < TRUSTEDGE_agentCountPolicies(pCtx->pPendingPolicies))
            {
                status = TRUSTEDGE_agentPolicyUnlinkNode(
                    pPolicy, &pCtx->pPendingPolicies);
                if (OK != status)
                {
                    goto exit;
                }

                /* reset values before adding back to policy list */
                pPolicy->status = TE_POLICY_STATUS_PENDING;
                pPolicy->lastMsgSentType = TE_MSG_TYPE_PENDING_POLICIES;
                advancePolicy = TRUE;
            }
            else
            {
                sbyte4 sleepTime = 1;
                sbyte4 maxShifts;

                maxShifts = (pCtx->curPolicy.pPolicy->errorResponseCount < 32)? pCtx->curPolicy.pPolicy->errorResponseCount : 31;
                for (sbyte4 i = 1; i < maxShifts; i++)
                {
                    sleepTime <<= 1;
                }

                if (TRUE == TRUSTEDGE_sleepCheckStatusMS(sleepTime*1000))
                {
                    status = ERR_TRUSTEDGE_AGENT_SIGNAL_INTERRUPT;
                    MSG_LOG_print(MSG_LOG_INFO,
                        "%s line %d status: %d = %s. Sleep interrupted.\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            break;
        default:
            pCtx->needToProcessResponse = TRUE;
            break;
    }

    if (TRUE == advancePolicy)
    {
        status = TRUSTEDGE_agentPolicyClearCurrent(&pCtx->curPolicy);
        if (OK != status)
        {
            goto exit;
        }

        pCtx->curPolicy.pPolicy = pCtx->pPendingPolicies;

        if (NULL != pCtx->curPolicy.pPolicy)
        {
            pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_PENDING;

            /* add timestamp for when policy was added to processing */
            status = TRUSTEDGE_utilsGetTime(&pProcessingTimestamp, 0);
            if (OK != status)
            {
                goto exit;
            }

            DIGI_FREE((void **) &pCtx->curPolicy.pPolicy->pProccessingTimestamp);
            pCtx->curPolicy.pPolicy->pProccessingTimestamp = pProcessingTimestamp;

            MSG_LOG_print(MSG_LOG_INFO,
                "Advancing to next policy: %s of type %s\n",
                pCtx->curPolicy.pPolicy->pId,
                (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type) ? "CERTIFICATE" : (TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type) ? "UPDATE" : "CLOUDPLATFORM");
        }
        else
        {
            pCtx->needToProcessResponse = FALSE;
        }

        /* add policy back into pending policy list */
        status = TRUSTEDGE_agentPolicyAddNodeEx(pPolicy, &(pCtx->pPendingPolicies));
        if (OK != status)
            goto exit;
    }

    if (TE_MSG_TYPE_PENDING_POLICIES != msgType && TE_MSG_TYPE_ERROR_RESPONSE != msgType)
    {
        pCtx->curPolicy.lastPolicyMsgType = msgType;
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentCloudPlatformPolicyProvisioningCredentials(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppBase64Cert,
    ubyte **ppFingerPrint,
    ubyte4 *pFingerPrintLen,
    sbyte *pAlias
)
{
    MSTATUS status;
    sbyte *pPemFile = NULL;
    ubyte *pCert = NULL;
    ubyte4 certLen = 0;
    ubyte pFingerprintSha256[SHA256_RESULT_SIZE];
    ubyte *pEncodedFingerprint = NULL;
    ubyte4 encodedFingerprintLen = 0;
    ubyte4 decodedLen = 0;
    ubyte *pDecoded = NULL;
    ubyte *pBase64Cert = NULL;
    ubyte4 base64CertLen = 0;

    status = DIGI_MALLOC((void **) &pPemFile, DIGI_STRLEN(pAlias) + 5);
    if (OK != status)
    {
        goto exit;
    }
    snprintf(pPemFile, DIGI_STRLEN(pAlias) + 5, "%s.pem", pAlias);

    status = COMMON_UTILS_addPathComponent(pCtx->pConfig->pKeystoreCertsDir, pPemFile, &pPemFile);
    if (OK != status)
    {
        goto exit;
    }

    if (FMGMT_pathExists(pPemFile, NULL))
    {
        status = DIGICERT_readFile(pPemFile, &pCert, &certLen);
        if (OK != status)
        {
            goto exit;
        }

        status = CA_MGMT_decodeCertificate(pCert, certLen, &pDecoded, &decodedLen);
        if (OK != status)
        {
            goto exit;
        }

        /*x5t#s256*/
        status = CRYPTO_INTERFACE_SHA256_completeDigest(pDecoded, decodedLen, pFingerprintSha256);
        if (OK != status)
        {
            goto exit;
        }

        status = BASE64_urlEncodeMessage(pFingerprintSha256, sizeof(pFingerprintSha256), &pEncodedFingerprint, &encodedFingerprintLen);
        if (OK != status)
        {
            goto exit;
        }

        pEncodedFingerprint[encodedFingerprintLen] = '\0';
        *pFingerPrintLen = encodedFingerprintLen;

        /*x5c*/
        status = BASE64_encodeMessage(pDecoded, decodedLen, &pBase64Cert, &base64CertLen);
        if (OK != status)
        {
            goto exit;
        }
        pBase64Cert[base64CertLen] = '\0';

        *ppBase64Cert = pBase64Cert;
        pBase64Cert = NULL;
        *ppFingerPrint = pEncodedFingerprint;
        pEncodedFingerprint = NULL;


    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_NO_CERTIFICATE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "File %s not found\n", pPemFile);
    }

exit:

    if (NULL != pPemFile)
    {
        DIGI_FREE((void **) &pPemFile);
    }

    if (NULL != pDecoded)
    {
        DIGI_FREE((void **) &pDecoded);
    }

    if (NULL != pCert)
    {
        DIGI_FREE((void **) &pCert);
    }

    if (NULL != pEncodedFingerprint)
    {
        DIGI_FREE((void **) &pEncodedFingerprint);
    }

    if (NULL != pBase64Cert)
    {
        DIGI_FREE((void **) &pBase64Cert);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructInitialPolicyRequest(
    TrustEdgeAgentCtx *pCtx,
    sbyte **ppUUID,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status = OK;
    int ret;
    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    ubyte *pBase64Cert = NULL;
    ubyte *pEncodedFingerprint = NULL;
    ubyte4 encodedFingerprintLen = 0;
    ubyte *credentialsArray = NULL;
    ubyte4 credentialsArrayLen = 0;
    ubyte4 i = 0;
    sbyte *pAlias;
    TrustEdgeAgentPolicyNode *pFound = NULL;
    ubyte4 tmpLen = 0;
    ubyte *pTempCredentials = NULL;
    ubyte *newArray = NULL;
    ubyte4 newArrayLen = 0;

    if (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type)
    {
        pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_REQ_CREATE;
        *ppUUID = "DeviceTM_Certificate_Specification_Request";
        status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
        if (OK != status)
            goto exit;

        if (pCtx->pPatData)
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_SPECIFICATION_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->configOptions.pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->pPatData);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_SPECIFICATION_NO_AUTH_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->configOptions.pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        if (pCtx->pPatData)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_SPECIFICATION_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->configOptions.pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->pPatData);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_SPECIFICATION_NO_AUTH_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->configOptions.pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }
    }
    else if (TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type)
    {
        *ppUUID = "DeviceTM_Update_Policy_Request";
        status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
        if (OK != status)
            goto exit;

        if (NULL != pCtx->pPatData)
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_REQUEST_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_UPDATE_POLICY_REQUEST_NO_AUTH_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId);

        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;

        if (NULL != pCtx->pPatData)
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_REQUEST_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData);
        }
        else
        {
            ret = snprintf(pMsg, ret + 1, MQTT_UPDATE_POLICY_REQUEST_NO_AUTH_MSG,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pTimeStamp,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId);
        }
        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }
    }
    else if (TE_POLICY_TYPE_CLOUDPLATFORM == pCtx->curPolicy.pPolicy->type)
    {
        *ppUUID = "DeviceTM_Cloudplatform_Policy_Request";

        status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
        if (OK != status)
            goto exit;

        if (0 < pCtx->curPolicy.pPolicy->pDependency->count)
        {
            status = DIGI_MALLOC((void **)&pCtx->curPolicy.data.cpps.ppX5t256, sizeof(sbyte *) * (pCtx->curPolicy.pPolicy->pDependency->count));
            if (OK != status)
            {
                goto exit;
            }
        }
        for (i = 0; i < pCtx->curPolicy.pPolicy->pDependency->count; i++)
        {
            if (pCtx->curPolicy.pPolicy->pDependency->pPolicies[i].pPolicyId != NULL
                && DIGI_STRNCMP(pCtx->curPolicy.pPolicy->pDependency->pPolicies[i].pPolicyType, "CERTIFICATE", DIGI_STRLEN("CERTIFICATE")) == 0)
            {
                status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
                    pCtx->pAppliedPolicies,
                    pCtx->curPolicy.pPolicy->pDependency->pPolicies[i].pPolicyId,
                    TE_POLICY_TYPE_CERTIFICATE,
                    &pFound);
                if (OK != status)
                {
                    goto exit;
                }
                if (NULL != pFound)
                {
                    pAlias = pFound->pAlias;
                }

                if (NULL == pFound)
                {
                    status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
                        pCtx->pErrorPolicies,
                        pCtx->curPolicy.pPolicy->pDependency->pPolicies[i].pPolicyId,
                        TE_POLICY_TYPE_CERTIFICATE,
                        &pFound);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    if (NULL != pFound)
                    {
                        status = ERR_TRUSTEDGE_AGENT_BAD_POLICY_ID;
                        goto exit;
                    }


                    if (NULL == pFound)
                    {
                        TRUSTEDGE_agentPolicyUnlinkNode(
                            pCtx->curPolicy.pPolicy, &pCtx->pPendingPolicies);

                        status = ERR_TRUSTEDGE_AGENT_POLICY_NOT_FOUND;
                        goto exit;
                    }
                }

                if (NULL != pBase64Cert)
                {
                    DIGI_FREE((void **) &pBase64Cert);
                }
                if (NULL != pEncodedFingerprint)
                {
                    DIGI_FREE((void **) &pEncodedFingerprint);
                }

                status = TRUSTEDGE_agentCloudPlatformPolicyProvisioningCredentials(pCtx, &pBase64Cert, &pEncodedFingerprint, &encodedFingerprintLen, pAlias);
                if (OK != status)
                {
                    goto exit;
                }

                tmpLen = snprintf(NULL, 0,
                    "{\n"
                    "  \"type\": \"x509\",\n"
                    "  \"x5c\": [\"%s\"],\n"
                    "  \"x5tS256\": \"%s\"\n"
                    "}", pBase64Cert, pEncodedFingerprint);

                if (i < pCtx->curPolicy.pPolicy->pDependency->count - 1)
                {
                    tmpLen += 1;
                }

                status = DIGI_MALLOC((void **) &pTempCredentials, tmpLen + 1);
                if (OK != status)
                {
                    goto exit;
                }

                snprintf(pTempCredentials, tmpLen + 1,
                    "{\n"
                    "  \"type\": \"x509\",\n"
                    "  \"x5c\": [\"%s\"],\n"
                    "  \"x5tS256\": \"%s\"\n"
                    "}%s\n", pBase64Cert, pEncodedFingerprint,
                    (i < pCtx->curPolicy.pPolicy->pDependency->count - 1) ? "," : "");

                if (credentialsArray == NULL)
                {
                    DIGI_MALLOC((void **)&credentialsArray, tmpLen + 1);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    DIGI_MEMCPY(credentialsArray, pTempCredentials, tmpLen + 1);
                    credentialsArrayLen = tmpLen;
                }
                else
                {
                    newArrayLen = credentialsArrayLen + tmpLen;
                    status  = DIGI_MALLOC((void **)&newArray, newArrayLen + 1);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    DIGI_MEMCPY(newArray, credentialsArray, credentialsArrayLen);
                    DIGI_MEMCPY(newArray + credentialsArrayLen, pTempCredentials, tmpLen + 1);

                    DIGI_FREE((void **)&credentialsArray);

                    credentialsArray = newArray;
                    credentialsArrayLen = newArrayLen;

                }

                DIGI_FREE((void **)&pTempCredentials);

                status = DIGI_MALLOC_MEMCPY((void **)&pCtx->curPolicy.data.cpps.ppX5t256[i], encodedFingerprintLen + 1, pEncodedFingerprint, encodedFingerprintLen);
                if (OK != status)
                {
                    goto exit;
                }
                pCtx->curPolicy.data.cpps.ppX5t256[i][encodedFingerprintLen] = '\0';
                pCtx->curPolicy.data.cpps.count++;
            }
        }

        ret = snprintf(NULL, 0, MQTT_CLOUDPLATFORM_POLICY_REQUEST_MSG,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pTimeStamp,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        credentialsArray);

        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
        {
            goto exit;
        }

        ret = snprintf(pMsg, ret + 1, MQTT_CLOUDPLATFORM_POLICY_REQUEST_MSG,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pTimeStamp,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        credentialsArray);

        if (0 > ret)
        {
            status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
            goto exit;
        }
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppReq = pMsg;
    *pReqLen = (ubyte4) ret;

exit:

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    if (NULL != pBase64Cert)
        DIGI_FREE((void **) &pBase64Cert);

    if (NULL != pEncodedFingerprint)
        DIGI_FREE((void **) &pEncodedFingerprint);

    if (NULL != pTempCredentials)
        DIGI_FREE((void **) &pTempCredentials);

    if (NULL != credentialsArray)
        DIGI_FREE((void **) &credentialsArray);

    if (OK != status)
    {
        TRUSTEDGE_agentPolicyFreeCloudPlatformCreds(&pCtx->curPolicy.data.cpps);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructCloudPlatformPolicyStatus(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pCloudPlatformPolicyId,
    intBoolean succeed,
    sbyte *pErrorCode,
    sbyte *pErrorDescr,
    ubyte **ppReq,
    ubyte4 *pReqLen
)
{
    MSTATUS status = OK;
    int ret;
    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (succeed)
    {
        ret = snprintf(NULL, 0, MQTT_CLOUDPLATFORM_POLICY_COMPLETED_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pCloudPlatformPolicyId);
        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;
        ret = snprintf(pMsg, ret + 1, MQTT_CLOUDPLATFORM_POLICY_COMPLETED_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pCloudPlatformPolicyId);
    }
    else
    {
        ret = snprintf(NULL, 0, MQTT_CLOUDPLATFORM_POLICY_FAILED_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pCloudPlatformPolicyId,
                        pErrorCode,
                        pErrorDescr);
        status = DIGI_MALLOC((void **) &pMsg, ret + 1);
        if (OK != status)
            goto exit;
        ret = snprintf(pMsg, ret + 1, MQTT_CLOUDPLATFORM_POLICY_FAILED_MSG,
                        pDeviceId,
                        pAccountId,
                        pTimeStamp,
                        pDeviceGroupId,
                        pCloudPlatformPolicyId,
                        pErrorCode,
                        pErrorDescr);
    }

    *ppReq = pMsg;
    *pReqLen = (ubyte4) ret;

exit:

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

extern MSTATUS TRUSTEDGE_evalFunction(
    void *pEvalFunctionArg,
    byteBoolean *pUseDefault,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen)
{
    MSTATUS status = OK;
    TrustEdgeAgentCtx *pCtx = pEvalFunctionArg;
    ubyte *pVal = NULL;
    ubyte4 valLen = 0;

    *pUseDefault = TRUE;

    /* Attempt to replace the eval expression */
    status = TRUSTEDGE_agentReplaceWithAttribute(
        pCtx, pExpression, expressionLen, &pVal, &valLen);
    if (OK != status)
        goto exit;

    if (NULL != pVal)
    {
        /* Found eval expression */
        *pUseDefault = FALSE;
        if (NULL == pOutput)
        {
            /* Caller just wants output size */
            status = ERR_BUFFER_TOO_SMALL;
            *pOutputLen = valLen;
        }
        else
        {
            /* Caller wants evaluated value copied to buffer */
            status = DIGI_MEMCPY(pOutput, pVal, valLen);
        }
    }

exit:

    if (NULL != pVal)
    {
        DIGI_FREE((void **) &pVal);
    }

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructCertificateRequest(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status = OK;
    int ret;
    sbyte *pMsg = NULL;
    ubyte *pPEM = NULL;
    ubyte4 pemLen = 0;
    sbyte *pTimeStamp = NULL;
    TrustEdgeAgentCertSpec *pCertSpec = NULL;
    CertEnrollAlg keyGenAlg = certEnrollAlgUndefined;
    CertEnrollAlg existingKeyGenAlg = certEnrollAlgUndefined;
    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;
    ubyte4 reqFormatNdx;
    sbyte *pFormat = NULL;
    CertEnrollFormat reqFormat = CE_FORMAT_UNDEFIND;
    sbyte *pSpec = NULL;
    CertEnrollMode reqSpec = CE_UNDEFINED;
    sbyte *pCopy = NULL;
    sbyte *pSigAlgStr = NULL;
    ubyte4 specNdx, ndx;
    ubyte4 arrNdx, srcNdx;
    JSON_TokenType arrToken = { 0 }, token = { 0 }, keyAlgoToken = { 0 };
    JSON_TokenType keySrcToken = { 0 };
    ubyte4 i;
    sbyte *pId = NULL;
    sbyte *pDeviceId = NULL;
    sbyte *pDeviceGroupId = NULL;
    sbyte *pAccountId = NULL;
    sbyte *pPath = NULL;
    sbyte *pOutFile = NULL;
    ubyte *pCSR = NULL;
    ubyte4 csrLen = 0;
    TrustEdgeAgentKeySource keySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
    TrustEdgeAgentKeySource existingKeySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
    ubyte4 sigAlg = ht_none;
    ExtendedEnrollFlow extFlow = EXT_ENROLL_FLOW_NONE;
#if defined(__ENABLE_DIGICERT_TAP__)
    intBoolean foundProvider;
    CertEnrollTAPAttributes tapAttributes = { 0 };
#endif

    if (TE_POLICY_TYPE_CERTIFICATE != pCtx->curPolicy.pPolicy->type)
    {
        status = ERR_NOT_IMPLEMENTED;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(
        pJCtx,
        pCtx->curPolicy.pPolicy->pCertSpecJson,
        pCtx->curPolicy.pPolicy->certSpecJsonLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "certificatePolicyId", &pId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceId", &pDeviceId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "accountId", &pAccountId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, 0, "deviceGroupId", &pDeviceGroupId, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_validateCurrentPolicy(pCtx, pId, pDeviceId, pAccountId,
        pDeviceGroupId, NULL, TE_POLICY_TYPE_CERTIFICATE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_RSP_PARSE;

    status = JSON_getJsonObjectIndex(
        pJCtx, 0, "certificateSpecification", &specNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "certificateRequestFormat", &reqFormatNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, reqFormatNdx, "format", &pFormat, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == DIGI_STRCMP(pFormat, "PKCS10"))
    {
        reqFormat = CE_FORMAT_PKCS10;
    }
    else if (0 == DIGI_STRCMP(pFormat, "CMC"))
    {
        reqFormat = CE_FORMAT_CMC;
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_FORMAT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonStringValue(
        pJCtx, reqFormatNdx, "specification", &pSpec, TRUE);

    if (OK == status)
    {
        if (0 == DIGI_STRCMP(pSpec, "TRUSTED_SIGNER"))
        {
            reqSpec = CE_TRUSTED_SIGNER;
        }
        else if (0 == DIGI_STRCMP(pSpec, "TPM2_ATTEST"))
        {
            reqSpec = CE_TPM2_ATTEST;
        }
        else
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_SPEC;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }
    else if (CE_FORMAT_PKCS10 == reqFormat && ERR_NOT_FOUND == status)
    {
        status = OK;
    }
    else if (CE_FORMAT_CMC == reqFormat && ERR_NOT_FOUND == status)
    {
        reqSpec = CE_TRUSTED_SIGNER;
        status = OK;
    }
    else
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "keyCertAttributes", &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx->curPolicy.data.cps.pNewKey)
    {
        status = COMMON_UTILS_addPathComponent(pCtx->pConfig->pKeystoreKeysDir, pCtx->curPolicy.pPolicy->pAlias, &pOutFile);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = COMMON_UTILS_addPathExtension(pOutFile, ".pem", &pOutFile);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TRUE == FMGMT_pathExists(pOutFile, NULL))
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "Using existing key from %s\n", pOutFile);

            status = TRUSTEDGE_utilsLoadKey(pOutFile, &pCtx->curPolicy.data.cps.pNewKey);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            status = TRUSTEDGE_utilsDetermineKeyParams(
                pCtx->curPolicy.data.cps.pNewKey, &existingKeyGenAlg, &existingKeySrc);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

    status = JSON_getJsonArrayValue(
        pJCtx, ndx, "keyAlgorithm", &arrNdx, &arrToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    arrNdx++;
    for (i = 0; i < arrToken.elemCnt; i++)
    {
        status = JSON_getToken(pJCtx, arrNdx + i, &keyAlgoToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (JSON_String != keyAlgoToken.type)
        {
            status = ERR_JSON_UNEXPECTED_TYPE;
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        keyGenAlg = certEnrollAlgUndefined;
        if (0 == DIGI_STRNCMP("RSA+2048", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = rsa2048;
        }
        else if (0 == DIGI_STRNCMP("RSA+3072", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = rsa3072;
        }
        else if (0 == DIGI_STRNCMP("RSA+4096", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = rsa4096;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P256", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = ecdsaP256;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P384", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = ecdsaP384;
        }
        else if (0 == DIGI_STRNCMP("ECDSA+P521", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = ecdsaP521;
        }
        else if (0 == DIGI_STRNCMP("EDDSA+Ed25519", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = eddsaEd25519;
        }
        else if (0 == DIGI_STRNCMP("EDDSA+Ed448", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = eddsaEd448;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        else if (0 == DIGI_STRNCMP("MLDSA+44", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = mldsa44;
        }
        else if (0 == DIGI_STRNCMP("MLDSA+65", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = mldsa65;
        }
        else if (0 == DIGI_STRNCMP("MLDSA+87", keyAlgoToken.pStart, keyAlgoToken.len))
        {
            keyGenAlg = mldsa87;
        }
#endif

        if (certEnrollAlgUndefined != keyGenAlg)
        {
            if (certEnrollAlgUndefined != existingKeyGenAlg)
            {
                if (keyGenAlg == existingKeyGenAlg)
                {
                    /* Found algorithm and key size which matches existing key */
                    break;
                }
            }
            else
            {
                /* Found algorithm and key size to generate */
                break;
            }
        }
    }

    if (certEnrollAlgUndefined == keyGenAlg)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_ALGO;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentGetKeyHashAlgorithm(
        keyGenAlg, &sigAlg);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getObjectIndex(
        pJCtx, "source", ndx, &srcNdx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    srcNdx++;
    status = JSON_getToken(pJCtx, srcNdx, &token);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (JSON_String == token.type)
    {
        if (KEY_SOURCE_SW_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_SW;
        }
        else if (KEY_SOURCE_SW_SERVER_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW_SERVER, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_SW_SERVER;
        }
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TEE, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TEE_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TEE, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_TEE;
        }
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_NANOROOT, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_NANOROOT_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_NANOROOT, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_NANOROOT;
        }
#else
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TPM2, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TPM2_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TPM2, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_TPM2;
        }
        else if ((OK == TAP_checkForProvider(TAP_PROVIDER_PKCS11, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_PKCS11_LEN == token.len && 0 == DIGI_STRNCMP(KEY_SOURCE_PKCS11, token.pStart, token.len))
        {
            keySrc = TRUSTEDGE_KEY_SOURCE_PKCS11;
        }
#endif
#endif
        if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != keySrc)
        {
            if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != existingKeySrc)
            {
                if (keySrc != existingKeySrc)
                {
                    /* Key source provided in specification does not match
                     * existing key, error and exit */
                    status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_SOURCE;
                    goto exit;
                }
            }
        }

        keySrcToken = token;
    }
    else if (JSON_Array == token.type)
    {
        srcNdx++;
        for (i = 0; i < token.elemCnt; i++)
        {
            status = JSON_getToken(pJCtx, srcNdx + i, &keySrcToken);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (JSON_String != keySrcToken.type)
            {
                status = ERR_JSON_UNEXPECTED_TYPE;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

            keySrc = TRUSTEDGE_KEY_SOURCE_UNDEFINED;
            if (KEY_SOURCE_SW_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_SW;
            }
            else if (KEY_SOURCE_SW_SERVER_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_SW_SERVER, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_SW_SERVER;
            }
#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_TEE__)
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TEE, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TEE_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TEE, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_TEE;
            }
#elif defined(__ENABLE_DIGICERT_SMP_NANOROOT__)
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_NANOROOT, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_NANOROOT_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_NANOROOT, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_NANOROOT;
            }
#else
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_TPM2, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_TPM2_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_TPM2, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_TPM2;
            }
            else if ((OK == TAP_checkForProvider(TAP_PROVIDER_PKCS11, &foundProvider)) && (TRUE == foundProvider) && KEY_SOURCE_PKCS11_LEN == keySrcToken.len && 0 == DIGI_STRNCMP(KEY_SOURCE_PKCS11, keySrcToken.pStart, keySrcToken.len))
            {
                keySrc = TRUSTEDGE_KEY_SOURCE_PKCS11;
            }
#endif
#endif
            if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != keySrc)
            {
                if (TRUSTEDGE_KEY_SOURCE_UNDEFINED != existingKeySrc)
                {
                    if (keyGenAlg == existingKeyGenAlg)
                    {
                        /* Found algorithm and key size which matches existing key */
                        break;
                    }
                }
                else
                {
                    /* Found algorithm and key size to generate */
                    break;
                }
            }
        }
    }

    if (TRUSTEDGE_KEY_SOURCE_UNDEFINED == keySrc)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_KEY_SOURCE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    if (TRUSTEDGE_KEY_SOURCE_SW != keySrc && TRUSTEDGE_KEY_SOURCE_SW_SERVER != keySrc)
    {
        /* Initialize defaults */
        tapAttributes.moduleId = 1;
        tapAttributes.primary = FALSE;
        tapAttributes.hierarchy = TAP_HIERARCHY_NONE;
        tapAttributes.keyUsage = TAP_KEY_USAGE_GENERAL;
        tapAttributes.sigScheme = TAP_SIG_SCHEME_NONE;
        tapAttributes.encScheme = TAP_ENC_SCHEME_NONE;
        tapAttributes.pKeyHandle = NULL;
        tapAttributes.keyNonceHandle = 0;
        tapAttributes.certHandle = 0;

        status = CERT_ENROLL_parseTAPAttributes(
            pJCtx, ndx, keyGenAlg, &tapAttributes);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s. Failed to parse TAP attributes\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Module ID: %d\n", tapAttributes.moduleId);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Primary: %d\n", tapAttributes.primary);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Hierarchy: %d\n", tapAttributes.primary);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Key Usage: %d\n", tapAttributes.keyUsage);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Signature Scheme: %d\n", tapAttributes.sigScheme);
        MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Encryption Scheme: %d\n", tapAttributes.encScheme);
        if (NULL != tapAttributes.pKeyHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TAP Key Handle: 0x");
            MSG_LOG_printRawBuffer(MSG_LOG_VERBOSE, tapAttributes.pKeyHandle->pBuffer, tapAttributes.pKeyHandle->bufferLen);
            MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "\n");
        }
        if (0 != tapAttributes.keyNonceHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Key Nonce Handle: 0x%llX\n", tapAttributes.keyNonceHandle);
        }
        if (0 != tapAttributes.certHandle)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "TAP Certificate Handle: 0x%llX\n", tapAttributes.certHandle);
        }

        if (TRUE == tapAttributes.primary)
        {
            if (TAP_KEY_USAGE_ATTESTATION == tapAttributes.keyUsage)
            {
                extFlow = EXT_ENROLL_FLOW_TPM2_IAK;
            }
            else
            {
                extFlow = EXT_ENROLL_FLOW_TPM2_IDEVID;
            }
        }
    }

    pCtx->curPolicy.data.cps.certHandle = tapAttributes.certHandle;
    pCtx->curPolicy.data.cps.primary = tapAttributes.primary;
#endif

    status = JSON_getJsonObjectIndex(
        pJCtx, specNdx, "csrAttributes", &ndx, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = JSON_getToken(pJCtx, ndx, &token);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_CERT_SPEC_CSR_GEN;

    if (CE_FORMAT_CMC == reqFormat)
    {
        if (CE_TRUSTED_SIGNER != reqSpec && CE_TPM2_ATTEST != reqSpec)
        {
            status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_SPEC;
            goto exit;
        }

        status = DIGI_MALLOC_MEMCPY(
            (void **) &pCopy, token.len + 1, (void *) token.pStart, token.len);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pCopy[token.len] = '\0';

        status = TRUSTEDGE_utilsGetSigAlgStr(sigAlg, &pSigAlgStr);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

#ifndef __DISABLE_TRUSTEDGE_EST__
        status = EST_createPKCS7RequestFromConfigWithPolicy(
            pCtx->pTrustedStore, pCopy, NULL, EST_CONFIG_JSON, NULL, 0,
            pCtx->curPolicy.data.cps.pNewKey, (NULL != pCtx->curPolicy.data.cps.pNewKey) ? pCtx->curPolicy.data.cps.pNewKey->type : akt_undefined,
            keyGenAlg, NULL, 0, akt_undefined,
            pSigAlgStr, DIGI_STRLEN(pSigAlgStr), -1, ENROLL, FALSE,
            &pCSR, &csrLen, extFlow, TRUSTEDGE_evalFunction, pCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif
    }
    else
    {
        status = DIGI_CALLOC(
            (void **) &pCertSpec, 1, sizeof(TrustEdgeAgentCertSpec));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CERT_ENROLL_addKeyCertAttributes( &pCertSpec->keyCtx, pCtx->curPolicy.data.cps.pNewKey, NULL, NULL,
                                                keyGenAlg, 0, TRUE,
                                                NULL, 0, NULL);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

#if defined(__ENABLE_DIGICERT_TAP__)
        status = CERT_ENROLL_setTAPCallback(&pCertSpec->csrCtx, TRUSTEDGE_TAP_getCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif

        /* token holds the csrAttributes object */
        status = CERT_ENROLL_addCsrAttributes(
            &pCertSpec->csrCtx, JSON, 0, TRUSTEDGE_evalFunction, pCtx,
            pCtx->curPolicy.data.cps.pNewKey, keyGenAlg, FALSE, sigAlg,
            (ubyte *) token.pStart, token.len, NULL, extFlow);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = CERT_ENROLL_generateCSRRequest(&pCertSpec->keyCtx, NULL, &pCertSpec->csrCtx, 0, &pCSR, &csrLen);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pKeystoreReqDir, "req.pem", &pOutFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "Writing CSR to %s\n", pOutFile);

    status = DIGICERT_writeFile(pOutFile, pCSR, csrLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx->curPolicy.stage = TE_POLICY_STAGE_CPS_ISSUED_CERT_REQ_CREATE;

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_utilsOneLineCSR(
        pCSR, csrLen, &pPEM, &pemLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Save certificate specification and meta-data */
    status = TRUSTEDGE_agentPersistCertSpec(
        pCtx,
        pCtx->curPolicy.pPolicy->pCertSpecJson,
        pCtx->curPolicy.pPolicy->certSpecJsonLen,
        (sbyte *) keySrcToken.pStart, keySrcToken.len,
        (sbyte *) keyAlgoToken.pStart, keyAlgoToken.len,
        pCtx->curPolicy.pPolicy->pAlias);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (CE_FORMAT_CMC == reqFormat)
    {
        if (TRUSTEDGE_KEY_SOURCE_SW_SERVER == keySrc)
        {
            if (pCtx->pPatData)
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_CMC_SKG_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart,
                                pCtx->pPatData);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_CMC_SKG_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart,
                                pCtx->pPatData);
            }
            else
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_CMC_SKG_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_CMC_SKG_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart);
            }
        }
        else
        {
            if (pCtx->pPatData)
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_CMC_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                pCtx->pPatData);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_CMC_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                pCtx->pPatData);
            }
            else
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_CMC_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_CMC_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM);
            }
        }
    }
    else
    {
        if (TRUSTEDGE_KEY_SOURCE_SW_SERVER == keySrc)
        {
            if (pCtx->pPatData)
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_SKG_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart,
                                pCtx->pPatData);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_SKG_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart,
                                pCtx->pPatData);
            }
            else
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_SKG_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_SKG_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                keyAlgoToken.len, keyAlgoToken.pStart);
            }
        }
        else
        {
            if (pCtx->pPatData)
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                pCtx->pPatData);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM,
                                pCtx->pPatData);
            }
            else
            {
                ret = snprintf(NULL, 0, MQTT_CERTIFICATE_REQUEST_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM);
                DIGI_MALLOC((void **) &pMsg, ret + 1);
                ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_REQUEST_NO_AUTH_MSG,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pTimeStamp,
                                pCtx->configOptions.pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pemLen, pPEM);
            }
        }
    }

    pCtx->curPolicy.data.cps.pCertSpec = pCertSpec;
    pCertSpec = NULL;
    pCtx->curPolicy.data.cps.pCSR = pCSR;
    pCtx->curPolicy.data.cps.csrLen = csrLen;
    pCSR = NULL;

    *ppReq = pMsg;
    *pReqLen = (ubyte4) ret;

exit:

#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != tapAttributes.pKeyHandle)
    {
        DIGI_FREE((void **) &tapAttributes.pKeyHandle->pBuffer);
        DIGI_FREE((void **) &tapAttributes.pKeyHandle);
    }
#endif

    DIGI_FREE((void **) &pCopy);
    DIGI_FREE((void **) &pSpec);
    DIGI_FREE((void **) &pFormat);

    if (NULL != pId)
        DIGI_FREE((void **) &pId);

    if (NULL != pPath)
        DIGI_FREE((void **) &pPath);

    if (NULL != pOutFile)
        DIGI_FREE((void **) &pOutFile);

    if (NULL != pCSR)
        DIGI_FREE((void **) &pCSR);

    if (NULL != pCertSpec)
    {
        CERT_ENROLL_cleanupCsrCtx(&(pCertSpec->csrCtx));
        CERT_ENROLL_cleanupKeyCtx(&(pCertSpec->keyCtx));
        DIGI_FREE((void **) &pCertSpec);
    }

    if (NULL != pJCtx)
        JSON_releaseContext(&pJCtx);

    DIGI_FREE((void **) &pPEM);

    DIGI_FREE((void **) &pDeviceId);
    DIGI_FREE((void **) &pAccountId);
    DIGI_FREE((void **) &pDeviceGroupId);

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructCertificateStatus(
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pCertPolicyId,
    sbyte *pAuthorizationToken,
    intBoolean succeed,
    TrustEdgeAgentPolicyStage stage,
    MSTATUS policyErrorStatus,
    sbyte *pServerErrorMsg,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status = OK;
    int ret;
    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte *pErrorCode = "UNKNOWN";
    sbyte *pErrorDescr = "agent error";
    MSTATUS clientErrorCode = ERR_TRUSTEDGE_AGENT_ERROR_UNKNOWN;
    sbyte *pClientErrorDescr = "unknown error";

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (succeed)
    {
        if (pAuthorizationToken)
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_POLICY_COMPLETED_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pAuthorizationToken);
            status = DIGI_MALLOC((void **) &pMsg, ret + 1);
            if (OK != status)
                goto exit;
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_POLICY_COMPLETED_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_POLICY_COMPLETED_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId);
            status = DIGI_MALLOC((void **) &pMsg, ret + 1);
            if (OK != status)
                goto exit;
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_POLICY_COMPLETED_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId);
        }
    }
    else
    {
        switch (stage)
        {
            case TE_POLICY_STAGE_CPS_CERT_SPEC_REQ_CREATE:
                pErrorCode = "TE_POLICY_STAGE_CPS_CERT_SPEC_REQ_CREATE";
                break;
            case TE_POLICY_STAGE_CPS_CERT_SPEC_RSP_PARSE:
                pErrorCode = "TE_POLICY_STAGE_CPS_CERT_SPEC_RSP_PARSE";
                break;
            case TE_POLICY_STAGE_CPS_CERT_SPEC_KEY_GEN:
                pErrorCode = "TE_POLICY_STAGE_CPS_CERT_SPEC_KEY_GEN";
                break;
            case TE_POLICY_STAGE_CPS_CERT_SPEC_CSR_GEN:
                pErrorCode = "TE_POLICY_STAGE_CPS_CERT_SPEC_CSR_GEN";
                break;
            case TE_POLICY_STAGE_CPS_ISSUED_CERT_REQ_CREATE:
                pErrorCode = "TE_POLICY_STAGE_CPS_ISSUED_CERT_REQ_CREATE";
                break;
            case TE_POLICY_STAGE_CPS_ISSUED_CERT_RSP_PARSE:
                pErrorCode = "TE_POLICY_STAGE_CPS_ISSUED_CERT_RSP_PARSE";
                break;
            case TE_POLICY_STAGE_CPS_ISSUED_CERT_TRUSTBUNDLE:
                pErrorCode = "TE_POLICY_STAGE_CPS_ISSUED_CERT_TRUSTBUNDLE";
                break;
            case TE_POLICY_STAGE_CPS_ISSUED_CERT_KEY_AND_CERT_PAIR:
                pErrorCode = "TE_POLICY_STAGE_CPS_ISSUED_CERT_KEY_AND_CERT_PAIR";
                break;
            case TE_POLICY_STAGE_UNKNOWN:
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
        }

        /* Error message from server */
        if (NULL != pServerErrorMsg)
        {
            pErrorDescr = pServerErrorMsg;
            clientErrorCode = ERR_TRUSTEDGE_AGENT_BACKEND_ERROR_RESPONSE;
            pClientErrorDescr = (sbyte *) MERROR_lookUpErrorCode(clientErrorCode);
        }
        else if (OK != policyErrorStatus)
        {
            clientErrorCode = policyErrorStatus;
            pClientErrorDescr = (sbyte *) MERROR_lookUpErrorCode(clientErrorCode);
        }

        if (pAuthorizationToken)
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_POLICY_FAILED_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pErrorCode,
                            pErrorDescr,
                            clientErrorCode,
                            pClientErrorDescr,
                            pAuthorizationToken);
            status = DIGI_MALLOC((void **) &pMsg, ret + 1);
            if (OK != status)
                goto exit;
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_POLICY_FAILED_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pErrorCode,
                            pErrorDescr,
                            clientErrorCode,
                            pClientErrorDescr,
                            pAuthorizationToken);
        }
        else
        {
            ret = snprintf(NULL, 0, MQTT_CERTIFICATE_POLICY_FAILED_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pErrorCode,
                            pErrorDescr,
                            clientErrorCode,
                            pClientErrorDescr);
            status = DIGI_MALLOC((void **) &pMsg, ret + 1);
            if (OK != status)
                goto exit;
            ret = snprintf(pMsg, ret + 1, MQTT_CERTIFICATE_POLICY_FAILED_NO_AUTH_MSG,
                            pDeviceId,
                            pAccountId,
                            pTimeStamp,
                            pDeviceGroupId,
                            pCertPolicyId,
                            pErrorCode,
                            pErrorDescr,
                            clientErrorCode,
                            pClientErrorDescr);
        }
    }

    *ppReq = pMsg;
    *pReqLen = (ubyte4) ret;

exit:

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

extern MSTATUS TRUSTEDGE_agentSendCertificateStatus(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pCertPolicyId,
    sbyte *pAuthorizationToken,
    intBoolean succeed,
    TrustEdgeAgentPolicyStage stage,
    MSTATUS policyErrorStatus)
{
    MSTATUS status;
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    ubyte *pPublishMsg = NULL;
    ubyte4 publishMsgLen = 0;
    ubyte *pUUID = "DeviceTM_Certificate_Policy_Failed";

    if (TRUE == succeed)
        pUUID = "DeviceTM_Certificate_Policy_Completed";

    status = TRUSTEDGE_agentConstructCertificateStatus(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        pCertPolicyId,
        pAuthorizationToken,
        succeed,
        stage,
        policyErrorStatus,
        pCtx->curPolicy.pPolicy->pServerErrorMsg,
        &pReq, &reqLen);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
    DIGI_FREE((void **) &pReq);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
    DIGI_FREE((void **) &pPublishMsg);
    if (OK != status)
    {
        goto exit;
    }
exit:

    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pPublishMsg);

    return status;
}


extern MSTATUS TRUSTEDGE_agentSendUpdatePolicyDeploymentStatus(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pAuthorizationToken,
    intBoolean isComplete,
    sbyte *pErrorCode,
    sbyte *pErrorDesc
)
{
    MSTATUS status;
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    ubyte *pPublishMsg = NULL;
    ubyte4 publishMsgLen = 0;
    ubyte *pUUID = "DeviceTM_Update_Policy_Deployment_Failed";

    if (TRUE == isComplete)
        pUUID = "DeviceTM_Update_Policy_Deployment_Completed";

    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        pUpdatePolicyId,
        pDeploymentId,
        pAuthorizationToken,
        isComplete,
        pErrorCode,
        pErrorDesc,
        &pReq,
        &reqLen);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
    DIGI_FREE((void **) &pReq);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
    DIGI_FREE((void **) &pPublishMsg);
    if (OK != status)
    {
        goto exit;
    }
exit:

    DIGI_FREE((void **) &pReq);
    DIGI_FREE((void **) &pPublishMsg);
    return status;
}

static MSTATUS TRUSTEDGE_agentConstructArtifactDownloadRequest(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType revertMessage,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status = OK;

    if (TE_ARTIFACT_STATE_PENDING == pCtx->curPolicy.data.ups.pArtifact->state ||
        TE_ARTIFACT_STATE_INSTALLED == pCtx->curPolicy.data.ups.pArtifact->state)
    {
        status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pCtx->curPolicy.pPolicy->pDeviceGroupId,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            pCtx->pPatData,
            TE_ARTIFACT_STATE_DOWNLOADING);
        if (OK != status)
        {
            pCtx->curPolicy.lastPolicyMsgType = revertMessage;
            goto exit;
        }

        pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_DOWNLOADING;
        pCtx->curPolicy.pPolicy->lastMsgSentType = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
    }

    TRUSTEDGE_agentPersistConfiguration(pCtx);

    if (TE_ARTIFACT_STATE_DOWNLOADING == pCtx->curPolicy.data.ups.pArtifact->state)
    {
        MSG_LOG_print(MSG_LOG_INFO, "Creating artifact download request for %s\n", pCtx->curPolicy.data.ups.pArtifact->pId);
        status = TRUSTEDGE_agentConstructAritfactDownloadRequest(
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pCtx->curPolicy.pPolicy->pDeviceGroupId,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            pCtx->pConfig->chunkSupported,
            pCtx->pConfig->chunkSize,
            pCtx->pPatData,
            ppReq,
            pReqLen);
        if (OK != status)
        {
            goto exit;
        }
    }

exit:
    return status;
}

extern MSTATUS TRUSTEDGE_agentConstructArtifactChunkAck(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status;
    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte4 ret;
    ubyte4 i;

    MSG_LOG_print(MSG_LOG_INFO, "Creating artifact chunk ack for sequence %d\n", pCtx->curPolicy.data.ups.pArtifact->seqNum);

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (pCtx->pPatData)
    {
        ret = snprintf(NULL, 0, ACK_CHUNK_MSG_WITH_AUTH,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->seqNum,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize,
            pCtx->pPatData);
    }
    else
    {
        ret = snprintf(NULL, 0, ACK_CHUNK_MSG,
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pTimeStamp,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->curPolicy.pPolicy->pDeploymentId,
                        pCtx->curPolicy.data.ups.pArtifact->pId,
                        (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
                        (unsigned long)pCtx->curPolicy.data.ups.pArtifact->seqNum,
                        (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
                        (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize);
    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    if (pCtx->pPatData)
    {
        ret = snprintf(pMsg, ret + 1, ACK_CHUNK_MSG_WITH_AUTH,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->seqNum,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize,
            pCtx->pPatData);
    }
    else
    {
        ret = snprintf(pMsg, ret + 1, ACK_CHUNK_MSG,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->seqNum,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize);

    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    for (i = 0; i < pCtx->curPolicy.data.ups.pArtifact->chunkTrackerSize; i++)
    {
        pCtx->curPolicy.data.ups.pArtifact->pChunkTracker[i] = FALSE;
    }

    *ppReq = pMsg; pMsg = NULL;
    *pReqLen = ret;

exit:

    if (NULL != pMsg)
        DIGI_FREE((void **) &pMsg);

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

extern MSTATUS TRUSTEDGE_agentSendChunkAck(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    ubyte *pReq = NULL;
    ubyte4 reqLen = 0;
    ubyte *pUUID = "DeviceTM_Artifact_Chunk_Ack";
    ubyte *pPublishMsg = NULL;
    ubyte4 publishMsgLen = 0;

    status = TRUSTEDGE_agentConstructArtifactChunkAck(
        pCtx, &pReq, &reqLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_agentProtobufCreate(
        pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
    DIGI_FREE((void **) &pReq);
    if (OK != status)
    {
        goto exit;
    }

    status = TRUSTEDGE_agentPublishMessage(
        pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
    DIGI_FREE((void **) &pPublishMsg);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentConstructArtifactChunkRequest(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    MSTATUS status;
    sbyte *pMsg = NULL;
    sbyte *pTimeStamp = NULL;
    sbyte4 ret;

    MSG_LOG_print(MSG_LOG_INFO, "Creating artifact chunk request for %s\n", pCtx->curPolicy.data.ups.pArtifact->pId);

    status = TRUSTEDGE_utilsGetTime(&pTimeStamp, 0);
    if (OK != status)
        goto exit;

    if (NULL != pCtx->pPatData)
    {
        ret = snprintf(NULL, 0, MQTT_ARTIFACT_CHUNK_REQ_MSG,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)(pCtx->curPolicy.data.ups.pArtifact->seqNum + 1),
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize,
            pCtx->pPatData);
    }
    else
    {
        ret = snprintf(NULL, 0, MQTT_ARTIFACT_CHUNK_REQ_NO_AUTH_MSG,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)(pCtx->curPolicy.data.ups.pArtifact->seqNum + 1),
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize);
    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pMsg, ret + 1);
    if (OK != status)
        goto exit;

    if (NULL != pCtx->pPatData)
    {
        ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_CHUNK_REQ_MSG,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)(pCtx->curPolicy.data.ups.pArtifact->seqNum + 1),
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize,
            pCtx->pPatData);
    }
    else
    {
        ret = snprintf(pMsg, ret + 1, MQTT_ARTIFACT_CHUNK_REQ_NO_AUTH_MSG,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pTimeStamp,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->downloadedSize,
            (unsigned long)(pCtx->curPolicy.data.ups.pArtifact->seqNum + 1),
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize,
            (unsigned long)pCtx->curPolicy.data.ups.pArtifact->chunkSize);
    }
    if (0 > ret)
    {
        status = ERR_TRUSTEDGE_AGENT_MSG_CREATION_FAILED;
        goto exit;
    }

    *ppReq = pMsg; pMsg = NULL;
    *pReqLen = ret;

exit:

    if (NULL != pMsg)
        DIGI_FREE((void **) &pMsg);

    if (NULL != pTimeStamp)
        DIGI_FREE((void **) &pTimeStamp);

    return status;
}

static MSTATUS TRUSTEDGE_agentAcknowledgeArtifacts(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status = OK;
    TrustEdgeAgentArtifactNode *pNode;

    pNode = pCtx->curPolicy.data.ups.pArtifactHead;
    while (NULL != pNode)
    {
        if (TE_ARTIFACT_STATE_UNDEFINED == pNode->state)
        {
            status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
                pCtx->configOptions.pDeviceId,
                pCtx->configOptions.pAccountId,
                pCtx->curPolicy.pPolicy->pDeviceGroupId,
                pCtx->curPolicy.pPolicy->pId,
                pCtx->curPolicy.pPolicy->pDeploymentId,
                pNode->pId,
                pCtx->pPatData,
                TE_ARTIFACT_STATE_PENDING);
            if (OK != status)
            {
                goto exit;
            }

            pNode->state = TE_ARTIFACT_STATE_PENDING;
        }

        pNode = pNode->pNext;
    }

exit:

    TRUSTEDGE_agentPersistConfiguration(pCtx);
    return status;
}

extern MSTATUS TRUSTEDGE_agentCheckStatusFile(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status;
    sbyte *pDirPath = NULL;
    sbyte *pFilePath = NULL;
#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
    sbyte *pArtifactDir = NULL;
#endif

    sbyte *pArtifactId = NULL;
    sbyte *pPolicyId = NULL;
    sbyte *pDeploymentId = NULL;
    sbyte *pMode = NULL;
    sbyte *pStatus = NULL;

    ubyte *pData = NULL;
    ubyte4 dataLen;

    JSON_ContextType *pJCtx = NULL;
    ubyte4 numTokens;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pConfig->pConfDir, "artifacts", &pDirPath);
    if (OK != status)
        goto exit;

    status = COMMON_UTILS_addPathComponent(
        pDirPath, pCtx->curPolicy.data.ups.pArtifact->pId, &pFilePath);
    if (OK != status)
        goto exit;

    if (TRUE == FMGMT_pathExists(pFilePath, NULL))
    {
        status = DIGICERT_readFile(pFilePath, &pData, &dataLen);
        if (OK != status)
            goto exit;

        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
            goto exit;

        status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
        if (OK != status)
            goto exit;

        status = JSON_getJsonStringValue(pJCtx, 0, "artifactId", &pArtifactId, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
            goto exit;

        if (0 != DIGI_STRNCMP(pArtifactId, pCtx->curPolicy.data.ups.pArtifact->pId, DIGI_STRLEN(pArtifactId)))
        {
            goto exit;
        }

        status = JSON_getJsonStringValue(pJCtx, 0, "policyId", &pPolicyId, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
            goto exit;

        status = JSON_getJsonStringValue(pJCtx, 0, "deploymentId", &pDeploymentId, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
            goto exit;

        status = JSON_getJsonStringValue(pJCtx, 0, "mode", &pMode, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
            goto exit;

        status = JSON_getJsonStringValue(pJCtx, 0, "status", &pStatus, TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
            goto exit;

        if (0 == DIGI_STRNICMP(pStatus, "Success", DIGI_STRLEN("Success")))
        {
            MSG_LOG_print(MSG_LOG_INFO, "Artifact %s succeeded\n", pArtifactId);
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALLED;
            else
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_INSTALLED;

            pCtx->needToProcessResponse = TRUE;
            (void) FMGMT_remove(pFilePath, FALSE);

#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
            if (FALSE == pCtx->persistArtifact)
            {
                status = COMMON_UTILS_addPathComponent(
                    pCtx->pWorkspaceDir, "artifact", &pArtifactDir);
                if (OK != status)
                    goto exit;

                (void) FMGMT_remove(pArtifactDir, TRUE);
            }
#endif
        }
        else if (0 == DIGI_STRNICMP(pStatus, "Failed", DIGI_STRLEN("Failed")))
        {
            MSG_LOG_print(MSG_LOG_INFO, "Artifact %s failed\n", pArtifactId);
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
            {
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALL_FAILED;
            }
            else
            {
                if (TE_POLICY_STATUS_PENDING == pCtx->curPolicy.pPolicy->status)
                    pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_FAILED;
            }

            pCtx->needToProcessResponse = TRUE;
            pCtx->curPolicy.lastPolicyMsgType = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
            (void) FMGMT_remove(pFilePath, FALSE);

#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
            if (FALSE == pCtx->persistArtifact)
            {
                status = COMMON_UTILS_addPathComponent(
                    pCtx->pWorkspaceDir, "artifact", &pArtifactDir);
                if (OK != status)
                    goto exit;

                (void) FMGMT_remove(pArtifactDir, TRUE);
            }
#endif
        }
        else if (0 == DIGI_STRNICMP(pStatus, "Pending", DIGI_STRLEN("Pending")))
        {
            MSG_LOG_print(MSG_LOG_INFO, "Artifact %s is pending\n", pArtifactId);
        }
    }
    else if (TRUE == pCtx->curPolicy.data.ups.pArtifact->isAsync &&
        ((TE_ARTIFACT_STATE_INSTALLING  == pCtx->curPolicy.data.ups.pArtifact->state) ||
        (TE_ARTIFACT_STATE_UNINSTALLING == pCtx->curPolicy.data.ups.pArtifact->state)))
    {
        /* not enough information to update state */
        status = ERR_TRUSTEDGE_AGENT;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
    }
exit:

    DIGI_FREE((void **) &pArtifactId);
    DIGI_FREE((void **) &pPolicyId);
    DIGI_FREE((void **) &pDeploymentId);
    DIGI_FREE((void **) &pMode);
    DIGI_FREE((void **) &pStatus);
#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
    DIGI_FREE((void **) &pArtifactDir);
#endif

    return status;
}

extern MSTATUS TRUSTEDGE_agentProcessCurrentPolicyNodes(
    TrustEdgeAgentCtx *pCtx)
{
    MSTATUS status = OK;
    ubyte *pReq = NULL, *pPublishMsg = NULL;
    ubyte4 reqLen = 0, publishMsgLen = 0;
    sbyte *pUUID = NULL;
    sbyte *pProcessingTimestamp = NULL;
    byteBoolean endOfPolicy;
    TrustEdgeAgentPolicyNode *pCur;
    TrustEdgeAgentArtifactNode *pNode;
    TrustEdgeAgentMessageType revertMessage;
    TrustEdgeAgentPolicyNode *pPolicy = NULL;
    ubyte4 i = 0;

    while (NULL != pCtx->curPolicy.pPolicy &&
        (TRUE == pCtx->needToProcessResponse || TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status))
    {
        if (FALSE == TRUSTEDGE_utilsTokenValid(
                pCtx->curPolicy.pPolicy->pId,
                pCtx->configOptions.pAccountId,
                pCtx->configOptions.pDeviceId,
                pCtx->configOptions.pDivisionId,
            pCtx->pPatData))
        {
            if (TRUE == FMGMT_pathExists(pCtx->pPatFile, NULL))
            {
                MSG_LOG_print(MSG_LOG_WARNING, "%s", "Policy Authorization Token failed to validate.\n");
                MSG_LOG_print(MSG_LOG_WARNING, "%s", "Clear Policy Authorization Token data.\n");
                DIGI_FREE((void **) &(pCtx->pPatData));
                status = FMGMT_remove(pCtx->pPatFile, FALSE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
            else if (TRUE == pCtx->enforceToken)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "%s", "Policy Authorization Token does not exist.\n");
            }

            if (TRUE == pCtx->enforceToken)
            {
                MSG_LOG_print(MSG_LOG_WARNING, "%s", "Sending policy refresh.\n");
                status = TRUSTEDGE_agentPolicyUnlinkNode(
                            pCtx->curPolicy.pPolicy, &pCtx->pPendingPolicies);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = TRUSTEDGE_agentPolicyDeleteNodes(&pCtx->pPendingPolicies);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pCtx->pPendingPolicies = pCtx->curPolicy.pPolicy;
                status = TRUSTEDGE_agentSendPolicyRefresh(
                            pCtx,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                pCtx->refreshToken          = TRUE;
                pCtx->needToProcessResponse = FALSE;
                goto exit;
            }
        }

        endOfPolicy = FALSE;
        revertMessage = pCtx->curPolicy.lastPolicyMsgType;
        switch (pCtx->curPolicy.lastPolicyMsgType)
        {
            case TE_MSG_TYPE_PENDING_POLICIES:
            {
                if (NULL != pCtx->curPolicy.pPolicy)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating initial message for policy ID %s (%d)\n", pCtx->curPolicy.pPolicy->pId, pCtx->curPolicy.pPolicy->type);
                }
                if (NULL != pCtx->curPolicy.pPolicy && TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    /* this occurs when initial policy request was sent and received a fatal error response */
                    if (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type)
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating certificate failed message\n");
                        status = TRUSTEDGE_agentConstructCertificateStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->pPatData,
                            FALSE,
                            pCtx->curPolicy.stage,
                            pCtx->curPolicy.policyErrorStatus,
                            pCtx->curPolicy.pPolicy->pServerErrorMsg,
                            &pReq, &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Certificate_Policy_Failed";
                    }
                    else if (TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type)
                    {
                        /* Deployment status */
                        status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData,
                            FALSE,
                            "-1",
                            "failed to process artifact list response",
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Update_Policy_Deployment_Failed";
                    }
                    else
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating cloud platform failed message\n");
                        status = TRUSTEDGE_agentConstructCloudPlatformPolicyStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            FALSE,
                            "-1",
                            "failed to process cloud platform response",
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Cloud_Platform_Policy_Failed";
                    }

                    endOfPolicy = TRUE;
                    break;
                }

                status = TRUSTEDGE_agentConstructInitialPolicyRequest(pCtx, &pUUID, &pReq, &reqLen);
                if (ERR_TRUSTEDGE_AGENT_POLICY_NOT_FOUND == status && TE_POLICY_TYPE_CLOUDPLATFORM == pCtx->curPolicy.pPolicy->type)
                {
                    endOfPolicy = TRUE;
                    break;
                }
                else if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "%s", "Failed to construct initial policy request\n");
                    pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                    pCtx->curPolicy.policyErrorStatus = status;
                    if (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type)
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating certificate failed message\n");
                        status = TRUSTEDGE_agentConstructCertificateStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->pPatData,
                            FALSE,
                            pCtx->curPolicy.stage,
                            pCtx->curPolicy.policyErrorStatus,
                            pCtx->curPolicy.pPolicy->pServerErrorMsg,
                            &pReq, &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Certificate_Policy_Failed";
                    }
                    else if (TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type)
                    {
                        /* Deployment status */
                        status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData,
                            FALSE,
                            "-1",
                            "failed to process artifact list response",
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Update_Policy_Deployment_Failed";
                    }
                    else
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating cloud platform failed message\n");
                        status = TRUSTEDGE_agentConstructCloudPlatformPolicyStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            FALSE,
                            "-1",
                            "failed to create cloud platform request",
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Cloud_Platform_Policy_Failed";
                    }
                    endOfPolicy = TRUE;
                }
                else
                {
                    if (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type)
                    {
                        pCtx->curPolicy.pPolicy->lastMsgSentType = TE_MSG_TYPE_CERTIFICATE_SPECIFICATION;
                    }
                    else if (TE_POLICY_TYPE_UPDATE == pCtx->curPolicy.pPolicy->type)
                    {
                        pCtx->curPolicy.pPolicy->lastMsgSentType = TE_MSG_TYPE_RELEASE_ARTIFACT_LIST;
                    }
                    else
                    {
                        pCtx->curPolicy.pPolicy->lastMsgSentType = TE_MSG_TYPE_CLOUDPLATFORM;
                    }
                }
                break;
            }
            case TE_MSG_TYPE_CERTIFICATE_SPECIFICATION:
            {
                if (TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating certificate failure message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCertificateStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->pPatData,
                        FALSE,
                        pCtx->curPolicy.stage,
                        pCtx->curPolicy.policyErrorStatus,
                        pCtx->curPolicy.pPolicy->pServerErrorMsg,
                        &pReq, &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Certificate_Policy_Failed";
                    endOfPolicy = TRUE;
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating certificate request message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCertificateRequest(pCtx, &pReq, &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s", "Failed to construct issued certificate request\n");
                        pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                        pCtx->curPolicy.policyErrorStatus = status;
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating certificate failed message\n");
                        status = TRUSTEDGE_agentConstructCertificateStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->pPatData,
                            FALSE,
                            pCtx->curPolicy.stage,
                            pCtx->curPolicy.policyErrorStatus,
                            pCtx->curPolicy.pPolicy->pServerErrorMsg,
                            &pReq, &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Certificate_Policy_Failed";
                        endOfPolicy = TRUE;
                    }
                    else
                    {
                        pUUID = "DeviceTM_Certificate_Request";
                        pCtx->curPolicy.pPolicy->lastMsgSentType = TE_MSG_TYPE_ISSUED_CERTIFICATE;
                    }
                }
                break;
            }
            case TE_MSG_TYPE_ISSUED_CERTIFICATE:
            {
                if (TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating certificate failed message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCertificateStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->pPatData,
                        FALSE,
                        pCtx->curPolicy.stage,
                        pCtx->curPolicy.policyErrorStatus,
                        pCtx->curPolicy.pPolicy->pServerErrorMsg,
                        &pReq, &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Certificate_Policy_Failed";
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating certificate completed message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCertificateStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->pPatData,
                        TRUE,
                        pCtx->curPolicy.stage,
                        OK,
                        pCtx->curPolicy.pPolicy->pServerErrorMsg,
                        &pReq, &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Certificate_Policy_Completed";
                }
                endOfPolicy = TRUE;
                break;
            }
            case TE_MSG_TYPE_CERTIFICATE_RENEW:
            {
                /* Nothing to do */
                status = OK;
                goto exit;
            }
            case TE_MSG_TYPE_RELEASE_ARTIFACT_LIST:
            {
                if (TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating deployment failure message for %s\n", pCtx->curPolicy.pPolicy->pDeploymentId);
                    /* Deployment status */
                    status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        pCtx->curPolicy.pPolicy->pDeploymentId,
                        pCtx->pPatData,
                        FALSE,
                        "-1",
                        "failed to process artifact list response",
                        &pReq,
                        &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Update_Policy_Deployment_Failed";
                    endOfPolicy = TRUE;
                }
                else
                {
                    if (NULL == pCtx->curPolicy.data.ups.pArtifact && TE_POLICY_STATUS_SUCCESS == pCtx->curPolicy.pPolicy->status)
                    {
                        /* if artifact list is empty, nothing to do in policy */
                        MSG_LOG_print(MSG_LOG_INFO, "Creating deployment complete message for %s\n", pCtx->curPolicy.pPolicy->pDeploymentId);
                        status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData,
                            TRUE,
                            NULL,
                            NULL,
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Update_Policy_Deployment_Completed";
                        endOfPolicy = TRUE;

                        /* persist */
                        status = TRUSTEDGE_agentPersistConfiguration(pCtx);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        break;
                    }

                    /* we are blocked until all artifacts are in "pending state" */
                    status = TRUSTEDGE_agentAcknowledgeArtifacts(pCtx);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                        revertMessage, &pReq, &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Update_Artifact_Request";

                    /* persist */
                    status = TRUSTEDGE_agentPersistConfiguration(pCtx);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }
                break;
            }
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK:
            case TE_MSG_TYPE_ARTIFACT_DOWNLOAD:
            {
                if (TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    if (TE_ARTIFACT_STATE_FAILED           == pCtx->curPolicy.data.ups.pArtifact->state ||
                        TE_ARTIFACT_STATE_UNINSTALL_FAILED == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->curPolicy.data.ups.pArtifact->pId,
                            pCtx->pPatData,
                            pCtx->curPolicy.data.ups.pArtifact->state);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                    }

                    /* if we have installed artifacts, switch to rollback state */
                    pNode = TRUSTEDGE_agentNextRollbackArtifact(pCtx->curPolicy.data.ups.pArtifact);
                    if (NULL != pNode)
                    {
                        pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_ROLLBACK;
                        pCtx->curPolicy.data.ups.pArtifact = pNode;
                        status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                            revertMessage, &pReq, &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Update_Artifact_Request";
                    }
                    else
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "Creating deployment failure message for %s\n", pCtx->curPolicy.pPolicy->pDeploymentId);
                        /* Deployment status */
                        status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->pPatData,
                            FALSE,
                            "-1",
                            "failed to process artifact download response",
                            &pReq,
                            &reqLen);
                        if (OK != status)
                        {
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        pUUID = "DeviceTM_Update_Policy_Deployment_Failed";
                        endOfPolicy = TRUE;
                    }
                }
                else if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                {
                    if (TE_ARTIFACT_STATE_UNINSTALLED      == pCtx->curPolicy.data.ups.pArtifact->state ||
                        TE_ARTIFACT_STATE_UNINSTALL_FAILED == pCtx->curPolicy.data.ups.pArtifact->state ||
                        TRUE == pCtx->curPolicy.data.ups.pArtifact->ignore)
                    {
                        if (FALSE == pCtx->curPolicy.data.ups.pArtifact->ignore)
                        {
                            status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pCtx->curPolicy.pPolicy->pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pCtx->curPolicy.pPolicy->pDeploymentId,
                                pCtx->curPolicy.data.ups.pArtifact->pId,
                                pCtx->pPatData,
                                pCtx->curPolicy.data.ups.pArtifact->state);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                        }

                        /* move to next artifact, if any */
                        pNode = TRUSTEDGE_agentNextRollbackArtifact(pCtx->curPolicy.data.ups.pArtifact);
                        if (NULL != pNode)
                        {
                            pCtx->curPolicy.data.ups.pArtifact = pNode;
                            status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                                revertMessage,
                                &pReq,
                                &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Artifact_Request";
                        }
                        else
                        {
                            /* rollback has been completed */
                            if (TRUE == pCtx->curPolicy.pPolicy->hasFailed)
                            {
                                MSG_LOG_print(MSG_LOG_INFO, "Creating deployment failure message for %s\n",  pCtx->curPolicy.pPolicy->pDeploymentId);
                                status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                                    pCtx->configOptions.pDeviceId,
                                    pCtx->configOptions.pAccountId,
                                    pCtx->curPolicy.pPolicy->pDeviceGroupId,
                                    pCtx->curPolicy.pPolicy->pId,
                                    pCtx->curPolicy.pPolicy->pDeploymentId,
                                    pCtx->pPatData,
                                    FALSE,
                                    "-1",
                                    "failed to process artifact download response",
                                    &pReq,
                                    &reqLen);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                                pUUID = "DeviceTM_Update_Policy_Deployment_Failed";

                                /* rollback completed, set fail state on policy */
                                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_FAILURE;
                                endOfPolicy = TRUE;
                            }
                            else
                            {
                                /* we need to move this policy to the end */
                                TRUSTEDGE_agentFreeAgentArtifactList(&pCtx->curPolicy.data.ups.pArtifactHead);
                                pCtx->curPolicy.data.ups.pArtifact = NULL;

                                pPolicy = pCtx->curPolicy.pPolicy;
                                status = TRUSTEDGE_agentPolicyUnlinkNode(
                                    pPolicy, &pCtx->pPendingPolicies);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }

                                pPolicy->status = TE_POLICY_STATUS_PENDING;
                                pPolicy->lastMsgSentType = TE_MSG_TYPE_PENDING_POLICIES;

                                status = TRUSTEDGE_agentPolicyClearCurrent(&pCtx->curPolicy);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }

                                /* get next policy */
                                pCtx->curPolicy.pPolicy = pCtx->pPendingPolicies;

                                if (NULL != pCtx->curPolicy.pPolicy)
                                {
                                    pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_PENDING;

                                    /* add timestamp for when policy was added to processing */
                                    status = TRUSTEDGE_utilsGetTime(&pProcessingTimestamp, 0);
                                    if (OK != status)
                                    {
                                        MSG_LOG_print(MSG_LOG_ERROR,
                                            "%s line %d status: %d = %s\n",
                                            __func__, __LINE__, status,
                                            MERROR_lookUpErrorCode(status));
                                        goto exit;
                                    }

                                    DIGI_FREE((void **) &pCtx->curPolicy.pPolicy->pProccessingTimestamp);
                                    pCtx->curPolicy.pPolicy->pProccessingTimestamp = pProcessingTimestamp;

                                    MSG_LOG_print(MSG_LOG_INFO,
                                        "Advancing to next policy: %s of type %s\n",
                                        pCtx->curPolicy.pPolicy->pId,
                                        (TE_POLICY_TYPE_CERTIFICATE == pCtx->curPolicy.pPolicy->type) ? "CERTIFICATE" : "UPDATE");
                                }

                                /* add policy back into pending policy list */
                                status = TRUSTEDGE_agentPolicyAddNodeEx(pPolicy, &(pCtx->pPendingPolicies));
                                if (OK != status)
                                    goto exit;
                                goto exit;
                            }
                        }
                    }
                    else if (TE_ARTIFACT_STATE_DOWNLOADING == pCtx->curPolicy.data.ups.pArtifact->state ||
                        TE_ARTIFACT_STATE_INSTALLED == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        if (TRUE == pCtx->curPolicy.data.ups.pArtifact->chunking)
                        {
                            if (FALSE == pCtx->curPolicy.data.ups.pArtifact->chunkInitialDone)
                            {
                                status = TRUSTEDGE_agentConstructArtifactChunkRequest(
                                    pCtx,
                                    &pReq,
                                    &reqLen);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                                pUUID = "DeviceTM_Artifact_Chunk_Request";
                            }
                            else
                            {
                                status = TRUSTEDGE_agentConstructArtifactChunkAck(
                                    pCtx,
                                    &pReq,
                                    &reqLen);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                                pUUID = "DeviceTM_Artifact_Chunk_Ack";
                            }
                        }
                        else
                        {
                            status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                                revertMessage,
                                &pReq,
                                &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Artifact_Request";
                        }
                    }
                    else if (TE_ARTIFACT_STATE_UNINSTALLING == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        /* do nothing */
                        pCtx->needToProcessResponse = FALSE;
                        status = OK;
                        goto exit;
                    }
                    else if (TE_ARTIFACT_STATE_PENDING == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        /* if policy state is in rollback mode, and artifact is pending
                         * we want to find next artifact to rollback and begin process */
                        pNode = TRUSTEDGE_agentNextRollbackArtifact(pCtx->curPolicy.data.ups.pArtifact);
                        if (NULL != pNode)
                        {
                            pCtx->curPolicy.data.ups.pArtifact = pNode;
                            status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                                revertMessage,
                                &pReq,
                                &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Artifact_Request";
                        }
                    }
                    else
                    {
                        status = ERR_TRUSTEDGE_AGENT_ERROR_UNKNOWN;
                        MSG_LOG_print(MSG_LOG_DEBUG,
                            "%s line %d status: %d = %s. unexpected artifact state: %d\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status), pCtx->curPolicy.data.ups.pArtifact->state);
                        goto exit;
                    }
                }
                else if (TE_POLICY_STATUS_PENDING == pCtx->curPolicy.pPolicy->status)
                {
                    if (TE_ARTIFACT_STATE_INSTALLED == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating deployment progress message\n");
                        status = TRUSTEDGE_agentSendDeploymentProgress(pCtx,
                            pCtx->configOptions.pDeviceId,
                            pCtx->configOptions.pAccountId,
                            pCtx->curPolicy.pPolicy->pDeviceGroupId,
                            pCtx->curPolicy.pPolicy->pId,
                            pCtx->curPolicy.pPolicy->pDeploymentId,
                            pCtx->curPolicy.data.ups.pArtifact->pId,
                            pCtx->pPatData,
                            pCtx->curPolicy.data.ups.pArtifact->state);
                        if (OK != status)
                        {
                            pCtx->curPolicy.lastPolicyMsgType = revertMessage;
                            MSG_LOG_print(MSG_LOG_ERROR,
                                "%s line %d status: %d = %s\n",
                                __func__, __LINE__, status,
                                MERROR_lookUpErrorCode(status));
                            goto exit;
                        }

                        /* move to next artifact, if any */
                        if (NULL != pCtx->curPolicy.data.ups.pArtifact->pNext)
                        {
                            pCtx->curPolicy.data.ups.pArtifact = pCtx->curPolicy.data.ups.pArtifact->pNext;
                            status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                                revertMessage, &pReq, &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Artifact_Request";
                        }
                        else
                        {
                            if (FALSE == TRUSTEDGE_agentIsArtifactListInstalled(pCtx->curPolicy.data.ups.pArtifactHead))
                            {
                                /* sanity check, all artifacts must be installed before sending complete message */
                                status = ERR_TRUSTEDGE_AGENT;
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            /* Deployment status */
                            MSG_LOG_print(MSG_LOG_INFO, "%s", "Creating deployment complete message\n");
                            status = TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
                                pCtx->configOptions.pDeviceId,
                                pCtx->configOptions.pAccountId,
                                pCtx->curPolicy.pPolicy->pDeviceGroupId,
                                pCtx->curPolicy.pPolicy->pId,
                                pCtx->curPolicy.pPolicy->pDeploymentId,
                                pCtx->pPatData,
                                TRUE,
                                NULL,
                                NULL,
                                &pReq,
                                &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Policy_Deployment_Completed";
                            endOfPolicy = TRUE;
                        }

                        break;
                    }
                    else if (TE_ARTIFACT_STATE_DOWNLOADING == pCtx->curPolicy.data.ups.pArtifact->state ||
                        TE_ARTIFACT_STATE_PENDING == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        if (TRUE == pCtx->curPolicy.data.ups.pArtifact->chunking)
                        {
                            if (FALSE == pCtx->curPolicy.data.ups.pArtifact->chunkInitialDone)
                            {
                                status = TRUSTEDGE_agentConstructArtifactChunkRequest(
                                    pCtx,
                                    &pReq,
                                    &reqLen);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                                pUUID = "DeviceTM_Artifact_Chunk_Request";
                            }
                            else
                            {
                                status = TRUSTEDGE_agentConstructArtifactChunkAck(
                                    pCtx,
                                    &pReq,
                                    &reqLen);
                                if (OK != status)
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                        "%s line %d status: %d = %s\n",
                                        __func__, __LINE__, status,
                                        MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                                pUUID = "DeviceTM_Artifact_Chunk_Ack";
                            }
                        }
                        else
                        {
                            status = TRUSTEDGE_agentConstructArtifactDownloadRequest(pCtx,
                                revertMessage, &pReq, &reqLen);
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR,
                                    "%s line %d status: %d = %s\n",
                                    __func__, __LINE__, status,
                                    MERROR_lookUpErrorCode(status));
                                goto exit;
                            }
                            pUUID = "DeviceTM_Update_Artifact_Request";
                        }
                    }
                    else if (TE_ARTIFACT_STATE_INSTALLING == pCtx->curPolicy.data.ups.pArtifact->state)
                    {
                        /* do nothing */
                        pCtx->needToProcessResponse = FALSE;
                        status = OK;
                        goto exit;
                    }
                    else
                    {
                        status = ERR_TRUSTEDGE_AGENT_ERROR_UNKNOWN;
                        MSG_LOG_print(MSG_LOG_DEBUG,
                            "%s line %d status: %d = %s. unexpected artifact state: %d\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status), pCtx->curPolicy.data.ups.pArtifact->state);
                        goto exit;
                    }
                }
                else if (TE_POLICY_STATUS_UNKNOWN == pCtx->curPolicy.pPolicy->status)
                {
                    status = ERR_TRUSTEDGE_AGENT;
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                /* persist */
                status = TRUSTEDGE_agentPersistConfiguration(pCtx);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                break;
            }
            case TE_MSG_TYPE_CLOUDPLATFORM:
            {
                if (TE_POLICY_STATUS_FAILURE == pCtx->curPolicy.pPolicy->status)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating cloud platform failure message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCloudPlatformPolicyStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        FALSE,
                        "-1",
                        "failed to process cloud platform response",
                        &pReq,
                        &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Cloud_Platform_Policy_Failed";
                    endOfPolicy = TRUE;
                }
                else
                {
                    MSG_LOG_print(MSG_LOG_INFO, "Creating cloud platform complete message for %s\n", pCtx->curPolicy.pPolicy->pId);
                    status = TRUSTEDGE_agentConstructCloudPlatformPolicyStatus(
                        pCtx->configOptions.pDeviceId,
                        pCtx->configOptions.pAccountId,
                        pCtx->curPolicy.pPolicy->pDeviceGroupId,
                        pCtx->curPolicy.pPolicy->pId,
                        TRUE,
                        NULL,
                        NULL,
                        &pReq,
                        &reqLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pUUID = "DeviceTM_Cloud_Platform_Policy_Completed";
                }
                endOfPolicy = TRUE;
                break;
            }
            case TE_MSG_TYPE_ERROR_RESPONSE:
            case TE_MSG_TYPE_UNKNOWN:
                status = ERR_TRUSTEDGE_AGENT;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
        }

        if (NULL != pReq && 0 != reqLen)
        {
            status = TRUSTEDGE_agentProtobufCreate(
                pCtx, pUUID, pReq, reqLen, &pPublishMsg, &publishMsgLen);
            DIGI_FREE((void **) &pReq);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)
            TRUSTEDGE_agentKeepMsg(pCtx, pUUID, pPublishMsg, publishMsgLen);
#endif

            status = TRUSTEDGE_agentPublishMessage(
                pCtx, TE_TOPIC_NDATA, pPublishMsg, publishMsgLen);
            DIGI_FREE((void **) &pPublishMsg);
            if (OK != status)
            {
                pCtx->curPolicy.lastPolicyMsgType = revertMessage;
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        if (TRUE == endOfPolicy)
        {
            pCur = pCtx->curPolicy.pPolicy;

            if (TE_POLICY_TYPE_UPDATE == pCur->type)
            {
                pCur->pArtifactList = pCtx->curPolicy.data.ups.pArtifactHead;
                pCtx->curPolicy.data.ups.pArtifactHead = NULL;
            }

            if (TE_POLICY_STATUS_FAILURE == pCur->status)
            {
                status = TRUSTEDGE_agentPolicyAddFinishedNode(
                    pCtx, pCur, &pCtx->pErrorPolicies);
                if (OK != status)
                {
                    goto exit;
                }
                pCur->status = TE_POLICY_STATUS_FAILURE; /* override with fail state */

                MSG_LOG_print(MSG_LOG_INFO,
                    "Failure processing policy: %s\n", pCur->pId);
            }
            else if (ERR_TRUSTEDGE_AGENT_POLICY_NOT_FOUND == status && TE_POLICY_TYPE_CLOUDPLATFORM == pCur->type)
            {
                MSG_LOG_print(MSG_LOG_WARNING,
                    "Dependent policies for cloud platform policy (ID: %s) not found\n", pCur->pId);

                MSG_LOG_print(MSG_LOG_INFO,
                    "%s", "Cloud platform dependent policies:\n");

                for (i = 0; i < pCur->pDependency->count; i++)
                {
                    MSG_LOG_print(MSG_LOG_INFO, "    - %s\n", pCur->pDependency->pPolicies[i].pPolicyId);
                }

                status = OK;

                status = TRUSTEDGE_agentPolicyDeleteNode(&pCtx->curPolicy.pPolicy);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                    goto exit;
                }

            }
            else
            {
                status = TRUSTEDGE_agentPolicyAddFinishedNode(
                    pCtx, pCur, &pCtx->pAppliedPolicies);
                if (OK != status)
                {
                    goto exit;
                }

                MSG_LOG_print(MSG_LOG_INFO,
                    "Finished processing policy: %s\n", pCur->pId);
            }

            status = TRUSTEDGE_agentPolicyClearCurrent(&pCtx->curPolicy);
            if (OK != status)
            {
                goto exit;
            }

            status = TRUSTEDGE_agentPolicyUnlinkNode(
                pCur, &pCtx->pPendingPolicies);
            if (OK != status)
            {
                goto exit;
            }

            pCtx->curPolicy.pPolicy = pCtx->pPendingPolicies;
            pCtx->curPolicy.lastPolicyMsgType = TE_MSG_TYPE_PENDING_POLICIES;

            if (NULL == pCtx->curPolicy.pPolicy)
            {
                pCtx->needToProcessResponse = FALSE;
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
                TRUSTEDGE_setState(CONNECTED);
#endif
            }
            else
            {
                /* At the next policy, force needToProcessResponse to be TRUE
                 * so initial policy message is sent */
                pCtx->curPolicy.pPolicy->status = TE_POLICY_STATUS_PENDING;
                pCtx->needToProcessResponse = TRUE;

                (void) DIGI_FREE((void **) &(pCtx->curPolicy.pPolicy->pProccessingTimestamp));
                status = TRUSTEDGE_utilsGetTime(&(pCtx->curPolicy.pPolicy->pProccessingTimestamp), 0);
                if (OK != status)
                    goto exit;
            }

            /* persist */
            status = TRUSTEDGE_agentPersistConfiguration(pCtx);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else
        {
            pCtx->needToProcessResponse = FALSE;
        }
    }

exit:

    DIGI_FREE((void **) &pPublishMsg);
    DIGI_FREE((void **) &pReq);

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyFindNodeByIdAndType(
    TrustEdgeAgentPolicyNode *pNode,
    sbyte *pId,
    TrustEdgeAgentPolicyType type,
    TrustEdgeAgentPolicyNode **ppNode)
{
    if (NULL == ppNode || NULL == pId)
        return ERR_NULL_POINTER;

    *ppNode = NULL;
    while (NULL != pNode)
    {
        if (0 == DIGI_STRCMP(pNode->pId, pId) && pNode->type == type)
        {
            *ppNode = pNode;
            break;
        }

        pNode = pNode->pNext;
    }

    return OK;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS TRUSTEDGE_validateAppliedPolicy(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pPolicyId,
    TrustEdgeAgentPolicyType type)
{
    MSTATUS status = OK;
    TrustEdgeAgentPolicyNode *pNode = NULL;

    if (NULL != pDeviceId && 0 != DIGI_STRCMP(pDeviceId, pCtx->configOptions.pDeviceId))
    {
        status = ERR_TRUSTEDGE_AGENT_BAD_DEVICE_ID;
        goto exit;
    }

    if (NULL != pAccountId && 0 != DIGI_STRCMP(pAccountId, pCtx->configOptions.pAccountId))
    {
        status = ERR_TRUSTEDGE_AGENT_BAD_ACCOUNT_ID;
        goto exit;
    }

    status = TRUSTEDGE_agentPolicyFindNodeByIdAndType(
        pCtx->pAppliedPolicies, pPolicyId, type, &pNode);
    if (OK != status)
        goto exit;

    if (NULL == pNode)
    {
        status = ERR_TRUSTEDGE_AGENT_BAD_POLICY_ID;
        goto exit;
    }

    if (NULL != pDeviceGroupId && 0 != DIGI_STRCMP(pDeviceGroupId, pNode->pDeviceGroupId))
    {
        status = ERR_TRUSTEDGE_AGENT_BAD_DEVICE_GROUP_ID;
        goto exit;
    }

exit:

    return status;
}

extern MSTATUS TRUSTEDGE_agentPolicyFindNodeByArtifactId(
    TrustEdgeAgentPolicyNode *pNode,
    sbyte *pArtifactId,
    TrustEdgeAgentPolicyNode **ppNode)
{
    if(NULL == pArtifactId || NULL == pNode || NULL == ppNode)
        return ERR_NULL_POINTER;

    *ppNode = NULL;
    MSG_LOG_print(MSG_LOG_INFO,"Searching for artifact %s\n", pArtifactId);

    while (NULL != pNode)
    {
        TrustEdgeAgentArtifactNode *pArtifactNode = pNode->pArtifactList;
        while(NULL != pArtifactNode)
        {
            MSG_LOG_print(MSG_LOG_INFO,"comparing against %s\n", pArtifactNode->pId);
            if (0 == DIGI_STRCMP(pArtifactNode->pId, pArtifactId))
            {
                *ppNode = pNode;
                return OK;
            }
            pArtifactNode = pArtifactNode->pNext;
        }
        pNode = pNode->pNext;
    }

    return OK;
}
