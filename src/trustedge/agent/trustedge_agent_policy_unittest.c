/*
 * trustedge_agent_policy_unittest.c
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

#include "trustedge_agent_policy.c"
#include "trustedge_agent_policy_unittest.h"

extern MSTATUS TRUSTEDGE_agentConstructUpdatePolicyDeploymentProgress_unit(
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
    return TRUSTEDGE_agentConstructUpdatePolicyDeploymentProgress(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        pUpdatePolicyId,
        pDeploymentId,
        pArtifactId,
        pAuthorizationToken,
        progressState,
        ppMsg,
        pMsgLen);
}

extern MSTATUS TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus_unit(
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
    return TRUSTEDGE_agentConstructUpdatePolicyDeploymentStatus(
        pDeviceId,
        pAccountId,
        pDeviceGroupId,
        pUpdatePolicyId,
        pDeploymentId,
        pAuthorizationToken,
        isComplete,
        pErrorCode,
        pErrorDesc,
        ppMsg,
        pMsgLen);
}

extern MSTATUS TRUSTEDGE_agentConstructCertificateRequest_unit(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppReq,
    ubyte4 *pReqLen)
{
    return TRUSTEDGE_agentConstructCertificateRequest(
        pCtx,
        ppReq,
        pReqLen);
}
