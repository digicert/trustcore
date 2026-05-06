/*
 * trustedge_agent_policy.h
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

#ifndef __TRUSTEDGE_AGENT_POLICY_HEADER__
#define __TRUSTEDGE_AGENT_POLICY_HEADER__

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_agentProtobufLoadMetricFile(
    TrustEdgeAgentCtx *pCtx,
    FileChoice fileChoice);

MOC_EXTERN void TRUSTEDGE_agentPolicyPrintNodes(
    TrustEdgeAgentPolicyNode *pNode);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyAddNode(
    TrustEdgeAgentPolicyType type,
    sbyte **ppDeviceGroupId,
    sbyte **ppPolicyId,
    sbyte **ppDeploymentId,
    sbyte4 priority,
    sbyte **ppCreationTimestamp,
    sbyte **ppProcessingTimestamp,
    TrustEdgeAgentArtifactNode **ppArtifactList,
    TrustEdgeAgentPolicyDependency **ppPolicyDependency,
    intBoolean hasFailed,
    sbyte4 errorResponseCount,
    TrustEdgeAgentPolicyNode **ppNode);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyAddNodeFinal(
    TrustEdgeAgentPolicyType type,
    sbyte **ppDeviceGroupId,
    sbyte **ppPolicyId,
    sbyte **ppDeploymentId,
    sbyte4 priority,
    sbyte **ppCreationTimestamp,
    sbyte **ppProcessingTimestamp,
    sbyte **ppCompletionTimestamp,
    TrustEdgeAgentPolicyStatus status,
    TrustEdgeAgentMessageType policyState,
    sbyte **ppAlias,
    TrustEdgeAgentArtifactNode **ppArtifactList,
    TrustEdgeAgentPolicyDependency **ppPolicyDependency,
    intBoolean hasFailed,
    sbyte4 errorResponseCount,
    TrustEdgeAgentPolicyNode **ppNode);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyDeleteNode(
    TrustEdgeAgentPolicyNode **ppNode);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyDeleteNodes(
    TrustEdgeAgentPolicyNode **ppNode);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyClearCurrent(
    TrustEdgeAgentPolicyState *pState);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyUnlinkNode(
    TrustEdgeAgentPolicyNode *pPolicy,
    TrustEdgeAgentPolicyNode **ppList);

MOC_EXTERN sbyte4 TRUSTEDGE_agentCountPolicies(
    TrustEdgeAgentPolicyNode *pPolicy);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyDetermineNext(
    TrustEdgeAgentCtx *pCtx,
    TrustEdgeAgentMessageType msgType);

MOC_EXTERN MSTATUS TRUSTEDGE_agentProcessCurrentPolicyNodes(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPolicyFindNodeByIdAndType(
    TrustEdgeAgentPolicyNode *pNode,
    sbyte *pId,
    TrustEdgeAgentPolicyType type,
    TrustEdgeAgentPolicyNode **ppNode);

MSTATUS TRUSTEDGE_agentPolicyFindNodeByArtifactId(
    TrustEdgeAgentPolicyNode *pNode,
    sbyte *pArtifactId,
    TrustEdgeAgentPolicyNode **ppNode);

MOC_EXTERN MSTATUS TRUSTEDGE_evalFunction(
    void *pEvalFunctionArg,
    byteBoolean *pUseDefault,
    sbyte *pExpression,
    ubyte4 expressionLen,
    sbyte *pOutput,
    ubyte4 *pOutputLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentSendUpdatePolicyDeploymentStatus(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pAuthorizationToken,
    intBoolean isComplete,
    sbyte *pErrorCode,
    sbyte *pErrorDesc);

MOC_EXTERN MSTATUS TRUSTEDGE_agentSendCertificateStatus(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pCertPolicyId,
    sbyte *pAuthorizationToken,
    intBoolean succeed,
    TrustEdgeAgentPolicyStage stage,
    MSTATUS policyErrorStatus);

MOC_EXTERN MSTATUS TRUSTEDGE_agentSendDeploymentProgress(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pUpdatePolicyId,
    sbyte *pDeploymentId,
    sbyte *pArtifactId,
    sbyte *pAuthorizationToken,
    enum TrustEdgeArtifactProgress progressState);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCheckStatusFile(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_validateAppliedPolicy(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pDeviceId,
    sbyte *pAccountId,
    sbyte *pDeviceGroupId,
    sbyte *pPolicyId,
    TrustEdgeAgentPolicyType type);

MOC_EXTERN MSTATUS TRUSTEDGE_agentSendChunkAck(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_agentSendPolicyRefresh(
        TrustEdgeAgentCtx *pCtx,
        sbyte *pDeviceId,
        sbyte *pAccountId,
        sbyte *pDeviceGroupId);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_POLICY_HEADER__ */
