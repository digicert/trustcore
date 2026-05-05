/*
 * trustedge_agent_artifact.h
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

#ifndef __TRUSTEDGE_AGENT_ARTIFACT_HEADER__
#define __TRUSTEDGE_AGENT_ARTIFACT_HEADER__

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/msg_logger.h"

#ifdef __cplusplus
extern "C" {
#endif


enum TrustEdgeArtifactProgress {
    TE_ARTIFACT_STATE_UNDEFINED = 0,
    TE_ARTIFACT_STATE_PENDING,
    TE_ARTIFACT_STATE_DOWNLOADING,
    TE_ARTIFACT_STATE_INSTALLING,
    TE_ARTIFACT_STATE_INSTALLED,
    TE_ARTIFACT_STATE_FAILED,
    TE_ARTIFACT_STATE_UNINSTALLING,
    TE_ARTIFACT_STATE_UNINSTALLED,
    TE_ARTIFACT_STATE_UNINSTALL_FAILED
};

typedef struct TrustEdgeAgentArtifactNode
{
    sbyte *pId;
    sbyte *pName;
    sbyte *pVersion;
    sbyte *pTimestamp;
    ubyte4 size;
    byteBoolean chunking;
    ubyte4 seqNum;
    ubyte4 downloadedSize;
    ubyte4 chunkSize;
    ubyte4 chunkWindowSize;
    byteBoolean *pChunkTracker;
    ubyte4 chunkTrackerSize;
    byteBoolean chunkInitialDone;
    enum TrustEdgeArtifactProgress state;
    intBoolean isAsync;
    intBoolean ignore;
    struct TrustEdgeAgentArtifactNode *pPrev;
    struct TrustEdgeAgentArtifactNode *pNext;
} TrustEdgeAgentArtifactNode;

MOC_EXTERN MSTATUS TRUSTEDGE_agentArtifactAddNode(
    sbyte **ppId,
    sbyte **ppName,
    sbyte **ppVersion,
    sbyte **ppTimestamp,
    sbyte *pStatus,
    ubyte4 size,
    intBoolean isAsync,
    intBoolean ignoreArtifact,
    byteBoolean chunking,
    ubyte4 downloadedBytes,
    ubyte4 seqNum,
    ubyte4 chunkSize,
    ubyte4 windowSize,
    TrustEdgeAgentArtifactNode **ppNode);

MOC_EXTERN void TRUSTEDGE_agentArtifactPrintNodes(
    TrustEdgeAgentArtifactNode *pNode);

MOC_EXTERN void TRUSTEDGE_agentFreeAgentArtifactNode(
    TrustEdgeAgentArtifactNode **ppNode);

MOC_EXTERN void TRUSTEDGE_agentFreeAgentArtifactList(
    TrustEdgeAgentArtifactNode **ppNode);

MOC_EXTERN intBoolean TRUSTEDGE_agentHasInstalledArtifact(
    TrustEdgeAgentArtifactNode *pNode);

MOC_EXTERN TrustEdgeAgentArtifactNode* TRUSTEDGE_agentNextRollbackArtifact(
    TrustEdgeAgentArtifactNode *pNode);

MOC_EXTERN intBoolean TRUSTEDGE_agentIsArtifactListInstalled(
    TrustEdgeAgentArtifactNode *pNode);

MOC_EXTERN sbyte* TRUSTEDGE_getArtifactProgressToString(
    enum TrustEdgeArtifactProgress progress);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_ARTIFACT_HEADER__ */
