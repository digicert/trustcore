/*
 * trustedge_agent_artifact.c
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

#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"
#include "../../trustedge/agent/trustedge_agent_artifact.h"

static enum TrustEdgeArtifactProgress TRUSTEDGE_getArtifactProgress(sbyte *pStatus)
{
    if (NULL == pStatus)
        return TE_ARTIFACT_STATE_UNDEFINED;

    if (0 == DIGI_STRNICMP(pStatus, "Pending", DIGI_STRLEN("Pending")))
    {
        return TE_ARTIFACT_STATE_PENDING;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Downloading", DIGI_STRLEN("Downloading")))
    {
        return TE_ARTIFACT_STATE_DOWNLOADING;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Installing", DIGI_STRLEN("Installing")))
    {
        return TE_ARTIFACT_STATE_INSTALLING;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Uninstalling", DIGI_STRLEN("Uninstalling")))
    {
        return TE_ARTIFACT_STATE_UNINSTALLING;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Installed", DIGI_STRLEN("Installed")))
    {
        return TE_ARTIFACT_STATE_INSTALLED;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Uninstalled", DIGI_STRLEN("Uninstalled")))
    {
        return TE_ARTIFACT_STATE_UNINSTALLED;
    }

    if (0 == DIGI_STRNICMP(pStatus, "Failed", DIGI_STRLEN("Failed")))
    {
        return TE_ARTIFACT_STATE_FAILED;
    }

    if (0 == DIGI_STRNICMP(pStatus, "UninstallFailed", DIGI_STRLEN("UninstallFailed")))
    {
        return TE_ARTIFACT_STATE_UNINSTALL_FAILED;
    }

    return TE_ARTIFACT_STATE_UNDEFINED;
}

extern sbyte* TRUSTEDGE_getArtifactProgressToString(enum TrustEdgeArtifactProgress progress)
{
    switch (progress)
    {
        case TE_ARTIFACT_STATE_PENDING:
            return "Pending";
        case TE_ARTIFACT_STATE_DOWNLOADING:
            return "Downloading";
        case TE_ARTIFACT_STATE_INSTALLING:
            return "Installing";
        case TE_ARTIFACT_STATE_UNINSTALLING:
            return "Uninstalling";
        case TE_ARTIFACT_STATE_INSTALLED:
            return "Installed";
        case TE_ARTIFACT_STATE_UNINSTALLED:
            return "Uninstalled";
        case TE_ARTIFACT_STATE_FAILED:
            return "Failed";
        case TE_ARTIFACT_STATE_UNINSTALL_FAILED:
            return "UninstallFailed";
        case TE_ARTIFACT_STATE_UNDEFINED:
        default:
            return "Undefined";
    };
}

extern MSTATUS TRUSTEDGE_agentArtifactAddNode(
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
    TrustEdgeAgentArtifactNode **ppNode)
{
    MSTATUS status;
    TrustEdgeAgentArtifactNode *pNode = NULL, *pPrevious = NULL;
    TrustEdgeAgentArtifactNode **ppCurrent = ppNode;

    status = DIGI_MALLOC((void **) &pNode, sizeof(TrustEdgeAgentArtifactNode));
    if (OK != status)
    {
        goto exit;
    }

    pNode->pId = *ppId; *ppId = NULL;
    pNode->pName = *ppName; *ppName = NULL;
    pNode->pVersion = *ppVersion; *ppVersion = NULL;
    pNode->pTimestamp = *ppTimestamp; *ppTimestamp = NULL;
    pNode->size = size;
    pNode->isAsync = isAsync;
    pNode->ignore = ignoreArtifact;
    pNode->chunking = chunking;
    pNode->seqNum = seqNum;
    pNode->pChunkTracker = NULL;
    pNode->chunkTrackerSize = 0;
    pNode->chunkInitialDone = FALSE;
    pNode->downloadedSize = downloadedBytes;
    pNode->chunkSize = chunkSize;
    pNode->chunkWindowSize = windowSize;
    if (NULL == pStatus)
    {
        pNode->state = TE_ARTIFACT_STATE_PENDING;
    }
    else
    {
        pNode->state = TRUSTEDGE_getArtifactProgress(pStatus);
    }

    pNode->pPrev = NULL;
    pNode->pNext = NULL;

    while (NULL != *ppCurrent)
    {
        pPrevious = *ppCurrent;
        ppCurrent = &((*ppCurrent)->pNext);
    }

    *ppCurrent = pNode;
    if (NULL != pPrevious)
    {
        /* list was not empty. */
        pPrevious->pNext = pNode;
        pNode->pPrev = pPrevious;
    }

exit:

    return status;
}

extern void TRUSTEDGE_agentArtifactPrintNodes(
    TrustEdgeAgentArtifactNode *pNode)
{
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", ">>> PRINTING ARTIFACT NODE(S) START\n");

    while (NULL != pNode)
    {
        MSG_LOG_print(MSG_LOG_VERBOSE, "NODE %p\n", pNode);

        MSG_LOG_print(MSG_LOG_VERBOSE, "> ID: %s\n", pNode->pId);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> NAME: %s\n", pNode->pName);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> VERSION: %s\n", pNode->pVersion);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> TIMESTAMP: %s\n", pNode->pTimestamp);
        MSG_LOG_print(MSG_LOG_VERBOSE, "> SIZE: %d\n", pNode->size);

        pNode = pNode->pNext;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "<<< PRINTING ARTIFACT NODE(S) END\n");
}

extern void TRUSTEDGE_agentFreeAgentArtifactNode(TrustEdgeAgentArtifactNode **ppNode)
{
    if (NULL == ppNode || NULL == *ppNode)
        return;

    DIGI_FREE((void **) &((*ppNode)->pId));
    DIGI_FREE((void **) &((*ppNode)->pName));
    DIGI_FREE((void **) &((*ppNode)->pVersion));
    DIGI_FREE((void **) &((*ppNode)->pTimestamp));
    DIGI_FREE((void **) &((*ppNode)->pChunkTracker));
    (*ppNode)->chunkTrackerSize = 0;
    DIGI_FREE((void **) ppNode);
}

extern void TRUSTEDGE_agentFreeAgentArtifactList(TrustEdgeAgentArtifactNode **ppNode)
{
    TrustEdgeAgentArtifactNode *pArtifactList;
    TrustEdgeAgentArtifactNode *pNode;
    if (NULL == ppNode || NULL == *ppNode)
        return;

    pArtifactList = *ppNode;
    while (NULL != pArtifactList)
    {
        pNode = pArtifactList;
        pArtifactList = pArtifactList->pNext;
        TRUSTEDGE_agentFreeAgentArtifactNode(&pNode);
    }
    *ppNode = NULL;
}

extern intBoolean TRUSTEDGE_agentHasInstalledArtifact(TrustEdgeAgentArtifactNode *pNode)
{
    while (NULL != pNode)
    {
        if (FALSE == pNode->ignore && TE_ARTIFACT_STATE_INSTALLED == pNode->state)
        {
            return TRUE;
        }

        pNode = pNode->pPrev;
    }

    return FALSE;
}

extern TrustEdgeAgentArtifactNode* TRUSTEDGE_agentNextRollbackArtifact(TrustEdgeAgentArtifactNode *pNode)
{
    while (NULL != pNode)
    {
        if (FALSE == pNode->ignore && TE_ARTIFACT_STATE_INSTALLED == pNode->state)
        {
            return pNode;
        }

        pNode = pNode->pPrev;
    }

    return NULL;
}

extern intBoolean TRUSTEDGE_agentIsArtifactListInstalled(TrustEdgeAgentArtifactNode *pNode)
{
    while (NULL != pNode)
    {
        if (FALSE == pNode->ignore && TE_ARTIFACT_STATE_INSTALLED != pNode->state)
        {
            return FALSE;
        }

        pNode = pNode->pNext;
    }

    return TRUE;
}
