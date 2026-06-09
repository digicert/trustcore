/*
 * trustedge_agent_updatepolicy.c
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

/* trustedge_agent_updatepolicy.c
 *
 * Handlers for update policy manifest
 *
*/

#include "../../../thirdparty/miniz/miniz.h"

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/base64.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/msg_logger.h"
#include "../../common/mime_parser.h"
#include "../../common/common_utils.h"

#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/pkcs_key.h"
#include "../../crypto/crypto_utils.h"

#include "../../crypto/hw_accel.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_sig.h"
#endif

#include "trustedge_agent_priv.h"
#include "trustedge_agent_updatepolicy.h"
#include "trustedge_agent_artifact.h"
#include "trustedge_agent_policy.h"
#include "trustedge_agent_artifact.h"
#include "trustedge_agent_actionhandler.h"
#include "../utils/trustedge_utils.h"

typedef struct mimeArtifactHandlerData {
    sbyte *pArtifactid;
    sbyte *pWorkingDir;
    enum TrustEdgeArtifactProgress state;
    ubyte4 artifactOffset;
    ubyte4 artifactLength;
    byteBoolean chunking;
    ubyte4 chunkOffset;
    ubyte4 chunkSize;
    ubyte4 windowSize;
    ubyte4 seqNum;
} mimeArtifactHandlerData;


MSTATUS TRUSTEDGE_agentCheckDependencies(TrustEdgeAgentCtx *pCtx, TrustEdgeArtifactManifest *pManifest)
{
    ubyte4 i = 0;
    MSTATUS status = OK;

    if(NULL == pCtx || NULL == pManifest)
        return ERR_NULL_POINTER;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Checking dependencies\n");
    for(i=0; i < pManifest->dependsOn.count; i++)
    {
        TrustEdgeAgentPolicyNode *pFound = NULL;
        MSG_LOG_print(MSG_LOG_INFO,"DependsOn Artifact name :%s Artifact ID: %s \n",
        pManifest->dependsOn.pArtifact[i].pName, pManifest->dependsOn.pArtifact[i].pId);
        if(NULL != pManifest->dependsOn.pArtifact[i].pId)
        {
            status = TRUSTEDGE_agentPolicyFindNodeByArtifactId(pCtx->pAppliedPolicies, pManifest->dependsOn.pArtifact[i].pId, &pFound);
            if (OK != status)
            {
                return status;
            }
            if(NULL == pFound)
            {
                MSG_LOG_print(MSG_LOG_ERROR,"Dependendent Artifact ID: %s Not found \n", pManifest->dependsOn.pArtifact[i].pId);
                return ERR_TRUSTEDGE_AGENT_DEPENDENCY_NOT_INSTALLED;
            }
            MSG_LOG_print(MSG_LOG_INFO,"Dependendent Artifact ID: %s found \n", pManifest->dependsOn.pArtifact[i].pId);
        }
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Verify dependencies stop\n");

    return status;
}


static MimePartProcessArg *createArtifactHandlerData (sbyte *pId, sbyte *pDir, enum TrustEdgeArtifactProgress state)
{
    mimeArtifactHandlerData *pStruct;

    if (OK != DIGI_MALLOC((void **) &pStruct, sizeof(*pStruct)))
    {
        return NULL;
    }

    if (OK != DIGI_MEMSET ((ubyte *)pStruct, 0x00, sizeof(*pStruct)))
    {
        DIGI_FREE((void **) &pStruct);
        return NULL;
    }

    pStruct->pArtifactid = pId;
    pStruct->pWorkingDir = pDir;
    pStruct->state = state;
    pStruct->artifactOffset = 0;
    pStruct->artifactLength = 0;
    pStruct->chunking = FALSE;
    pStruct->chunkSize = 0;
    pStruct->windowSize = 0;
    pStruct->seqNum = 0;

    return (MimePartProcessArg *) pStruct;
}

static void freeArtifactHandlerData (MimePartProcessArg **ppStruct)
{
    if (NULL == ppStruct) return;
    DIGI_FREE((void **) ppStruct);
}

extern sbyte *TRUSTEDGE_actionTypeToString(TrustEdgeAgentActionType type)
{
    sbyte *pType;

    switch (type)
    {
        case TE_ACTION_UNKNOWN:
            pType = JSON_STR_UNKNOWN;
            break;
        case TE_ACTION_PREINSTALL:
            pType = JSON_STR_PREINSTALL;
            break;
        case TE_ACTION_INSTALL:
            pType = JSON_STR_INSTALL;
            break;
        case TE_ACTION_POSTINSTALL:
            pType = JSON_STR_POSTINSTALL;
            break;
        case TE_ACTION_ROLLBACK:
            pType = JSON_STR_ROLLBACK;
            break;
        default:
            pType = JSON_STR_UNDEFINED;
            break;
    };
    return pType;
}

extern sbyte *TRUSTEDGE_actionHandlerTypeToString(TrustEdgeAgentActionHandlerType type)
{
    sbyte *pType;

    switch (type)
    {
        case TE_ACTION_HANDLER_UNKNOWN:
            pType = JSON_STR_UNKNOWN;
            break;
        case TE_ACTION_HANDLER_SCRIPT:
            pType = JSON_STR_HTYPE_SCRIPT;
            break;
        case TE_ACTION_HANDLER_EXE:
            pType = JSON_STR_HTYPE_EXE;
            break;
        case TE_ACTION_HANDLER_PKG_MGR_TYPE:
            pType = JSON_STR_HTYPE_PKGMGR;
            break;
        default:
            pType = JSON_STR_UNDEFINED;
            break;
    };

    return pType;
}

extern sbyte *TRUSTEDGE_actionHandlerSubTypeToString(TrustEdgeAgentActionHandlerSubType subtype)
{
    sbyte *pType;

    switch (subtype)
    {
        case TE_ACTION_HANDLER_SUBTYPE_UNKNOWN:
            pType = JSON_STR_UNKNOWN;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_PYTHON3:
            pType = JSON_STR_PYTHON3;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_BASH:
            pType = JSON_STR_BASH;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_NODEJS:
            pType = JSON_STR_NODEJS;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_TEXT:
            pType = JSON_STR_TEXT;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_RPM:
            pType = JSON_STR_RPM;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_DPKG:
            pType = JSON_STR_DPKG;
            break;
        case TE_ACTION_HANDLER_SUBTYPE_BATCH:
            pType = JSON_STR_CMD;
            break;
        default:
            pType = JSON_STR_UNDEFINED;
            break;
    };

    return pType;
}

MSTATUS processArtifactMimePart(MimePart *pPart, MimePartProcessArg *pInfo)
{
    MSTATUS status = OK;
    sbyte *pId = NULL;
    ubyte4 numTokens;
    JSON_ContextType *pJCtx = NULL;
    mimeArtifactHandlerData *pArgs = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte4 ndx;
    sbyte *pProtocol = NULL;
    sbyte4 maxChunkSize, senderWindowSize;

    if (NULL == pPart || NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pArgs = (mimeArtifactHandlerData *) pInfo;

    if(pPart != NULL && pPart->contentType == MIME_CONTENT_TYPE_OCTET_STREAM)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact File Offset:%d \n",pPart->fileOffset);
        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact Data Length:%d \n",pPart->dataLen);

        pArgs->artifactOffset = pPart->fileOffset;
        pArgs->artifactLength = pPart->dataLen;
    }
    else if (pPart != NULL && pPart->contentType == MIME_CONTENT_TYPE_JSON)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "JSON Header File Offset:%d \n",pPart->fileOffset);
        MSG_LOG_print(MSG_LOG_DEBUG, "JSON Header Data Length:%d \n",pPart->dataLen);

        status = DIGI_MALLOC((void **) &pData, pPart->dataLen);
        if (OK != status)
            goto exit;

        status = FMGMT_fseek(pPart->pFile, pPart->fileOffset, MSEEK_SET);
        if (OK != status)
            goto exit;

        status = FMGMT_fread(pData, 1, pPart->dataLen, pPart->pFile, &dataLen);
        if (OK != status)
            goto exit;

        if (dataLen != pPart->dataLen)
        {
            status = ERR_FILE_READ_FAILED;
            goto exit;
        }

        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "artifactId", &pId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (0 != DIGI_STRNCMP(pArgs->pArtifactid, pId, DIGI_STRLEN(pArgs->pArtifactid)))
        {
            MSG_LOG_print(MSG_LOG_WARNING,
            "Artifact ID %s does not match expected ID %s\n", pArgs->pArtifactid, pId);
            status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
            goto exit;
        }
        else
        {
            /* we found artifact, check state */
            if (TE_ARTIFACT_STATE_DOWNLOADING != pArgs->state)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Artifact ID %s is not in downloading state.\n", pId);
                MSG_LOG_print(MSG_LOG_DEBUG,
                    "Artifact state = %s\n", TRUSTEDGE_getArtifactProgressToString(pArgs->state));
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                goto exit;
            }
        }

        status = JSON_getJsonObjectIndex(
            pJCtx, 0, "artifactDownloadInfo", &ndx, TRUE);
        if (OK == status)
        {


            status = JSON_getJsonStringValue(
                pJCtx, ndx, "protocol", &pProtocol, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            if (0 != DIGI_STRCMP(pProtocol, "mqtts"))
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Unsupported protocol %s\n", pProtocol);
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            status = JSON_getJsonIntegerValue(
                pJCtx, ndx, "maxChunkSize", &maxChunkSize, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            if (0 >= maxChunkSize)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Invalid maxChunkSize %d\n", maxChunkSize);
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            status = JSON_getJsonIntegerValue(
                pJCtx, ndx, "senderWindowSize", &senderWindowSize, TRUE);
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            if (0 >= senderWindowSize)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Invalid senderWindowSize %d\n", senderWindowSize);
                status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
                goto exit;
            }

            pArgs->chunkSize = maxChunkSize;
            pArgs->windowSize = senderWindowSize;
            pArgs->chunking = TRUE;
        }
        else if (ERR_NOT_FOUND == status)
        {
            status = OK;
        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }
    }

exit:

    DIGI_FREE((void **) &pProtocol);
    DIGI_FREE((void **) &pData);
    DIGI_FREE((void **) &pId);

    JSON_releaseContext(&pJCtx);
    return status;
}

MSTATUS processArtifactChunkMimePart(MimePart *pPart, MimePartProcessArg *pInfo)
{
    MSTATUS status = OK;
    sbyte *pId = NULL;
    ubyte4 numTokens;
    JSON_ContextType *pJCtx = NULL;
    mimeArtifactHandlerData *pArgs = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte *pProtocol = NULL;
    sbyte4 seqNum;

    if (NULL == pPart || NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pArgs = (mimeArtifactHandlerData *) pInfo;

    if(pPart != NULL && pPart->contentType == MIME_CONTENT_TYPE_OCTET_STREAM)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact File Offset:%d \n",pPart->fileOffset);
        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact Data Length:%d \n",pPart->dataLen);

        pArgs->artifactOffset = pPart->fileOffset;
        pArgs->artifactLength = pPart->dataLen;
    }
    else if (pPart != NULL && pPart->contentType == MIME_CONTENT_TYPE_JSON)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "JSON Header File Offset:%d \n",pPart->fileOffset);
        MSG_LOG_print(MSG_LOG_DEBUG, "JSON Header Data Length:%d \n",pPart->dataLen);

        status = DIGI_MALLOC((void **) &pData, pPart->dataLen);
        if (OK != status)
            goto exit;

        status = FMGMT_fseek(pPart->pFile, pPart->fileOffset, MSEEK_SET);
        if (OK != status)
            goto exit;

        status = FMGMT_fread(pData, 1, pPart->dataLen, pPart->pFile, &dataLen);
        if (OK != status)
            goto exit;

        if (dataLen != pPart->dataLen)
        {
            status = ERR_FILE_READ_FAILED;
            goto exit;
        }

        status = JSON_acquireContext(&pJCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = JSON_parse(pJCtx, pData, dataLen, &numTokens);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonStringValue(
            pJCtx, 0, "artifactId", &pId, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        if (0 != DIGI_STRNCMP(pArgs->pArtifactid, pId, DIGI_STRLEN(pArgs->pArtifactid)))
        {
            MSG_LOG_print(MSG_LOG_WARNING,
            "Artifact ID %s does not match expected ID %s\n", pArgs->pArtifactid, pId);
            status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
            goto exit;
        }
        else
        {
            /* we found artifact, check state */
            if (TE_ARTIFACT_STATE_DOWNLOADING != pArgs->state)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                    "Artifact ID %s is not in downloading state.\n", pId);
                MSG_LOG_print(MSG_LOG_DEBUG,
                    "Artifact state = %s\n", TRUSTEDGE_getArtifactProgressToString(pArgs->state));
                status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
                goto exit;
            }
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, 0, "seqNum", &seqNum, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        pArgs->seqNum = seqNum;

        status = JSON_getJsonIntegerValue(
            pJCtx, 0, "artifactChunkOffset", &pArgs->chunkOffset, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        status = JSON_getJsonIntegerValue(
            pJCtx, 0, "artifactChunkSize", &pArgs->chunkSize, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_MSG_PARSING_ERROR;
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact Chunk Offset:%d \n", pArgs->chunkOffset);
        MSG_LOG_print(MSG_LOG_DEBUG, "Artifact Chunk Size:%d \n", pArgs->chunkSize);
    }

exit:

    DIGI_FREE((void **) &pProtocol);
    DIGI_FREE((void **) &pData);
    DIGI_FREE((void **) &pId);

    JSON_releaseContext(&pJCtx);
    return status;
}

static MSTATUS processResponse(
    TrustEdgeAgentCtx *pCtx,
    MimePayload *pPayloadData,
    ubyte4 *pArtifactOffset,
    ubyte4 *pArtifactLength,
    byteBoolean *pChunking,
    ubyte4 *pChunkSize,
    ubyte4 *pWindowSize)
{
    MSTATUS status;
    MimePartProcessArg *pHandlerData = NULL;

    TrustEdgeAgentArtifactNode *pArtifact;

    if (NULL == pCtx->pWorkspaceDir)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. No working space directory provided for artifact unpacking\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx->curPolicy.pPolicy)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, no policy currently in progress\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pArtifact = pCtx->curPolicy.data.ups.pArtifact;
    if (NULL == pArtifact)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, no artifact currently expected\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pHandlerData = createArtifactHandlerData (pArtifact->pId, pCtx->pWorkspaceDir, pArtifact->state);

    status = OK;
    MSG_LOG_print(MSG_LOG_INFO, "Parsing download response: %d\n", status);

    status = MIME_process (pPayloadData, processArtifactMimePart, pHandlerData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Mime Process failed: %d\n", status);
        goto exit;
    }

    *pArtifactOffset = ((mimeArtifactHandlerData *) pHandlerData)->artifactOffset;
    *pArtifactLength = ((mimeArtifactHandlerData *) pHandlerData)->artifactLength;
    *pChunking = ((mimeArtifactHandlerData *) pHandlerData)->chunking;
    *pChunkSize = ((mimeArtifactHandlerData *) pHandlerData)->chunkSize;
    *pWindowSize = ((mimeArtifactHandlerData *) pHandlerData)->windowSize;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "Mime process success");
exit:

    freeArtifactHandlerData (&pHandlerData);

    return status;
}

static MSTATUS processChunkResponse(
    TrustEdgeAgentCtx *pCtx,
    MimePayload *pPayloadData,
    ubyte4 *pArtifactOffset,
    ubyte4 *pArtifactLength,
    ubyte4 *pChunkOffset,
    ubyte4 *pChunkSize,
    ubyte4 *pSeqNum)
{
    MSTATUS status;
    MimePartProcessArg *pHandlerData = NULL;

    TrustEdgeAgentArtifactNode *pArtifact;


    if (NULL == pCtx->pWorkspaceDir)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. No working space directory provided for artifact unpacking\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx->curPolicy.pPolicy)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, no policy currently in progress\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pArtifact = pCtx->curPolicy.data.ups.pArtifact;
    if (NULL == pArtifact)
    {
        status = ERR_TRUSTEDGE_UNEXPECTED_MSG;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Unexpected message, no artifact currently expected\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pHandlerData = createArtifactHandlerData (pArtifact->pId, pCtx->pWorkspaceDir, pArtifact->state);

    status = OK;
    MSG_LOG_print(MSG_LOG_INFO, "Parsing download chunk response: %d\n", status);

    status = MIME_process (pPayloadData, processArtifactChunkMimePart, pHandlerData);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Mime Process failed: %d\n", status);
        goto exit;
    }

    *pArtifactOffset = ((mimeArtifactHandlerData *) pHandlerData)->artifactOffset;
    *pArtifactLength = ((mimeArtifactHandlerData *) pHandlerData)->artifactLength;
    *pSeqNum = ((mimeArtifactHandlerData *) pHandlerData)->seqNum;
    *pChunkOffset = ((mimeArtifactHandlerData *) pHandlerData)->chunkOffset;
    *pChunkSize = ((mimeArtifactHandlerData *) pHandlerData)->chunkSize;

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s\n", "Mime process success");
exit:

    freeArtifactHandlerData (&pHandlerData);

    return status;
}

static void freeComponent(TrustEdgeAgentArtifactComponent **ppComp)
{
    if (NULL == ppComp || NULL == *ppComp)
        return;

    DIGI_FREE((void **) &((*ppComp)->pName));
    DIGI_FREE((void **) &((*ppComp)->pLocation));
    DIGI_FREE((void **) &((*ppComp)->pCheckSum));
    DIGI_FREE((void **) ppComp);
}

static void freeComponentsList(TrustEdgeAgentArtifactComponent *pComp)
{
    TrustEdgeAgentArtifactComponent *pTmp;
    if (NULL == pComp)
        return;

    while (pComp)
    {
        pTmp = pComp;
        pComp = pComp->pNext;
        freeComponent(&pTmp);
    }
}

static MSTATUS addNewComponent(sbyte **ppName, sbyte **ppLocation, sbyte **ppCheckSum,
    TrustEdgeAgentArtifactComponent **ppCompList)
{
    MSTATUS status;
    TrustEdgeAgentArtifactComponent *pComp = NULL;
    TrustEdgeAgentArtifactComponent *pLast;
    if (NULL == ppName || NULL == ppLocation || NULL == ppCheckSum || NULL == ppCompList)
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **) &pComp, sizeof(TrustEdgeAgentArtifactComponent));
    if (OK != status)
    {
        return status;
    }

    pComp->pName = *ppName; *ppName = NULL;
    pComp->pLocation = *ppLocation; *ppLocation = NULL;
    pComp->pCheckSum = *ppCheckSum; *ppCheckSum = NULL;
    pComp->checkSumLen = DIGI_STRLEN(pComp->pCheckSum);
    pComp->pNext = NULL;

    if (NULL == *ppCompList)
    {
        *ppCompList = pComp;
    }
    else
    {
        pLast = *ppCompList;
        while (pLast->pNext)
        {
            pLast = pLast->pNext;
        }
        pLast->pNext = pComp;
    }

    pComp = NULL;

    return OK;
}

extern MSTATUS TRUSTEDGE_getFirstFileWithExtension(
    sbyte *pDirPath,
    sbyte *pExt,
    sbyte **ppFile)
{
    MSTATUS status;
    DirectoryDescriptor pDir = NULL;
    DirectoryEntry dirEntry = { 0 };
    ubyte4 strLen, cmp = -1;

    strLen = DIGI_STRLEN(pExt);

    status = FMGMT_getFirstFile(pDirPath, &pDir, &dirEntry);
    if (OK != status)
    {
        goto exit;
    }

    while (FTNone != dirEntry.type)
    {
        if (FTFile == dirEntry.type)
        {
            if (strLen <= dirEntry.nameLength)
            {
                status = DIGI_MEMCMP(
                    pExt, dirEntry.pName + dirEntry.nameLength - strLen, strLen, &cmp);
                if (OK != status)
                {
                    goto exit;
                }

                if (0 == cmp)
                {
                    strLen = DIGI_STRLEN(pDirPath) + 1 + dirEntry.nameLength + 1;
                    status = DIGI_MALLOC((void **) ppFile, strLen);
                    if (OK != status)
                    {
                        goto exit;
                    }
                    DIGI_MEMCPY(*ppFile, pDirPath, DIGI_STRLEN(pDirPath));
                    (*ppFile)[DIGI_STRLEN(pDirPath)] = '/';
                    DIGI_MEMCPY(*ppFile + DIGI_STRLEN(pDirPath) + 1, dirEntry.pName, dirEntry.nameLength);
                    (*ppFile)[strLen - 1] = '\0';

                    goto exit;
                }
            }
        }

        status = FMGMT_getNextFile(pDir, &dirEntry);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = ERR_NOT_FOUND;

exit:

    if (NULL != pDir)
    {
        FMGMT_closeDir(&pDir);
    }

    return status;
}

/* validate that the signature is of the hash value in the component.
 * TODO: add support for multiple components */
MSTATUS TRUSTEDGE_agentsignaturehandler(certStorePtr pTrustedStore, TrustEdgeArtifactManifest *pManifest)
{
    MSTATUS status;
    sbyte *pHash = NULL;
    sbyte4 hashLen;
    ubyte hashAlgo;

    AsymmetricKey pubKey;
    AsymmetricKey privKey;
    ubyte *pInput = NULL;
    ubyte4 inputLen = 0;
    ubyte *pDerCert = NULL;
    ubyte4 derCertLen;

    ubyte *pDerSig = NULL;
    ubyte4 derSigLen;

    ubyte4 verifyFailed = 1;

    ASN1_ITEMPTR pRoot = NULL;

    CStream cs = { 0 };
    MemFile mf = { 0 };

    CRYPTO_initAsymmetricKey(&pubKey);
    CRYPTO_initAsymmetricKey(&privKey);

    if (NULL == pManifest->signature.pSignature  || 0 == pManifest->signature.signatureLength ||
        NULL == pManifest->signature.pCertificate || 0 == pManifest->signature.certificateLength)
    {
        status = OK; /* TODO: make this null pointer error once server starts sending signatures */
        goto exit;
    }

    status = DIGICERT_readFile(pManifest->pComponents->pLocation, &pInput, &inputLen);
    if (OK != status)
        goto exit;

    if (TE_ARTIFACT_SIG_FORMAT_PEM != pManifest->signature.signatureFormat)
    {
        status = ERR_TRUSTEDGE_AGENT_CERT_SPEC_BAD_FORMAT;
        goto exit;
    }

    status = CA_MGMT_decodeCertificate(
        pManifest->signature.pCertificate,
        pManifest->signature.certificateLength,
        &pDerCert, &derCertLen);
    if (OK != status)
        goto exit;

    status = TRUSTEDGE_utilsValidateCert (pTrustedStore, pDerCert, derCertLen, TRUE);
    if (OK != status)
        goto exit;

    MF_attach(&mf, derCertLen, pDerCert);
    CS_AttachMemFile(&cs, &mf);

    status = X509_parseCertificate(cs, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    status = X509_setKeyFromSubjectPublicKeyInfo(
        ASN1_FIRST_CHILD(pRoot), cs, &pubKey);
    if (OK != status)
    {
        goto exit;
    }

    status = BASE64_decodeMessage(
        pManifest->signature.pSignature,
        pManifest->signature.signatureLength,
        &pDerSig, &derSigLen);
    if (OK != status)
        goto exit;

    if (JWS_ALG_RS256 == pManifest->signature.signatureAlgorithm ||
        JWS_ALG_ES256 == pManifest->signature.signatureAlgorithm ||
        JWS_ALG_PS256 == pManifest->signature.signatureAlgorithm)
    {
        hashAlgo = ht_sha256;
    }
    else if (JWS_ALG_RS384 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_ES384 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_PS384 == pManifest->signature.signatureAlgorithm)
    {
        hashAlgo = ht_sha384;
    }
    else if (JWS_ALG_RS512 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_ES512 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_PS512 == pManifest->signature.signatureAlgorithm)
    {
        hashAlgo = ht_sha512;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (JWS_ALG_MLDSA44 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_MLDSA65 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_MLDSA87 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_128F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_128S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_192F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_192S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_256F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_256S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_128F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_128S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_192F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_192S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_256F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_256S == pManifest->signature.signatureAlgorithm)
    {
        hashAlgo = ht_none;
    }
#endif
    else
    {
        status = ERR_TRUSTEDGE_AGENT;
        goto exit;
    }

    if (JWS_ALG_RS256 == pManifest->signature.signatureAlgorithm ||
        JWS_ALG_RS384 == pManifest->signature.signatureAlgorithm ||
        JWS_ALG_RS512 == pManifest->signature.signatureAlgorithm)
    {
        intBoolean verified = FALSE;

        pHash = TRUSTEDGE_generateFileDigest (pManifest->pComponents->pLocation, hashAlgo, &hashLen);
        if (NULL == pHash)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        status = CRYPTO_INTERFACE_RSA_verifyDigest (pubKey.key.pRSA,
            pHash, hashLen, pDerSig, derSigLen, &verified, NULL);

        verifyFailed = 1;
        if (TRUE == verified)
        {
            verifyFailed = 0;
        }
    }
    else if (JWS_ALG_PS256 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_PS384 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_PS512 == pManifest->signature.signatureAlgorithm)
    {
        status = CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt (pubKey.key.pRSA,
            hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pInput, inputLen,
            pDerSig, derSigLen, SHA256_RESULT_SIZE, &verifyFailed, NULL);
        if (OK != status)
            goto exit;
    }
    else if (JWS_ALG_ES256 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_ES384 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_ES512 == pManifest->signature.signatureAlgorithm)
    {
        status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt (
            pubKey.key.pECC, hashAlgo, pInput, inputLen,
            pDerSig, derSigLen, &verifyFailed, NULL);
        if (OK != status)
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (JWS_ALG_MLDSA44 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_MLDSA65 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_MLDSA87 == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_128F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_128S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_192F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_192S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_256F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHA2_256S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_128F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_128S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_192F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_192S == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_256F == pManifest->signature.signatureAlgorithm ||
             JWS_ALG_SLHDSA_SHAKE_256S == pManifest->signature.signatureAlgorithm)
    {
        status = CRYPTO_INTERFACE_QS_SIG_verify(pubKey.pQsCtx, pInput, inputLen, pDerSig, derSigLen, &verifyFailed);
        if (OK != status)
            goto exit;
    }
#endif
    else
    {
        status = ERR_TRUSTEDGE_AGENT_SIG_ALGO_NOT_SUPPORTED;
        goto exit;
    }

    if (!verifyFailed)
    {
        status = OK;
        MSG_LOG_print(MSG_LOG_INFO, "%s", "signature verified\n");
    }
    else
    {
        status = ERR_TRUSTEDGE_AGENT_SIGNATURE_FAILED;
        MSG_LOG_print(MSG_LOG_ERROR, "%s", "signature failed\n");
    }

exit:
    DIGI_FREE((void **) &pHash);
    DIGI_FREE((void **) &pInput);
    DIGI_FREE((void **) &pDerSig);
    DIGI_FREE((void **) &pDerCert);

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    CRYPTO_uninitAsymmetricKey(&privKey, NULL);
    return status;
}

/*
 * Convert the action type string to TrustEdgeAgentActionType enum
 */
static TrustEdgeAgentActionType TRUSTEDGE_getActionType(sbyte *pActionTypeStr)
{
    TrustEdgeAgentActionType actionType = TE_ACTION_UNKNOWN;
    ubyte4 inputLen = DIGI_STRLEN(pActionTypeStr);

    if ((inputLen == DIGI_STRLEN(JSON_STR_PREINSTALL) &&
         DIGI_STRNICMP(pActionTypeStr, JSON_STR_PREINSTALL, inputLen) == 0) ||
        (inputLen == DIGI_STRLEN(JSON_STR_PREINSTALL_ALT) &&
         DIGI_STRNICMP(pActionTypeStr, JSON_STR_PREINSTALL_ALT, inputLen) == 0))
        actionType = TE_ACTION_PREINSTALL;
    else if (inputLen == DIGI_STRLEN(JSON_STR_INSTALL) &&
             DIGI_STRNICMP(pActionTypeStr, JSON_STR_INSTALL, inputLen) == 0)
        actionType = TE_ACTION_INSTALL;
    else if ((inputLen == DIGI_STRLEN(JSON_STR_POSTINSTALL) &&
              DIGI_STRNICMP(pActionTypeStr, JSON_STR_POSTINSTALL, inputLen) == 0) ||
             (inputLen == DIGI_STRLEN(JSON_STR_POSTINSTALL_ALT) &&
              DIGI_STRNICMP(pActionTypeStr, JSON_STR_POSTINSTALL_ALT, inputLen) == 0))
        actionType = TE_ACTION_POSTINSTALL;
    else if ((inputLen == DIGI_STRLEN(JSON_STR_ROLLBACK) &&
              DIGI_STRNICMP(pActionTypeStr, JSON_STR_ROLLBACK, inputLen) == 0) ||
             (inputLen == DIGI_STRLEN(JSON_STR_ROLLBACK_ALT) &&
              DIGI_STRNICMP(pActionTypeStr, JSON_STR_ROLLBACK_ALT, inputLen) == 0))
        actionType = TE_ACTION_ROLLBACK;

    MSG_LOG_print(MSG_LOG_VERBOSE, "TRUSTEDGE_getActionType returning %d\n", actionType);

    return actionType;
}

static TrustEdgeAgentActionHandler TRUSTEDGE_getHandler(sbyte *pHandlerType, sbyte *pHandlerSubType)
{
    TrustEdgeAgentActionHandler handler = {TE_ACTION_HANDLER_UNKNOWN, TE_ACTION_HANDLER_SUBTYPE_UNKNOWN};
    ubyte4 typeLen = DIGI_STRLEN(pHandlerType);
    ubyte4 subTypeLen = DIGI_STRLEN(pHandlerSubType);

    if (typeLen == DIGI_STRLEN(JSON_STR_HTYPE_SCRIPT) &&
        DIGI_STRNICMP(pHandlerType, JSON_STR_HTYPE_SCRIPT, typeLen) == 0)
        handler.type = TE_ACTION_HANDLER_SCRIPT;
    else if (typeLen == DIGI_STRLEN(JSON_STR_HTYPE_EXE) &&
             DIGI_STRNICMP(pHandlerType, JSON_STR_HTYPE_EXE, typeLen) == 0)
        handler.type = TE_ACTION_HANDLER_EXE;
    else if (typeLen == DIGI_STRLEN(JSON_STR_HTYPE_PKGMGR) &&
             DIGI_STRNICMP(pHandlerType, JSON_STR_HTYPE_PKGMGR, typeLen) == 0)
        handler.type = TE_ACTION_HANDLER_PKG_MGR_TYPE;

    if (subTypeLen == DIGI_STRLEN(JSON_STR_PYTHON3) &&
        DIGI_STRNICMP(pHandlerSubType, JSON_STR_PYTHON3, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_PYTHON3;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_BASH) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_BASH, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_BASH;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_NODEJS) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_NODEJS, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_NODEJS;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_TEXT) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_TEXT, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_TEXT;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_DPKG) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_DPKG, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_DPKG;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_RPM) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_RPM, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_RPM;
    else if (subTypeLen == DIGI_STRLEN(JSON_STR_CMD) &&
             DIGI_STRNICMP(pHandlerSubType, JSON_STR_CMD, subTypeLen) == 0)
        handler.subtype = TE_ACTION_HANDLER_SUBTYPE_BATCH;

    MSG_LOG_print(MSG_LOG_VERBOSE, "TRUSTEDGE_getHandler returning type:%s  subtype:%s\n",  TRUSTEDGE_actionHandlerTypeToString(handler.type), TRUSTEDGE_actionHandlerSubTypeToString(handler.subtype));

    return handler;
}

/*
Handler for manifest.json
Check if the manifest.json is valid
*/
MSTATUS TRUSTEDGE_agentmanifesthandler(TrustEdgeArtifactManifest* pManifest, sbyte *pDir)
{
    MSTATUS status = OK;
    ubyte *pManifestFile = NULL;
    ubyte4 manifestbufLen = 0, tokensFound = 0, ndx = 0, actionsNdx = 0, i = 0, dependsOnNdx = 0;
    JSON_ContextType *pJCtx = NULL;
    JSON_TokenType actionsToken = { 0 }, dependsOnToken = { 0 };
    sbyte *pArtifactType = NULL, *pArtifactName = NULL, *pArtifactVersion = NULL;
    sbyte *pArtifactDescription = NULL;
    sbyte *pHandlerType = NULL, *pHandlerSubType = NULL;
    sbyte* pAction = NULL, *pActionPath = NULL, *pActionArgument = NULL;
    sbyte *pManifestFilePath = NULL;

    TrustEdgeAgentArtifactComponent *pComponents = NULL;
    sbyte4 ret;

    sbyte4 componentNdx;
    JSON_TokenType componentsToken = { 0 };
    sbyte *pComponentName = NULL;
    sbyte *pComponentLocation = NULL;
    sbyte *pComponentChecksum = NULL;
    sbyte *pComponentFullPath = NULL;

    sbyte4 signatureNdx;
    JSON_TokenType signaturesToken = { 0 };
    sbyte *pSigAlg = NULL;
    sbyte *pSig = NULL;
    sbyte *pSigFormat = NULL;
    sbyte *pSigCert = NULL;

    MSG_LOG_print(MSG_LOG_INFO,"%s", "--- Placeholder verify manifest json reading manifest \n");
    MSG_LOG_print(MSG_LOG_VERBOSE,"Searching \"%s\" for manifest file\n", pDir);

    status = TRUSTEDGE_getFirstFileWithExtension(pDir, JSON_EXT, &pManifestFilePath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Manifest handler: failed to find manifest file\n");
        goto exit;
    }

    status = DIGICERT_readFile(pManifestFilePath, &pManifestFile, &manifestbufLen);
    if (OK != status)
    {
       MSG_LOG_print(MSG_LOG_ERROR,"%s", "Manifest handler: failed to read manifest file\n");
       goto exit;
    }

    status = JSON_acquireContext (&pJCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Manifest handler: failed to parse manifest file\n");
        goto exit;
    }

    status = JSON_parse (pJCtx, pManifestFile, manifestbufLen, &tokensFound);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Manifest handler: failed to parse manifest file\n");
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE,"%s", "Successfully parsed manifest file\n");

    /* JSON_DBG_dumpAllTokens(pJCtx, FALSE); */
    status = JSON_getJsonStringValue(pJCtx, ndx, JSON_STR_TYPE, &pArtifactType, TRUE);
    if(OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found.\n", JSON_STR_TYPE);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"Artifact type: %s\n",pArtifactType);

    status = JSON_getJsonStringValue(pJCtx, ndx, JSON_STR_NAME, &pArtifactName, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found.\n", JSON_STR_NAME);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"Artifact name: %s\n", pArtifactName);

    status = JSON_getJsonStringValue(pJCtx, ndx, JSON_STR_DESCRIPTION, &pArtifactDescription, TRUE);
    if (OK != status && ERR_NOT_FOUND != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: error searching for %s.\n", JSON_STR_DESCRIPTION);
        goto exit;
    }

    if (ERR_NOT_FOUND == status)
        MSG_LOG_print(MSG_LOG_VERBOSE, "Manifest handler: %s not found.\n", JSON_STR_DESCRIPTION);
    else
        MSG_LOG_print(MSG_LOG_VERBOSE,"Artifact description: %s\n", pArtifactDescription);

    status = JSON_getJsonStringValue(pJCtx, ndx, JSON_STR_VERSION, &pArtifactVersion, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found.\n", JSON_STR_VERSION);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"Artifact version: %s\n", pArtifactVersion);

    pManifest->pName = pArtifactName; pArtifactName = NULL;
    pManifest->pVersion = pArtifactVersion; pArtifactVersion = NULL;
    pManifest->pDescription = pArtifactDescription; pArtifactDescription = NULL;

    status = JSON_getJsonArrayValue(pJCtx, ndx, JSON_STR_ACTIONS, &actionsNdx, &actionsToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: unable to read %s attribute\n", JSON_STR_ACTIONS);
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonArrayValue for actions, Success type: %d Element Count:%d\n", actionsToken.type, actionsToken.elemCnt);
    actionsNdx++;

    for(i=0;i<actionsToken.elemCnt;i++)
    {
        ubyte4 handlerNdx = 0;
        JSON_TokenType actionToken = {0};
        JSON_TokenType handlerToken = {0};
        TrustEdgeAgentActionType action_type = TE_ACTION_UNKNOWN;

        status = JSON_getToken(pJCtx, actionsNdx, &actionToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to parse manifest file\n");
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getToken Success type:%d Element Count:%d \n", actionToken.type, actionToken.elemCnt);

        DIGI_FREE((void **) &pAction);
        status = JSON_getJsonStringValue(pJCtx, actionsNdx, JSON_STR_ACTION, &pAction, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_ACTION);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "Action type: %s\n", pAction);

        DIGI_FREE((void **) &pActionPath);
        status = JSON_getJsonStringValue(pJCtx, actionsNdx, JSON_STR_ACTIONPATH, &pActionPath,TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_ACTIONPATH);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_ACTIONPATH, pActionPath);

        DIGI_FREE((void **) &pActionArgument);
        status = JSON_getJsonStringValue(pJCtx, actionsNdx, JSON_STR_ACTIONARG, &pActionArgument,TRUE);
        if (OK != status && ERR_NOT_FOUND != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: failed to process %s\n", JSON_STR_ACTIONARG);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success actionArgument:%s \n", pActionArgument);

        status = JSON_getJsonObjectIndex( pJCtx, actionsNdx, JSON_STR_HANDLER, &handlerNdx, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_HANDLER);
            goto exit;
        }

        /* JSON_DBG_dumpToken(pJCtx, handlerNdx, TRUE); */
        status = JSON_getToken(pJCtx, handlerNdx, &handlerToken);
        if (OK != status)
        {
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getToken for handler Success type:%d Element Count:%d\n", handlerToken.type, handlerToken.elemCnt);
        DIGI_FREE((void **) &pHandlerType);

        status = JSON_getJsonStringValue(pJCtx, actionsNdx, JSON_STR_HANDLERTYPE, &pHandlerType,TRUE);
        if(OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_HANDLERTYPE);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success handler Type: %s\n", pHandlerType);

        DIGI_FREE((void **) &pHandlerSubType);
        status = JSON_getJsonStringValue(pJCtx, actionsNdx, JSON_STR_HANDLERSUBTYPE, &pHandlerSubType,TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_HANDLERSUBTYPE);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success handler Sub Type: %s\n", pHandlerSubType);

        action_type = TRUSTEDGE_getActionType(pAction);
        if(action_type != TE_ACTION_UNKNOWN)
        {
            status = DIGI_CALLOC((void **) &pManifest->pActions[action_type], 1, sizeof(TrustEdgeArtifactAction));
            if (OK != status)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to process action handler information\n");
                goto exit;
            }

            MSG_LOG_print(MSG_LOG_VERBOSE, "Allocated memory for action type: %d \n",action_type);
            MSG_LOG_print(MSG_LOG_VERBOSE, "Action allocated :%p\n", pManifest->pActions[action_type]);

            pManifest->pActions[action_type]->type = action_type;
            pManifest->pActions[action_type]->handler = TRUSTEDGE_getHandler(pHandlerType, pHandlerSubType);


            if (NULL != pActionPath)
            {
                DIGI_MALLOC_MEMCPY((void **) &pManifest->pActions[action_type]->pActionPath, 1+DIGI_STRLEN(pActionPath), pActionPath, 1+DIGI_STRLEN(pActionPath));
                MSG_LOG_print(MSG_LOG_VERBOSE, "Copied %s action path :%s \n", TRUSTEDGE_actionTypeToString(action_type), pManifest->pActions[action_type]->pActionPath);
            }

            if (NULL != pActionArgument)
            {
                DIGI_MALLOC_MEMCPY((void **) &pManifest->pActions[action_type]->pActionArgument, 1+DIGI_STRLEN(pActionArgument), pActionArgument, 1+DIGI_STRLEN(pActionArgument));
                MSG_LOG_print(MSG_LOG_VERBOSE, "Copied %s action argument :%s \n", TRUSTEDGE_actionTypeToString(action_type), pManifest->pActions[action_type]->pActionArgument);
            }
            else
            {
                MSG_LOG_print(MSG_LOG_VERBOSE, "%s action has no arguments\n", TRUSTEDGE_actionTypeToString(action_type));
            }

            pManifest->pActions[action_type]->ppActionArgs = TRUSTEDGE_actionHandlerGenerateArgs(pManifest->pActions[action_type]);

        }
        else
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: unknown action type. Skipping.\n");
        }

        actionsNdx += (handlerToken.elemCnt+actionToken.elemCnt)*2 + 1;
        MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "--------------------\n");
    }

    status = JSON_getJsonArrayValue(pJCtx, ndx, JSON_STR_COMPONENT, &componentNdx, &componentsToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: unable to read %s attribute\n", JSON_STR_COMPONENT);
        goto exit;
    }
    componentNdx++;

    MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonArrayValue for components, Success type: %d Element Count:%d\n", componentsToken.type, componentsToken.elemCnt);

    for(i = 0;i < componentsToken.elemCnt; i++)
    {
        JSON_TokenType componentToken = {0};

        status = JSON_getToken(pJCtx, componentNdx, &componentToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to parse components array\n");
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getToken Success type:%d Element Count:%d \n", componentToken.type, componentToken.elemCnt);

        DIGI_FREE((void **) &pComponentName);
        status = JSON_getJsonStringValue(pJCtx, componentNdx, JSON_STR_NAME, &pComponentName, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: component %s not found\n", JSON_STR_NAME);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_NAME, pComponentName);
        DIGI_FREE((void **) &pComponentLocation);
        status = JSON_getJsonStringValue(pJCtx, componentNdx, JSON_STR_LOCATION, &pComponentLocation, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_LOCATION);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_LOCATION, pComponentLocation);

        if (DIGI_STRNICMP(pComponentLocation, "./", 2) == 0)
        {
            ret = snprintf(NULL, 0, "%s/%s", pDir, (pComponentLocation + 2));
            if (ret < 0)
            {
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
            }

            status = DIGI_MALLOC((void **) &pComponentFullPath, ret + 1);
            if (OK != status)
                goto exit;

            ret = snprintf(pComponentFullPath, ret + 1, "%s/%s", pDir, (pComponentLocation + 2));
            if (ret < 0)
            {
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
            }
        }
        else if (DIGI_STRNICMP(pComponentLocation, "/", 1) == 0)
        {
            /* if absolute path, do not prefix pDir */
            pComponentFullPath = pComponentLocation;
            pComponentLocation = NULL;
        }
        else
        {
            ret = snprintf(NULL, 0, "%s/%s", pDir, pComponentLocation);
            if (ret < 0)
            {
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
            }

            status = DIGI_MALLOC((void **) &pComponentFullPath, ret + 1);
            if (OK != status)
                goto exit;

            ret = snprintf(pComponentFullPath, ret + 1, "%s/%s", pDir, pComponentLocation);
            if (ret < 0)
            {
                status = ERR_TRUSTEDGE_AGENT;
                goto exit;
            }
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "Component full path: %s\n", pComponentFullPath);

#if 0
        /* we do not use checksum anymore */
        DIGI_FREE((void **) &pComponentChecksum);
        status = JSON_getJsonStringValue(pJCtx, componentNdx, JSON_STR_CHECKSUM, &pComponentChecksum, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: %s not found\n", JSON_STR_CHECKSUM);
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_CHECKSUM, pComponentChecksum);
#endif

        addNewComponent(&pComponentName, &pComponentFullPath, &pComponentChecksum, &pComponents);
        MSG_LOG_print(MSG_LOG_VERBOSE, "validated component %s\n", pComponentName);

        componentNdx += (componentToken.elemCnt)*2;
    }

    pManifest->pComponents = pComponents;

    pManifest->signature.pCertificate = NULL;
    pManifest->signature.pSignature = NULL;

    status = JSON_getJsonArrayValue(pJCtx, ndx, JSON_STR_SIGNATURE, &signatureNdx, &signaturesToken, TRUE);
    if (ERR_NOT_FOUND == status) /* TODO: when server adds signature, remove this check */
    {
        status = OK;
        goto exit;
    }
    else if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: unable to read %s attribute\n", JSON_STR_COMPONENT);
        goto exit;
    }
    signatureNdx++;


    MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonArrayValue for signature, Success type: %d Element Count:%d\n",
        signaturesToken.type, signaturesToken.elemCnt);

    for(i = 0;i < signaturesToken.elemCnt; i++)
    {
        JSON_TokenType signatureToken = {0};

        status = JSON_getToken(pJCtx, signatureNdx, &signatureToken);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to parse signature array\n");
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getToken Success type:%d Element Count:%d \n", signatureToken.type, signatureToken.elemCnt);

        DIGI_FREE((void **) &pSigAlg);
        status = JSON_getJsonStringValue(pJCtx, signatureNdx, JSON_STR_SIGALG, &pSigAlg, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: signature %s not found\n", JSON_STR_SIGALG);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_SIGALG, pSigAlg);

        DIGI_FREE((void **) &pSig);
        status = JSON_getJsonStringValue(pJCtx, signatureNdx, JSON_STR_SIG, &pSig, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: signature %s not found\n", JSON_STR_SIG);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_SIG, pSig);

        DIGI_FREE((void **) &pSigFormat);
        status = JSON_getJsonStringValue(pJCtx, signatureNdx, JSON_STR_SIGFORMAT, &pSigFormat, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: signature %s not found\n", JSON_STR_SIGFORMAT);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_SIGFORMAT, pSigFormat);

        DIGI_FREE((void **) &pSigCert);
        status = JSON_getJsonStringValue(pJCtx, signatureNdx, JSON_STR_SIGCERT, &pSigCert, TRUE);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "Manifest handler: signature %s not found\n", JSON_STR_SIGCERT);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getJsonStringValue Success %s:%s \n", JSON_STR_SIGCERT, pSigCert);

        pManifest->signature.certificateLength = DIGI_STRLEN(pSigCert);
        pManifest->signature.pCertificate = pSigCert; pSigCert = NULL;

        pManifest->signature.signatureLength = DIGI_STRLEN(pSig);
        pManifest->signature.pSignature = pSig; pSig = NULL;

        if (0 == DIGI_STRNCMP(pSigFormat, "base64", DIGI_STRLEN("base64")))
            pManifest->signature.signatureFormat = TE_ARTIFACT_SIG_FORMAT_PEM;
        else
            pManifest->signature.signatureFormat = TE_ARTIFACT_SIG_FORMAT_UNKNOWN;

        pManifest->signature.signatureAlgorithm = (JWSAlg) TRUSTEDGE_utilsGetJWTSigAlg(pSigAlg);

        signatureNdx += (signaturesToken.elemCnt)*2;
        break; /* TODO: add multiple signature support */
    }

    MSG_LOG_print(MSG_LOG_VERBOSE,"%s","Start DependsOn \n");
    status = JSON_getJsonArrayValue(pJCtx, ndx, JSON_STR_DEPENDSON, &dependsOnNdx, &dependsOnToken, TRUE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s line %d status: %d = %s. Unable to read %s attribute\n",
            __func__, __LINE__, status, MERROR_lookUpErrorCode(status), JSON_STR_DEPENDSON);
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "JSON_getToken dependsOn Success type:%d Element Count:%d \n",
        dependsOnToken.type, dependsOnToken.elemCnt);
    pManifest->dependsOn.count = dependsOnToken.elemCnt;

    if(0 < pManifest->dependsOn.count)
    {
        status = DIGI_CALLOC((void **)&pManifest->dependsOn.pArtifact, dependsOnToken.elemCnt, sizeof(TrustEdgeAgentDependsOnArtifact));
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to process dependsOn information\n");
            goto exit;
        }
        dependsOnNdx++;
        for(i=0; i < pManifest->dependsOn.count; i++)
        {
            JSON_TokenType dependsOnTokenElement = {0};
            sbyte *pArtName = NULL, *pArtId = NULL;

           status = JSON_getToken(pJCtx, dependsOnNdx, &dependsOnTokenElement);
           if (OK != status)
           {
               MSG_LOG_print(MSG_LOG_ERROR, "%s", "Manifest handler: failed to parse manifest file\n");
               goto exit;
           }

           status = JSON_getJsonStringValue(pJCtx, dependsOnNdx, JSON_STR_NAME, &pArtName,TRUE);
           if (OK != status)
           {
               MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "Could not retrieve dependsOn artifact Name");
               goto exit;
           }
           pManifest->dependsOn.pArtifact[i].pName = pArtName;
           MSG_LOG_print(MSG_LOG_VERBOSE, "DependsOn Artifact Name: %s \n", pManifest->dependsOn.pArtifact[i].pName);

           status = JSON_getJsonStringValue(pJCtx, dependsOnNdx, JSON_STR_ID, &pArtId,TRUE);
           if (OK != status)
           {
               MSG_LOG_print(MSG_LOG_ERROR, "%s\n", "Could not retrieve dependsOn artifact ID");
               goto exit;
           }
           pManifest->dependsOn.pArtifact[i].pId = pArtId;
           MSG_LOG_print(MSG_LOG_VERBOSE, "DependsOn Artifact Id: %s \n", pManifest->dependsOn.pArtifact[i].pId);

           dependsOnNdx += dependsOnTokenElement.elemCnt * 2 + 1;
       }
    }
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Stop DependsOn \n");

exit:
    DIGI_FREE((void **) &pComponentName);
    DIGI_FREE((void **) &pComponentLocation);
    DIGI_FREE((void **) &pComponentChecksum);
    DIGI_FREE((void **) &pComponentFullPath);
    DIGI_FREE((void **) &pManifestFilePath);
    DIGI_FREE((void **) &pArtifactType);
    DIGI_FREE((void **) &pArtifactName);
    DIGI_FREE((void **) &pArtifactVersion);
    DIGI_FREE((void **) &pArtifactDescription);
    DIGI_FREE((void **) &pHandlerType);
    DIGI_FREE((void **) &pHandlerSubType);
    DIGI_FREE((void **) &pAction);
    DIGI_FREE((void **) &pActionPath);
    DIGI_FREE((void **) &pActionArgument);

    DIGI_FREE((void **) &pSigAlg);
    DIGI_FREE((void **) &pSig);
    DIGI_FREE((void **) &pSigFormat);
    DIGI_FREE((void **) &pSigCert);

    DIGICERT_freeReadFile(&pManifestFile);
    JSON_releaseContext(&pJCtx);

    return status;
}

static void initManifest(TrustEdgeArtifactManifest *pManifest)
{
    if (NULL == pManifest) return;
    DIGI_MEMSET((void *)pManifest, 0x00, sizeof(*pManifest));
}

static void cleanUpManifest(TrustEdgeArtifactManifest *pManifest)
{
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "Entered cleanUpManifest\n");
    for(int i = 0;i<4;i++)
    {
        if(pManifest->pActions[i] != NULL) {
            MSG_LOG_print(MSG_LOG_DEBUG, "FREE action %s\n",TRUSTEDGE_actionTypeToString(i));
            if(pManifest->pActions[i]->pActionPath != NULL)
                DIGI_FREE((void **)&pManifest->pActions[i]->pActionPath);
            if(pManifest->pActions[i]->pActionArgument != NULL)
                DIGI_FREE((void**)&pManifest->pActions[i]->pActionArgument);

            TRUSTEDGE_actionHandlerDeleteArgs(pManifest->pActions[i]);

            DIGI_FREE((void**) &pManifest->pActions[i]);
        }
    }

    if(pManifest->dependsOn.pArtifact)
    {
        for(unsigned int i = 0;i < pManifest->dependsOn.count ;i++)
        {
            if(pManifest->dependsOn.pArtifact[i].pName)
                DIGI_FREE((void **)&pManifest->dependsOn.pArtifact[i].pName);
            if(pManifest->dependsOn.pArtifact[i].pId)
                DIGI_FREE((void **)&pManifest->dependsOn.pArtifact[i].pId);
        }
        DIGI_FREE((void **) &(pManifest->dependsOn.pArtifact));
    }

    DIGI_FREE((void **) &(pManifest->signature.pSignature));
    DIGI_FREE((void **) &(pManifest->signature.pCertificate));
    freeComponentsList(pManifest->pComponents);

    DIGI_FREE((void**) &pManifest->pName);
    DIGI_FREE((void**) &pManifest->pVersion);
    DIGI_FREE((void**) &pManifest->pDescription);
    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", " Done with cleanUpManifest\n");
}

static MSTATUS TRUSTEDGE_agentProcessArtifact(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pFilePath,
    ubyte4 artifactOffset,
    ubyte4 artifactLength,
    TrustEdgeAgentActionType action)
{
    MSTATUS status;
    TrustEdgeArtifactManifest manifest;
#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
    sbyte *pArtifactDir = NULL;
#endif
    sbyte *pArtifactDirPath = NULL;
    sbyte *pArtifactFile = NULL;

    initManifest(&manifest);

    status = TRUSTEDGE_utilsExtractInlineZip(
        pFilePath, artifactOffset, artifactLength, pCtx->pWorkspaceDir);
    FMGMT_remove(pFilePath, FALSE);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Error extracting artifact payload\n");
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"%s", "Artifact payload extracted successfully\n");

    /* parse manifest and validate it - does the actions section have the required fields etc. */
    status = COMMON_UTILS_addPathComponent(
        pCtx->pWorkspaceDir, (sbyte *)"artifact", &pArtifactDirPath);
    if (OK != status)
        goto exit;

#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
    pArtifactDir = pArtifactDirPath;
#endif
    status = TRUSTEDGE_agentmanifesthandler(&manifest, pArtifactDirPath);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Error processing manifest\n");
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"%s", " Processed manifest, checking dependencies\n");

    status = TRUSTEDGE_agentCheckDependencies(pCtx, &manifest);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Dependencies check failed \n");
        goto exit;
    }
    MSG_LOG_print(MSG_LOG_INFO,"%s", " Processed manifest, dependencies check successful\n");

    status = TRUSTEDGE_agentsignaturehandler(pCtx->pTrustedStore, &manifest);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", " Signature verification failed \n");
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"%s", " Signature verified succesfully, extracting payload\n");
    MSG_LOG_print(MSG_LOG_VERBOSE," Searching \"%s\" for payload ZIP file\n", pArtifactDirPath);

    status = TRUSTEDGE_getFirstFileWithExtension(pArtifactDirPath, ".zip", &pArtifactFile);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Error getting artifact file\n");
        goto exit;
    }

    /* extract payload ZIP file */
    status = TRUSTEDGE_utilsExtractZip(pArtifactFile, pArtifactDirPath);
    if(OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", " Payload extraction Failed!\n");
        goto exit;
    }

    MSG_LOG_print(MSG_LOG_INFO,"%s", " Payload extracted successfully\n");

    if (manifest.pActions[action] != NULL)
    {
        pCtx->curPolicy.data.ups.pArtifact->state = (TE_ACTION_ROLLBACK == action) ? TE_ARTIFACT_STATE_UNINSTALLING : TE_ARTIFACT_STATE_INSTALLING;
#ifndef __ENABLE_DIGICERT_UNITTEST__
        (void) TRUSTEDGE_agentSendDeploymentProgress(pCtx,
            pCtx->configOptions.pDeviceId,
            pCtx->configOptions.pAccountId,
            pCtx->curPolicy.pPolicy->pDeviceGroupId,
            pCtx->curPolicy.pPolicy->pId,
            pCtx->curPolicy.pPolicy->pDeploymentId,
            pCtx->curPolicy.data.ups.pArtifact->pId,
            pCtx->pPatData,
            pCtx->curPolicy.data.ups.pArtifact->state);
#endif

        MSG_LOG_print(MSG_LOG_INFO,"%s", " Calling install action handler \n");

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)
        if (NULL != pCtx->pTable && NULL != pCtx->pTable->pFuncActionHandler)
        {
            status = (MSTATUS) pCtx->pTable->pFuncActionHandler(manifest.pActions[action], pArtifactDirPath);
        }
        else
#endif
        {
            status = TRUSTEDGE_launchActionHandler(manifest.pActions[action], pArtifactDirPath, pCtx);
        }
        if (OK != status)
        {
            goto exit;
        }
    }
    else
    {
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "no action set\n");
        status = ERR_TRUSTEDGE_AGENT;
    }

exit:

    cleanUpManifest(&manifest);
    DIGI_FREE((void **) &pArtifactFile);

#ifndef __DISABLE_DIGICERT_ARTIFACT_PAYLOAD_CLEANUP__
    if (FALSE == pCtx->curPolicy.data.ups.pArtifact->isAsync && NULL != pArtifactDir &&
        FALSE == pCtx->persistArtifact)
    {
        FMGMT_remove(pArtifactDir, TRUE);
    }
#endif

    DIGI_FREE((void **) &pArtifactDirPath);

    if (TRUE == pCtx->curPolicy.data.ups.pArtifact->chunking)
    {
        DIGI_FREE((void **) &pCtx->pChunkBuffer);
        pCtx->chunkBufferOffset = 0;
        pCtx->chunkBufferSize = 0;
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentParseArtifactDownload(TrustEdgeAgentCtx *pCtx, ubyte *pMimeFile, ubyte4 mimeFileLen, TrustEdgeAgentActionType action)
{
    MOC_UNUSED(pMimeFile);
    MOC_UNUSED(mimeFileLen);
    MSTATUS status;
    sbyte *pFilePath = NULL;
    FileDescriptor pFile = NULL;
    MimePayload payloadData = { 0 };
    ubyte4 artifactOffset = 0;
    ubyte4 artifactLength = 0;
    byteBoolean chunking = FALSE;
    ubyte4 chunkSize = 0;
    ubyte4 chunkWindowSize = 0;
    sbyte *pArtifactFile = NULL;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pWorkspaceDir, (sbyte *)"payload.mime", &pFilePath);
    if (OK != status)
    {
        goto exit;
    }

    status = FMGMT_fopen(pFilePath, "rb", &pFile);  /* Binary mode required on Windows */
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: FMGMT_fopen failed: %d (file: %s)\n", 
            __func__, status, pFilePath);
        FMGMT_remove(pFilePath, FALSE);
        goto exit;
    }

    payloadData.pFile = pFile;
    payloadData.pPayLoad = NULL;
    payloadData.payloadLen = 0;

    status = processResponse(
        pCtx, &payloadData, &artifactOffset, &artifactLength,
        &chunking, &chunkSize, &chunkWindowSize);
    if (OK != status)
        goto exit;

    if (TRUE == chunking)
    {
        pCtx->curPolicy.data.ups.pArtifact->chunking = TRUE;
        if (chunkSize > pCtx->pConfig->chunkSize)
        {
            chunkSize = pCtx->pConfig->chunkSize;
        }
        pCtx->curPolicy.data.ups.pArtifact->chunkSize = chunkSize;
        if (chunkWindowSize > pCtx->pConfig->chunkWindowSize)
        {
            chunkWindowSize = pCtx->pConfig->chunkWindowSize;
        }
        pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize = chunkWindowSize;

        /* Initialize chunking values */
        pCtx->curPolicy.data.ups.pArtifact->seqNum = 0;
        pCtx->curPolicy.data.ups.pArtifact->downloadedSize = 0;
        DIGI_FREE((void **) &(pCtx->curPolicy.data.ups.pArtifact->pChunkTracker));
        pCtx->curPolicy.data.ups.pArtifact->pChunkTracker = NULL;
        pCtx->curPolicy.data.ups.pArtifact->chunkTrackerSize = 0;

        /* Remove chunk payload file */
        status = COMMON_UTILS_addPathComponent(
            pCtx->pWorkspaceDir, (sbyte *)"chunk-payload.zip", &pArtifactFile);
        if (OK != status)
            goto exit;

        FMGMT_remove(pArtifactFile, FALSE);

        goto exit;
    }

    status = TRUSTEDGE_agentProcessArtifact(
        pCtx, pFilePath, artifactOffset, artifactLength, action);
    if (OK != status)
    {
        FMGMT_remove(pFilePath, FALSE);
        MSG_LOG_print(MSG_LOG_ERROR,"%s", "Error processing artifact\n");
        goto exit;
    }

exit:

    DIGI_FREE((void **) &pArtifactFile);
    DIGI_FREE((void **) &pFilePath);
    FMGMT_fclose(&pFile);

    if (NULL != pCtx->curPolicy.pPolicy && NULL != pCtx->curPolicy.data.ups.pArtifact &&
        FALSE == pCtx->curPolicy.data.ups.pArtifact->isAsync)
    {
        if(OK != status && ERR_TRUSTEDGE_UNEXPECTED_MSG != status && ERR_TRUSTEDGE_MSG_PARSING_ERROR != status)
        {
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALL_FAILED;
            else
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_FAILED;
        }
        else if (OK == status && FALSE == pCtx->curPolicy.data.ups.pArtifact->chunking)
        {
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALLED;
            else
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_INSTALLED;
        }
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentParseArtifactDownloadChunk(TrustEdgeAgentCtx *pCtx, ubyte *pMimeFile, ubyte4 mimeFileLen, TrustEdgeAgentActionType action)
{
    MOC_UNUSED(pMimeFile);
    MOC_UNUSED(mimeFileLen);
    MSTATUS status;
    sbyte *pFilePath = NULL;
    sbyte *pArtifactFile = NULL;
    FileDescriptor pFile = NULL;
    MimePayload payloadData = { 0 };
    ubyte4 chunkOffset = 0;
    ubyte4 chunkSize = 0;
    ubyte4 seqNum = 0;
    ubyte4 chunkNumber;
    ubyte4 totalWindowSize, bytesWritten, read;
    ubyte4 artifactOffset = 0, artifactLength = 0;
    byteBoolean processedArtifact = FALSE;
    ubyte4 chunkBufferOffset;
    ubyte *pMode = "ab";  /* Binary mode required for ZIP file */

    pCtx->needToProcessResponse = FALSE;

    status = COMMON_UTILS_addPathComponent(
        pCtx->pWorkspaceDir, (sbyte *)"payload.mime", &pFilePath);
    if (OK != status)
        goto exit;

    status = FMGMT_fopen(pFilePath, "rb", &pFile);  /* Binary mode required on Windows */
    if (OK != status)
    {
        goto exit;
    }

    payloadData.pFile = pFile;
    payloadData.pPayLoad = NULL;
    payloadData.payloadLen = 0;

    status = processChunkResponse(
        pCtx, &payloadData, &artifactOffset, &artifactLength,
        &chunkOffset, &chunkSize, &seqNum);
    if (OK != status)
        goto exit;

    if (NULL == pCtx->pChunkBuffer || pCtx->chunkBufferSize != pCtx->curPolicy.data.ups.pArtifact->chunkSize * pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize)
    {
        DIGI_FREE((void **) &pCtx->pChunkBuffer);
        status = DIGI_MALLOC(
            (void **) &pCtx->pChunkBuffer,
            pCtx->curPolicy.data.ups.pArtifact->chunkSize * pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize);
        if (OK != status)
        {
            goto exit;
        }
        pCtx->chunkBufferSize = pCtx->curPolicy.data.ups.pArtifact->chunkSize * pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize;
        pCtx->chunkBufferOffset = 0;
    }

    if (NULL == pCtx->curPolicy.data.ups.pArtifact->pChunkTracker || pCtx->curPolicy.data.ups.pArtifact->chunkTrackerSize != pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize)
    {
        DIGI_FREE((void **) &pCtx->curPolicy.data.ups.pArtifact->pChunkTracker);
        status = DIGI_CALLOC(
            (void **) &pCtx->curPolicy.data.ups.pArtifact->pChunkTracker,
            sizeof(byteBoolean),
            pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize);
        if (OK != status)
        {
            goto exit;
        }
        pCtx->curPolicy.data.ups.pArtifact->chunkTrackerSize = pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize;
    }

    chunkNumber = chunkOffset / pCtx->curPolicy.data.ups.pArtifact->chunkSize;

    MSG_LOG_print(MSG_LOG_INFO, "Recieved Chunk number: %d\n", chunkNumber);

    status = TRUSTEDGE_agentComputeTotalWindowSize(pCtx->curPolicy.data.ups.pArtifact, &totalWindowSize);
    if (OK != status)
        goto exit;

    if (chunkOffset < pCtx->curPolicy.data.ups.pArtifact->downloadedSize)
    {
        MSG_LOG_print(MSG_LOG_WARNING, "%s", "Dropping chunk starting from previous window\n");
        status = OK;
        goto exit;
    }

    if (chunkOffset + chunkSize > pCtx->curPolicy.data.ups.pArtifact->downloadedSize + totalWindowSize)
    {
        MSG_LOG_print(MSG_LOG_WARNING, "%s", "Dropping chunk ending in future window\n");
        status = OK;
        goto exit;
    }

    if (pCtx->curPolicy.data.ups.pArtifact->pChunkTracker[chunkNumber % pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize])
    {
        MSG_LOG_print(MSG_LOG_WARNING, "%s", "Dropping duplicate chunk\n");
        status = OK;
        goto exit;
    }
    pCtx->curPolicy.data.ups.pArtifact->pChunkTracker[chunkNumber % pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize] = TRUE;

    status = FMGMT_fseek(pFile, artifactOffset, MSEEK_SET);
    if (OK != status)
    {
        goto exit;
    }

    chunkBufferOffset = chunkNumber % pCtx->curPolicy.data.ups.pArtifact->chunkWindowSize;

    MSG_LOG_print(MSG_LOG_VERBOSE, "Chunk Buffer Offset: %d\n", chunkBufferOffset);
    MSG_LOG_print(MSG_LOG_VERBOSE, "Chunk Size: %d\n", artifactLength);

    status = FMGMT_fread(
        pCtx->pChunkBuffer + (chunkBufferOffset * pCtx->curPolicy.data.ups.pArtifact->chunkSize), 1, artifactLength, pFile, &read);
    if (OK != status)
    {
        FMGMT_remove(pFilePath, FALSE);
        goto exit;
    }

    pCtx->chunkBufferOffset += artifactLength;
    pCtx->curPolicy.data.ups.pArtifact->seqNum++;

    MSG_LOG_print(MSG_LOG_VERBOSE, "Current chunk buffer size: %d\n", pCtx->chunkBufferOffset);
    MSG_LOG_print(MSG_LOG_VERBOSE, "Expected total window size: %d\n", totalWindowSize);

    if (pCtx->chunkBufferOffset == totalWindowSize)
    {
        MSG_LOG_print(MSG_LOG_INFO, "Processing received chunks of total size %d\n", pCtx->chunkBufferOffset);

        status = COMMON_UTILS_addPathComponent(
            pCtx->pWorkspaceDir, (sbyte *)"chunk-payload.zip", &pArtifactFile);
        if (OK != status)
            goto exit;

        FMGMT_fclose(&pFile);

        /* For first window of a fresh download, delete any existing file */
        if (0 == pCtx->curPolicy.data.ups.pArtifact->downloadedSize)
        {
            FMGMT_remove(pArtifactFile, FALSE);
            pMode = "wb";  /* Write binary mode for new file */
        }
        else if (FALSE == FMGMT_pathExists(pArtifactFile, NULL))
        {
            pMode = "wb";  /* Binary mode required for ZIP file */
        }

        status = FMGMT_fopen(pArtifactFile, pMode, &pFile);
        if (OK != status)
        {
            FMGMT_remove(pArtifactFile, FALSE);
            goto exit;
        }

        status = FMGMT_fwrite(pCtx->pChunkBuffer, 1, pCtx->chunkBufferOffset, pFile, &bytesWritten);
        if (OK != status)
        {
            FMGMT_remove(pArtifactFile, FALSE);
            goto exit;
        }

        FMGMT_fflush(pFile);
        FMGMT_fclose(&pFile);
        pFile = NULL;

        pCtx->curPolicy.data.ups.pArtifact->downloadedSize += pCtx->chunkBufferOffset;
        pCtx->chunkBufferOffset = 0;

        if (FALSE == pCtx->curPolicy.data.ups.pArtifact->chunkInitialDone)
        {
            pCtx->curPolicy.data.ups.pArtifact->chunkInitialDone = TRUE;
        }

        pCtx->needToProcessResponse = TRUE;
    }

    if (pCtx->curPolicy.data.ups.pArtifact->downloadedSize == pCtx->curPolicy.data.ups.pArtifact->size)
    {
        status = TRUSTEDGE_agentSendChunkAck(pCtx);
        if (OK != status)
        {
            FMGMT_remove(pArtifactFile, FALSE);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_INFO, "Processing artifact of size %d\n", pCtx->curPolicy.data.ups.pArtifact->downloadedSize);

        /* File handle was already closed after writing - no need to close again */
        /* FMGMT_fclose(&pFile); -- removed, already closed above */

        if (NULL == pArtifactFile)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: pArtifactFile is NULL\n", __func__);
            status = ERR_NULL_POINTER;
            goto exit;
        }

        processedArtifact = TRUE;
        status = TRUSTEDGE_agentProcessArtifact(
            pCtx, pArtifactFile, 0, pCtx->curPolicy.data.ups.pArtifact->size,
            action);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,"%s", "Error processing chunked artifact\n");
            goto exit;
        }

    }

exit:

    /* Close file before removing - Windows cannot delete open files */
    if (NULL != pFile)
    {
        FMGMT_fclose(&pFile);
    }
    FMGMT_remove(pFilePath, FALSE);
    DIGI_FREE((void **) &pFilePath);

    if (NULL != pCtx->curPolicy.pPolicy && NULL != pCtx->curPolicy.data.ups.pArtifact &&
        FALSE == pCtx->curPolicy.data.ups.pArtifact->isAsync)
    {
        if(OK != status && ERR_TRUSTEDGE_UNEXPECTED_MSG != status && ERR_TRUSTEDGE_MSG_PARSING_ERROR != status)
        {
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALL_FAILED;
            else
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_FAILED;

            FMGMT_remove(pArtifactFile, FALSE);
        }
        else if (OK == status && TRUE == processedArtifact)
        {
            if (TE_POLICY_STATUS_ROLLBACK == pCtx->curPolicy.pPolicy->status)
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_UNINSTALLED;
            else
                pCtx->curPolicy.data.ups.pArtifact->state = TE_ARTIFACT_STATE_INSTALLED;
        }
    }

    DIGI_FREE((void **) &pArtifactFile);

    return status;
}

extern MSTATUS TRUSTEDGE_agentComputeTotalWindowSize(
    TrustEdgeAgentArtifactNode *pArtifact,
    ubyte4 *pTotalWindowSize)
{
    ubyte4 size;

    size = pArtifact->chunkWindowSize * pArtifact->chunkSize;
    if (pArtifact->downloadedSize + size > pArtifact->size)
    {
        size = pArtifact->size - pArtifact->downloadedSize;
    }

    *pTotalWindowSize = size;

    return OK;
}

