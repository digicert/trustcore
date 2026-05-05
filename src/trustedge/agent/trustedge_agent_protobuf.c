/*
 * trustedge_agent_protobuf.c
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

#include "../../trustedge/agent/trustedge_agent_protobuf.h"
#include "../../common/common_utils.h"

#include <stdio.h>

typedef struct
{
    TrustEdgeAgentCtx *pAgentCtx;
    /* Timestamp */
    ubyte8 timestamp;
    /* Metric data */
    ubyte *pName;
    ubyte4 nameLen;
    ubyte *pValue;
    ubyte4 valueLen;
    /* UUID */
    sbyte *pUUID;
    /* Body */
    ubyte *pBody;
    ubyte4 bodyLen;
    FileChoice fileChoice;
} TrustEdgeProtobufArg;

ProtobufMessage gpMetricOneofValue[] = {
    { 15, PB_STRING }
};
ProtobufMessage gpMetadata[] = {
    { 1, PB_BOOL, PB_OPTIONAL },
    { 2, PB_STRING, PB_OPTIONAL },
    { 3, PB_UINT64, PB_OPTIONAL },
    { 4, PB_UINT64, PB_OPTIONAL },
    { 5, PB_STRING, PB_OPTIONAL },
    { 6, PB_STRING, PB_OPTIONAL },
    { 7, PB_STRING, PB_OPTIONAL },
    { 8, PB_STRING, PB_OPTIONAL }
};
ProtobufMessage gpMetric[] = {
    { 1, PB_STRING, PB_OPTIONAL },
    { 2, PB_UINT64, PB_OPTIONAL },
    { 3, PB_UINT64, PB_OPTIONAL },
    { 4, PB_UINT32, PB_OPTIONAL },
    { 5, PB_BOOL, PB_OPTIONAL },
    { 6, PB_BOOL, PB_OPTIONAL },
    { 7, PB_BOOL, PB_OPTIONAL },
    { 8, PB_MESSAGE, PB_OPTIONAL, gpMetadata, COUNTOF(gpMetadata) },
    { 0, PB_ONEOF, 0, gpMetricOneofValue, COUNTOF(gpMetricOneofValue) }
};
ProtobufMessage gpPayload[] = {
    { 1, PB_UINT64, PB_OPTIONAL },
    { 2, PB_MESSAGE, PB_REPEATED, gpMetric, COUNTOF(gpMetric) },
    { 3, PB_UINT64, PB_OPTIONAL },
    { 4, PB_STRING, PB_OPTIONAL },
    { 5, PB_BYTES, PB_OPTIONAL }
};

static MSTATUS TRUSTEDGE_agentProtobufMetricDecoder(
    void *pArg,
    ProtobufMessage *pMsg,
    ubyte4 msgCount,
    ProtobufDecodedField *pField,
    byteBoolean finalChunk)
{
    MOC_UNUSED(msgCount);
    MSTATUS status = OK;
    TrustEdgeProtobufArg *pPBArg = (TrustEdgeProtobufArg *) pArg;

    if (PB_MESSAGE == pField->fieldType)
    {
        /* Check what type of message it is */
        if (pMsg == gpPayload && 2 == pField->fieldNumber)
        {
            /* Reset name */
            DIGI_FREE((void **) &pPBArg->pName);
        }

        goto exit;
    }

    /* Currently decoding entire payload in memory, we expect fields with the
     * entire set of data */
    if (TRUE != finalChunk)
    {
        status = ERR_TRUSTEDGE_AGENT_PROTOBUF_DECODE;
        goto exit;
    }

    if (pMsg == gpMetric && 1 == pField->fieldNumber && 0 != pField->data.bytes.bufLen)
    {
        /* Save name */
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pPBArg->pName, pField->data.bytes.bufLen,
            pField->data.bytes.pBuf, pField->data.bytes.bufLen);
        if (OK != status)
        {
            goto exit;
        }
        pPBArg->nameLen = pField->data.bytes.bufLen;
    }

    /* timestamp */
    if (pMsg == gpPayload && 1 == pField->fieldNumber)
    {
        pPBArg->timestamp = pField->data.uint64;
    }

    if (pMsg == gpMetricOneofValue && 15 == pField->fieldNumber && 0 != pField->data.bytes.bufLen)
    {
        /* Add entry */
        if (NULL != pPBArg->pName)
        {
            status = TRUSTEDGE_agentAddMetric(
                pPBArg->pAgentCtx,
                pPBArg->fileChoice,
                pPBArg->pName, pPBArg->nameLen,
                pField->data.bytes.pBuf, pField->data.bytes.bufLen);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}

static MSTATUS TRUSTEDGE_agentProtobufPrintMessageDecoder(
    void *pArg,
    ProtobufMessage *pMsg,
    ubyte4 msgCount,
    ProtobufDecodedField *pField,
    byteBoolean finalChunk)
{
    ubyte4 i;
    MOC_UNUSED(pArg);
    MOC_UNUSED(msgCount);

    if (gpPayload == pMsg)
    {
        if (1 == pField->fieldNumber)
        {
            MSG_LOG_printRaw(MSG_LOG_VERBOSE, "    Protobuf Timestamp: %llu\n", pField->data.uint64);
        }
        else if (2 == pField->fieldNumber)
        {
            MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "    Protobuf Metric:\n");
        }
        else if (3 == pField->fieldNumber)
        {
            MSG_LOG_printRaw(MSG_LOG_VERBOSE, "    Protobuf Sequence: %llu\n", pField->data.uint64);
        }
        else if (4 == pField->fieldNumber)
        {
            if (0 == pField->data.bytes.offset)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "    Protobuf UUID: ");
            }

            if (TRUE == finalChunk)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%.*s\n", pField->data.bytes.bufLen, pField->data.bytes.pBuf);
            }
            else
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%.*s", pField->data.bytes.bufLen, pField->data.bytes.pBuf);
            }
        }
        else if (5 == pField->fieldNumber)
        {
            if (0 == pField->data.bytes.offset)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "    Protobuf Body [HEX]: ");
            }

            if (TRUE == TRUSTEDGE_isLogPayloadEnabled())
            {
                for (i = 0; i < pField->data.bytes.bufLen; i++)
                {
                    MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%02X", pField->data.bytes.pBuf[i]);
                }

            }

            if (TRUE == finalChunk)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "\n\n");
            }
        }
    }

    if (gpMetric == pMsg)
    {
        if (1 == pField->fieldNumber)
        {
            if (0 == pField->data.bytes.offset)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "        Name: ");
            }

            if (TRUE == finalChunk)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%.*s\n", pField->data.bytes.bufLen, pField->data.bytes.pBuf);
            }
            else
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%.*s", pField->data.bytes.bufLen, pField->data.bytes.pBuf);
            }
        }
    }

    if (gpMetricOneofValue == pMsg)
    {
        if (15 == pField->fieldNumber)
        {
            if (0 == pField->data.bytes.offset)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "        Value [HEX]: ");
            }

            if (TRUE == TRUSTEDGE_isLogPayloadEnabled())
            {
                for (i = 0; i < pField->data.bytes.bufLen; i++)
                {
                    MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%02X", pField->data.bytes.pBuf[i]);
                }
            }

            if (TRUE == finalChunk)
            {
                MSG_LOG_printRaw(MSG_LOG_VERBOSE, "%s", "\n");
            }
        }
    }

    return OK;
}

static MSTATUS TRUSTEDGE_agentProtobufMessageDecoder(
    void *pArg,
    ProtobufMessage *pMsg,
    ubyte4 msgCount,
    ProtobufDecodedField *pField,
    byteBoolean finalChunk)
{
    MOC_UNUSED(msgCount);
    MSTATUS status = OK;
    TrustEdgeAgentCtx *pAgentCtx = (TrustEdgeAgentCtx *) pArg;
    sbyte *pFilePath = NULL;
    ubyte4 written = 0;
    sbyte **ppNames = NULL;
    sbyte **ppValues = NULL;
    ubyte4 i;
    sbyte *pPayloadFile = NULL;

    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: ENTER - pArg=%p, pMsg=%p, fieldNumber=%u, finalChunk=%d\n",
        __func__, pArg, (void*)pMsg, pField->fieldNumber, finalChunk);

    (void) TRUSTEDGE_agentProtobufPrintMessageDecoder(
        pArg, pMsg, msgCount, pField, finalChunk);

    if (gpPayload == pMsg)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Processing gpPayload, fieldNumber=%u\n", 
            __func__, pField->fieldNumber);

        if (2 == pField->fieldNumber)
        {
            /* Metric */
            MSG_LOG_print(MSG_LOG_DEBUG, "%s: Processing Metric field\n", __func__);
            status = DIGI_CALLOC(
                (void **) &ppNames, pAgentCtx->pbMsg.metricCount + 1, sizeof(sbyte *));
            if (OK != status)
            {
                goto exit;
            }

            DIGI_MEMCPY(ppNames, pAgentCtx->pbMsg.ppNames, pAgentCtx->pbMsg.metricCount * sizeof(sbyte *));
            DIGI_FREE((void **) &pAgentCtx->pbMsg.ppNames);
            pAgentCtx->pbMsg.ppNames = ppNames;

            status = DIGI_CALLOC(
                (void **) &ppValues, pAgentCtx->pbMsg.metricCount + 1, sizeof(sbyte *));
            if (OK != status)
            {
                goto exit;
            }

            DIGI_MEMCPY(ppValues, pAgentCtx->pbMsg.ppValues, pAgentCtx->pbMsg.metricCount * sizeof(sbyte *));
            DIGI_FREE((void **) &pAgentCtx->pbMsg.ppValues);
            pAgentCtx->pbMsg.ppValues = ppValues;

            pAgentCtx->pbMsg.metricCount++;
            MSG_LOG_print(MSG_LOG_DEBUG, "%s: metricCount now %u\n", __func__, pAgentCtx->pbMsg.metricCount);
        }
        else if (4 == pField->fieldNumber)
        {
            /* UUID */
            MSG_LOG_print(MSG_LOG_DEBUG, "%s: Processing UUID field, offset=%u, bufLen=%u, totalLen=%u\n", 
                __func__, pField->data.bytes.offset, pField->data.bytes.bufLen, pField->data.bytes.totalLen);

            if (NULL == pAgentCtx->pbMsg.pUUID)
            {
                status = DIGI_CALLOC(
                    (void **) &pAgentCtx->pbMsg.pUUID, 1,
                    pField->data.bytes.totalLen + 1);
                if (OK != status)
                {
                    goto exit;
                }
            }

            DIGI_MEMCPY(
                pAgentCtx->pbMsg.pUUID + pField->data.bytes.offset,
                pField->data.bytes.pBuf, pField->data.bytes.bufLen);

            if (TRUE == finalChunk)
            {
                MSG_LOG_print(MSG_LOG_DEBUG, "%s: UUID finalChunk, pUUID=%s\n", 
                    __func__, pAgentCtx->pbMsg.pUUID);

                if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Pending_Policies"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_PENDING_POLICIES;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Certificate_Specification_Response"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_CERTIFICATE_SPECIFICATION;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Certificate_Response"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_ISSUED_CERTIFICATE;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Certificate_Policy_Renew_Response"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_CERTIFICATE_RENEW;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Release_Artifact_List"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_RELEASE_ARTIFACT_LIST;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Artifact_Download"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_ARTIFACT_DOWNLOAD;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Artifact_Download_Chunk"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_Error_Response"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_ERROR_RESPONSE;
                }
                else if (0 == DIGI_STRCMP(pAgentCtx->pbMsg.pUUID, "DeviceTM_CloudPlatform_Policy_Credentials"))
                {
                    pAgentCtx->pbMsg.msgType = TE_MSG_TYPE_CLOUDPLATFORM;
                }

                MSG_LOG_print(MSG_LOG_DEBUG, "%s: msgType set to %d\n", 
                    __func__, pAgentCtx->pbMsg.msgType);

                if (TE_MSG_TYPE_UNKNOWN != pAgentCtx->pbMsg.msgType)
                {
                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Adding %u desired attributes\n", 
                        __func__, pAgentCtx->pbMsg.metricCount);

                    for (i = 0; i < pAgentCtx->pbMsg.metricCount; i++)
                    {
                        if (NULL != pAgentCtx->pbMsg.ppNames[i] && NULL != pAgentCtx->pbMsg.ppValues[i])
                        {
                            status = TRUSTEDGE_addDesiredAttributes(
                                pAgentCtx,
                                pAgentCtx->pbMsg.ppNames[i], DIGI_STRLEN(pAgentCtx->pbMsg.ppNames[i]),
                                pAgentCtx->pbMsg.ppValues[i], DIGI_STRLEN(pAgentCtx->pbMsg.ppValues[i]));
                            if (OK != status)
                            {
                                MSG_LOG_print(MSG_LOG_ERROR, "%s: TRUSTEDGE_addDesiredAttributes failed: %d\n", 
                                    __func__, status);
                                goto exit;
                            }
                        }
                    }
                }
            }
        }
        else if (5 == pField->fieldNumber)
        {
            /* Payload */
            MSG_LOG_print(MSG_LOG_DEBUG, 
                "%s: Processing Payload field (5), msgType=%d, offset=%u, bufLen=%u, totalLen=%u, finalChunk=%d\n", 
                __func__, pAgentCtx->pbMsg.msgType, pField->data.bytes.offset, 
                pField->data.bytes.bufLen, pField->data.bytes.totalLen, finalChunk);

            if (TE_MSG_TYPE_UNKNOWN == pAgentCtx->pbMsg.msgType)
            {
                /* Unknown message, just drop the data */
                MSG_LOG_print(MSG_LOG_DEBUG, "%s: Unknown msgType, dropping data\n", __func__);
                status = OK;
            }
            else if (pAgentCtx->pbMsg.msgType == TE_MSG_TYPE_ARTIFACT_DOWNLOAD ||
                     pAgentCtx->pbMsg.msgType == TE_MSG_TYPE_ARTIFACT_DOWNLOAD_CHUNK)
            {
                /* partial chunk */
                MSG_LOG_print(MSG_LOG_DEBUG, "%s: ARTIFACT_DOWNLOAD path, pWorkspaceDir=%s\n", 
                    __func__, pAgentCtx->pWorkspaceDir ? pAgentCtx->pWorkspaceDir : (sbyte *)"NULL");

                /* 1. Create mime parser context if not created */
                /* 2. Pass chunk to mime parser context */
                /* 3. Have mime parser callback store artifact on file system */

                if (0 == pField->data.bytes.offset)
                {
                    pPayloadFile = "payload.mime";
                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: First chunk, creating file %s\n", 
                        __func__, pPayloadFile);

                    /* First chunk - create file with appropriate size */
                    if (NULL == pAgentCtx->pWorkspaceDir)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - pWorkspaceDir is NULL\n", __func__);
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }

                    status = COMMON_UTILS_addPathComponent(
                        pAgentCtx->pWorkspaceDir, (sbyte *)pPayloadFile, &pFilePath);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s: COMMON_UTILS_addPathComponent failed: %d\n", __func__, status);
                        goto exit;
                    }

                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Opening file %s\n", __func__, pFilePath);
                    FMGMT_remove(pFilePath, FALSE);

                    status = FMGMT_fopen(
                        pFilePath, "wb", &pAgentCtx->pbMsg.pArtifactFile);  /* Binary mode required on Windows */
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s: FMGMT_fopen failed: %d\n", __func__, status);
                        goto exit;
                    }

                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: File opened, pArtifactFile=%p\n", 
                        __func__, (void*)pAgentCtx->pbMsg.pArtifactFile);

                    DIGI_FREE((void **) &pFilePath);
                }

                MSG_LOG_print(MSG_LOG_DEBUG, "%s: Writing %u bytes to artifact file\n", 
                    __func__, pField->data.bytes.bufLen);

                if (NULL == pAgentCtx->pbMsg.pArtifactFile)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - pArtifactFile is NULL\n", __func__);
                    status = ERR_NULL_POINTER;
                    goto exit;
                }

                status = FMGMT_fwrite(
                    pField->data.bytes.pBuf, 1, pField->data.bytes.bufLen,
                    pAgentCtx->pbMsg.pArtifactFile, &written);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "%s: FMGMT_fwrite failed: %d\n", __func__, status);
                    goto exit;
                }

                status = FMGMT_fflush(pAgentCtx->pbMsg.pArtifactFile);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR, "%s: FMGMT_fflush failed: %d\n", __func__, status);
                    goto exit;
                }

                if (TRUE == finalChunk)
                {
                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: finalChunk - closing file and processing body\n", __func__);
                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: pBody=%p, bodyLen=%u\n", 
                        __func__, (void*)pAgentCtx->pbMsg.pBody, pAgentCtx->pbMsg.bodyLen);

                    FMGMT_fclose(&pAgentCtx->pbMsg.pArtifactFile);
                    pAgentCtx->pbMsg.pArtifactFile = NULL;

                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Calling TRUSTEDGE_agentProcessBody(msgType=%d, pBody=%p, bodyLen=%u)\n", 
                        __func__, pAgentCtx->pbMsg.msgType, (void*)pAgentCtx->pbMsg.pBody, pAgentCtx->pbMsg.bodyLen);

                    status = TRUSTEDGE_agentProcessBody(
                        pAgentCtx, pAgentCtx->pbMsg.msgType,
                        pAgentCtx->pbMsg.pBody, pAgentCtx->pbMsg.bodyLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s: TRUSTEDGE_agentProcessBody failed: %d\n", 
                            __func__, status);
                        goto exit;
                    }
                }
            }
            else
            {
                MSG_LOG_print(MSG_LOG_DEBUG, "%s: Regular body path (non-artifact)\n", __func__);

                if (NULL == pAgentCtx->pbMsg.pBody)
                {
                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Allocating pBody, size=%u\n", 
                        __func__, pField->data.bytes.totalLen + 1);

                    status = DIGI_CALLOC(
                        (void **) &pAgentCtx->pbMsg.pBody, 1,
                        pField->data.bytes.totalLen + 1);
                    if (OK != status)
                    {
                        goto exit;
                    }
                }

                DIGI_MEMCPY(
                    pAgentCtx->pbMsg.pBody + pField->data.bytes.offset,
                    pField->data.bytes.pBuf, pField->data.bytes.bufLen);

                if (TRUE == finalChunk)
                {
                    pAgentCtx->pbMsg.bodyLen = pField->data.bytes.totalLen;

                    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Calling TRUSTEDGE_agentProcessBody(msgType=%d, pBody=%p, bodyLen=%u)\n", 
                        __func__, pAgentCtx->pbMsg.msgType, (void*)pAgentCtx->pbMsg.pBody, pAgentCtx->pbMsg.bodyLen);

                    status = TRUSTEDGE_agentProcessBody(
                        pAgentCtx, pAgentCtx->pbMsg.msgType,
                        pAgentCtx->pbMsg.pBody, pAgentCtx->pbMsg.bodyLen);
                    if (OK != status)
                    {
                        MSG_LOG_print(MSG_LOG_ERROR, "%s: TRUSTEDGE_agentProcessBody failed: %d\n", 
                            __func__, status);
                        goto exit;
                    }
                }
            }
        }
    }

    if (gpMetric == pMsg)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Processing gpMetric, fieldNumber=%u\n", 
            __func__, pField->fieldNumber);

        if (1 == pField->fieldNumber)
        {
            /* Name */
            if (pAgentCtx->pbMsg.metricCount == 0)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - metricCount is 0 when processing Name\n", __func__);
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (NULL == pAgentCtx->pbMsg.ppNames)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - ppNames is NULL\n", __func__);
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (NULL == pAgentCtx->pbMsg.ppNames[pAgentCtx->pbMsg.metricCount - 1])
            {
                status = DIGI_CALLOC(
                    (void **) &pAgentCtx->pbMsg.ppNames[pAgentCtx->pbMsg.metricCount - 1],
                    1, pField->data.bytes.totalLen + 1);
                if (OK != status)
                {
                    goto exit;
                }
            }

            DIGI_MEMCPY(
                pAgentCtx->pbMsg.ppNames[pAgentCtx->pbMsg.metricCount - 1] + pField->data.bytes.offset,
                pField->data.bytes.pBuf, pField->data.bytes.bufLen);
        }
    }

    if (gpMetricOneofValue == pMsg)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Processing gpMetricOneofValue, fieldNumber=%u\n", 
            __func__, pField->fieldNumber);

        if (15 == pField->fieldNumber)
        {
            /* Value */
            if (pAgentCtx->pbMsg.metricCount == 0)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - metricCount is 0 when processing Value\n", __func__);
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (NULL == pAgentCtx->pbMsg.ppValues)
            {
                MSG_LOG_print(MSG_LOG_ERROR, "%s: ERROR - ppValues is NULL\n", __func__);
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (NULL == pAgentCtx->pbMsg.ppValues[pAgentCtx->pbMsg.metricCount - 1])
            {
                status = DIGI_CALLOC(
                    (void **) &pAgentCtx->pbMsg.ppValues[pAgentCtx->pbMsg.metricCount - 1],
                    1, pField->data.bytes.totalLen + 1);
                if (OK != status)
                {
                    goto exit;
                }
            }

            DIGI_MEMCPY(
                pAgentCtx->pbMsg.ppValues[pAgentCtx->pbMsg.metricCount - 1] + pField->data.bytes.offset,
                pField->data.bytes.pBuf, pField->data.bytes.bufLen);
        }
    }

exit:

    MSG_LOG_print(MSG_LOG_DEBUG, "%s: EXIT - status=%d\n", __func__, status);
    return status;
}

extern MSTATUS TRUSTEDGE_agentProtobufLoadMetricFile(
    TrustEdgeAgentCtx *pAgentCtx,
    FileChoice fileChoice)
{
    MSTATUS status;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ProtobufContext *pPBCtx = NULL;
    TrustEdgeProtobufArg arg = { 0 };
    sbyte *pFile;

    switch (fileChoice)
    {
        case TE_METRICS_FILE:
            pFile = pAgentCtx->pMetricFile;
            break;
        case TE_DESIRED_ATTRIBUTES_FILE:
            pFile = pAgentCtx->pDesiredAttributeFile;
            break;
        default:
            status = ERR_TRUSTEDGE_AGENT;
            goto exit;
    }

    status = DIGICERT_readFile(pFile, &pMsg, &msgLen);
    if (OK != status)
    {
        goto exit;
    }

    status = PROTOBUF_acquireContext(&pPBCtx);
    if (OK != status)
    {
        goto exit;
    }

    arg.pAgentCtx = pAgentCtx;
    arg.fileChoice = fileChoice;
    status = PROTOBUF_setMessageDecoder(
        pPBCtx, gpPayload, COUNTOF(gpPayload),
        TRUSTEDGE_agentProtobufMetricDecoder, &arg);
    if (OK != status)
    {
        goto exit;
    }

    status = PROTOBUF_messageDecode(pPBCtx, pMsg, msgLen);
    if (OK != status)
    {
        goto exit;
    }

    if (TE_METRICS_FILE == fileChoice)
    {
        pAgentCtx->lastAttrScanTime = arg.timestamp;
    }

exit:

    DIGI_FREE((void **) &arg.pName);
    DIGI_FREE((void **) &arg.pValue);
    PROTOBUF_releaseContext(&pPBCtx);
    DIGI_FREE((void **) &pMsg);

    return status;
}

static MSTATUS TRUSTEDGE_agentProtobufClearHeader(
    TrustEdgeAgentPBMsg *ppbMsg)
{
    ubyte4 i;

    DIGI_FREE((void **) &ppbMsg->pUUID);
    ppbMsg->msgType = TE_MSG_TYPE_UNKNOWN;

    for (i = 0; i < ppbMsg->metricCount; i++)
    {
        DIGI_FREE((void **) &ppbMsg->ppNames[i]);
        DIGI_FREE((void **) &ppbMsg->ppValues[i]);
    }

    DIGI_FREE((void **) &ppbMsg->ppNames);
    DIGI_FREE((void **) &ppbMsg->ppValues);
    ppbMsg->metricCount = 0;

    DIGI_FREE((void **) &ppbMsg->pBody);
    ppbMsg->bodyLen = 0;

    if (NULL != ppbMsg->pArtifactFile)
    {
        FMGMT_fclose(&ppbMsg->pArtifactFile);
        ppbMsg->pArtifactFile = NULL;
    }

    return OK;
}

extern MSTATUS TRUSTEDGE_agentProtobufProcess(
    TrustEdgeAgentCtx *pAgentCtx,
    ubyte *pPayload,
    ubyte4 payloadLen,
    byteBoolean finished)
{
    MSTATUS status;

    /* Debug: Validate inputs */
    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: ENTER - pAgentCtx=%p, pPayload=%p, payloadLen=%u, finished=%d\n",
        __func__, (void*)pAgentCtx, (void*)pPayload, payloadLen, finished);

    MSG_LOG_print(MSG_LOG_DEBUG,
        "%s: pAgentCtx->pPBCtx=%p, curTopic=%u\n",
        __func__, (void*)pAgentCtx->pPBCtx, pAgentCtx->curTopic);

    if (NULL == pAgentCtx->pPBCtx)
    {
        MSG_LOG_printRaw(MSG_LOG_VERBOSE, "\n    Inbound Message on Topic: %.*s\n", DIGI_STRLEN(pAgentCtx->pAllTopics[pAgentCtx->curTopic].pTopic), pAgentCtx->pAllTopics[pAgentCtx->curTopic].pTopic);

        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Clearing protobuf header\n", __func__);
        status = TRUSTEDGE_agentProtobufClearHeader(&pAgentCtx->pbMsg);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: TRUSTEDGE_agentProtobufClearHeader failed: %d\n", 
                __func__, status);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Acquiring protobuf context\n", __func__);
        status = PROTOBUF_acquireContext(&pAgentCtx->pPBCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: PROTOBUF_acquireContext failed: %d\n", 
                __func__, status);
            goto exit;
        }

        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Setting message decoder\n", __func__);
        status = PROTOBUF_setMessageDecoder(
            pAgentCtx->pPBCtx, gpPayload, COUNTOF(gpPayload),
            TRUSTEDGE_agentProtobufMessageDecoder, pAgentCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s: PROTOBUF_setMessageDecoder failed: %d\n", 
                __func__, status);
            goto exit;
        }
    }

    MSG_LOG_print(MSG_LOG_DEBUG, "%s: Decoding message, payloadLen=%u\n", __func__, payloadLen);
    status = PROTOBUF_messageDecode(pAgentCtx->pPBCtx, pPayload, payloadLen);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s: PROTOBUF_messageDecode failed: %d\n", 
            __func__, status);
        goto exit;
    }

exit:

    if ((TRUE == finished || OK != status) && NULL != pAgentCtx->pPBCtx)
    {
        MSG_LOG_print(MSG_LOG_DEBUG, "%s: Cleanup - releasing context\n", __func__);
        TRUSTEDGE_agentProtobufClearHeader(&pAgentCtx->pbMsg);
        PROTOBUF_releaseContext(&pAgentCtx->pPBCtx);
    }

    MSG_LOG_print(MSG_LOG_DEBUG, "%s: EXIT - status=%d\n", __func__, status);
    return status;
}

extern MSTATUS TRUSTEDGE_agentProtobufCreate(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pUUID,
    ubyte *pBodyMsg,
    ubyte4 bodyMsgLen,
    ubyte **ppPBMsg,
    ubyte4 *pPBMsgLen)
{
    MSTATUS status;
    ProtobufPayload payload;
    TrustEdgeAgentMetric *pMetric;
    void *pBucketCookie = NULL;
    ubyte4 index = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen = 0;
    ubyte *pBody;
    sbyte *pUuid;
    ubyte4 uuidLen = 0;

    PROTOBUF_resetSequenceNumber();

    status = PROTOBUF_preparePayload(&payload);
    if (OK != status)
    {
        goto exit;
    }

    uuidLen = DIGI_STRLEN(pUUID);
    status = DIGI_MALLOC((void**)&pUuid, uuidLen + 1);
    if (OK != status)
    {
        goto exit;
    }
    DIGI_MEMCPY(pUuid, pUUID, uuidLen + 1);
    /* UUID value doesn't matter, authentication JWS message will eventually be
     * moved to being a MQTT authentication message. Set it to whatever */
    payload.pUuid = pUuid;

    /* Add metrics */
    while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(pCtx->pMetrics, &pBucketCookie, &index)))
    {
        status = PROTOBUF_addMetricToPayload(&payload, pMetric->pName, pMetric->pValue, PB_METRIC_DATA_TYPE_STRING, pMetric->valueLen-1);
        if (OK != status)
        {
            goto exit;
        }
    }

    index = 0;
    pBucketCookie = NULL;

    while (NULL != (pMetric = (TrustEdgeAgentMetric *) HASH_TABLE_iteratePtrTable(pCtx->pDesiredAttributes, &pBucketCookie, &index)))
    {
        status = PROTOBUF_addMetricToPayload(&payload, pMetric->pName, pMetric->pValue, PB_METRIC_DATA_TYPE_STRING, pMetric->valueLen-1);
        if (OK != status)
        {
            goto exit;
        }
    }

    status = DIGI_MALLOC((void**)&pBody, bodyMsgLen);
    if (OK != status)
    {
        goto exit;
    }
    DIGI_MEMCPY(pBody, pBodyMsg, bodyMsgLen);

    payload.pBody = pBody;
    payload.bodyLen = bodyMsgLen;

   
    status = PROTOBUF_encodePayload(&payload, &pMsg, &msgLen);
    *ppPBMsg = pMsg;
    *pPBMsgLen = msgLen;

exit:

    PROTOBUF_freePayload(&payload);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s. Failed to construct protobuf message\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
    }

    return status;
}

extern MSTATUS TRUSTEDGE_agentProtobufPrintMessage(
    ubyte *pMsg,
    ubyte4 msgLen)
{
    ProtobufContext *pCtx = NULL;
    MSTATUS status;

    status = PROTOBUF_acquireContext(&pCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = PROTOBUF_setMessageDecoder(
        pCtx, gpPayload, COUNTOF(gpPayload),
        TRUSTEDGE_agentProtobufPrintMessageDecoder, NULL);
    if (OK != status)
    {
        goto exit;
    }

    status = PROTOBUF_messageDecode(pCtx, pMsg, msgLen);
    if (OK != status)
    {
        goto exit;
    }

exit:

    PROTOBUF_releaseContext(&pCtx);

    return status;
}
