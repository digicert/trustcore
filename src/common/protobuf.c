/*
 * protobuf.c
 *
 * Protobuf Implementation
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "moptions.h"


#if defined(__ENABLE_DIGICERT_PROTOBUF__)

#include "protobuf.h"
#include "mstdlib.h"
#include "mrtos.h"
#include "datetime.h"

#define PB_MAX_VARINT_LEN 10
static ubyte4 payloadSequence;

typedef enum
{
    PB_STATE_TAG = 0,
    PB_STATE_LENGTH,
    PB_STATE_VALUE,
    PB_STATE_ERROR
} ProtobufState;

typedef struct
{
    ProtobufRawField rawField;
    ProtobufDecodedField decodedField;
    ubyte pVarint[PB_MAX_VARINT_LEN];
    ubyte4 varintLen;
    ubyte4 remainingLen;
} ProtobufField;

typedef MSTATUS (*ProtobufHandler)(ProtobufContext *pCtx, ubyte **ppInput, ubyte4 *pInputLen);

typedef struct
{
    ProtobufState state;
    ProtobufField field;
    ProtobufHandler dataHandler;
    ProtobufRawDecodeCb rawDecoder;
    void *pRawDecoderArg;
    ProtobufMessageDecodeCb msgDecoder;
    void *pMsgDecoderArg;
    ProtobufMessage *pMsg;
    ubyte4 msgCount;
    ubyte4 curIdx;
    ProtobufMessage *pMatchingMessage;
    ubyte4 matchingFieldIdx;
    ProtobufContext *pSubCtx;
} ProtobufCtx;

/* This function accumulates bytes until a full VARINT has been stored. The max
 * size for VARINT is 10 bytes.
 */
static MSTATUS PROTOBUF_processVarintValue(
    ProtobufContext *pContext,
    ubyte **ppInput,
    ubyte4 *pInputLen)
{
    MSTATUS status = OK;
    ProtobufCtx *pCtx = pContext;

    /* Keep looping while there are more bytes to process */
    while (*pInputLen > 0)
    {
        /* Store the next byte */
        pCtx->field.pVarint[pCtx->field.varintLen] = **ppInput;
        pCtx->field.varintLen++;

        /* Move buffer forward */
        (*ppInput)++;
        (*pInputLen)--;

        /* Need to determine if this is the last byte for the VARINT. If the
         * most significant bit isn't set then this is the last byte. */
        if (!(pCtx->field.pVarint[pCtx->field.varintLen - 1] & 0x80))
        {
            /* We have the full VARINT - set raw field parameters */
            pCtx->field.rawField.pBuf = pCtx->field.pVarint;
            pCtx->field.rawField.bufLen = pCtx->field.varintLen;
            pCtx->field.rawField.totalLen = pCtx->field.varintLen;

            /* Invoke raw decoder */
            status = pCtx->rawDecoder(pCtx->pRawDecoderArg, &pCtx->field.rawField, TRUE);
            if (OK != status)
                goto exit;

            /* Done with this VARINT field, move state to tag */
            pCtx->state = PB_STATE_TAG;
            break;
        }
        else if (PB_MAX_VARINT_LEN == pCtx->field.varintLen)
        {
            /* Exceeded maximum VARINT length, error out */
            status = ERR_PROTOBUF_VARINT_TOO_LONG;
            goto exit;
        }
    }

exit:

    return status;
}

/* This function decodes a VARINT.
 */
static MSTATUS PROTOBUF_varintDecode(
    ubyte *pVarint,
    ubyte4 varintLen,
    ubyte8 *pVal)
{
    ubyte4 i;

    /* Compute value */
    *pVal = 0;
    for (i = 0; i < varintLen; i++)
    {
        *pVal |= (((ubyte8) (pVarint[i] & 0x7F)) << (i * 7));
    }

    return OK;
}

/* This function takes in input data and sends the application intended data
 * to the raw callback.
 */
static MSTATUS PROTOBUF_processLenValue(
    ProtobufContext *pContext,
    ubyte **ppInput,
    ubyte4 *pInputLen)
{
    MSTATUS status = OK;
    ProtobufCtx *pCtx = pContext;
    ubyte4 processLen = pCtx->field.remainingLen;
    byteBoolean finalChunk;

    /* Determine how many bytes can be processed. processLen is already set to
     * remaining number of bytes for this field. If this number exceeds the
     * inputLen, then set it to inputLen */
    if (processLen > *pInputLen)
    {
        processLen = *pInputLen;
    }

    /* Set up raw field structure */
    pCtx->field.remainingLen -= processLen;
    finalChunk = pCtx->field.remainingLen ? FALSE : TRUE;
    pCtx->field.rawField.pBuf = *ppInput;
    pCtx->field.rawField.bufLen = processLen;

    /* Invoke callback */
    status = pCtx->rawDecoder(pCtx->pRawDecoderArg, &pCtx->field.rawField, finalChunk);
    if (OK != status)
        goto exit;

    pCtx->field.rawField.offset += processLen;

    /* Adjust for number of bytes processed */
    (*ppInput) += processLen;
    (*pInputLen) -= processLen;

    /* If this is the final chunk for this field, then move to the next field */
    if (TRUE == finalChunk)
    {
        pCtx->state = PB_STATE_TAG;
    }

exit:

    return status;
}
/* This function accumulates bytes until all the bytes for LEN wire type are
 * processed. The length is encoded as VARINT.
 */
static MSTATUS PROTOBUF_processLenLength(
    ProtobufContext *pContext,
    ubyte **ppInput,
    ubyte4 *pInputLen)
{
    MSTATUS status = OK;
    ProtobufCtx *pCtx = pContext;
    ubyte8 varintTotalLen;

    /* Keep looping while there are more bytes to process */
    while (*pInputLen > 0)
    {
        /* Store the byte */
        pCtx->field.pVarint[pCtx->field.varintLen] = **ppInput;
        pCtx->field.varintLen++;

        /* Move buffer forward */
        (*ppInput)++;
        (*pInputLen)--;

        /* Need to determine if this is the last byte for the VARINT. If the
         * most significant bit isn't set then this is the last byte. */
        if (!(pCtx->field.pVarint[pCtx->field.varintLen - 1] & 0x80))
        {
            /* Decode the VARINT to get the length */
            status = PROTOBUF_varintDecode(
                pCtx->field.pVarint, pCtx->field.varintLen, &varintTotalLen);
            if (OK != status)
                goto exit;

            if (0 > ((sbyte4) varintTotalLen))
            {
                /* Length is negative, error out */
                status = ERR_PROTOBUF_LEN_NEGATIVE;
                goto exit;
            }

            pCtx->field.rawField.totalLen = (ubyte4) varintTotalLen;
            pCtx->field.rawField.offset = 0;

            /* Length for LEN wire type has processed, save it and move onto
             * the next state */
            pCtx->field.remainingLen = pCtx->field.rawField.totalLen;
            pCtx->dataHandler = PROTOBUF_processLenValue;
            pCtx->state = PB_STATE_VALUE;
            break;
        }
        else if (PB_MAX_VARINT_LEN == pCtx->field.varintLen)
        {
            /* Exceeded maximum VARINT length, error out */
            status = ERR_PROTOBUF_VARINT_TOO_LONG;
            goto exit;
        }
    }

exit:

    return status;
}

extern MSTATUS PROTOBUF_acquireContext(
    ProtobufContext **ppContext)
{
    MSTATUS status;
    ProtobufCtx *pCtx = NULL;

    if (NULL == ppContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pCtx, sizeof(ProtobufCtx));
    if (OK != status)
        goto exit;

    /* Initialize state to tag and current index to 0 */
    pCtx->state = PB_STATE_TAG;
    pCtx->curIdx = 0;
    pCtx->pSubCtx = NULL;
    pCtx->pMatchingMessage = NULL;
    pCtx->matchingFieldIdx = 0;

    *ppContext = (ProtobufContext *) pCtx;
    pCtx = NULL;

exit:

    if (NULL != pCtx)
        PROTOBUF_releaseContext((ProtobufContext **) &pCtx);

    return status;
}

extern MSTATUS PROTOBUF_releaseContext(
    ProtobufContext **ppContext)
{
    MSTATUS status = OK;

    if (NULL != ppContext && NULL != *ppContext)
    {
        status = DIGI_FREE((void **) ppContext);
    }

    return status;
}

extern MSTATUS PROTOBUF_rawDecode(
    ProtobufContext *pContext,
    ubyte *pInput,
    ubyte4 inputLen)
{
    MSTATUS status = OK;
    ProtobufCtx *pCtx = NULL;

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (ProtobufCtx *) pContext;

    /* Keep looping while there are more bytes to process */
    while (inputLen > 0)
    {
        switch (pCtx->state)
        {
            /* Process tag byte */
            case PB_STATE_TAG:
                /* 5 most significant bits are field number */
                pCtx->field.rawField.fieldNumber = *pInput >> 3;
                /* 3 least signifcant bits are wire type */
                pCtx->field.rawField.wireType = *pInput & 0x07;

                /* Determine wire type and set appropriate data handler */
                switch (pCtx->field.rawField.wireType)
                {
                    case PB_VARINT:
                        pCtx->dataHandler = PROTOBUF_processVarintValue;
                        pCtx->state = PB_STATE_VALUE;
                        break;

                    case PB_LEN:
                        pCtx->dataHandler = PROTOBUF_processLenLength;
                        pCtx->state = PB_STATE_LENGTH;
                        break;

                    default:
                        status = ERR_PROTOBUF_BAD_WIRE_TYPE;
                        goto exit;
                }

                /* Initialize data when reading new field */
                pCtx->field.varintLen = 0;
                /* Move processed byte forward */
                pInput++;
                inputLen--;
                status = OK;
                break;

            case PB_STATE_LENGTH:
                status = pCtx->dataHandler(pCtx, &pInput, &inputLen);
                break;

            case PB_STATE_VALUE:
                status = pCtx->dataHandler(pCtx, &pInput, &inputLen);
                break;

            case PB_STATE_ERROR:
                status = ERR_PROTOBUF_DECODE_ERROR;
                goto exit;

            default:
                status = ERR_PROTOBUF_STATE;
                goto exit;

        }
        if (OK != status)
        {
            goto exit;
        }
    }

exit:

    if (OK != status && NULL != pCtx)
    {
        pCtx->state = PB_STATE_ERROR;
    }

    return status;
}

extern MSTATUS PROTOBUF_setRawDecoder(
    ProtobufContext *pContext,
    ProtobufRawDecodeCb rawDecoder,
    void *pArg)
{
    MSTATUS status;

    if (NULL == pContext || NULL == rawDecoder)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ((ProtobufCtx *) pContext)->rawDecoder = rawDecoder;
    ((ProtobufCtx *) pContext)->pRawDecoderArg = pArg;
    status = OK;

exit:

    return status;
}

/* This function parses raw Protobuf data into decoded Protobuf data
 */
static MSTATUS PROTOBUF_msgDecoder(
    void *pArg,
    ProtobufRawField *pField,
    byteBoolean finalChunk)
{
    MSTATUS status = OK;
    ProtobufCtx *pCtx = pArg;
    ubyte4 i;

    /* Ensure we haven't gone out of bounds for the message that is being
     * processed */
    if (pCtx->curIdx >= pCtx->msgCount)
    {
        status = ERR_PROTOBUF_MSG_OOB;
        goto exit;
    }

    /* If we haven't already found a field in the message that corresponds to
     * the raw data being received, then we need to find it
     */
    if (NULL == pCtx->pMatchingMessage)
    {
        do
        {
            if (PB_ONEOF == pCtx->pMsg[pCtx->curIdx].fieldType)
            {
                for (i = 0; i < pCtx->pMsg[pCtx->curIdx].subMsgCount; i++)
                {
                    if ( (pCtx->pMsg[pCtx->curIdx].pSubMsg[i].fieldNumber == pField->fieldNumber) &&
                         (pCtx->pMsg[pCtx->curIdx].pSubMsg[i].fieldType & (1 << pField->wireType)) )
                    {
                        pCtx->pMatchingMessage = pCtx->pMsg[pCtx->curIdx].pSubMsg;
                        pCtx->matchingFieldIdx = i;
                        break;
                    }
                }
            }
            else
            {
                if ( (pCtx->pMsg[pCtx->curIdx].fieldNumber == pField->fieldNumber) &&
                     (pCtx->pMsg[pCtx->curIdx].fieldType & (1 << pField->wireType)) )
                {
                    pCtx->pMatchingMessage = pCtx->pMsg;
                    pCtx->matchingFieldIdx = pCtx->curIdx;
                }
                /* If the field is required then this is an error scenario */
                else if ( !((pCtx->pMsg[pCtx->curIdx].params & PB_OPTIONAL) ||
                            (pCtx->pMsg[pCtx->curIdx].params & PB_REPEATED)) )
                {
                    status = ERR_PROTOBUF_MISSING_REQUIRED_FIELD;
                    goto exit;
                }
            }

            if (NULL != pCtx->pMatchingMessage)
            {
                break;
            }

            pCtx->curIdx++;

        } while (pCtx->curIdx < pCtx->msgCount);

        if (NULL == pCtx->pMatchingMessage)
        {
            status = ERR_PROTOBUF_UNEXPECTED_FIELD;
            goto exit;
        }

        /* Set decoded field parameters */
        pCtx->field.decodedField.fieldNumber = pField->fieldNumber;
        pCtx->field.decodedField.fieldType = (pCtx->pMatchingMessage + pCtx->matchingFieldIdx)->fieldType;
    }

    /* Check what the field type in the message format is and process it
     * accordingly */
    switch ((pCtx->pMatchingMessage + pCtx->matchingFieldIdx)->fieldType)
    {
        case PB_BOOL:
        case PB_INT32:
        case PB_UINT32:
        case PB_UINT64:
            /* Code assumes VARINT provides full chunk - finalChunk is always TRUE */
            status = PROTOBUF_varintDecode(
                pField->pBuf, pField->bufLen,
                &pCtx->field.decodedField.data.uint64);
            if (OK != status)
                goto exit;

            /* Invoke message callback */
            status = pCtx->msgDecoder(
                pCtx->pMsgDecoderArg,
                pCtx->pMatchingMessage, pCtx->matchingFieldIdx,
                &pCtx->field.decodedField, finalChunk);
            if (OK != status)
                goto exit;

            break;

        case PB_MESSAGE:
            /* Create sub context to parse the embedded message */
            if (NULL == pCtx->pSubCtx)
            {
                /* Invoke message callback with PB_MESSAGE field type, this way
                 * the application can know when a new embedded message is
                 * found */

                /* Invoke message callback */
                status = pCtx->msgDecoder(
                    pCtx->pMsgDecoderArg,
                    pCtx->pMatchingMessage, pCtx->matchingFieldIdx,
                    &pCtx->field.decodedField, finalChunk);
                if (OK != status)
                    goto exit;

                status = PROTOBUF_acquireContext(&pCtx->pSubCtx);
                if (OK != status)
                    goto exit;
            }

            /* Set the same message decoder callback as the original context */
            status = PROTOBUF_setMessageDecoder(
                pCtx->pSubCtx,
                (pCtx->pMatchingMessage + pCtx->matchingFieldIdx)->pSubMsg,
                (pCtx->pMatchingMessage + pCtx->matchingFieldIdx)->subMsgCount,
                pCtx->msgDecoder, pCtx->pMsgDecoderArg);
            if (OK != status)
                goto exit;

            /* Decode the message */
            status = PROTOBUF_rawDecode(pCtx->pSubCtx, pField->pBuf, pField->bufLen);
            if (OK != status)
                goto exit;

            break;

        case PB_STRING:
        case PB_BYTES:
            pCtx->field.decodedField.data.bytes.pBuf = pField->pBuf;
            pCtx->field.decodedField.data.bytes.bufLen = pField->bufLen;
            pCtx->field.decodedField.data.bytes.offset = pField->offset;
            pCtx->field.decodedField.data.bytes.totalLen = pField->totalLen;

            /* Invoke message callback */
            status = pCtx->msgDecoder(
                pCtx->pMsgDecoderArg,
                pCtx->pMatchingMessage, pCtx->matchingFieldIdx,
                &pCtx->field.decodedField, finalChunk);
            if (OK != status)
                goto exit;

            break;

        default:
            status = ERR_PROTOBUF_MSG_TYPE;
            goto exit;
    }

    /* If this is the final chunk then determine whether we need to move to the
     * next field in the message. */
    if (TRUE == finalChunk)
    {
        if (NULL != pCtx->pSubCtx)
        {
            status = PROTOBUF_releaseContext(&pCtx->pSubCtx);
            if (OK != status)
                goto exit;
        }

        /* Only move the index forward if this is not a repeated value */
        if (!(PB_REPEATED & pCtx->pMsg[pCtx->curIdx].params))
        {
            pCtx->curIdx++;
        }

        pCtx->pMatchingMessage = NULL;
        pCtx->matchingFieldIdx = 0;
    }

exit:

    return status;
}

extern MSTATUS PROTOBUF_setMessageDecoder(
    ProtobufContext *pContext,
    ProtobufMessage *pMsg,
    ubyte4 msgCount,
    ProtobufMessageDecodeCb msgDecoder,
    void *pArg)
{
    MSTATUS status;

    if (NULL == pContext || NULL == msgDecoder || NULL == pMsg || 0 == msgCount)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = PROTOBUF_setRawDecoder(pContext, PROTOBUF_msgDecoder, pContext);
    if (OK != status)
        goto exit;

    ((ProtobufCtx *) pContext)->pMsg = pMsg;
    ((ProtobufCtx *) pContext)->msgCount = msgCount;
    ((ProtobufCtx *) pContext)->msgDecoder = msgDecoder;
    ((ProtobufCtx *) pContext)->pMsgDecoderArg = pArg;
    status = OK;

exit:

    return status;
}

extern MSTATUS PROTOBUF_messageDecode(
    ProtobufContext *pContext,
    ubyte *pInput,
    ubyte4 inputLen)
{
    MSTATUS status;

    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = PROTOBUF_rawDecode(pContext, pInput, inputLen);
    if (OK != status)
        goto exit;
exit:

    return status;
}

static MSTATUS PROTOBUF_getCurrentTimeStamp(ubyte8 *pTimeStamp)
{
    MSTATUS status = OK;
    TimeDate currentTime;
    TimeDate epochTime;
    sbyte4 totalSeconds = 0;
    ubyte8 milliseconds;

    status = RTOS_timeGMT(&currentTime);
    if (OK != status)
        goto exit;

    epochTime.m_year = 0;
    epochTime.m_month = 1;
    epochTime.m_day = 1;
    epochTime.m_hour = 0;
    epochTime.m_minute = 0;
    epochTime.m_second = 0;

    currentTime.m_day += 1;
    status = DATETIME_diffTime(&currentTime, &epochTime, &totalSeconds);
    if (OK != status)
        goto exit;

    milliseconds = (ubyte8)totalSeconds * 1000;
    *pTimeStamp = milliseconds;

exit:

    return status;

}

extern MSTATUS PROTOBUF_resetSequenceNumber(void)
{
    payloadSequence = 0;
    return OK;
}

extern MSTATUS PROTOBUF_preparePayload(
    ProtobufPayload *pPayload)
{
    MSTATUS status;

    status = DIGI_MEMSET((ubyte *)pPayload, 0x00, sizeof(ProtobufPayload));
    if (OK != status)
        goto exit;

    /* set the timestamp */
    status = PROTOBUF_getCurrentTimeStamp(&pPayload->timestamp);
    if (OK != status)
        goto exit;

    /* Increment the sequence number */
    pPayload->sequenceNumber = payloadSequence;
    payloadSequence++;

exit:
    return status;
}

extern MSTATUS PROTOBUF_addMetricToPayload(
    ProtobufPayload *pPayload,
    ubyte *pName,
    void *pValue,
    ProtobufMetricDataType dataType,
    ubyte4 valueLen)
{
    MSTATUS status = OK;
    ProtobufMetric *pMetric = NULL;
    ProtobufMetric *newMetric = NULL;

    if (NULL == pPayload || NULL == pName || NULL == pValue || 0 == valueLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pMetric, sizeof(ProtobufMetric));
    if (OK != status)
        goto exit;

    status = DIGI_MEMSET((ubyte *)pMetric, 0x00, sizeof(ProtobufMetric));
    if (OK != status)
        goto exit;

    pMetric->pName = pName;
    status = PROTOBUF_getCurrentTimeStamp(&pMetric->timestamp);
    if (OK != status)
        goto exit;
    pMetric->datatype = dataType;
    pMetric->valueLen = valueLen;
    switch(dataType)
    {
        case PB_METRIC_DATA_TYPE_BOOLEAN:
            pMetric->value.booleanValue = *(byteBoolean *)pValue;
            break;
        case PB_METRIC_DATA_TYPE_UINT32:
            pMetric->value.intValue = *(ubyte4 *)pValue;
            break;
        case PB_METRIC_DATA_TYPE_STRING:
            pMetric->value.stringValue = (ubyte *)pValue;
            break;
        default:
            break;
    }
    pPayload->metricCount++;

    status = DIGI_MALLOC((void **)&newMetric, sizeof(ProtobufMetric) * (pPayload->metricCount));
    if (OK != status)
        goto exit;

    if (pPayload->metricCount > 1)
    {
        status = DIGI_MEMCPY(newMetric, pPayload->pMetrics, sizeof(ProtobufMetric) * (pPayload->metricCount-1));
        if (OK != status)
            goto exit;
    }
    newMetric[pPayload->metricCount-1] = *pMetric;

    if (NULL != pPayload->pMetrics)
    {
        DIGI_FREE((void **)&pPayload->pMetrics);
    }
    pPayload->pMetrics = newMetric;

exit:

    DIGI_FREE((void **)&pMetric);
    return status;
}

static ubyte4 PROTOBUF_encodeVarintSize(ubyte8 val)
{
    ubyte4 size = 0;

    do
    {
        size++;
        val >>= 7;
    } while (0 != val);

    return size;
}

static MSTATUS PROTOBUF_encodeVarint(ubyte *pInput, ubyte8 val, ubyte **ppOutput)
{
    MSTATUS status = OK;

    if (NULL == pInput || NULL == ppOutput)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    do
    {
        *pInput = (val & 0x7F);
        val >>= 7;
        if (val)
        {
            *pInput |= 0x80;
        }
        pInput++;
    } while (val);

    *ppOutput = pInput;

exit:

        return status;

}

static MSTATUS PROTOBUF_encodeString(ubyte *pInput, ubyte *pData, ubyte4 dataLen, ubyte **ppOutput)
{
    ubyte4 i = 0;
    MSTATUS status = OK;

    if (NULL == pInput || NULL == ppOutput || NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < dataLen; i++)
    {
        *pInput++ = pData[i];
    }
    *ppOutput = pInput;

exit:
    return status;
}

MSTATUS PROTOBUF_encodePayload(
    ProtobufPayload *pPayload,
    ubyte **ppOutput,
    ubyte4 *pOutputLen)
{
    MSTATUS status = OK;
    ubyte *buffer = NULL;
    ubyte *pCurrent = NULL;
    ubyte4 estimatedSize = 0, metricSize;
    ubyte4 actualSize = 0;
    ubyte4 uuidLen = 0;
    ubyte4 nameLen = 0;
    ubyte4 valueLen = 0;
    ubyte4 i;

    /* estimate the size of payload */

    estimatedSize += 1 + PROTOBUF_encodeVarintSize(pPayload->timestamp); /* timestamp */

    /* metrics */
    if (pPayload->metricCount > 0)
    {
        for (i = 0; i < pPayload->metricCount; i++)
        {
            ProtobufMetric *pMetric = &pPayload->pMetrics[i];
            nameLen = DIGI_STRLEN(pMetric->pName);
            metricSize = 1 + PROTOBUF_encodeVarintSize(pMetric->timestamp); /* timestamp */
            metricSize += 1 + nameLen + PROTOBUF_encodeVarintSize((ubyte8)nameLen); /* name */
            metricSize += 1; /* data type */
            switch (pMetric->datatype)
            {
                case PB_METRIC_DATA_TYPE_BOOLEAN:
                    metricSize += PROTOBUF_encodeVarintSize((ubyte8)PB_METRIC_DATA_TYPE_BOOLEAN);
                    break;
                case PB_METRIC_DATA_TYPE_UINT32:
                    metricSize += PROTOBUF_encodeVarintSize((ubyte8)PB_METRIC_DATA_TYPE_UINT32);
                    break;
                case PB_METRIC_DATA_TYPE_STRING:
                    metricSize += PROTOBUF_encodeVarintSize((ubyte8)PB_METRIC_DATA_TYPE_STRING);
                    break;
                default:
                    break;
            }

            /* value */
            metricSize += 1; /* tag */
            switch (pMetric->datatype)
            {
                case PB_METRIC_DATA_TYPE_BOOLEAN:
                    metricSize += 1; /* boolean value */
                    break;
                case PB_METRIC_DATA_TYPE_UINT32:
                    metricSize += PROTOBUF_encodeVarintSize((ubyte8)pMetric->value.intValue); /* uint32 value */
                    break;
                case PB_METRIC_DATA_TYPE_STRING:
                    valueLen = DIGI_STRLEN(pMetric->value.stringValue);
                    metricSize += valueLen + PROTOBUF_encodeVarintSize((ubyte8)valueLen); /* string value */
                    break;
                default:
                    break;
            }

            estimatedSize += 1 + PROTOBUF_encodeVarintSize(metricSize) + metricSize;
            pMetric->totalLen = metricSize;
        }

    }

    estimatedSize += 1 + PROTOBUF_encodeVarintSize((ubyte8)pPayload->sequenceNumber); /* sequence number */

    /* uuid */
    if (NULL != pPayload->pUuid)
    {
        uuidLen = DIGI_STRLEN(pPayload->pUuid);
        /*
        1 byte for tag (field number << 3 | wire type)
        + length of the string
        + varint size for the length of the string
        */
        estimatedSize += 1 + uuidLen + PROTOBUF_encodeVarintSize((ubyte8)uuidLen);
    }

    /* body */
    if (NULL != pPayload->pBody)
    {
        estimatedSize += 1 + pPayload->bodyLen + PROTOBUF_encodeVarintSize((ubyte8)pPayload->bodyLen);
    }


    /* Encoding */

    status = DIGI_MALLOC((void **)&buffer, estimatedSize);
    if (OK != status)
        goto exit;

    pCurrent = buffer;

    /* encode timestamp */
    status = PROTOBUF_encodeVarint(pCurrent, (TIMESTAMP_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
    if (OK != status)
        goto exit;
    status = PROTOBUF_encodeVarint(pCurrent, pPayload->timestamp, &pCurrent);
    if (OK != status)
        goto exit;

    /* encode metrics*/
    for (i = 0; i < pPayload->metricCount; i++)
    {
        ProtobufMetric *pMetric = &pPayload->pMetrics[i];
        nameLen = DIGI_STRLEN(pMetric->pName);

        status = PROTOBUF_encodeVarint(pCurrent, (METRIC_FIELD_NUMBER << 3) | PB_LEN, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeVarint(pCurrent, pMetric->totalLen, &pCurrent);
        if (OK != status)
            goto exit;

        /* encode name */
        status = PROTOBUF_encodeVarint(pCurrent, (METRIC_NAME_FIELD_NUMBER << 3) | PB_LEN, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeVarint(pCurrent, nameLen, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeString(pCurrent, pMetric->pName, nameLen, &pCurrent);
        if (OK != status)
            goto exit;

        /* encode timestamp */
        status = PROTOBUF_encodeVarint(pCurrent, (METRIC_TIMESTAMP_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeVarint(pCurrent, pMetric->timestamp, &pCurrent);
        if (OK != status)
            goto exit;

        /* encode data type */
        status = PROTOBUF_encodeVarint(pCurrent, (METRIC_DATATYPE_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
        if (OK != status)
            goto exit;
        switch (pMetric->datatype)
        {
            case PB_METRIC_DATA_TYPE_BOOLEAN:
                status = PROTOBUF_encodeVarint(pCurrent, PB_METRIC_DATA_TYPE_BOOLEAN, &pCurrent);
                if (OK != status)
                    goto exit;
                break;
            case PB_METRIC_DATA_TYPE_UINT32:
                status = PROTOBUF_encodeVarint(pCurrent, PB_METRIC_DATA_TYPE_UINT32, &pCurrent);
                if (OK != status)
                    goto exit;
                break;
            case PB_METRIC_DATA_TYPE_STRING:
                status = PROTOBUF_encodeVarint(pCurrent, PB_METRIC_DATA_TYPE_STRING, &pCurrent);
                if (OK != status)
                    goto exit;
                break;
            default:
                break;
        }

        /* encode value */
        switch (pMetric->datatype)
        {
            case PB_METRIC_DATA_TYPE_BOOLEAN:
                status = PROTOBUF_encodeVarint(pCurrent, (METRIC_VALUE_BOOLEAN_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
                if (OK != status)
                    goto exit;
                *pCurrent++ = pMetric->value.booleanValue ? 1 : 0;
                break;
            case PB_METRIC_DATA_TYPE_UINT32:
                status = PROTOBUF_encodeVarint(pCurrent, (METRIC_VALUE_INT_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
                if (OK != status)
                    goto exit;
                status = PROTOBUF_encodeVarint(pCurrent, pMetric->value.intValue, &pCurrent);
                if (OK != status)
                    goto exit;
                break;
            case PB_METRIC_DATA_TYPE_STRING:
                status = PROTOBUF_encodeVarint(pCurrent, (METRIC_VALUE_STRING_FIELD_NUMBER << 3) | PB_LEN, &pCurrent);
                if (OK != status)
                    goto exit;
                status = PROTOBUF_encodeVarint(pCurrent, pMetric->valueLen, &pCurrent);
                if (OK != status)
                    goto exit;
                status = PROTOBUF_encodeString(pCurrent, pMetric->value.stringValue, pMetric->valueLen, &pCurrent);
                if (OK != status)
                    goto exit;
                break;
            default:
                break;
        }
    }

    /* encode sequence number */
    status = PROTOBUF_encodeVarint(pCurrent, (SEQUENCE_FIELD_NUMBER << 3) | PB_VARINT, &pCurrent);
    if (OK != status)
        goto exit;
    status = PROTOBUF_encodeVarint(pCurrent, pPayload->sequenceNumber, &pCurrent);
    if (OK != status)
        goto exit;

    /* encode uuid */
    if (NULL != pPayload->pUuid)
    {
        status = PROTOBUF_encodeVarint(pCurrent, (UUID_FIELD_NUMBER << 3) | PB_LEN, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeVarint(pCurrent, uuidLen, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeString(pCurrent, pPayload->pUuid, uuidLen, &pCurrent);
        if (OK != status)
            goto exit;
    }

    /* encode body */
    if (NULL != pPayload->pBody)
    {
        status = PROTOBUF_encodeVarint(pCurrent, (BODY_FIELD_NUMBER << 3) | PB_LEN, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeVarint(pCurrent, pPayload->bodyLen, &pCurrent);
        if (OK != status)
            goto exit;
        status = PROTOBUF_encodeString(pCurrent, pPayload->pBody, pPayload->bodyLen, &pCurrent);
        if (OK != status)
            goto exit;
    }

    actualSize = pCurrent - buffer;
    *ppOutput = buffer;
    *pOutputLen = actualSize;

exit:
    if (OK != status)
    {
        if (NULL != buffer)
            DIGI_FREE((void **)&buffer);
    }

    return status;

}

extern MSTATUS PROTOBUF_freePayload(ProtobufPayload *pPayload)
{
    MSTATUS status = OK;

    if (NULL != pPayload->pMetrics)
    {
        DIGI_FREE((void **)&pPayload->pMetrics);
    }

    DIGI_FREE((void **)&pPayload->pUuid);
    DIGI_FREE((void **)&pPayload->pBody);

    return status;
}
#endif /* __ENABLE_DIGICERT_PROTOBUF__ */