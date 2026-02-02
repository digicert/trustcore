/*
 * moccms_asn.c
 *
 * Mocana CMS ASN1 Parsing API
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/**
 * The functions in this file support the parsing of a CMS messaged encoded
 * in ASN1.
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../asn1/mocasn1.h"
#include "../asn1/oiddefs.h"

#include "../crypto/pubcrypto.h"
#include "../crypto/moccms.h"
#include "../crypto/moccms_asn.h"

#if defined(__ENABLE_DIGICERT_CMS__)

/* Allocate memory in 2K page increments */
#define CAPTURE_PAGE_SIZE  (1024*2)

/*----------------------------------------------------------------------*/

/** Collect ASN1 codec data inside an indefinite length encoded item.
 *  <p>A pointer to this function is passed to <code>MAsn1DecodeIndefiniteUpdate</code>.
 *  <p>The parameters passed to this call are used to create and fill a buffer
 *     with the encoded ASN1 string.
 *  <p><b>NOTE</b>: We should consider using 'chunked' MALLOC sizes larger than 1 byte
 *     to avoid thrashing (and fragmenting) memory.
 */
extern MSTATUS
DIGI_CMS_A_decodeSeqDataReturn(void *pCallbackInfo,
                              ubyte *pData,
                              ubyte4 dataLen,
                              MAsn1Element *pElement)
{
    MSTATUS status;
    ubyte4 totalSize;
    ubyte *pBuf = NULL;
    MOC_CMS_DataInfo *pInfo = (MOC_CMS_DataInfo *)pCallbackInfo;
    MOC_CMS_DataInfo *pPrevious;
    MOC_CMS_DataInfo *pNew = NULL;

    status = ERR_NULL_POINTER;
    if (NULL == pCallbackInfo)
        goto exit;

    /* Is there any data?
     */
    status = OK;
    if ( (NULL == pData) || (0 == dataLen) )
        goto exit;

    /* Search the link list until finding the entry with the same pElement or NULL.
     */
    pPrevious = NULL;
    do
    {
        if (NULL == pInfo->pElement)
            break;

        if (pElement == pInfo->pElement)
            break;

        pPrevious = pInfo;
        pInfo = (MOC_CMS_DataInfo *)(pInfo->pNext);
        if (NULL == pInfo)
            break;
    } while (1);

    if (NULL == pInfo)
    {
        status = DIGI_CALLOC ((void **)&pNew, 1, sizeof (MOC_CMS_DataInfo));
        if (OK != status)
            goto exit;

        pInfo = pNew;
        if (NULL != pPrevious)
            pPrevious->pNext = (void *)pNew;
    }

    pInfo->pElement = pElement;

    /* How much space do we need? If we don't have enough, realloc.
     */
    totalSize = pInfo->len + dataLen;
    if (pInfo->size < totalSize)
    {
        /* Convert to one more page with a size of 'CAPTURE_PAGE_SIZE' bytes */
        ubyte4 page = totalSize / CAPTURE_PAGE_SIZE;
        totalSize = (page + 1) * CAPTURE_PAGE_SIZE;

        status = DIGI_MALLOC ((void **)&pBuf, totalSize);
        if (OK != status)
            goto exit;

        /* If there's any old data, copy it into the new buffer.
         */
        if (0 != pInfo->len)
        {
            status = DIGI_MEMCPY ((void *)pBuf,
                                 (void *)(pInfo->pData),
                                 pInfo->len);
            if (OK != status)
                goto exit;
        }

        /* Get rid of the old, replace it with the new.
         */
        if (NULL != pInfo->pData)
        {
            status = DIGI_FREE ((void **)&(pInfo->pData));
            if (OK != status)
                goto exit;
        }

        pInfo->size = totalSize;
        pInfo->pData = pBuf;
        pBuf = NULL;
    }

    status = DIGI_MEMCPY ((void *)(pInfo->pData + pInfo->len),
                         (void *)pData,
                         dataLen);
    if (OK != status)
        goto exit;

    /* Success */
    pInfo->len = pInfo->len + dataLen;

exit:
    if (NULL != pBuf)
    {
        DIGI_FREE ((void **)&pBuf);
    }
    if (NULL != pNew)
    {
        DIGI_FREE ((void **)&pNew);
    }
    return status;
}


/*----------------------------------------------------------------------*/

/** Free all memory allocated by an instance of 'MOC_CMS_DataInfo'.
 *  <p>This is a convenience function to ensure consistent release of memory
 *  inside this data type in all source code.
 *
 * @param pDataInfo  Pointer the instance that is being freed.
 */
extern MSTATUS
DIGI_CMS_A_freeDataInfo(MOC_CMS_DataInfo *pDataInfo)
{
    MOC_CMS_DataInfo *pCurrent, *pNext;

    if (NULL == pDataInfo)
    {
        goto exit;
    }

    pNext = (MOC_CMS_DataInfo *)(pDataInfo->pNext);
    if (NULL != pDataInfo->pData)
    {
        DIGI_FREE ((void **)&(pDataInfo->pData));
    }

    while (NULL != pNext)
    {
        pCurrent = pNext;
        pNext = (MOC_CMS_DataInfo *)(pNext->pNext);
        if (NULL != pCurrent->pData)
        {
            DIGI_FREE ((void **)&(pCurrent->pData));
        }
        DIGI_FREE ((void **)&pCurrent);
    }

exit:
    return OK;
}


/*----------------------------------------------------------------------*/

/** Create a new instance of the type 'MOC_CMS_CollectData'
 *  <p>The fields of the new instance are cleared (set to 0), and the
 *  two input values are copied to the matching field.
 *  <p>Make sure you are freeing this instance with <code>DIGI_CMS_A_freeCollectData</code>
 *  when it is no longer needed.
 *
 *  @param ppData  The pointer to a 'MOC_CMS_CollectData' pointer that will be set;
 *  @param pParent The pointer to the ASN1 element that is the parent of this ASN1 item;
 *  @param pTarget The pointer to the ASN1 item that needs its value stored while
 *                 streaming data;
 */
extern MSTATUS
DIGI_CMS_A_createCollectData(MOC_CMS_CollectData **ppData,
                            MAsn1Element *pParent,
                            MAsn1Element *pTarget)
{
    MSTATUS status = OK;

    if (NULL == ppData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **)ppData, 1, sizeof(MOC_CMS_CollectData));
    if (OK != status)
        goto exit;

    (*ppData)->pParent  = pParent;
    (*ppData)->pElement = pTarget;

exit:
    return OK;
}


/*----------------------------------------------------------------------*/

/** Free an instance of the type 'MOC_CMS_CollectData'
 *  <p>All newly allocated memory referenced in this instance is freed.
 *  <p>The ASN1 items referenced in this instance are not touched.
 *  <p>The pointer variable referenced as input is also set to NULL.
 *
 *  @param ppData  The pointer to a 'MOC_CMS_CollectData' pointer that will be freed;
 */
extern MSTATUS
DIGI_CMS_A_freeCollectData(MOC_CMS_CollectData **ppData)
{
    if ((NULL != ppData) && (NULL != *ppData))
    {
        DIGI_FREE((void **)&((*ppData)->pKeepData));
    }
    DIGI_FREE((void **)ppData);

    return OK;
}


/*----------------------------------------------------------------------*/

/** Capture the whole encoded ASN1 ENCODED string for the given input, while it is streamed.
 *  <p>The 'MOC_CMS_CollectData' instance describes the ASN1 ENCODED item that is
 *     captured, and contains the buffer to hold the complete string.
 *
 *  @param pData  The pointer to the 'MOC_CMS_CollectData' instance being processed;
 */
extern MSTATUS
DIGI_CMS_A_collectEncoded(MOC_CMS_CollectData* pData)
{
    MSTATUS status = OK;
    ubyte   *storeAt = NULL;
    ubyte   *loadFrom = NULL;
    ubyte4  addLen;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Completed already? */
    if (TRUE == pData->keepDone)
        goto exit;

    if ((NULL != pData->pElement->value.pValue) &&
        (0 < pData->pElement->valueLen) &&
        (MASN1_STATE_DECODE_PARTIAL <= pData->pElement->state))
    {
        if (NULL == pData->pKeepData)
        {
            pData->keepDataSize = pData->pElement->encodingLen;
            status = DIGI_MALLOC ((void**) &(pData->pKeepData), pData->keepDataSize);
            if (OK != status)
                goto exit;
        }
        else
        {
            if (pData->lastState > MASN1_STATE_NONE)
            {
                ubyte* tmpData = pData->pKeepData;
                ubyte4 tmpDataLen = pData->keepDataLen;

                pData->lastState = MASN1_STATE_NONE;

                pData->keepDataSize = pData->pElement->encodingLen;
                pData->keepDataLen = 0;

                status = DIGI_MALLOC ((void**) &(pData->pKeepData), pData->keepDataSize);
                if (OK != status)
                    goto exit;

                if (NULL != tmpData)
                {
                    status = DIGI_MEMCPY (pData->pKeepData, tmpData, tmpDataLen);
                    if (OK != status)
                        goto exit;

                    pData->keepDataLen += tmpDataLen;

                    DIGI_FREE ((void**) &tmpData);
                    tmpData = NULL;
                    tmpDataLen = 0;
                }
            }
        }

        loadFrom = pData->pElement->value.pValue;
        storeAt = pData->pKeepData + pData->keepDataLen;
        addLen = pData->pElement->valueLen;

        status = DIGI_MEMCPY (storeAt,
                             loadFrom,
                             addLen);
        if (OK != status)
            goto exit;

        pData->keepDataLen += addLen;

        if ((FALSE == pData->keepDone) &&
            (MASN1_STATE_DECODE_COMPLETE == (0xF00 & pData->pElement->state)))
        {
            pData->keepDone = TRUE;
        }
    }
    else if ((NULL != pData->pElement->value.pValue) &&
             (0 < pData->pElement->valueLen) &&
             (MASN1_STATE_NONE < pData->pElement->state))
    {
        /* Save in temp space until we start value data */
        if (NULL == pData->pKeepData)
        {
            status = DIGI_MALLOC ((void**)&(pData->pKeepData), 16);
            if (OK != status)
                goto exit;

            pData->keepDataLen = 0;
        }

        addLen = pData->pElement->valueLen;
        loadFrom = pData->pElement->value.pValue;
        storeAt = pData->pKeepData + pData->keepDataLen;

        status = DIGI_MEMCPY (storeAt,
                             loadFrom,
                             addLen);
        if (OK != status)
            goto exit;

        pData->keepDataLen += addLen;
        pData->lastState = pData->pElement->state;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

/** Capture the whole encoded ASN1 SET_OF string for the given input, while it is streamed.
 *  <p>The 'MOC_CMS_CollectData' instance describes the ASN1 SET_OF item that is
 *     captured, and contains the buffer to hold the complete string.
 *
 *  @param pData  The pointer to the 'MOC_CMS_CollectData' instance being processed;
 */
extern MSTATUS
DIGI_CMS_A_collectSetOF(MOC_CMS_CollectData* pData)
{
    MSTATUS status = OK;
    ubyte   *storeAt = NULL;
    ubyte   *loadFrom = NULL;
    ubyte4  addLen;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Completed already? */
    if (TRUE == pData->keepDone)
        goto exit;

    /* Look for any part of the SET that contains a valid value array */
    while ((NULL != pData->pElement) &&
           (MASN1_STATE_DECODE_TAG <= pData->pElement->state))
    {
        /* First time? Allocate buffer with a size as needed by the container (parent) */
        if ((NULL == pData->pKeepData) &&
            (0 < pData->pParent->encodingLen))
        {
            pData->keepDataSize = pData->pParent->encodingLen;
            status = DIGI_MALLOC ((void**) &(pData->pKeepData), pData->keepDataSize);
            if (OK != status)
                goto exit;
        }
        else
        {
            pData->keepDataSize = 0;
        }

        if ((NULL != pData->pElement->value.pValue) &&
            (0 < pData->pElement->valueLen))
        {
            /* Copy data as it has arrived */
            loadFrom = pData->pElement->value.pValue;
            storeAt = pData->pKeepData + pData->keepDataLen;
            addLen = pData->pElement->valueLen;

            status = DIGI_MEMCPY (storeAt,
                                 loadFrom,
                                 addLen);
            if (OK != status)
                goto exit;

            pData->keepDataLen += addLen;
        }

        /* Has this element finished? Then skip to the next one */
        if ((FALSE == pData->keepDone) &&
            (MASN1_STATE_DECODE_COMPLETE == (0xF00 & pData->pElement->state)))
        {
            MAsn1OfEntry *pDone = &(pData->pParent->value.pOfTemplate->entry);

            /* Move on to the current entry */
            while (pDone->pElement != pData->pElement)
            {
                /* BAD: This only is true IFF the current element is not a SET member */
                if (NULL == pDone->pNext)
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
                pDone = pDone->pNext;
            }

            if (NULL == pDone->pNext)
            {
                /* Last Entry -> Stop using current */
                pDone->pElement->valueLen = 0;
                break;
            }
            else
            {
                /* Switch to next one */
                pData->pElement = pDone->pNext->pElement;
            }
        }
        else
        {
            /* Partial data, stop working on it */
            break;
        }
    }

    /* Is the container in COMPLETE mode? */
    if ((FALSE == pData->keepDone) &&
        (MASN1_STATE_DECODE_COMPLETE == (0xF00 & pData->pParent->state)))
    {
        pData->keepDone = TRUE;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

/** Capture the whole encoded ASN1 OID string for the given input, while it is streamed.
 *  <p>The 'MOC_CMS_CollectData' instance describes the ASN1 OID item that is
 *     captured, and contains the buffer to hold the complete string.
 *  <p>When the OID value has been captured fully, it is used to create an OID that is
 *     fully ASN1 encoded, so it can be used for calls to 'ASN1_compareOID'.
 *
 *  @param pData  The pointer to the 'MOC_CMS_CollectData' instance being processed;
 */
extern MSTATUS
DIGI_CMS_A_collectOid(MOC_CMS_CollectData* pData)
{
    MSTATUS status = OK;
    ubyte   *storeAt = NULL;
    ubyte   *loadFrom = NULL;
    ubyte4  addLen;

    MAsn1Element *pFull = NULL;

    ubyte  *pOID    = NULL;
    ubyte4 OIDSize = 0;
    ubyte4 OIDLen  = 0;

    /* Template for creating an OID from its value */
    MAsn1TypeAndCount defFull[1] =
    {
       {  MASN1_TYPE_OID, 0},
    };

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Completed already? */
    if (TRUE == pData->keepDone)
        goto exit;

    if ((NULL != pData->pElement->value.pValue) &&
        (0 < pData->pElement->valueLen) &&
        (MASN1_STATE_DECODE_PARTIAL <= pData->pElement->state))
    {
        if (NULL == pData->pKeepData)
        {
            pData->keepDataSize = pData->pElement->encodingLen;
            status = DIGI_MALLOC ((void**) &(pData->pKeepData), pData->keepDataSize);
            if (OK != status)
                goto exit;
        }
        else
        {
            if (pData->lastState > MASN1_STATE_NONE)
            {
                ubyte* tmpData = pData->pKeepData;
                ubyte4 tmpDataLen = pData->keepDataLen;

                pData->lastState = MASN1_STATE_NONE;

                pData->keepDataSize = pData->pElement->encodingLen;
                pData->keepDataLen = 0;

                status = DIGI_MALLOC ((void**) &(pData->pKeepData), pData->keepDataSize);
                if (OK != status)
                    goto exit;

                if (NULL != tmpData)
                {
                    status = DIGI_MEMCPY (pData->pKeepData, tmpData, tmpDataLen);
                    if (OK != status)
                        goto exit;

                    pData->keepDataLen += tmpDataLen;

                    DIGI_FREE ((void**) &tmpData);
                    tmpData = NULL;
                    tmpDataLen = 0;
                }
            }
        }

        loadFrom = pData->pElement->value.pValue;
        storeAt = pData->pKeepData + pData->keepDataLen;
        addLen = pData->pElement->valueLen;

        status = DIGI_MEMCPY (storeAt,
                             loadFrom,
                             addLen);
        if (OK != status)
            goto exit;

        pData->keepDataLen += addLen;
    }
    else if ((NULL != pData->pElement->value.pValue) &&
             (0 < pData->pElement->valueLen) &&
             (MASN1_STATE_NONE < pData->pElement->state))
    {
        /* Save in temp space until we start value data */
        if (NULL == pData->pKeepData)
        {
            status = DIGI_MALLOC ((void**)&(pData->pKeepData), 16);
            if (OK != status)
                goto exit;

            pData->keepDataLen = 0;
        }

        addLen = pData->pElement->valueLen;
        loadFrom = pData->pElement->value.pValue;
        storeAt = pData->pKeepData + pData->keepDataLen;

        status = DIGI_MEMCPY (storeAt,
                             loadFrom,
                             addLen);
        if (OK != status)
            goto exit;

        pData->keepDataLen += addLen;
        pData->lastState = pData->pElement->state;
    }

    if ((FALSE == pData->keepDone) &&
        (MASN1_STATE_DECODE_COMPLETE == (0xF00 & pData->pElement->state)))
    {
        status = MAsn1CreateElementArray (defFull, 1,
                                          MASN1_FNCT_ENCODE, NULL,
                                          &pFull);
        if (OK != status)
            goto exit;

        pFull->value.pValue = pData->pKeepData;
        pFull->valueLen = pData->keepDataLen;

        OIDSize = pData->keepDataLen + 4;
        status = DIGI_MALLOC ((void**)&(pOID), OIDSize);
        if (OK != status)
            goto exit;

        status = MAsn1Encode (pFull,
                              pOID,
                              OIDSize,
                              &OIDLen);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pData->pKeepData));

        pData->pKeepData = pOID;
        pData->keepDataLen = OIDLen;

        pOID = NULL;
        pData->keepDone = TRUE;
    }

exit:
    if (NULL != pOID)
    {
        DIGI_FREE ((void**)pOID);
    }
    MAsn1FreeElementArray (&pFull);
    return status;
}

#endif  /* defined(__ENABLE_DIGICERT_CMS__) */
