/*
 * ocsp_store.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/hash_table.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/hash_value.h"
#include "../common/datetime.h"
#include "../common/mocana.h"

#include "../crypto/hw_accel.h"
#include "../crypto/ca_mgmt.h"

#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"

#include "../http/http_context.h"

#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ocsp/ocsp_http.h"
#include "../ocsp/client/ocsp_client.h"
#include "../ocsp/ocsp_store.h"

#if defined(__ENABLE_DIGICERT_OCSP_STORE__)

#define MOCANA_OCSP_STORE_INIT_HASH_VALUE (0x56804B8F)

#ifndef MAX_SIZE_OCSP_STORE_RESPONSE_HASH_TABLE
#define MAX_SIZE_OCSP_STORE_RESPONSE_HASH_TABLE (0x1F)
#endif

#define OCSP_STORE_DEFAULT_TIME_SKEW (60)

/*----------------------------------------------------------------------------*/

/* OCSP store structure.
 *
 * pResponseHashTable - Hash table which contains the cached response
 * storeMutex - Mutex for protecting the store when adding entries
 */
typedef struct ocspStore
{
    hashTableOfPtrs *pResponseHashTable;
    RTOS_MUTEX storeMutex;
} ocspStore;

/* OCSP response entry.
 *
 * pResponse - Cached response
 * responseLen - Length of the cached response
 * nextUpdate - Amount of time the cached response is valid for
 * responseMutex - Mutex used to protect updating and reading of the cached
 *  response
 * gettingResponse - Variable used to indicate that an OCSP response is being
 *  retrieved
 */
typedef struct ocspCachedEntry
{
    ubyte *pResponse;
    ubyte4 responseLen;
    TimeDate nextUpdate;
    RTOS_MUTEX responseMutex;
    intBoolean gettingResponse;
} ocspCachedEntry;

/*----------------------------------------------------------------------------*/

/* static methods
 */

/* Method used to generate the hashed value for a certificate.
 */
static MSTATUS OCSP_STORE_genHashValue(
    ASN1_ITEMPTR pCert, CStream cs, ubyte4 *pHashValue);

/* Method used to allocate hash table elements.
 */
static MSTATUS OCSP_STORE_allocHashPtrElement(
    void *pHashCookie, hashTablePtrElement **ppRetNewHashElement);

/* Method used to free hash table elements.
 */
static MSTATUS OCSP_STORE_freeHashPtrElement(
    void *pHashCookie, hashTablePtrElement *pFreeHashElement);

/* Method used to free cached entries stored in the hash table.
 */
static MSTATUS OCSP_STORE_deleteCachedEntry(ocspCachedEntry **ppEntry);

/* Method used to create cached entries to store in the hash table.
 */
static MSTATUS OCSP_STORE_createCachedEntry(ocspCachedEntry **ppRetEntry);

/* Method used to retrieve a cached entry OR create a cached entry if it does
 * not exist based on the hash value.
 */
static MSTATUS OCSP_STORE_findCachedEntry(
    ocspStore *pStore, ubyte4 hashVal, ocspCachedEntry **ppEntry);

/* Method used to get a valid OCSP response. This response may be NULL/0 if
 * another thread is already attempting to get the response. Otherwise it will
 * use the cached response if it is valid. If the cached response is not valid
 * then a response will be retrieved from the responder URL stored in the
 * certificate.
 */
static MSTATUS OCSP_STORE_getValidResponse(
    ocspCachedEntry *pEntry, ubyte *pCert, ubyte4 certLen, ubyte *pIssuer,
    ubyte4 issuerLen, ubyte **ppResponse, ubyte4 *pResponseLen);

/*----------------------------------------------------------------------------*/

extern MSTATUS OCSP_STORE_createStore(ocspStore **ppNewStore)
{
    MSTATUS status;
    ocspStore *pStore = NULL;

    if (NULL == ppNewStore)
    {
        status = ERR_OCSP_STORE_NULL_POINTER;
        goto exit;
    }

    /* There is already an OCSP store stored in the caller provided store. Do
     * nothing and exit.
     */
    if (NULL != *ppNewStore)
    {
        status = OK;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pStore, 1, sizeof(ocspStore));
    if (OK != status)
    {
        goto exit;
    }

    /* Create the hash table.
     */
    status = HASH_TABLE_createPtrsTable(
        &(pStore->pResponseHashTable), MAX_SIZE_OCSP_STORE_RESPONSE_HASH_TABLE,
        NULL, OCSP_STORE_allocHashPtrElement, OCSP_STORE_freeHashPtrElement);
    if (OK != status)
    {
        goto exit;
    }

    /* Create the mutex for protecting the hash table.
     */
    status = RTOS_mutexCreate(&(pStore->storeMutex), OCSP_CACHE_MUTEX, 0);
    if (OK != status)
    {
        goto exit;
    }

    *ppNewStore = pStore;
    pStore = NULL;

exit:

    if (NULL != pStore)
    {
        OCSP_STORE_releaseStore(&pStore);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS OCSP_STORE_releaseStore(ocspStore **ppStore)
{
    MSTATUS status = OK, fstatus;

    if ( (NULL == ppStore) || (NULL == *ppStore) )
    {
        status = ERR_OCSP_STORE_NULL_POINTER;
        goto exit;
    }

    RTOS_mutexWait((*ppStore)->storeMutex);

    /* Free the hash table.
     */
    if (NULL != (*ppStore)->pResponseHashTable)
    {
        status = HASH_TABLE_removePtrsTable(
            (*ppStore)->pResponseHashTable, NULL);
    }

    RTOS_mutexRelease((*ppStore)->storeMutex);

    /* Free the mutex.
     */
    fstatus = RTOS_mutexFree(&((*ppStore)->storeMutex));
    if (OK == status)
    {
        status = fstatus;
    }

    fstatus = DIGI_FREE((void **) ppStore);
    if (OK == status)
    {
        status = fstatus;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_genHashValue(
    ASN1_ITEMPTR pCert, CStream cs, ubyte4 *pHashValue)
{
    MSTATUS status;
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    ubyte *pIssuerBuffer, *pSerialNumberBuffer;
    ubyte *pHashData = NULL;

    /* Get the certificate issuer and serial number.
     */
    status = X509_getCertificateIssuerSerialNumber(
        pCert, &pIssuer, &pSerialNumber);
    if (OK != status)
    {
        goto exit;
    }

    /* Access the issuer data.
     */
    pIssuerBuffer = (ubyte *) CS_memaccess(
        cs, pIssuer->dataOffset, pIssuer->length);
    if (NULL == pIssuerBuffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    /* Access the serial number.
     */
    pSerialNumberBuffer = (ubyte *) CS_memaccess(
        cs, pSerialNumber->dataOffset, pSerialNumber->length);
    if (NULL == pSerialNumberBuffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    /* Create a single buffer which holds the issuer and serial number.
     */
    status = DIGI_MALLOC(
        (void **) &pHashData, pIssuer->length + pSerialNumber->length);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pHashData, pIssuerBuffer, pIssuer->length);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pHashData + pIssuer->length, pSerialNumberBuffer,
        pSerialNumber->length);
    if (OK != status)
    {
        goto exit;
    }

    /* Generate the hash value for the certificate.
     */
    HASH_VALUE_hashGen(
        pHashData, pIssuer->length + pSerialNumber->length,
        MOCANA_OCSP_STORE_INIT_HASH_VALUE, pHashValue);

exit:

    if (NULL != pHashData)
    {
        DIGI_FREE((void **) &pHashData);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_allocHashPtrElement(
    void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    return DIGI_MALLOC(
        (void **) ppRetNewHashElement, sizeof(hashTablePtrElement));
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_freeHashPtrElement(
    void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    MSTATUS status = OK, fstatus;

    if (NULL != pFreeHashElement->pAppData)
    {
        status = OCSP_STORE_deleteCachedEntry(
            (ocspCachedEntry **) &(pFreeHashElement->pAppData));
    }

    fstatus = DIGI_FREE((void **) &pFreeHashElement);
    if (OK == status)
    {
        status = fstatus;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_deleteCachedEntry(ocspCachedEntry **ppEntry)
{
    MSTATUS status = OK, fstatus;

    if ( (NULL == ppEntry) || (NULL == *ppEntry) )
    {
        status = ERR_OCSP_STORE_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppEntry)->pResponse)
    {
        status = DIGI_FREE((void **) &((*ppEntry)->pResponse));
    }

    fstatus = RTOS_mutexFree(&((*ppEntry)->responseMutex));
    if (OK == status)
    {
        status = fstatus;
    }

    fstatus = DIGI_FREE((void **) ppEntry);
    if (OK == status)
    {
        status = fstatus;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_createCachedEntry(ocspCachedEntry **ppRetEntry)
{
    MSTATUS status;
    ocspCachedEntry *pEntry = NULL;

    if (NULL == ppRetEntry)
    {
        status = ERR_OCSP_STORE_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC((void **) &pEntry, 1, sizeof(ocspCachedEntry));
    if (OK != status)
    {
        goto exit;
    }

    status = RTOS_mutexCreate(&(pEntry->responseMutex), OCSP_CACHE_MUTEX, 0);
    if (OK != status)
    {
        goto exit;
    }

    pEntry->pResponse = NULL;
    pEntry->responseLen = 0;
    pEntry->gettingResponse = FALSE;

    *ppRetEntry = pEntry;
    pEntry = NULL;

exit:

    if (NULL != pEntry)
    {
        OCSP_STORE_deleteCachedEntry(&pEntry);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_findCachedEntry(
    ocspStore *pStore, ubyte4 hashVal, ocspCachedEntry **ppEntry)
{
    MSTATUS status;
    intBoolean releaseMutex = FALSE, foundEntry;
    ocspCachedEntry *pEntry = NULL;

    /* Acquire the store mutex. An entry must be created if it does exist so
     * do not allow other methods to get the cached entry.
     */
    status = RTOS_mutexWait(pStore->storeMutex);
    if (OK != status)
    {
        goto exit;
    }

    releaseMutex = TRUE;

    /* Check if the hash table has a cached response.
     */
    status = HASH_TABLE_findPtr(
        pStore->pResponseHashTable, hashVal, NULL, NULL, (void **) ppEntry,
        &foundEntry);
    if (OK != status)
    {
        goto exit;
    }

    /* If the entry was not found then create one.
     */
    if (FALSE == foundEntry)
    {
        status = OCSP_STORE_createCachedEntry(&pEntry);
        if (OK != status)
        {
            goto exit;
        }

        /* Add the new entry to the hash table with the associated hash value.
         */
        status = HASH_TABLE_addPtr(
            pStore->pResponseHashTable, hashVal, pEntry);
        if (OK != status)
        {
            goto exit;
        }

        *ppEntry = pEntry;
        pEntry = NULL;
    }

exit:

    if (NULL != pEntry)
    {
        OCSP_STORE_deleteCachedEntry(&pEntry);
    }

    if (TRUE == releaseMutex)
    {
        RTOS_mutexRelease(pStore->storeMutex);
    }

    return status;
}

/*------------------------------------------------------------------*/

/* Method used to set a default timeout if a timeout is not provided.
 */
static MSTATUS OCSP_STORE_setDefaultNextUpdateTime(
    TimeDate *pTime)
{
    MSTATUS status;
    TimeDate curTime;

    if (NULL == pTime)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RTOS_timeGMT(&curTime);
    if (OK > status)
    {
        goto exit;
    }

    status = DATETIME_getNewTime(
        &curTime, OCSP_DEFAULT_NEXT_UPDATE_TIME, pTime);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_getSingleResponse(
    ubyte *pCert, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen,
    sbyte *pResponderUrl, extensions *pExt, ubyte4 extLen,
    ubyte **ppRetResponse, ubyte4 *pRetResponseLen, TimeDate *pNextUpdate)
{
    MSTATUS status;
    ocspContext *pOcspCtx = NULL;
    httpContext *pHttpCtx = NULL;
    ubyte *pRequest = NULL, *pResp = NULL;
    ubyte4 requestLen = 0, respLen = 0;
    intBoolean isDone = FALSE, freeUrl = FALSE;
    byteBoolean isNextUpdate;

    /* Create OCSP context.
     */
    status = OCSP_CONTEXT_createContextLocal(&pOcspCtx, OCSP_CLIENT);
    if (OK != status)
    {
        goto exit;
    }

    /* If the caller has not provided the OCSP URL then retrieve it from the
     * certificate, otherwise use the one provided by the caller.
     */
    if (NULL == pResponderUrl)
    {
        status = OCSP_CLIENT_getResponderIdfromCert(
            pCert, certLen, (ubyte **) &(pOcspCtx->pOcspSettings->pResponderUrl));
        if (OK != status)
        {
            goto exit;
        }

        freeUrl = TRUE;
    }
    else
    {
        pOcspCtx->pOcspSettings->pResponderUrl = pResponderUrl;
    }

    /* Default OCSP values.
     */
    pOcspCtx->pOcspSettings->hashAlgo = sha1_OID;
    pOcspCtx->pOcspSettings->shouldAddServiceLocator = FALSE;
    pOcspCtx->pOcspSettings->shouldSign = FALSE;
    pOcspCtx->pOcspSettings->signingAlgo = FALSE;
    pOcspCtx->pOcspSettings->timeSkewAllowed = OCSP_STORE_DEFAULT_TIME_SKEW;

    status = OCSP_CLIENT_httpInit(&pHttpCtx, pOcspCtx);
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate for a single certificate. This structure will hold the
     * certificate for which the OCSP response is being retrieved.
     */
    status = DIGI_CALLOC(
        (void **) &(pOcspCtx->pOcspSettings->pCertInfo), 1,
        sizeof(OCSP_singleRequestInfo));
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate for a single certificate. This structure will hold the
     * issuer of the certificate for which the OCSP response is being retrieved.
     */
    status = DIGI_CALLOC(
        (void **) &(pOcspCtx->pOcspSettings->pIssuerCertInfo), 1,
        sizeof(OCSP_singleRequestInfo));
    if (OK != status)
    {
        goto exit;
    }

    /* Allocate and copy over the certificate. When the OCSP context is freed,
     * this information is freed as well so a copy must be made.
     */
    status = DIGI_MALLOC(
        (void **) &(pOcspCtx->pOcspSettings->pCertInfo[0].pCert), certLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pOcspCtx->pOcspSettings->pCertInfo[0].pCert, pCert, certLen);
    if (OK != status)
    {
        goto exit;
    }

    pOcspCtx->pOcspSettings->pCertInfo[0].certLen = certLen;

    /* Allocate and copy over the issuer certificate. When the OCSP context is
     * freed, this information is freed as well so a copy must be made.
     */
    status = DIGI_MALLOC(
        (void **) &(pOcspCtx->pOcspSettings->pIssuerCertInfo[0].pCertPath),
        issuerCertLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pOcspCtx->pOcspSettings->pIssuerCertInfo[0].pCertPath, pIssuerCert,
        issuerCertLen);
    if (OK != status)
    {
        goto exit;
    }

    pOcspCtx->pOcspSettings->pIssuerCertInfo[0].certLen = issuerCertLen;

    /* Set the total amount of certificates and issuer certificates. The OCSP
     * context requires that each certificate has an issuer certificate set.
     */
    pOcspCtx->pOcspSettings->certCount = 1;

    /* Generate the OCSP request.
     */
    status = OCSP_CLIENT_generateRequest(
        pOcspCtx, pExt, extLen, &pRequest, &requestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Make an OCSP request to the server.
     */
    status = OCSP_CLIENT_sendRequest(pOcspCtx, pHttpCtx, pRequest, requestLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Retrieve the OCSP response.
     */
    while (!isDone)
    {
        status = OCSP_CLIENT_recv(
            pOcspCtx, pHttpCtx, &isDone, &pResp, &respLen);
        if (OK != status)
        {
            goto exit;
        }
    }

    /* Ensure the response is valid.
     */
    status = OCSP_CLIENT_parseResponse(pOcspCtx, pResp, respLen);
    if (OK != status)
    {
        goto exit;
    }

    /* If the caller wants the next update time then retrieve it from the
     * response which is stored in the OCSP context.
     */
    if (NULL != pNextUpdate)
    {
        status = OCSP_CLIENT_getCurrentNextUpdate(
            pOcspCtx, pNextUpdate, &isNextUpdate);
        if (OK != status)
        {
            goto exit;
        }

        /* Next update time is not available. Set a default of timeout value to
         * avoid constantly retrieving a response.
         */
        if (FALSE == isNextUpdate)
        {
            status = OCSP_STORE_setDefaultNextUpdateTime(pNextUpdate);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

    /* Successfully got an OCSP response and was able to retrieve the
     * next update value from the response. Set all the return values and
     * return.
     */
    *ppRetResponse = pResp;
    *pRetResponseLen = respLen;
    pResp = NULL;

exit:

    if (NULL != pRequest)
    {
        DIGI_FREE((void **) &pRequest);
    }

    if (NULL != pResp)
    {
        DIGI_FREE((void **) &pResp);
    }

    if (NULL != pHttpCtx)
    {
        OCSP_CLIENT_httpUninit(&pHttpCtx);
    }

    if (TRUE == freeUrl)
    {
        DIGI_FREE((void **) &(pOcspCtx->pOcspSettings->pResponderUrl));
    }

    if (NULL != pOcspCtx)
    {
        if (NULL != pOcspCtx->pOcspSettings)
        {
            if (NULL != pOcspCtx->pOcspSettings->pCertInfo)
            {
                if (pOcspCtx->pOcspSettings->pCertInfo[0].pCert)
                {
                    DIGI_FREE((void **) &(pOcspCtx->pOcspSettings->pCertInfo[0].pCert));
                }
            }

            if (NULL != pOcspCtx->pOcspSettings->pIssuerCertInfo)
            {
                if (NULL != pOcspCtx->pOcspSettings->pIssuerCertInfo[0].pCertPath)
                {
                    DIGI_FREE((void **) &(pOcspCtx->pOcspSettings->pIssuerCertInfo[0].pCertPath));
                }
            }
        }

        OCSP_CONTEXT_releaseContextLocal(&pOcspCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS OCSP_STORE_getValidResponse(
    ocspCachedEntry *pEntry, ubyte *pCert, ubyte4 certLen, ubyte *pIssuer,
    ubyte4 issuerLen, ubyte **ppResponse, ubyte4 *pResponseLen)
{
    MSTATUS status;
    intBoolean releaseMutex = FALSE;
    ubyte *pResp = NULL;
    ubyte4 respLen = 0;
    TimeDate time;

    /* Set default return values.
     */
    *ppResponse = NULL;
    *pResponseLen = 0;

    /* Acquire the mutex for the current entry.
     */
    status = RTOS_mutexWait(pEntry->responseMutex);
    if (OK != status)
    {
        goto exit;
    }

    releaseMutex = TRUE;

    /* If the response is being retrieved by another thread then just exit. The
     * response returned will be NULL/0.
     *
     * If another thread is not attempting to get a response and there is a
     * response stored in the entry then check the response so see if it is
     * still valid.
     *
     * If another thread is not attempting to get a response and there is no
     * response then get the response.
     */
    if (TRUE == pEntry->gettingResponse)
    {
        /* Another thread is getting a response, return NULL/0.
         */
        goto exit;
    }
    else if (NULL != pEntry->pResponse)
    {
        /* Response is cached, check if it is outdated.
         */
        sbyte4 timeDiff = 0;

        /* Get the current time.
         */
        status = RTOS_timeGMT(&time);
        if (OK != status)
        {
            goto exit;
        }

        /* Diff the current time against the time stored in the cached response.
         */
        status = DATETIME_diffTime(&(pEntry->nextUpdate), &time, &timeDiff);
        if (OK != status)
        {
            goto exit;
        }

        /* If (response time - current time) > 0 then the response is valid.
         */
        if (0 < timeDiff)
        {
            /* Valid response. Create a copy and exit.
             */
            status = DIGI_MALLOC((void **) &pResp, pEntry->responseLen);
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(pResp, pEntry->pResponse, pEntry->responseLen);
            if (OK != status)
            {
                goto exit;
            }

            *ppResponse = pResp;
            *pResponseLen = pEntry->responseLen;
            pResp = NULL;
            goto exit;
        }
        else
        {
            /* Response is invalid. Free the response data and signal to the
             * other threads that the response is being retrieved.
             */
            DIGI_FREE((void **) &(pEntry->pResponse));
            DIGI_MEMSET((ubyte *) &(pEntry->nextUpdate), 0x00, sizeof(TimeDate));
            pEntry->responseLen = 0;
            pEntry->gettingResponse = TRUE;
        }
    }
    else
    {
        /* Another thread is not getting a response and there is no cached
         * response. Make this thread get the response. Signal to all other
         * threads that the response is being retrieved.
         */
        pEntry->gettingResponse = TRUE;
    }

    releaseMutex = FALSE;

    status = RTOS_mutexRelease(pEntry->responseMutex);
    if (OK != status)
    {
        goto exit;
    }

    /* If this point has been reached then retrieve the response for the
     * certificate.
     */
    status = OCSP_STORE_getSingleResponse(
        pCert, certLen, pIssuer, issuerLen, NULL, NULL, 0, &pResp, &respLen,
        &time);
    if (OK != status)
    {
        goto exit;
    }

    /* Got a response with a time update. Acquire the entry mutex and update the
     * values.
     */
    status = RTOS_mutexWait(pEntry->responseMutex);
    if (OK != status)
    {
        goto exit;
    }

    releaseMutex = TRUE;
    pEntry->gettingResponse = FALSE;

    /* Free the existing response.
     */
    if (NULL != pEntry->pResponse)
    {
        status = DIGI_FREE((void **) &(pEntry->pResponse));
        if (OK != status)
        {
            goto exit;
        }
    }

    /* Copy over the new update time.
     */
    status = DIGI_MEMCPY(&(pEntry->nextUpdate), &time, sizeof(TimeDate));
    if (OK != status)
    {
        goto exit;
    }

    /* Set the values in entry.
     */
    pEntry->pResponse = pResp;
    pEntry->responseLen = respLen;
    pResp = NULL;

    /* Create a copy of the cached response and return it to the caller.
     */
    status = DIGI_MALLOC((void **) &pResp, pEntry->responseLen);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(pResp, pEntry->pResponse, pEntry->responseLen);
    if (OK != status)
    {
        goto exit;
    }

    *ppResponse = pResp;
    *pResponseLen = pEntry->responseLen;
    pResp = NULL;

    releaseMutex = FALSE;

    status = RTOS_mutexRelease(pEntry->responseMutex);

exit:

    if (TRUE == releaseMutex)
    {
        RTOS_mutexRelease(pEntry->responseMutex);
    }

    if (NULL != pResp)
    {
        DIGI_FREE((void **) &pResp);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS OCSP_STORE_findResponseByCert(
    ocspStore *pStore, ubyte *pCert, ubyte4 certLen, ubyte *pIssuerCert,
    ubyte4 issuerCertLen, sbyte *pResponderUrl, extensions *pExt, ubyte4 extLen,
    ubyte **ppResponse, ubyte4 *pResponseLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = NULL;
    ubyte4 hashVal;
    ocspCachedEntry *pEntry = NULL;

    if ( (NULL == pStore) || (NULL == ppResponse) || (NULL == pResponseLen) ||
         (NULL == pCert) || (NULL == pIssuerCert) )
    {
        status = ERR_OCSP_STORE_NULL_POINTER;
        goto exit;
    }

    if ( (0 == certLen) || (0 == issuerCertLen) )
    {
        status = ERR_OCSP_STORE_INVALID_CERT_LENGTH;
        goto exit;
    }

    /* If the caller provided a responder URL or extensions then always go to
     * the server to get a response, otherwise attempt to look up a cached
     * response.
     */
    if ( (NULL != pResponderUrl) || (NULL != pExt) )
    {
        /* Get the response with the specified responder/extensions. Do not
         * cache this response since it is not a generic response.
         */
        status = OCSP_STORE_getSingleResponse(
            pCert, certLen, pIssuerCert, issuerCertLen, pResponderUrl,
            pExt, extLen, ppResponse, pResponseLen, NULL);
    }
    else
    {
        MF_attach(&mf, certLen, pCert);
        CS_AttachMemFile(&cs, &mf);

        /* Parse the certificate for which the OCSP response is being retrieved.
         * The hash value will be retrieved from this certificate to see if
         * there is an existing entry in the hash table.
         */
        status = ASN1_Parse(cs, &pRoot);
        if (OK != status)
        {
            goto exit;
        }

        /* Generate the hash value based on the certificate.
         */
        status = OCSP_STORE_genHashValue(ASN1_FIRST_CHILD(pRoot), cs, &hashVal);
        if (OK != status)
        {
            goto exit;
        }

        /* Find the cached entry. If the entry does not exist then this API
         * will create it.
         */
        status = OCSP_STORE_findCachedEntry(pStore, hashVal, &pEntry);
        if (OK != status)
        {
            goto exit;
        }

        /* Retrieve a valid response. This may be NULL/0 if another thread is
         * already attempting to get a response.
         */
        status = OCSP_STORE_getValidResponse(
            pEntry, pCert, certLen, pIssuerCert, issuerCertLen, ppResponse,
            pResponseLen);
    }

exit:

    if (NULL != pRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pRoot);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

#endif /* __ENABLE_DIGICERT_OCSP_STORE__ */
