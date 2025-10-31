/*
 * mqtt_core.c
 *
 * MQTT client core, management of internal global structures
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

#include "../common/moptions.h"

#ifdef __ENABLE_MQTT_CLIENT__

#include "mqtt_client.h"
#include "mqtt_client_priv.h"
#include "mqtt_core.h"
#include "mqtt_util.h"
#include "mqtt_msg.h"
#include "../common/mrtos.h"
#include "../common/hash_table.h"
#include "../common/hash_value.h"
#include "../common/sort.h"
#include "../common/mfmgmt.h"

#if defined (__LINUX_RTOS__)
#include <stdio.h>
#endif

/*----------------------------------------------------------------------------*/

/* Global variables for MQTT stack initialization and connections */
static byteBoolean gInitialized = FALSE;
static RTOS_MUTEX gpMqttConnectTableMutex = NULL;
static MqttCtx** gppMqttConnectTable = NULL;
#if defined(__ENABLE_MQTT_HASH_TABLE__)
static hashTableOfPtrs* gpMqttPublishHashTable = NULL;
static hashTableOfPtrs* gpMqttInboundPublishHashTable = NULL;
#endif
static ubyte4 gMaxConnections = 0;

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_HASH_TABLE__)

static MSTATUS allocHashPtrElement(
    void *pHashCookie,
    hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = OK;

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS freeHashPtrElement(
    void *pHashCookie,
    hashTablePtrElement *pFreeHashElement)
{
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    FREE(pFreeHashElement);

    return OK;
}

#endif

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_initCore(
    sbyte4 mqttMaxClientConnections)
{
    MSTATUS status;
    RTOS_MUTEX pMutex = NULL;
    MqttCtx** ppTable = NULL;
    ubyte4 i;
#if defined(__ENABLE_MQTT_HASH_TABLE__)
    hashTableOfPtrs* pPublishHashTable = NULL;
    hashTableOfPtrs* pInboundPublishHashTable = NULL;
    ubyte4 remain;
    ubyte4 count;
#endif

    if (FALSE == gInitialized)
    {
        if (0 >= mqttMaxClientConnections)
        {
            status = ERR_MQTT_INVALID_MAX_CLIENT_CONN;
            goto exit;
        }

        /* Create connect table mutex */
        status = RTOS_mutexCreate(&pMutex, MQTT_CACHE_MUTEX, 0);
        if (OK != status)
            goto exit;

        /* Create and initialize connect table */
        status = MOC_MALLOC(
            (void **) &ppTable,
            sizeof(MqttCtx*) * mqttMaxClientConnections);
        if (OK != status)
            goto exit;

        for (i = 0; i < (ubyte4)mqttMaxClientConnections; i++)
        {
            ppTable[i] = NULL;
        }

#if defined(__ENABLE_MQTT_HASH_TABLE__)
        /* Create connect hash table */
        count = 0;
        remain = mqttMaxClientConnections;
        while (remain > 0)
        {
            remain = remain >> 1;
            count++;
        }

        /* TODO: determine if this table size is acceptable, might need to be bigger */
        status = HASH_TABLE_createPtrsTable(
            &pPublishHashTable, (1 << count) - 1, NULL,
            allocHashPtrElement, freeHashPtrElement);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_createPtrsTable(
            &pInboundPublishHashTable, (1 << count) - 1, NULL,
            allocHashPtrElement, freeHashPtrElement);
        if (OK != status)
            goto exit;
#endif

        gpMqttConnectTableMutex = pMutex; pMutex = NULL;
        gppMqttConnectTable = ppTable; ppTable = NULL;
#if defined(__ENABLE_MQTT_HASH_TABLE__)
        gpMqttPublishHashTable = pPublishHashTable; pPublishHashTable = NULL;
        gpMqttInboundPublishHashTable = pInboundPublishHashTable; pInboundPublishHashTable = NULL;
#endif
        gMaxConnections = mqttMaxClientConnections;
        gInitialized = TRUE;
    }
    else
    {
        /* Already initialized, just ensure the caller is not trying to
         * initialize with a larger number of connections */
        if ((ubyte4)mqttMaxClientConnections > gMaxConnections)
        {
            status = ERR_MQTT_INVALID_MAX_CLIENT_CONN;
            goto exit;
        }

        status = OK;
    }

exit:

#if defined(__ENABLE_MQTT_HASH_TABLE__)

    if (NULL != pPublishHashTable)
    {
        HASH_TABLE_removePtrsTable(pPublishHashTable, NULL);
    }
#endif

    if (NULL != ppTable)
    {
        MOC_FREE((void **) &ppTable);
    }

    if (NULL != pMutex)
    {
        RTOS_mutexFree(&pMutex);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_uninitCore(void)
{
    MSTATUS status = OK, fstatus;

    if (TRUE == gInitialized)
    {
        status = RTOS_mutexWait(gpMqttConnectTableMutex);
        if (OK != status)
            goto exit;

        status = MOC_FREE((void **) &gppMqttConnectTable);

#if defined(__ENABLE_MQTT_HASH_TABLE__)

        fstatus = HASH_TABLE_removePtrsTable(gpMqttPublishHashTable, NULL);
        if (OK == fstatus)
        {
            gpMqttPublishHashTable = NULL;
        }
        if (OK == status)
            status = fstatus;

        fstatus = HASH_TABLE_removePtrsTable(gpMqttInboundPublishHashTable, NULL);
        if (OK == fstatus)
        {
            gpMqttInboundPublishHashTable = NULL;
        }
        if (OK == status)
            status = fstatus;
#endif

        fstatus = RTOS_mutexRelease(gpMqttConnectTableMutex);
        if (OK == status)
            status = fstatus;

        fstatus = RTOS_mutexFree(&gpMqttConnectTableMutex);
        if (OK == status)
            status = fstatus;

        gMaxConnections = 0;
        gInitialized = FALSE;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_getCtxFromConnInst(sbyte4 connectionInstance, MqttCtx **ppCtx)
{
    MqttCtx *pCtx;
    if ( (0 > connectionInstance) || ((ubyte4)connectionInstance > gMaxConnections) )
    {
        return ERR_MQTT_INVALID_CONN_INST_RANGE;
    }

    pCtx = gppMqttConnectTable[connectionInstance];
    if (NULL == pCtx)
    {
        return ERR_NULL_POINTER;
    }
    *ppCtx = pCtx;
    return OK;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_createClientCtx(
    MqttCtx **ppNewCtx,
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen,
    ubyte4 internalFlags)
{
    MSTATUS status;
    MqttCtx *pNewCtx = NULL;

    /* Input argument validation not required */

    status = MOC_CALLOC((void **)&pNewCtx, 1, sizeof(MqttCtx));
    if (OK != status)
        goto exit;

    if (NULL != pClientId)
    {
        /* Allocate an extra 2 bytes for the client id buffer to be used for appending the packet id
         * when calculating the hash key later when storing publishes */
        status = MOC_MALLOC_MEMCPY((void **)&pNewCtx->pClientId, clientIdLen + 2, pClientId, clientIdLen);
        if (OK != status)
            goto exit;

        pNewCtx->clientIdLen = clientIdLen;
        pNewCtx->assignedClientId = FALSE;
    }
    else
    {
        pNewCtx->assignedClientId = TRUE;
    }
    pNewCtx->version = version;
    pNewCtx->connectionState = CONNECT_NEGOTIATE;
    pNewCtx->internalFlags = internalFlags;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_SYNC(pNewCtx))
#endif
    {
        pNewCtx->syncBufferSize = MQTT_SYNC_BUFFER_SIZE;
#if defined(__ENABLE_MQTT_STREAMING__)
        pNewCtx->streamingCurPkt = FALSE;
        pNewCtx->pktHandler = NULL;
        pNewCtx->publishState = MQTT_PUBLISH_TYPE_STATE;
        MOC_MEMSET((ubyte *) &pNewCtx->publishInfo, 0x00, sizeof(MqttPublishInfo));
        MOC_MEMSET((ubyte *) &pNewCtx->publishData, 0x00, sizeof(MqttPublishData));
#endif
    }

    status = RTOS_mutexCreate(&(pNewCtx->pMutex), MQTT_CACHE_MUTEX, 0);
    if (OK != status)
        goto exit;

    pNewCtx->keepAliveMS = 0;
    pNewCtx->publishTimeoutSeconds = MQTT_DEFAULT_PUBLISH_TIMEOUT_SECONDS;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
    {
        MOC_FREE((void **)&pNewCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

/* If we already have an entry for the client id return that, otherwise put
 * a new entry in the table */
extern MSTATUS MQTT_createConnectInstanceFromId(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen,
    sbyte4 *pConnectionInstance,
    ubyte4 internalFlags)
{
    MSTATUS status;
    MqttCtx *pNewCtx = NULL;
    ubyte4 i;

    /* NULL check on pConnectionInstance not required */

    /* For NULL/0 client ID we expect the server to provide the client ID in
     * the CONNACK message */
    if ( ( (NULL == pClientId) && (0 != clientIdLen) ) ||
         ( (NULL != pClientId) && (0 == clientIdLen) ) )
    {
        status = ERR_MQTT_INVALID_CLIENT_ID;
        goto exit;
    }

    /* Check for supported version */
    switch (version)
    {
        case MQTT_V5:
        case MQTT_V3_1_1:
            break;

        default:
            status = ERR_MQTT_VERSION_UNSUPPORTED;
            goto exit;
    }

    if (FALSE == gInitialized)
    {
        /* MQTT stack is not initialized */
        status = ERR_MQTT_UNINITIALIZED;
        goto exit;
    }

    if (NULL != pClientId)
    {
        if (!isValidUtf8(pClientId, clientIdLen))
        {
            status = ERR_MQTT_INVALID_UTF8;
            goto exit;
        }
    }

    for (i = 0; i < gMaxConnections; i++)
    {
        if (NULL == gppMqttConnectTable[i])
        {
            break;
        }
    }

    /* If i equals gMaxConnections then an empty space was not found */
    if (i == gMaxConnections)
    {
        status = ERR_MQTT_CONNECT_TABLE_NO_SPACE;
        goto exit;
    }

    /* Create new MQTT client context */
    status = MQTT_createClientCtx(
        &pNewCtx, version, pClientId, clientIdLen, internalFlags);
    if (OK != status)
        goto exit;

    pNewCtx->connInst = i;
    gppMqttConnectTable[i] = pNewCtx; pNewCtx = NULL;
    *pConnectionInstance = i;

exit:
    return status;
}

MSTATUS MQTT_closeConnectionInternal(sbyte4 connectionInstance)
{
    MSTATUS status;
    
    if ( (connectionInstance < 0) || ((ubyte4)connectionInstance > gMaxConnections) )
    {
        return ERR_INVALID_ARG;
    }

    status = MQTT_releaseClientCtx(&gppMqttConnectTable[connectionInstance]);
    gppMqttConnectTable[connectionInstance] = NULL;
    return status;
}

MSTATUS MQTT_releaseClientCtx(MqttCtx **ppClientCtx)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (NULL == ppClientCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MqttCtx *)*ppClientCtx;
    if (NULL == pCtx)
    {
        status = OK;
        goto exit;
    }

    if (NULL != pCtx->pClientId)
    {
        MOC_FREE((void **) &pCtx->pClientId);
    }

    if (NULL != pCtx->pSyncBuffer)
    {
        MOC_FREE((void **) &pCtx->pSyncBuffer);
    }

    if (NULL != pCtx->pRecvBuffer)
    {
        MOC_FREE((void **) &pCtx->pRecvBuffer);
    }

    if (NULL != pCtx->pPacketIdList)
    {
        MQTT_freePacketIdList(pCtx);
    }

    if (NULL != pCtx->pMutex)
    {
        RTOS_mutexFree(&pCtx->pMutex);
    }

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (NULL != pCtx->pDir)
    {
        MOC_FREE((void **) &pCtx->pDir);
    }
    if (NULL != pCtx->pFilename)
    {
        MOC_FREE((void **) &pCtx->pFilename);
    }
#endif

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    MQTT_freeMsgList(&pCtx->pMsgListHead);
#endif

    if (TRUE == pCtx->keepAliveThreadActive)
    {
        pCtx->keepAliveThreadActive = FALSE;

        status = RTOS_semSignal(pCtx->keepAliveSem);
        if (OK != status)
            goto exit;

        status = RTOS_joinThread(pCtx->keepAliveTID, NULL);
        if (OK != status)
            goto exit;

        status = RTOS_mutexFree(&pCtx->keepAliveMutex);
        if (OK != status)
            goto exit;

        status = RTOS_semFree(&pCtx->keepAliveSem);
        if (OK != status)
            goto exit;
    }

    MOC_FREE((void **)&pCtx);

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

typedef struct
{
    ubyte4 numElements;
    MqttPacketList *pHead;
    MqttPacketList *pTail;
} MqttPacketListWrapper;

static MSTATUS MQTT_computeHashKey(MqttCtx *pCtx, ubyte2 packetId, ubyte4 *pHashVal)
{
    MSTATUS status = OK;
    ubyte4 hashVal = 0;

    /* Client id buffer has 2 extra bytes for the packet id, compute
     * Key = (clientId || packetId) */
    if(pCtx->pClientId != NULL)
    {
        MOC_HTONS((pCtx->pClientId + pCtx->clientIdLen), packetId);
        HASH_VALUE_hashGen(pCtx->pClientId, pCtx->clientIdLen + 2, 0, &hashVal);
        *pHashVal = hashVal;
    }

    return status;
}

void MQTT_freePacketIdList(MqttCtx *pCtx)
{
    MqttPacketList *pNode = NULL;
    MqttPacketList *pTemp = NULL;
    MqttPacketListWrapper *pWrapper = NULL;

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    if (NULL != pWrapper)
    {
        pNode = pWrapper->pHead;
        while(NULL != pNode)
        {
            pTemp = pNode->pNext;
            MOC_FREE((void **)&pNode);
            pNode = pTemp;
        }

        MOC_FREE((void **)&pWrapper);
    }
}

byteBoolean MQTT_packetIdExists(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status = OK;
    intBoolean found = FALSE;
    ubyte *pValue = NULL;
    ubyte4 hashVal = 0;

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
    {
        return FALSE;
    }

    status = HASH_TABLE_findPtr (
        gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
    {
        return FALSE;
    }

    return (byteBoolean)found;

}

MSTATUS MQTT_addPacketIdToList(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;

    status = MOC_CALLOC((void **) &pNode, 1, sizeof(MqttPacketList));
    if (OK != status)
        goto exit;

    pNode->packetId = packetId;
    pNode->pNext = NULL;

    pWrapper = pCtx->pPacketIdList;
    if (NULL == pWrapper)
    {
        /* First addition to the list, create it new */
        status = MOC_CALLOC((void **) &pWrapper, 1, sizeof(MqttPacketListWrapper));
        if (OK != status)
            goto exit;
    }
    
    if (0 == pWrapper->numElements)
    {
        pWrapper->pHead = pNode;
        pWrapper->pTail = pNode;
        pWrapper->numElements = 1;
        pNode = NULL;

        pCtx->pPacketIdList = (void *)pWrapper;
    }
    else
    {
        /* Add the new node to the end of the list */
        pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
        pWrapper->pTail->pNext = pNode;
        pWrapper->pTail = pNode;
        pWrapper->numElements++;
        pNode = NULL;
    }

exit:

    if (NULL != pNode)
    {
        MOC_FREE((void **)&pNode);
    }

    return status;
}

MSTATUS MQTT_removePacketIdFromList(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status = OK;
    MqttPacketList *pPrev = NULL;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;

    if (NULL == pWrapper)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    pNode = pWrapper->pHead;
    pPrev = pNode;
    while(NULL != pNode)
    {
        if (packetId == pNode->packetId)
        {
            if (pNode == pWrapper->pHead)
            {
                pWrapper->pHead = pNode->pNext;
            }
            else
            {
                if (NULL == pNode->pNext)
                {
                    pWrapper->pTail = pPrev;
                }
                pPrev->pNext = pNode->pNext;
            }
            
            MOC_FREE((void **)&pNode);
            pWrapper->numElements--;
            break;
        }

        pPrev = pNode;
        pNode = pNode->pNext;
    }

exit:
    return status;
}

MSTATUS MQTT_addPacketId(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId)
{
    MSTATUS status;
    moctime_t timer = {0};
    ubyte *pValue = NULL;
    ubyte *pIter = NULL;
    ubyte4 hashVal = 0;
    ubyte encodedLen[4];
    ubyte bytesUsed = 0;
    ubyte i = 0;

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
    {
        goto exit;
    }

    status = MQTT_encodeVariableByteInt((8 + pMsg->dataLen), (ubyte *)encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;
    
    status = MOC_MALLOC((void **)&pValue, (bytesUsed + 8 + pMsg->dataLen));
    if (OK != status)
        goto exit;

    pIter = pValue;

    for  (i = 0; i < bytesUsed; i++)
    {
        pIter[i] = encodedLen[i];
    }
    pIter += bytesUsed;

    RTOS_deltaMS(NULL, &timer);
    MOC_HTONL(pIter, timer.u.time[0]);
    pIter += 4;
    MOC_HTONL(pIter, timer.u.time[1]);
    pIter += 4;

    status = MOC_MEMCPY((void *)pIter, (void *)pMsg->pData, pMsg->dataLen);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_addPtr(gpMqttPublishHashTable, hashVal, pValue);
    if (OK != status)
        goto exit;

    pValue = NULL;

exit:
    if (NULL != pValue)
    {
        MOC_FREE((void **)&pValue);
    }
    
    return status;
}

MSTATUS MQTT_checkAndMarkAcked(MqttCtx *pCtx, ubyte2 packetId, intBoolean *found)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    ubyte *pValue = NULL;

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
    {
        goto exit;
    }

    status = HASH_TABLE_deletePtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, found);
    if (OK != status)
        goto exit;

    if (TRUE == *found)
    {
        MOC_FREE((void **)&pValue);
    }

exit:
    return status;
}

#if defined(__MQTT_ENABLE_FILE_PERSIST__)

MSTATUS MQTT_initFilenameBuffer(MqttCtx *pCtx)
{
    MSTATUS status;
    sbyte *pDirName = NULL;

    if (NULL == pCtx->pDir)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pCtx->pFilename)
    {
        status = OK;
        goto exit;
    }

    status = MOC_CALLOC((void **)&pDirName, 1, MOC_STRLEN(pCtx->pDir) + 1 + pCtx->clientIdLen + 1);
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pDirName, pCtx->pDir, MOC_STRLEN(pCtx->pDir));
    if (OK != status)
        goto exit;

    pDirName[MOC_STRLEN(pCtx->pDir)] = MQTT_DIR_SLASH;

    status = MOC_MEMCPY(pDirName + MOC_STRLEN(pCtx->pDir) + 1, pCtx->pClientId, pCtx->clientIdLen);
    if (OK != status)
        goto exit;

    /* We will reuse filename buffer, enough space for persistdir/clientid-out/65535 */
    status = MOC_CALLOC((void **)&(pCtx->pFilename), 1, (MOC_STRLEN(pDirName) + 4 + 1 + 6 + 5));
    if (OK != status)
        goto exit;

    status = MOC_MEMCPY(pCtx->pFilename, pDirName, MOC_STRLEN(pDirName));
    if (OK != status)
        goto exit;

    pCtx->filePrefixLen = MOC_STRLEN(pDirName);

exit:

    if (NULL != pDirName)
    {
        MOC_FREE((void **)&pDirName);
    }

    return status;
}

MSTATUS MQTT_persistMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId, sbyte *pSuffix, ubyte4 suffixLen)
{
    MSTATUS status;
    sbyte strPacketIdBuf[6];
    ubyte *pRet = NULL;
    FileDescriptor pFile = NULL;
    ubyte4 bytesWritten = 0;

    MOC_MEMSET((void *)strPacketIdBuf, 0, 6);

    pRet = MOC_LTOA((sbyte4)packetId, (sbyte *)strPacketIdBuf, 6);
    if (NULL == pRet)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    /* memset everything beyond persistdir/clientid , enough space for -out (4) || / (1) || 65535 (6) */
    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY(pCtx->pFilename + pCtx->filePrefixLen, pSuffix, suffixLen);
    if (OK != status)
        goto exit;

    if (FALSE == pCtx->outDirCreated)
    {
        if (FALSE == FMGMT_pathExists(pCtx->pFilename, NULL))
        {
            status = FMGMT_mkdir(pCtx->pFilename, 0777);
            if (OK != status)
                goto exit;
        }

        pCtx->outDirCreated = TRUE;
    }

    pCtx->pFilename[pCtx->filePrefixLen + suffixLen] = MQTT_DIR_SLASH;
    
    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen + suffixLen + 1, 
        strPacketIdBuf, MOC_STRLEN(strPacketIdBuf));
    if (OK != status)
        goto exit;

    status = FMGMT_fopen(pCtx->pFilename, "w", &pFile);
    if (OK != status)
        goto exit;

    status = FMGMT_fwrite(pMsg->pData, 1, pMsg->dataLen, pFile, &bytesWritten);
    if (OK != status)
        goto exit;

    if (pMsg->dataLen != bytesWritten)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

exit:

    if (NULL != pFile)
    {
        FMGMT_fclose(&pFile);
    }
    RTOS_mutexRelease(pCtx->pMutex);

    return status;
}


MSTATUS MQTT_persistPublishMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId)
{
    return MQTT_persistMsg(pCtx, pMsg, packetId, "-out", 4);
}

MSTATUS MQTT_persistPubRelMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId)
{
    return MQTT_persistMsg(pCtx, pMsg, packetId, "-out", 4);
}

#endif

MSTATUS MQTT_storePublishMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId)
{
    MSTATUS status;
    moctime_t timer = {0};
    ubyte *pValue = NULL;
    ubyte *pIter = NULL;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    ubyte encodedLen[4];
    ubyte bytesUsed = 0;
    ubyte i = 0;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_persistPublishMsg(pCtx, pMsg, packetId);
    }
#endif

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
        goto exit;

    /* Value = (len || timestamp || message) */
    status = MQTT_encodeVariableByteInt((8 + pMsg->dataLen), (ubyte *)encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;
    
    status = MOC_MALLOC((void **)&pValue, (bytesUsed + 8 + pMsg->dataLen));
    if (OK != status)
        goto exit;

    pIter = pValue;

    for (i = 0; i < bytesUsed; i++)
    {
        pIter[i] = encodedLen[i];
    }
    pIter += bytesUsed;

    RTOS_deltaMS(NULL, &timer);
    MOC_HTONL(pIter, timer.u.time[0]);
    pIter += 4;
    MOC_HTONL(pIter, timer.u.time[1]);
    pIter += 4;

    status = MOC_MEMCPY((void *)pIter, (void *)pMsg->pData, pMsg->dataLen);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_addPtr(gpMqttPublishHashTable, hashVal, pValue);
    if (OK != status)
        goto exit;

    pValue = NULL;

    status = MQTT_addPacketIdToList(pCtx, packetId);
    if (OK != status)
    {
        HASH_TABLE_deletePtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    }

exit:

    if (NULL != pValue)
    {
        MOC_FREE((void **)&pValue);
    }

    return status;
}

MSTATUS MQTT_storePubRelMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId)
{
    MSTATUS status;
    moctime_t timer = {0};
    ubyte4 hashVal = 0;
    ubyte *pIter = NULL;
    ubyte *pValue = NULL;
    intBoolean found = FALSE;
    ubyte encodedLen[4];
    ubyte bytesUsed = 0;
    ubyte i = 0;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_persistPubRelMsg(pCtx, pMsg, packetId);
    }
#endif

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_findPtr (
        gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    /* TODO: determine error handling for this case, probably should never happen */
    if (FALSE == found)
    {
        status = ERR_GENERAL;
        goto exit;
    }

    /* Remove the existing entry and replace it with the pubrel */
    status = HASH_TABLE_deletePtr (
        gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (NULL != pValue)
    {
        MOC_FREE((void **)&pValue);
    }

    /* Construct the new value and store it in the hash table */

    /* Value = (len || timestamp || message) */
    status = MQTT_encodeVariableByteInt((8 + pMsg->dataLen), (ubyte *)encodedLen, &bytesUsed);
    if (OK != status)
        goto exit;

    status = MOC_CALLOC((void **)&pValue, 1, (bytesUsed + 8 + pMsg->dataLen));
    if (OK != status)
        goto exit;

    pIter = pValue;

    for (i = 0; i < bytesUsed; i++)
    {
        pIter[i] = encodedLen[i];
    }
    pIter += bytesUsed;

    RTOS_deltaMS(NULL, &timer);
    MOC_HTONL(pIter, timer.u.time[0]);
    pIter += 4;
    MOC_HTONL(pIter, timer.u.time[1]);
    pIter += 4;

    status = MOC_MEMCPY((void *)pIter, (void *)pMsg->pData, pMsg->dataLen);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_addPtr(gpMqttPublishHashTable, hashVal, (void *)pValue);
    if (OK != status)
        goto exit;

exit:

    return status;
}

#if defined(__MQTT_ENABLE_FILE_PERSIST__)

MSTATUS MQTT_markAckedPersist(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status;
    sbyte strPacketIdBuf[6];
    ubyte *pRet = NULL;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)strPacketIdBuf, 0, 6);

    pRet = MOC_LTOA((sbyte4)packetId, (sbyte *)strPacketIdBuf, 6);
    if (NULL == pRet)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* memset everything beyond persistdir/clientid , enough space for -out (4) || / (1) || 65535 (6) */
    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-out", 4);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 4] = MQTT_DIR_SLASH;
    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen + 4 + 1, strPacketIdBuf, MOC_STRLEN(strPacketIdBuf));
    if (OK != status)
        goto exit;

    status = FMGMT_remove(pCtx->pFilename, FALSE);

exit:
    RTOS_mutexRelease(pCtx->pMutex);
    return status;
}


MSTATUS MQTT_markInboundPubrelPersist(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status;
    sbyte strPacketIdBuf[6];
    ubyte *pRet = NULL;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)strPacketIdBuf, 0, 6);

    pRet = MOC_LTOA((sbyte4)packetId, (sbyte *)strPacketIdBuf, 6);
    if (NULL == pRet)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-in", 3);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 3] = MQTT_DIR_SLASH;
    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen + 3 + 1, strPacketIdBuf, MOC_STRLEN(strPacketIdBuf));
    if (OK != status)
        goto exit;

    status = FMGMT_remove(pCtx->pFilename, FALSE);

exit:
    RTOS_mutexRelease(pCtx->pMutex);
    return status;
}

MSTATUS MQTT_checkPublishDeliveryAllowedPersist(MqttCtx *pCtx, ubyte2 packetId, byteBoolean *pAllowed)
{
    MSTATUS status;
    sbyte strPacketIdBuf[6];
    ubyte *pRet = NULL;
    FileDescriptor pFile = NULL;
    ubyte4 bytesWritten = 0;
    sbyte *pOne = "1";

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)strPacketIdBuf, 0, 6);

    pRet = MOC_LTOA((sbyte4)packetId, (sbyte *)strPacketIdBuf, 6);
    if (NULL == pRet)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-in", 3);
    if (OK != status)
        goto exit;

    if (FALSE == pCtx->inDirCreated)
    {
        if (FALSE == FMGMT_pathExists(pCtx->pFilename, NULL))
        {
            status = FMGMT_mkdir(pCtx->pFilename, 0777);
            if (OK != status)
                goto exit;
        }
    }

    pCtx->pFilename[pCtx->filePrefixLen + 3] = MQTT_DIR_SLASH;
    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen + 3 + 1, strPacketIdBuf, MOC_STRLEN(strPacketIdBuf));
    if (OK != status)
        goto exit;

    if (FALSE == FMGMT_pathExists(pCtx->pFilename, NULL))
    {
        /* This is our first time receiving this publish with this packet id */
        status = FMGMT_fopen(pCtx->pFilename, "w", &pFile);
        if (OK != status)
            goto exit;

        /* Contents of msg do not matter, file existence and time are all that matter. */
        status = FMGMT_fwrite(pOne, 1, 1, pFile, &bytesWritten);
        if (OK != status)
            goto exit;

        *pAllowed = TRUE;
    }
    else
    {
        *pAllowed = FALSE;
    }

exit:

    if (NULL != pFile)
    {
        FMGMT_fclose(&pFile);
    }
    RTOS_mutexRelease(pCtx->pMutex);

    return status;
}
#endif

MSTATUS MQTT_markAcked(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    ubyte *pValue = NULL;
    intBoolean found = FALSE;

    /* MQTT spec v5 4.9:
     * The send quota is incremented by 1 Each time a PUBACK or PUBCOMP packet is received, and
     * Each time a PUBREC packet is received with a Return Code of 0x80 or greater. */
    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    if (pCtx->sendQuota < pCtx->recvMax)
    {
        pCtx->sendQuota++;
    }

    RTOS_mutexRelease(pCtx->pMutex);

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_markAckedPersist(pCtx, packetId);
    }
#endif

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
        goto exit;

    status = MQTT_removePacketIdFromList(pCtx, packetId);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_deletePtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        MOC_FREE((void **)&pValue);
    }

    

exit:

    return status;
}

MSTATUS MQTT_checkPublishDeliveryAllowed(MqttCtx *pCtx, ubyte2 packetId, byteBoolean *pAllowed)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    ubyte *pValue = NULL;
    intBoolean found = FALSE;
    ubyte4 intPacketId = (ubyte4)packetId;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_checkPublishDeliveryAllowedPersist(pCtx, packetId, pAllowed);
    }
#endif

    if (NULL == pAllowed)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pAllowed = FALSE;

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_findPtr (
        gpMqttInboundPublishHashTable, hashVal, (void *)((uintptr)intPacketId), NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (FALSE == found)
    {
        /* We did not already have an entry, add an entry now and tell the caller that the 
         * delivery of the PUBLISH to the application is allowed.*/
        status = HASH_TABLE_addPtr(gpMqttInboundPublishHashTable, hashVal, (void *)((uintptr)intPacketId));
        if (OK != status)
            goto exit;

        *pAllowed = TRUE;
    }

    /* If found, *pAllowed is already FALSE */

exit:
    return status;
}

MSTATUS MQTT_markInboundPubrel(MqttCtx *pCtx, ubyte2 packetId)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    ubyte *pValue = NULL;
    intBoolean found = FALSE;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_markInboundPubrelPersist(pCtx, packetId);
    }
#endif

    status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
    if (OK != status)
        goto exit;

    status = HASH_TABLE_deletePtr(gpMqttInboundPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);

exit:
    return status;
}

#if defined(__MQTT_ENABLE_FILE_PERSIST__)

typedef struct {
    ubyte strPacketId[6];
#ifdef __ENABLE_MOCANA_64_BIT__
    sbyte8 timeStamp;
#else
    sbyte4 timeStamp;
#endif
    ubyte *pValue;
    MqttMessage *pMsg;
} ResendPersistElem;

static MSTATUS MQTT_persistElemCompare(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess)
{
    ResendPersistElem *pFirst = (ResendPersistElem *)pFirstItem;
    ResendPersistElem *pSecond = (ResendPersistElem *)pSecondItem;

    *pRetIsLess = (pFirst->timeStamp < pSecond->timeStamp) ? TRUE : FALSE;

    return OK;
}

MSTATUS MQTT_resendUnackedPacketsPersist(MqttCtx *pCtx)
{
    MSTATUS status, fstatus;
    ubyte4 i = 0;
    ubyte4 fileCount = 0;
    ubyte4 fileSize = 0;
    ubyte4 bytesRead = 0;
    ubyte4 offset = 0;
    ResendPersistElem *pElements = NULL;
    FileDescriptor pFile = NULL;
    DirectoryDescriptor dir_list = NULL;
    ubyte *pByteValue = NULL;
    FileDescriptorInfo f = {0};
    MqttMessage msg = {0};
    MqttMessage *pCurrentMsg = NULL;
    DirectoryEntry dir_entry;
    byteBoolean locked = FALSE;

    fstatus = OK;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    locked = TRUE;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-out", 4);
    if (OK != status)
        goto exit;

    /* Count how many files we have */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);

    /* TODO: review logic, not a good way to differentiate between dir does not exist yet and
     * problems with accessing dir. Proposed current solution, if dir does not exist assume
      * no packets to be resent. */
    if (OK != status)
    {
        status = OK;
        goto exit;
    }

    while (FTNone != dir_entry.type)
    {
        if (FTFile == dir_entry.type)
        {
            fileCount++;
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;
    }

    /* Emptry directory is also OK */
    if (0 == fileCount)
    {
        status = OK;
        goto exit;
    }

    /* Allocate array of resend elements */
    status = MOC_CALLOC((void **)&pElements, fileCount, sizeof(ResendPersistElem));
    if (OK != status)
        goto exit;

    FMGMT_closeDir (&dir_list);

    /* Populate list of packet ids with timestamps */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);
    if (OK != status)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    pCtx->pFilename[pCtx->filePrefixLen + 4] = MQTT_DIR_SLASH;

    while (FTNone != dir_entry.type)
    {
        MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 4 + 1), 0, 6);
        if (FTFile == dir_entry.type)
        {
            MOC_MEMSET((void *)(pElements[i].strPacketId), 0, 6);
            status = MOC_MEMCPY (
                pCtx->pFilename + pCtx->filePrefixLen + 4 + 1, dir_entry.pName, dir_entry.nameLength);
            if (OK != status)
                goto exit;

            if (FALSE == FMGMT_pathExists(pCtx->pFilename, &f))
            {
                /* Do not fatal error on malformed or missing entries, send everything we can */
                fstatus = ERR_FILE;
                continue;
            }

            status = MOC_MEMCPY (
                pElements[i].strPacketId, dir_entry.pName, dir_entry.nameLength);
            if (OK != status)
                goto exit;

            pElements[i].timeStamp = f.modifyTime;
            i++;
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;

        
    }

    FMGMT_closeDir (&dir_list);

    RTOS_mutexRelease(pCtx->pMutex);
    locked = FALSE;

    /* Sort the array by timestamp */
    status = SORT_shellSort (
        (void *)pElements, sizeof(ResendPersistElem), 0, fileCount - 1, MQTT_persistElemCompare);
    if (OK != status)
        goto exit;


    /* Loop through elements to resend */
    for (i = 0; i < fileCount; i++)
    {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            status = MOC_CALLOC((void **)&pElements[i].pMsg, 1, sizeof(MqttMessage));
            if (OK != status)
                goto exit;
            pCurrentMsg = pElements[i].pMsg;
        }
        else
#endif
        {
            pElements[i].pMsg = NULL;
            pCurrentMsg = &msg;
        }

        status = RTOS_mutexWait(pCtx->pMutex);
        if (OK != status)
            goto exit;

        locked = TRUE;

        /* Construct the filename */
        MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 4 + 1), 0, 6);
        status = MOC_MEMCPY (
            pCtx->pFilename + pCtx->filePrefixLen + 4 + 1, pElements[i].strPacketId, MOC_STRLEN(pElements[i].strPacketId));
        if (OK != status)
            goto exit;

        /* Read the file data, containing a raw PUBLISH or PUBREL */
        status = FMGMT_fopen(pCtx->pFilename, "r", &pFile);
        if (OK != status)
        {
            /* Do not fatal error on malformed or missing entries, send everything we can */
            fstatus = ERR_FILE;
            continue;
        }

        FMGMT_fseek (pFile, 0, MSEEK_END);
        FMGMT_ftell (pFile, &fileSize);
        FMGMT_fseek (pFile, 0, MSEEK_SET);

        if (NULL != pByteValue)
        {
            MOC_FREE((void **)&pByteValue);
        }

        status = MOC_CALLOC((void **)&pByteValue, 1, fileSize);
        if (OK != status)
            goto exit;

        status = FMGMT_fread(pByteValue, 1, fileSize, pFile, &bytesRead);
        if (OK != status)
        {
            /* Do not fatal error on malformed or missing entries, send everything we can */
            fstatus = ERR_FILE;
            continue;
        }

        FMGMT_fclose(&pFile);
        RTOS_mutexRelease(pCtx->pMutex);
        locked = FALSE;

        /* Determine packet type by looking right at packet type byte in message */
        if (0x30 == ((*(pByteValue + offset)) & 0x30))
        {
            pCurrentMsg->type = MQTT_PUBLISH;

            /* MQTTv5 spec 3.3.1.1
             * The DUP flag MUST be set to 1 by the Client or Server when it attempts 
             * to re-deliver a PUBLISH packet */
            (*(pByteValue + offset)) = (*(pByteValue + offset)) | 0x08;
        }
        else
        {
            /* This list only contains publishes and pubrels */
            pCurrentMsg->type = MQTT_PUBREL;
        }

        /* Set up the message structure */
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            /* async will need a copy of the data */
            status = MOC_MALLOC_MEMCPY (
                (void **)&pCurrentMsg->pData, fileSize,
                 pByteValue, fileSize);
            if (OK != status)
                goto exit;
        }
        else
#endif
        {
            pCurrentMsg->pData = pByteValue;
        }
        pCurrentMsg->dataLen = fileSize;

        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "Resending ");
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)((pCurrentMsg->type == MQTT_PUBLISH) ? "PUBLISH" : "PUBREL"));
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, " with packetid: ");
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, pElements[i].strPacketId);
        DEBUG_PRINTNL(DEBUG_MQTT_TRANSPORT, (sbyte *)"");

        status = MQTT_processPacket(
            pCtx->connInst, pCtx, &pCurrentMsg,
            pCtx->keepAliveThreadActive);
        if (OK != status)
            goto exit;
    }



exit:

    if (NULL != pFile)
    {
        FMGMT_fclose(&pFile);
    }
    
    if (NULL != pByteValue)
    {
        MOC_FREE((void **)&pByteValue);
    }

    if (NULL != pElements)
    {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            for (i = 0; i < fileCount; i++)
            {
                if (NULL != pElements[i].pMsg)
                {
                    MQTT_freeMsg(&pElements[i].pMsg);
                }
            }
        }
#endif

        MOC_FREE((void **)&pElements);
    }

    if (NULL != dir_list)
        FMGMT_closeDir (&dir_list);
    
    if (TRUE == locked)
    {
        RTOS_mutexRelease(pCtx->pMutex);
    }
    
    if (OK != status)
        return status;

    return fstatus;
}

MSTATUS MQTT_timeoutStoredPublishesPersist(MqttCtx *pCtx)
{
    MSTATUS status, fstatus;
    DirectoryDescriptor dir_list = NULL;
    FileDescriptorInfo f = {0};
    DirectoryEntry dir_entry;
    byteBoolean locked = FALSE;
    moctime_t timeStamp = {0};
    ubyte4 packetId = 0;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    locked = TRUE;
    fstatus = OK;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-out", 4);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 4] = MQTT_DIR_SLASH;

    /* Count how many files we have */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);

    /* If we cant open the dir, assume it does not exist and thus no publishes to timeout */
    if (OK != status)
    {
        status = OK;
        goto exit;
    }

    while (FTNone != dir_entry.type)
    {
        if (FTFile == dir_entry.type)
        {
            status = MOC_MEMCPY (
                pCtx->pFilename + pCtx->filePrefixLen + 4 + 1, dir_entry.pName, dir_entry.nameLength);
            if (OK != status)
                goto exit;

            if (FALSE == FMGMT_pathExists(pCtx->pFilename, &f))
            {
                /* Do not fatal error on malformed or missing entries, send everything we can */
                fstatus = ERR_FILE;
                continue;
            }

            RTOS_deltaMS(NULL, &timeStamp);

            /* Modify time is in seconds since epoch, no way currently to convert seconds since epoch to
             * a moctime_t reliably, so we have no choice but to make assumption on contents of moctime_t */
            if ((timeStamp.u.time[0] - f.modifyTime) > pCtx->publishTimeoutSeconds)
            {
                packetId = MOC_ATOL(dir_entry.pName, NULL);

                /* markacked will also try for the file buffer mutex, prevent recursive lock */
                if (TRUE == locked)
                {
                    RTOS_mutexRelease(pCtx->pMutex);
                    locked = FALSE;
                }
                
                /* Not catching status intentional, nothing to be done if it fails */
                MQTT_markAcked(pCtx, packetId);

                if (FALSE == locked)
                {
                    status = RTOS_mutexWait(pCtx->pMutex);
                    if (OK != status)
                        goto exit;

                    locked = TRUE;
                }
            }
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != dir_list)
        FMGMT_closeDir (&dir_list);
    
    if (TRUE == locked)
    {
        RTOS_mutexRelease(pCtx->pMutex);
    }

    if (OK != status)
        return status;

    return fstatus;
}

#endif /* if defined(__MQTT_ENABLE_FILE_PERSIST__) */

typedef struct {
    ubyte2 packetId;
    moctime_t timeStamp;
    ubyte4 hashVal;
    ubyte *pValue;
    MqttMessage *pMsg;
} ResendElem;

static MSTATUS MQTT_elemCompare(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess)
{
    ResendElem *pFirst = (ResendElem *)pFirstItem;
    ResendElem *pSecond = (ResendElem *)pSecondItem;

    *pRetIsLess = (-1 == RTOS_timeCompare(&(pFirst->timeStamp), &(pSecond->timeStamp))) ? TRUE : FALSE;

    return OK;
}

MSTATUS MQTT_resendUnackedPackets(MqttCtx *pCtx)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashVal = 0;
    ubyte *pValue = NULL;
    ubyte *pByteValue = NULL;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    intBoolean found = FALSE;
    ResendElem *pElements = NULL;
    MqttMessage msg = {0};
    MqttMessage *pCurrentMsg = NULL;
    ubyte4 offset = 0;
    ubyte4 len = 0;
    ubyte numBytesUsed = 0;

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    pValue = NULL;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_resendUnackedPacketsPersist(pCtx);
    }
#endif

    /* If list is empty thats OK, just means we have no unacked packets */
    if ( (NULL == pWrapper) || (NULL == pWrapper->pHead) )
    {
        status = OK;
        goto exit;
    }

    /* Allocate list of elements containing information needed to resend packets. */
    status = MOC_CALLOC((void **)&pElements, pWrapper->numElements, sizeof(ResendElem));
    if (OK != status)
        goto exit;

    /* Loop through the list of packet ids that are unacked PUBLISH/PUBREL */
    pNode = pWrapper->pHead;
    while(NULL != pNode)
    {
        pValue = NULL;
        found = FALSE;

        /* Build an array of elements containing the packetid, hashval, timestamp, and packet */
        status = MQTT_computeHashKey(pCtx, pNode->packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;

        if (FALSE == found)
        {
            /* We should never have a mismatch between packetid list and hash table values */
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        status = MQTT_decodeVariableByteInt(pValue, 4, &len, &numBytesUsed);
        if (OK != status)
            goto exit;

        if (len < 8)
        {
            /* Not even enough room for the timestamp, entry is malformed */
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        pElements[i].hashVal = hashVal;
        pElements[i].packetId = pNode->packetId;
        pElements[i].pValue = pValue;
        pElements[i].timeStamp.u.time[0] = (ubyte4)MOC_NTOHL(pValue + numBytesUsed);
        pElements[i].timeStamp.u.time[1] = (ubyte4)MOC_NTOHL(pValue + numBytesUsed + 4);

        i++;
        pNode = pNode->pNext;
    }

    /* Sort the array by timestamp */
    status = SORT_shellSort (
        (void *)pElements, sizeof(ResendElem), 0, pWrapper->numElements - 1, MQTT_elemCompare);
    if (OK != status)
        goto exit;

    /* Loop through the sorted list and resend all packets. Ordering by timestamp guarantees
     * we will be compliant with ordering constraints laid out in MQTTv5 spec 4.6 */
    for (i = 0; i < pWrapper->numElements; i++)
    {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            status = MOC_CALLOC((void **)&pElements[i].pMsg, 1, sizeof(MqttMessage));
            if (OK != status)
                goto exit;
            pCurrentMsg = pElements[i].pMsg;
        }
        else
#endif
        {
            pElements[i].pMsg = NULL;
            pCurrentMsg = &msg;
        }
        
        /* Determine packet length */
        status = MQTT_decodeVariableByteInt(pElements[i].pValue, 4, &len, &numBytesUsed);
        if (OK != status)
            goto exit;

        offset = numBytesUsed + 8;
        pByteValue = (ubyte *)pElements[i].pValue;

        /* Determine packet type by looking right at packet type byte in message */
        if (0x30 == ((*(pByteValue + offset)) & 0x30))
        {
            pCurrentMsg->type = MQTT_PUBLISH;

            /* MQTTv5 spec 3.3.1.1
             * The DUP flag MUST be set to 1 by the Client or Server when it attempts 
             * to re-deliver a PUBLISH packet */
            (*(pByteValue + offset)) = (*(pByteValue + offset)) | 0x08;
        }
        else
        {
            /* This list only contains publishes and pubrels */
            pCurrentMsg->type = MQTT_PUBREL;
        }

        /* Set up the message structure, setting pointer and len based on 
         * value format (len || timestamp || message) */
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            /* async will need a copy of the data */
            status = MOC_MALLOC_MEMCPY (
                (void **)&pCurrentMsg->pData, len - 8,
                 pByteValue + offset, len - 8);
            if (OK != status)
                goto exit;
        }
        else
#endif
        {
            pCurrentMsg->pData = pByteValue + offset;
        }
        pCurrentMsg->dataLen = len - 8;

        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, "Resending ");
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, (sbyte *)((pCurrentMsg->type == MQTT_PUBLISH) ? "PUBLISH" : "PUBREL"));
        DEBUG_PRINT(DEBUG_MQTT_TRANSPORT, " with packetid: ");
        DEBUG_INT(DEBUG_MQTT_TRANSPORT, pElements[i].packetId);
        DEBUG_PRINTNL(DEBUG_MQTT_TRANSPORT, (sbyte *)"");

        status = MQTT_processPacket(
            pCtx->connInst, pCtx, &pCurrentMsg,
            pCtx->keepAliveThreadActive);
        if (OK != status)
            goto exit;
    }

exit:

    if (NULL != pElements)
    {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (MQTT_IS_ASYNC(pCtx))
        {
            for (i = 0; i < pWrapper->numElements; i++)
            {
                if (NULL != pElements[i].pMsg)
                {
                    MQTT_freeMsg(&pElements[i].pMsg);
                }
            }
        }
#endif

        MOC_FREE((void **)&pElements);
    }

    return status;
}

byteBoolean MQTT_hasUnackedPackets(MqttCtx *pCtx)
{
    MqttPacketListWrapper *pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;

    if (NULL == pWrapper)
    {
        return 0;
    }

    if (pWrapper->numElements > 0)
    {
        return 1;
    }

    return 0;
}

MSTATUS MQTT_timeoutStoredPublishes(MqttCtx *pCtx)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    ubyte *pValue = NULL;
    ubyte4 len = 0;
    ubyte numBytesUsed = 0;
    moctime_t timeStamp = {0};
    ubyte4 packetId = 0;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_timeoutStoredPublishesPersist(pCtx);
    }
#endif

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;

    if (NULL == pWrapper)
    {
        status = OK;
        goto exit;
    }

    /* Loop through the list of packet ids that are unacked PUBLISH/PUBREL */
    pNode = pWrapper->pHead;
    while(NULL != pNode)
    {
        pValue = NULL;
        found = FALSE;

        status = MQTT_computeHashKey(pCtx, pNode->packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;

        if (FALSE == found)
        {
            /* We should never have a mismatch between packetid list and hash table values */
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        status = MQTT_decodeVariableByteInt(pValue, 4, &len, &numBytesUsed);
        if (OK != status)
            goto exit;

        if (len < 8)
        {
            /* Not even enough room for the timestamp, entry is malformed */
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        timeStamp.u.time[0] = (ubyte4)MOC_NTOHL(pValue + numBytesUsed);
        timeStamp.u.time[1] = (ubyte4)MOC_NTOHL(pValue + numBytesUsed + 4);

        /* If we call markAcked, pNode will be freed so get the next element now */
        packetId = pNode->packetId;
        pNode = pNode->pNext;        

        /* All existing time delta APIs are ubyte4 ms based so we will use ms for comparison */
        if (RTOS_deltaMS(&timeStamp, NULL) > (pCtx->publishTimeoutSeconds * 1000))
        {
            MQTT_markAcked(pCtx, packetId);
        }
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_TEST__)

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/
/* BEGIN TEST-BUILD ONLY INTERNAL VERIFICATION FUNCTIONS */
/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
MSTATUS MQTT_verifyOutboundEmptyPersist(MqttCtx *pCtx)
{
    MSTATUS status;
    DirectoryDescriptor dir_list = NULL;
    DirectoryEntry dir_entry;
    byteBoolean locked = FALSE;
    ubyte4 packetId = 0;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    locked = TRUE;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-out", 4);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 4] = MQTT_DIR_SLASH;

    /* Count how many files we have */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);

    /* If we cant open the dir, it is empty */
    if (OK != status)
    {
        status = OK;
        goto exit;
    }

    while (FTNone != dir_entry.type)
    {
        /* We are verifying that the outbound is empty, there should be no files */
        if (FTFile == dir_entry.type)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;
    }

    status = OK;

exit:
    if (NULL != dir_list)
        FMGMT_closeDir (&dir_list);
    
    if (TRUE == locked)
    {
        RTOS_mutexRelease(pCtx->pMutex);
    }

    return status;
}
#endif

MSTATUS MQTT_verifyOutboundEmpty(sbyte4 connectionInstance)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    void *pValue = NULL;
    ubyte4 packetId = 0;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_verifyOutboundEmptyPersist(pCtx);
    }
#endif

    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    if ( (NULL != pWrapper) && (0 != pWrapper->numElements) )
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* Loop through all possible packet ids and verify the hash table does not
     * contain any of those entries */
    while(packetId < 0xFFFF)
    {
        pValue = NULL;
        found = FALSE;

        status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;

        if (TRUE == found)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        packetId++;
    }

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

typedef struct
{
    ubyte2 packetId;
    ubyte packetType;
} ExpectOutboundElem;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
MSTATUS MQTT_expectOutboundPersist(MqttCtx *pCtx, ExpectOutboundElem *pElems, ubyte4 numElems)
{
    MSTATUS status;
    DirectoryDescriptor dir_list = NULL;
    DirectoryEntry dir_entry;
    byteBoolean locked = FALSE;
    ubyte4 packetId = 0;
    ubyte4 i = 0;
    ubyte *pMarked = NULL;
    ubyte4 fileSize = 0;
    ubyte4 bytesRead = 0;
    ubyte4 offset = 0;
    ubyte4 len = 0;
    ubyte numBytesUsed = 0;
    ResendPersistElem *pElements = NULL;
    FileDescriptor pFile = NULL;
    ubyte *pByteValue = NULL;
    ubyte markedThisRound = FALSE;
    FileDescriptorInfo f = {0};

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    locked = TRUE;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    status = MOC_CALLOC((void **)&pMarked, numElems, sizeof(ubyte));
    if (OK != status)
        goto exit;

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-out", 4);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 4] = MQTT_DIR_SLASH;

    /* Count how many files we have */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);

    /* If we cant open the dir, it is empty */
    if (OK != status)
    {
        status = OK;
        goto exit;
    }

    while (FTNone != dir_entry.type)
    {
        if (FTFile == dir_entry.type)
        {
            markedThisRound = FALSE;

            status = MOC_MEMCPY (
                pCtx->pFilename + pCtx->filePrefixLen + 4 + 1, dir_entry.pName, dir_entry.nameLength);
            if (OK != status)
                goto exit;

            packetId = MOC_ATOL(dir_entry.pName, NULL);

            for (i = 0; i < numElems; i++)
            {
                /* If we have not already found this entry */
                if (0 == pMarked[i])
                {
                    /* If this is the entry we are looking for */
                    if (pElems[i].packetId == packetId)
                    {
                        /* mark it as found */
                        pMarked[i] = 1;
                        markedThisRound = TRUE;
                    }
                }
            }

            /* It is an error to not mark for a round, means we found a packet we did not expect */
            if (FALSE == markedThisRound)
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }

            if (FALSE == FMGMT_pathExists(pCtx->pFilename, &f))
            {
                /* We expect to find exactly what was specified */
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }

            /* Read the file data, containing a raw PUBLISH or PUBREL */
            status = FMGMT_fopen(pCtx->pFilename, "r", &pFile);
            if (OK != status)
            {
                status = ERR_FILE;
                continue;
            }

            FMGMT_fseek (pFile, 0, MSEEK_END);
            FMGMT_ftell (pFile, &fileSize);
            FMGMT_fseek (pFile, 0, MSEEK_SET);

            if (NULL != pByteValue)
            {
                MOC_FREE((void **)&pByteValue);
            }

            status = MOC_CALLOC((void **)&pByteValue, 1, fileSize);
            if (OK != status)
                goto exit;

            status = FMGMT_fread(pByteValue, 1, fileSize, pFile, &bytesRead);
            if (OK != status)
            {
                status = ERR_FILE;
                continue;
            }

            FMGMT_fclose(&pFile);

            if (MQTT_PUBLISH == pElems[i].packetType)
            {
                if (0x30 != ((*(pByteValue)) & 0x30))
                {
                    status = ERR_INTERNAL_ERROR;
                    goto exit;
                }
            }
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;
    }

    /* It is an error to not find all packets expected */
    for (i = 0; i < numElems; i++)
    {
        if (0 == pMarked[i])
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }
    }

    status = OK;

exit:
    if (NULL != dir_list)
        FMGMT_closeDir (&dir_list);
    if (NULL != pByteValue)
    {
        MOC_FREE((void **)&pByteValue);
    }
    if (NULL != pMarked)
    {
        MOC_FREE((void **)&pMarked);
    }
    
    if (TRUE == locked)
    {
        RTOS_mutexRelease(pCtx->pMutex);
    }

    return status;
}
#endif

MSTATUS MQTT_expectOutbound(sbyte4 connectionInstance, ExpectOutboundElem *pElems, ubyte4 numElems)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttPacketList *pNode = NULL;
    MqttPacketListWrapper *pWrapper = NULL;
    void *pValue = NULL;
    ubyte *pByteValue = NULL;
    ubyte4 packetId = 0;
    ubyte4 len = 0;
    ubyte numBytesUsed = 0;
    ubyte4 offset = 0;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_expectOutboundPersist(pCtx, pElems, numElems);
    }
#endif

    /* The number of expected elements and the length of the packet id list must match */
    pWrapper = (MqttPacketListWrapper *)pCtx->pPacketIdList;
    if ( (NULL == pWrapper) || (numElems != pWrapper->numElements) )
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    for (i = 0; i < numElems; i++)
    {
        pValue = NULL;
        found = FALSE;

        status = MQTT_computeHashKey(pCtx, pElems[i].packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;

        if (FALSE == found)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        /* Determine packet length */
        status = MQTT_decodeVariableByteInt(pValue, 4, &len, &numBytesUsed);
        if (OK != status)
            goto exit;

        offset = numBytesUsed + 8;
        pByteValue = (ubyte *)pValue;

        /* Verify packet type */
        if (MQTT_PUBLISH == pElems[i].packetType)
        {
            if (0x30 != ((*(pByteValue + offset)) & 0x30))
            {
                status = ERR_INTERNAL_ERROR;
                goto exit;
            }
        }
    }

    /* Verify that no other packets with other ids exist in the global list */
    packetId = 0;
    while(packetId < 0xFFFF)
    {
        pValue = NULL;
        found = FALSE;
        for (i = 0; i < numElems; i++)
        {
            if (packetId == pElems[i].packetId)
            {
                /* Dont look at packets that we expected to find */
                packetId++;
                continue;
            }
        }

        status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;
        
        /* We should never find anything else */
        if (TRUE == found)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        packetId++;
    }

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/
#if defined(__MQTT_ENABLE_FILE_PERSIST__)
MSTATUS MQTT_verifyInboundEmptyPersist(MqttCtx *pCtx)
{
    MSTATUS status;
    DirectoryDescriptor dir_list = NULL;
    DirectoryEntry dir_entry;
    byteBoolean locked = FALSE;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    locked = TRUE;

    if (NULL == pCtx->pFilename)
    {
        status = MQTT_initFilenameBuffer(pCtx);
        if (OK != status)
            goto exit;
    }

    MOC_MEMSET((void *)(pCtx->pFilename + pCtx->filePrefixLen + 1), 0, 4 + 1 + 6);

    status = MOC_MEMCPY (
        pCtx->pFilename + pCtx->filePrefixLen, "-in", 3);
    if (OK != status)
        goto exit;

    pCtx->pFilename[pCtx->filePrefixLen + 3] = MQTT_DIR_SLASH;

    /* Count how many files we have */
    status = FMGMT_getFirstFile (pCtx->pFilename, &dir_list, &dir_entry);

    /* If we cant open the dir, it is empty */
    if (OK != status)
    {
        status = OK;
        goto exit;
    }

    while (FTNone != dir_entry.type)
    {
        /* We are verifying that the inbound is empty, there should be no files */
        if (FTFile == dir_entry.type)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        status = FMGMT_getNextFile (dir_list, &dir_entry);
        if (OK != status)
            goto exit;
    }

    status = OK;

exit:
    if (NULL != dir_list)
        FMGMT_closeDir (&dir_list);
    
    if (TRUE == locked)
    {
        RTOS_mutexRelease(pCtx->pMutex);
    }

    return status;
}
#endif

MSTATUS MQTT_verifyInboundEmpty(sbyte4 connectionInstance)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    void *pValue = NULL;
    ubyte4 packetId = 0;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__MQTT_ENABLE_FILE_PERSIST__)
    if (MQTT_PERSIST_MODE_FILE == pCtx->persistMode)
    {
        return MQTT_verifyInboundEmptyPersist(pCtx);
    }
#endif

    /* Loop through all possible packet ids and verify the hash table does not
     * contain any of those entries */
    while(packetId < 0xFFFF)
    {
        pValue = NULL;
        found = FALSE;

        status = MQTT_computeHashKey(pCtx, packetId, &hashVal);
        if (OK != status)
            goto exit;

        status = HASH_TABLE_findPtr (
            gpMqttInboundPublishHashTable, hashVal, NULL, NULL, (void **)&pValue, &found);
        if (OK != status)
            goto exit;

        if (TRUE == found)
        {
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        packetId++;
    }

    status = OK;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

#endif /* if defined(__ENABLE_MQTT_TEST__) */

#endif /* ifdef __ENABLE_MQTT_CLIENT__ */
