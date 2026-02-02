/*
 * smp_pkcs11_api.c
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
 * @file       smp_pkcs11_api.c
 * @brief      NanoSMP module feature API definitions for PKCS11.
 * @details    This C file contains feature function
               definitions implemented by the PKCS11 NanoSMP.
 */

#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_PKCS11__))
#include "smp_pkcs11_api.h"
#include "smp_pkcs11.h"


#ifdef __ENABLE_DIGICERT_SMP_PKCS11_FULLCMC__
#define __ENABLE_DIGICERT_TPM2__
#include "../smp_tpm2/tpm2_lib/tpm2_types.h"
#include "../smp_tpm2/tpm2_lib/sapi2/sapi2_serialize.h"
#include "../smp_tpm2/tpm2_lib/sapi2/sapi2_utils.h"
#endif
#include "../../common/base64.h"
#include "../../crypto/aesalgo.h"
#include "../../crypto/aes.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/crypto_interface_sha1.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto_interface/crypto_interface_sha512.h"
#endif
#include "../../tap/tap_base_serialize.h"
#include "../../tap/tap_serialize_smp.h"
#include "../../tap/tap_utils.h"

#ifdef PKCS11_PROFILING
#include <sys/time.h>
struct timezone tz;
struct timeval startTv;
struct timeval endTv;
unsigned long long diffTime;
double diffTimeInSec, diffSzInMb;
#endif

#if !(defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
#define DB_PRINT(...)
#endif

/* Global Mutex for protecting pkcs11 modules */
RTOS_MUTEX gGemMutex = NULL;
/* Global required to store all the pkcs11 modules in the system */
Pkcs11_ModuleList* gModListHead = NULL;
Pkcs11_Config* gConfig = NULL;
/*NIST curves OID's*/
const ubyte eccOid192[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01};
const ubyte eccOid224[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21};
const ubyte eccOid256[] = {0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
const ubyte eccOid384[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22};
const ubyte eccOid521[] = {0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23};

const sbyte iniFile[] = "/etc/IDGo800/Pkcs11.PKCS11.ini";

#define MOC_SMP_PKCS11_RT_CERT  "/etc/mocana/moc_pkcs11_root_cert.der"
#define MOC_SMP_PKCS11_RT_KEY   "/etc/mocana/moc_pkcs11_root_key"
#define MAX_SYM_BLOCK_SIZE (16)
#define AES_BLOCK_SIZE     (16)
#define DES_BLOCK_SIZE     (8)
#define THREE_DES_BLOCK_SIZE     (8)
#define SHA256_OID_LEN     19

#define RAW_KEY_MAX_LEN 4096

#define CKM_AES  "CKM_AES"
#define CKM_DES  "CKM_DES"
#define CKM_DES3 "CKM_DES3"

#define CBC      "CBC"
#define ECB      "ECB"
#define CTR      "CTR"
#define CBC_PAD  "CBC_PAD"
#define OFB      "OFB"
#define CFB128   "CFB128"
#define GCM      "GCM"

typedef struct _P11SymAlgorithm
{
    ubyte *pAlg;
    CK_ULONG p11AlgId;
}P11SymAlgorithm;

P11SymAlgorithm gSymAlgTable[] =
{
    {(ubyte*)"CKM_AES_CBC",      CKM_AES_CBC},
    {(ubyte*)"CKM_AES_CBC_PAD",  CKM_AES_CBC_PAD},
    {(ubyte*)"CKM_AES_ECB",      CKM_AES_ECB},
    {(ubyte*)"CKM_AES_CTR",      CKM_AES_CTR},
    {(ubyte*)"CKM_AES_GCM",      CKM_AES_GCM},
    {(ubyte*)"CKM_AES_OFB",      CKM_AES_OFB},
    {(ubyte*)"CKM_AES_CFB128",   CKM_AES_CFB128},
    {(ubyte*)"CKM_DES_CBC",      CKM_DES_CBC},
    {(ubyte*)"CKM_DES_CBC_PAD",  CKM_DES_CBC_PAD},
    {(ubyte*)"CKM_DES_ECB",      CKM_DES_ECB},
    {(ubyte*)"CKM_DES3_CBC",     CKM_DES3_CBC},
    {(ubyte*)"CKM_DES3_CBC_PAD", CKM_DES3_CBC_PAD},
    {(ubyte*)"CKM_DES3_ECB",     CKM_DES3_ECB},
};



#define INSERT_ATTRIBUTE(attribute, attr_type, value, length) \
                           { \
                             (attribute).type=(attr_type); \
                             (attribute).pValue=(value);   \
                             (attribute).ulValueLen=length;\
                           }

static void copyBufferIdToUlong(TAP_ObjectId *pDest, TAP_Buffer src)
{
    ubyte4 i = 0;

    /* caller will make sure input is not null */
    *pDest = 0;

    /* not enough space? return with it set to 0 */
    if (src.bufferLen > sizeof(TAP_ObjectId))
        return;

    /* treat buffer as Little Endian */
    for (i = 0; i < src.bufferLen; i++)
    {
        *pDest += ( ((TAP_ObjectId) (src.pBuffer[i])) << (8*i) );
    }
}

/* always makes the buffer the sizeof(src) in bytes. Zero pads high end */
static MSTATUS copyUlongIdToBuffer(TAP_Buffer *pDest, TAP_ObjectId src)
{
    MSTATUS status = OK;
    ubyte4 j = 0;
    
    /* clear old id if there is one */
    if (NULL != pDest->pBuffer)
    {
        status = DIGI_MEMSET_FREE(&pDest->pBuffer, pDest->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free memory. status=%d\n",
                __FUNCTION__, __LINE__, status);
                goto exit;
        }
        pDest->bufferLen = 0;
    }
    
    status = DIGI_CALLOC((void **) &pDest->pBuffer, 1, sizeof(TAP_ObjectId));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
            __FUNCTION__, __LINE__, status);
            goto exit;
    }

    for (j = 0; j < sizeof(TAP_ObjectId); j++)
    {
        pDest->pBuffer[j] = (ubyte) ((src >> (j*8)) & (TAP_ObjectId) 0xff);
    }
    pDest->bufferLen = (ubyte4) sizeof(TAP_ObjectId);

exit:

    return status;
}

/*------------------------------------------------------------------*/
   /* Static function declarations*/
/*------------------------------------------------------------------*/
#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
static MSTATUS
PKCS11_verifyInit(Pkcs11_Module *pGemModule,
                   Pkcs11_Token *pGemToken,
                   Pkcs11_Object *pGemObject,
                   TAP_MechanismAttributes *pMechanism);
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
static MSTATUS
PKCS11_signInit(Pkcs11_Module *pGemModule,
                 Pkcs11_Token *pGemToken,
                 Pkcs11_Object *pGemObject,
                 TAP_SIG_SCHEME type);
#endif

/*------------------------------------------------------------------*/

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
MSTATUS SMP_API(PKCS11, getModuleList,
        TAP_ModuleCapabilityAttributes *pModuleAttributes,
        TAP_EntityList *pModuleIdList
)
{
    ubyte4 i = 0;
    ubyte4 modCount = 0;
    MSTATUS status = OK;
    Pkcs11_ModuleList* pModList = NULL;
    byteBoolean isMutexLocked = FALSE;

    MOC_UNUSED(pModuleAttributes);
    
    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if (NULL == pModuleIdList)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pModuleIdList = %p\n",
                __FUNCTION__, __LINE__, pModuleIdList);
        goto exit;
    }

    /* If list doesn't exists, create one */
    if (NULL == gModListHead)
    {
        if (OK != (status = PKCS11_createModuleList(NULL)))
        {
            DB_PRINT("%s.%d Failed to create module list. status:%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pModList = gModListHead;
        while (NULL != pModList)
        {
            if (pModList->moduleId != EMULATED_MODULE_ID)
            {
                PKCS11_parseIni(iniFile, pModList->labelStr);
            }
            pModList = pModList->pNext;
        }
    }

    pModList = gModListHead;
    while (NULL != pModList)
    {
        modCount++;
        pModList = pModList->pNext;
    }

    /* Return the module list output */
    pModuleIdList->entityType = TAP_ENTITY_TYPE_MODULE;
    pModuleIdList->entityIdList.numEntities = modCount;
    pModuleIdList->entityIdList.pEntityIdList = MALLOC(sizeof(TAP_EntityId) * modCount);
    if (NULL == pModuleIdList->entityIdList.pEntityIdList)
    {
        status = ERR_MEM_ALLOC_FAIL;
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                 __FUNCTION__, __LINE__,status);
        goto exit;
    }

    pModList = gModListHead;
    for (i=0; i<modCount; i++)
    {
        pModuleIdList->entityIdList.pEntityIdList[i] = pModList->moduleId;
        pModList = pModList->pNext;
    }

exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
MSTATUS SMP_API(PKCS11, freeModuleList,
        TAP_EntityList *pModuleList

)
{
    if (NULL != pModuleList)
    {
        if (NULL != pModuleList->entityIdList.pEntityIdList)
        {
            FREE(pModuleList->entityIdList.pEntityIdList);
        }
    }

    return OK;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__
MSTATUS SMP_API(PKCS11, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
)
{
    ubyte4 i = 0;
    MSTATUS status = OK;
    Pkcs11_ModuleList* pModList = gModListHead;
    ubyte4 attrCount = 4;
    ubyte4 firmware_ver[2] = {0, 0};
    ubyte4 strLen = 0;
    ubyte4 algoCount = 0;
    const ubyte4 maxModuleAttr = 6;
    Pkcs11_Config *pModuleConfig = NULL;

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if (NULL == pModuleCapabilities)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL Pointer on inpue, pModuleCapabilities=%p status=%d\n",
                 __FUNCTION__, __LINE__, pModuleCapabilities, status);
        goto exit;
    }
    pModuleConfig = gConfig;
    while (pModuleConfig)
    {
        if (moduleId == pModuleConfig->moduleId)
            break;

        pModuleConfig = pModuleConfig->pNext;
    }
    if (!pModuleConfig)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Module configuration not found.\n",
                 __FUNCTION__, __LINE__);
        goto exit;
    }

    while ((NULL != pModList) && (pModList->moduleId != moduleId))
        pModList = pModList->pNext;

    if (NULL == pModList)
    {
        status = ERR_NOT_FOUND;
        DB_PRINT("%s.%d Module list not found. status=%d\n",
                 __FUNCTION__, __LINE__,status);
        goto exit;
    }

    if (EMULATED_MODULE_ID != moduleId)
    {
        if (NULL != pCapabilitySelectAttributes)
            attrCount =  PKCS11_supportedAttributesCount(pCapabilitySelectAttributes);
        else
            attrCount = maxModuleAttr;

        if (NULL == pModuleConfig->credentialFile.pBuffer || 0 == pModuleConfig->credentialFile.bufferLen)
        {
            attrCount--;
        }
        pModuleCapabilities->listLen = attrCount;

        if(0 == attrCount)
        {
            pModuleCapabilities->pAttributeList = NULL;
        }
        else
        {
            status = DIGI_CALLOC((void **) &pModuleCapabilities->pAttributeList, sizeof(TAP_Attribute), attrCount);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                        __FUNCTION__, __LINE__,status);
                goto exit;
            }

            if ((NULL == pCapabilitySelectAttributes) ||
                    (PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_TOKEN_TYPE)))
            {
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_TOKEN_TYPE;
                pModuleCapabilities->pAttributeList[i].length = sizeof(ubyte4);
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(ubyte4));
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                *((ubyte4 *)pModuleCapabilities->pAttributeList[i].pStructOfType) = TAP_TOKEN_TYPE_DEFAULT;
                i++;
            }
            if ((NULL == pCapabilitySelectAttributes) ||
                    (PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_FIRMWARE_VERSION)))
            {
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_FIRMWARE_VERSION;
                pModuleCapabilities->pAttributeList[i].length = sizeof(firmware_ver);
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(firmware_ver));
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                (void) DIGI_MEMCPY((void*)pModuleCapabilities->pAttributeList[i].pStructOfType, (void*)firmware_ver, sizeof(firmware_ver));
                i++;
            }
            if ((NULL == pCapabilitySelectAttributes) ||
                    (PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_TAP_PROVIDER)))
            {
                strLen = DIGI_STRLEN((const sbyte *)PROVIDER_NAME) + 1;
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_TAP_PROVIDER;
                pModuleCapabilities->pAttributeList[i].length = strLen;
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(strLen);
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory status:%d.\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                (void) DIGI_STRCBCPY((sbyte *)pModuleCapabilities->pAttributeList[i].pStructOfType, strLen, (const sbyte *)PROVIDER_NAME);
                i++;
            }
            if ((NULL == pCapabilitySelectAttributes) ||
                    (PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_KEY_ALGORITHM)))
            {
                status = PKCS11_supportedAlgorithm(pModList, NULL, pModList->phySlotId, &algoCount);
                if ((OK != status) || (!algoCount))
                    goto exit;
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_KEY_ALGORITHM;
                pModuleCapabilities->pAttributeList[i].length = sizeof(ubyte) * algoCount;
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(ubyte) * algoCount);
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                status = PKCS11_supportedAlgorithm(pModList, pModuleCapabilities->pAttributeList[i].pStructOfType, pModList->phySlotId, &algoCount);
                if (OK != status)
                {
                    FREE(pModuleCapabilities->pAttributeList[i].pStructOfType);
                }
                i++;
            }

            /* Only add TAP_ATTR_GET_MODULE_CREDENTIALS attribute if credential was provided */
            if ( NULL != pModuleConfig->credentialFile.pBuffer && 0 != pModuleConfig->credentialFile.bufferLen && 
                (NULL == pCapabilitySelectAttributes || PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_GET_MODULE_CREDENTIALS)))
            {
                ubyte *pBuffer = NULL;
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_GET_MODULE_CREDENTIALS;
                pModuleCapabilities->pAttributeList[i].length = sizeof(pModuleConfig->credentialFile);
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(pModuleConfig->credentialFile));
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                if (OK != (status = DIGI_CALLOC((void**)&pBuffer, 1, pModuleConfig->credentialFile.bufferLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                status = DIGI_MEMCPY(pBuffer,
                        pModuleConfig->credentialFile.pBuffer, pModuleConfig->credentialFile.bufferLen);
                if (OK != status)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to copy. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                ((TAP_Buffer*)(pModuleCapabilities->pAttributeList[i].pStructOfType))->pBuffer = pBuffer;
                ((TAP_Buffer*)(pModuleCapabilities->pAttributeList[i].pStructOfType))->bufferLen = pModuleConfig->credentialFile.bufferLen;
                i++;
            }
            if ((NULL == pCapabilitySelectAttributes) ||
                    (PKCS11_checkAttributesType(pCapabilitySelectAttributes, TAP_ATTR_MODULE_PROVISION_STATE)))
            {
                /* Assume provision state is TRUE at this point */
                TAP_MODULE_PROVISION_STATE provisionState = TRUE;
                pModuleCapabilities->pAttributeList[i].type = TAP_ATTR_MODULE_PROVISION_STATE;
                pModuleCapabilities->pAttributeList[i].length = sizeof(provisionState);
                pModuleCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(provisionState));
                if (NULL == pModuleCapabilities->pAttributeList[i].pStructOfType)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__,status);
                    goto exit;
                }
                (void) DIGI_MEMCPY((void*)pModuleCapabilities->pAttributeList[i].pStructOfType, (void*)&provisionState, sizeof(provisionState));
            }
        }
    }

exit:

    if (OK != status)
    {
        if (pModuleCapabilities && pModuleCapabilities->pAttributeList)
        {
            for (i=0; i<attrCount; i++)
            {
                if (pModuleCapabilities->pAttributeList[i].pStructOfType)
                    FREE(pModuleCapabilities->pAttributeList[i].pStructOfType);
            }

            FREE(pModuleCapabilities->pAttributeList);
        }
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_SLOTS__
MSTATUS SMP_API(PKCS11, getModuleSlots,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleSlotList *pModuleSlotList
)
{
    ubyte4 i = 0;
    MSTATUS status = OK;
    CK_ULONG count = 0;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pModuleSlotList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Null pointer on input, pGemModule=%p,"
                  "pModuleSlotList=%p, status=%d\n",
                  __FUNCTION__, __LINE__, pGemModule, pModuleSlotList,
                  status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    pModuleSlotList->numSlots = MAX_MODULE_SLOTS;
    pModuleSlotList->pSlotIdList = MALLOC(sizeof(TAP_EntityId) * pModuleSlotList->numSlots);
    if (NULL == pModuleSlotList->pSlotIdList)
    {
        DB_PRINT("%s.%d Failed to allocate memory.\n",
                 __FUNCTION__, __LINE__);
        goto exit;
    }
    /* Get number of slots in system */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_FALSE, NULL_PTR, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed in C_GetSlotList status=%d\n",
                 __FUNCTION__, __LINE__,status);
        goto exit;
    }

    if (OK != (status = DIGI_MALLOC((void**)&pSlotList, (ubyte4)count * sizeof(CK_SLOT_ID))))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                 __FUNCTION__,__LINE__,status);
        goto exit;
    }

    /* Now Get the complete slot list */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_FALSE, pSlotList, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed in C_GetSlotList. status=%d\n",
                 __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (0 == count)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d No slots found.\n",
                 __FUNCTION__,__LINE__);
        goto exit;
    }
    for (i=0; i < count; i++)
    {
        pModuleSlotList->pSlotIdList[i] = pSlotList[i];/*i + pGemModule->phySlotId;*/
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    if (NULL != pSlotList)
        DIGI_FREE((void**)&pSlotList);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
MSTATUS SMP_API(PKCS11, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes *pTokenAttributes,
        TAP_EntityList *pTokenIdList
)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    CK_ULONG count = 0;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_RV rVal = CKR_OK;
    ubyte4 i = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if ((0 == moduleHandle) || (NULL == pTokenIdList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pTokenIdList = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTokenIdList);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = ((Pkcs11_Module *)((uintptr) moduleHandle))->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* Attestation capability is not supported */
    if (pTokenAttributes && pTokenAttributes->listLen)
    {
        pAttribute = pTokenAttributes->pAttributeList;

        while (listCount < pTokenAttributes->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_CAPABILITY_CATEGORY:
                case TAP_ATTR_CAPABILITY_FUNCTIONALITY:
                    if ((sizeof(TAP_CAPABILITY_FUNCTIONALITY) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid capability structure length %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_CAPABILITY_FUNCTIONALITY *)pAttribute->pStructOfType))
                    {
                        case TAP_CAPABILITY_REMOTE_ATTESTATION:
                        case TAP_CAPABILITY_TRUSTED_DATA:
                        case TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA:
                        case TAP_CAPABILITY_KEY_STORAGE_ASYMMETRIC_KEY:
                        case TAP_CAPABILITY_KEY_STORAGE_SYMMETRIC_KEY:
                        case TAP_CAPABILITY_ATTESTATION_ANONYMOUS:
                        case TAP_CAPABILITY_RNG_SEED:
                        case TAP_CAPABILITY_TRUSTED_DATA_TIME:
                        case TAP_CAPABILITY_TRUSTED_DATA_MEASUREMENT:
                        case TAP_CAPABILITY_TRUSTED_DATA_IDENTITY:
                            {
                                status = ERR_INVALID_ARG;
                                DB_PRINT("%s.%d Token capability not supported\n",
                                        __FUNCTION__, __LINE__);
                                goto exit;
                            }
                            break;

                        default:
                            break;
                    }
                    break;

                case TAP_ATTR_KEY_USAGE:
                    if ((sizeof(TAP_KEY_USAGE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key-usage structure length %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    /* Get number of slots in system which has token present. */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, NULL_PTR, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed in C_GetSlotList. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_MALLOC((void**)&pSlotList, (ubyte4)count * sizeof(CK_SLOT_ID))))
    {
        DB_PRINT("%s.%d Failed to allocate Memory. status=%d\n",
                  __FUNCTION__,__LINE__,status);
        goto exit;
    }

    /* Now Get the complete slot list */
    rVal = CALL_PKCS11_API(C_GetSlotList, CK_TRUE, pSlotList, &count);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(NULL, rVal);
        DB_PRINT("%s.%d Failed in C_GetSlotList. status=%d\n",
                  __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (0 == count)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d No slots found.\n",
                  __FUNCTION__,__LINE__);
        goto exit;
    }

    pTokenIdList->entityType = TAP_ENTITY_TYPE_TOKEN;
    pTokenIdList->entityIdList.numEntities = (ubyte4)count;

    status = DIGI_CALLOC((void **)&(pTokenIdList->entityIdList.pEntityIdList),
            1, sizeof(*pTokenIdList->entityIdList.pEntityIdList) *
            pTokenIdList->entityIdList.numEntities);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Token list, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    for (i=0; i < pTokenIdList->entityIdList.numEntities; i++)
    {
        pTokenIdList->entityIdList.pEntityIdList[i] = pSlotList[i];
    }

exit:
    if (NULL != pSlotList)
        DIGI_FREE((void**)&pSlotList);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_INFO__
MSTATUS SMP_API(PKCS11, getTokenInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenId tokenId,
        TAP_TokenCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_TokenCapabilityAttributes  *pTokenCapabilities
)
{
    ubyte4 i = 0;
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    TAP_CAPABILITY_CATEGORY supportedCap[] =
        {TAP_CAPABILITY_RNG, TAP_CAPABILITY_CRYPTO_OP, TAP_CAPABILITY_KEY_STORAGE, TAP_CAPABILITY_SECURE_STORAGE};

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pTokenCapabilities))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Null pointer on input, pGemModule=%p,"
                 "pTokenCapabilities=%p\n", __FUNCTION__,__LINE__, pGemModule, pTokenCapabilities);
        goto exit;
    }

    pTokenCapabilities->listLen = MAX_CAP_SUPPORTED;
    pTokenCapabilities->pAttributeList = MALLOC(sizeof(TAP_Attribute) * MAX_CAP_SUPPORTED);
    if (NULL == pTokenCapabilities->pAttributeList)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        DB_PRINT("%s.%d Failed in memory allocation. status=%d\n",
                  __FUNCTION__,__LINE__,status);
        goto exit;
    }

    for (i=0; i<MAX_CAP_SUPPORTED; i++)
    {
        pTokenCapabilities->pAttributeList[i].type = TAP_ATTR_CAPABILITY_CATEGORY;
        pTokenCapabilities->pAttributeList[i].length = sizeof(TAP_CAPABILITY_CATEGORY);
        pTokenCapabilities->pAttributeList[i].pStructOfType = MALLOC(sizeof(TAP_CAPABILITY_CATEGORY));
        if (NULL == pTokenCapabilities->pAttributeList[i].pStructOfType)
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
            DB_PRINT("%s.%d Failed in memory allocation. status=%d\n",
                      __FUNCTION__,__LINE__,status);
            goto exit;
        }
        *(TAP_CAPABILITY_CATEGORY *)(pTokenCapabilities->pAttributeList[i].pStructOfType) = supportedCap[i];
    }

exit:

    if (OK != status)
    {
        if (pTokenCapabilities && pTokenCapabilities->pAttributeList)
        {
            for (i=0; i<MAX_CAP_SUPPORTED; i++)
            {
                if (pTokenCapabilities->pAttributeList[i].pStructOfType)
                    FREE(pTokenCapabilities->pAttributeList[i].pStructOfType);
            }

            FREE(pTokenCapabilities->pAttributeList);
        }
    }


    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_LIST__
MSTATUS SMP_API(PKCS11, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
)
{
        return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_INFO__
MSTATUS SMP_API(PKCS11, getObjectInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectCapabilityAttributes *pCapabiltySelectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectCapabilities
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);
    Pkcs11_Object* pObjList = NULL;

    CK_ULONG ulModulusBitSz = 0;
    ubyte eccOid[10] = {0};

    ubyte4 k = 0;
    ubyte4 attrCount = 0;
    sbyte4 result = 0;
    ubyte eccCurveType = 0;
    ubyte rsaKeySz = 0;

    CK_ATTRIBUTE modAttr = {CKA_MODULUS_BITS, &ulModulusBitSz, sizeof(ulModulusBitSz)};
    CK_ATTRIBUTE paramAttr = {CKA_EC_PARAMS, (CK_VOID_PTR)eccOid, sizeof(eccOid)};

    CK_KEY_TYPE keyType = 0;
    CK_ATTRIBUTE keyAttr = {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)};
    TAP_AttributeList* pCapAttr;
    TAP_AttributeList capAttr;
    TAP_Attribute eccAttr[] = {
            {TAP_ATTR_KEY_ALGORITHM, 0, NULL},
            {TAP_ATTR_CURVE, 0, NULL},
    };
    TAP_Attribute rsaAttr[] = {
            {TAP_ATTR_KEY_ALGORITHM, 0, NULL},
            {TAP_ATTR_KEY_SIZE, 0, NULL},
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        DB_PRINT("%s.%d Null pointer on input, pGemModule=%p,"
                 "pGemToken=%p, pGemObject=%p\n", __FUNCTION__,
                 __LINE__, pGemModule, pGemToken, pGemObject);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    pObjList = pGemObject;

    /* Get the Key Type (RSA/ECC)*/
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pObjList->pubObject, &keyAttr, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed in C_GetAttributeValue status=%d\n",
                 __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (NULL != pCapabiltySelectAttributes)
        pCapAttr = pCapabiltySelectAttributes;
    else
        pCapAttr = &capAttr;

    switch(keyType)
    {
        case CKK_EC:
            if (NULL == pCapabiltySelectAttributes)
            {
                capAttr.pAttributeList = eccAttr;
                capAttr.listLen= 2;
            }

            if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_ALGORITHM))
                attrCount++;

            if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_CURVE))
            {
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pObjList->pubObject, &paramAttr, 1);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    DB_PRINT("%s.%d Failed in C_GetAttributeValue status=%d\n",
                             __FUNCTION__,__LINE__,status);
                    goto exit;
                }
                attrCount++;

                DIGI_MEMCMP((const ubyte *)eccOid, (const ubyte *)eccOid192, sizeof(eccOid192), &result);
                if (OK == result)
                {
                    eccCurveType = TAP_ECC_CURVE_NIST_P192;
                    break;
                }

                DIGI_MEMCMP((const ubyte *)eccOid, (const ubyte *)eccOid224, sizeof(eccOid224), &result);
                if (OK == result)
                {
                    eccCurveType = TAP_ECC_CURVE_NIST_P224;
                    break;
                }

                DIGI_MEMCMP((const ubyte *)eccOid, (const ubyte *)eccOid256, sizeof(eccOid256), &result);
                if (OK == result)
                {
                    eccCurveType = TAP_ECC_CURVE_NIST_P256;
                    break;
                }

                DIGI_MEMCMP((const ubyte *)eccOid, (const ubyte *)eccOid384, sizeof(eccOid384), &result);
                if (OK == result)
                {
                    eccCurveType = TAP_ECC_CURVE_NIST_P384;
                    break;
                }

                DIGI_MEMCMP((const ubyte *)eccOid, (const ubyte *)eccOid521, sizeof(eccOid521), &result);
                if (OK == result)
                    eccCurveType = TAP_ECC_CURVE_NIST_P521;
            }
            break;

        case CKK_RSA :
            if (NULL == pCapabiltySelectAttributes)
            {
                capAttr.pAttributeList = rsaAttr;
                capAttr.listLen= 2;
            }

            if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_ALGORITHM))
                attrCount++;

            if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_SIZE))
            {
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pObjList->pubObject, &modAttr, 1);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    DB_PRINT("%s.%d Failed in C_GetAttributeValue status=%d\n",
                             __FUNCTION__,__LINE__,status);
                    goto exit;
                }

                attrCount++;

                switch(ulModulusBitSz)
                {
                    case 1024:
                        rsaKeySz = TAP_KEY_SIZE_1024;
                        break;

                    case 2048:
                        rsaKeySz = TAP_KEY_SIZE_2048;
                        break;

                    case 3072:
                        rsaKeySz = TAP_KEY_SIZE_3072;
                        break;

                    case 4096:
                        rsaKeySz = TAP_KEY_SIZE_4096;
                        break;
                }
                break;
            }
            break;

        default:
            break;
    }

    if (attrCount)
    {
        pObjectCapabilities->listLen = attrCount;
        pObjectCapabilities->pAttributeList = MALLOC(sizeof(TAP_Attribute) * attrCount);
        if (NULL == pObjectCapabilities->pAttributeList)
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
            DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                      __FUNCTION__,__LINE__,status);
            goto exit;
        }
        switch(keyType)
        {
            case CKK_EC:
                if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_ALGORITHM))
                {
                    pObjectCapabilities->pAttributeList[k].type = TAP_ATTR_KEY_ALGORITHM;
                    pObjectCapabilities->pAttributeList[k].length = sizeof(ubyte);
                    pObjectCapabilities->pAttributeList[k].pStructOfType = MALLOC(sizeof(ubyte));
                    if (NULL == pObjectCapabilities->pAttributeList[k].pStructOfType)
                    {
                        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                                __FUNCTION__,__LINE__,status);
                        goto exit;
                    }
                    *((ubyte *)pObjectCapabilities->pAttributeList[k].pStructOfType) = TAP_KEY_ALGORITHM_ECC;
                    k++;
                }

                if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_CURVE))
                {
                    pObjectCapabilities->pAttributeList[k].type = TAP_ATTR_CURVE;
                    pObjectCapabilities->pAttributeList[k].length = sizeof(ubyte);
                    pObjectCapabilities->pAttributeList[k].pStructOfType = MALLOC(sizeof(ubyte4));
                    if (NULL == pObjectCapabilities->pAttributeList[k].pStructOfType)
                    {
                        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                        goto exit;
                    }
                    *((ubyte *)pObjectCapabilities->pAttributeList[k].pStructOfType) = eccCurveType;
                    k++;
                }
                break;
            case CKK_RSA:
                if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_ALGORITHM))
                {
                    pObjectCapabilities->pAttributeList[k].type = TAP_ATTR_KEY_ALGORITHM;
                    pObjectCapabilities->pAttributeList[k].length = sizeof(ubyte);
                    pObjectCapabilities->pAttributeList[k].pStructOfType = MALLOC(sizeof(ubyte));
                    if (NULL == pObjectCapabilities->pAttributeList[k].pStructOfType)
                    {
                        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                        goto exit;
                    }
                    *((ubyte *)pObjectCapabilities->pAttributeList[k].pStructOfType) = TAP_KEY_ALGORITHM_RSA;
                    k++;
                }

                if (PKCS11_checkAttributesType(pCapAttr, TAP_ATTR_KEY_SIZE))
                {
                    pObjectCapabilities->pAttributeList[k].type = TAP_ATTR_KEY_SIZE;
                    pObjectCapabilities->pAttributeList[k].length = sizeof(ubyte);
                    pObjectCapabilities->pAttributeList[k].pStructOfType = MALLOC(sizeof(ubyte));
                    if (NULL == pObjectCapabilities->pAttributeList[k].pStructOfType)
                    {
                        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                        goto exit;
                    }
                    *((ubyte *)pObjectCapabilities->pAttributeList[k].pStructOfType) = rsaKeySz;
                    k++;
                }
                break;
        }
    }

exit:

    if (OK != status)
    {
        if (pObjectCapabilities->pAttributeList)
        {
            for (k=0; k<attrCount; k++)
            {
                if (pObjectCapabilities->pAttributeList[k].pStructOfType)
                    FREE(pObjectCapabilities->pAttributeList[k].pStructOfType);
            }

            FREE(pObjectCapabilities->pAttributeList);
        }
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_MODULE__
MSTATUS SMP_API(PKCS11, provisionModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes* pModuleProvisionAttributes
)
{
    ubyte4 pinLen = 0, newPinLen = 0;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_CHAR* pOrigPin = NULL;
    CK_CHAR* pNewPin = NULL;
    byteBoolean isLogin = FALSE;

    byteBoolean isMutexLocked = FALSE;
    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_EntityCredential* pEntityCred = NULL;
    TAP_Credential* pCredential = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pModuleProvisionAttributes))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    /* Fetch the SO Pin */
    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pModuleProvisionAttributes, TAP_ATTR_CREDENTIAL_USAGE, NULL);
    if (NULL != pCredentials)
    {
        pEntityCred = pCredentials->pEntityCredentials;
        pCredential = PKCS11_fetchCredentialFromList(&pEntityCred->credentialList,
                            TAP_CREDENTIAL_CONTEXT_OWNER);
        if (NULL != pCredential)
        {
            if ((NULL != pCredential->credentialData.pBuffer) && (SO_PIN_LEN == pCredential->credentialData.bufferLen))
            {
                pOrigPin = pCredential->credentialData.pBuffer;
                pinLen = pCredential->credentialData.bufferLen;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }

        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }


    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pModuleProvisionAttributes, TAP_ATTR_CREDENTIAL_SET, NULL);
    if (NULL != pCredentials)
    {
        pEntityCred = pCredentials->pEntityCredentials;
        pCredential = PKCS11_fetchCredentialFromList(&pEntityCred->credentialList,
                            TAP_CREDENTIAL_CONTEXT_OWNER);
        if (NULL != pCredential)
        {
            if ((NULL != pCredential->credentialData.pBuffer) && (SO_PIN_LEN == pCredential->credentialData.bufferLen))
            {
                pNewPin = pCredential->credentialData.pBuffer;
                newPinLen = pCredential->credentialData.bufferLen;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }

        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    /* Login using SO Pin */
    rVal = CALL_PKCS11_API(C_Login, pGemModule->moduleSession, CKU_SO, pOrigPin, pinLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    isLogin = TRUE;

    /* Set the New SO Pin */
    rVal = CALL_PKCS11_API(C_SetPIN, pGemModule->moduleSession, pOrigPin, pinLen, pNewPin, newPinLen);
    if (CKR_OK != rVal)
        status = PKCS11_nanosmpErr(pGemModule, rVal);

exit:
    /* logout after provisioning */
    if (TRUE == isLogin)
    {
        CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_MODULE__
MSTATUS SMP_API(PKCS11, resetModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
)
{
    ubyte4 i = 0;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_CHAR* pSoPin = NULL;
    CK_CHAR pinCode[4] = RESET_PIN_CODE;
    CK_CHAR label[32] = "No label";
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    CK_SESSION_HANDLE tmpSession;

    byteBoolean isSessionClosed = FALSE;
    byteBoolean isMutexLocked = FALSE;
    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_EntityCredential* pEntityCred = NULL;
    TAP_Credential* pCredential = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if (NULL == pGemModule)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pModuleProvisionAttributes, TAP_ATTR_CREDENTIAL, NULL);
    if (NULL != pCredentials)
    {
        pEntityCred = pCredentials->pEntityCredentials;
        pCredential = PKCS11_fetchCredentialFromList(&pEntityCred->credentialList,
                            TAP_CREDENTIAL_CONTEXT_OWNER);
        if (NULL != pCredential)
        {
            if ((NULL != pCredential->credentialData.pBuffer) && (SO_PIN_LEN == pCredential->credentialData.bufferLen))
            {
                pSoPin = pCredential->credentialData.pBuffer;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }

        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    /* Close all sessions and re-open module session before exit */
    rVal = PKCS11_closeAllModuleSessions(pGemModule);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }
    isSessionClosed = TRUE;

    DIGI_MEMSET(label, ' ', 32);
    for (i=0; i<MAX_MODULE_SLOTS; i++)
    {
        /* Init Token, requires SO Pin, if fails continue with next slot */

        rVal = CALL_PKCS11_API(C_InitToken, pGemModule->phySlotId + i, pSoPin, SO_PIN_LEN, label);
        if (CKR_OK != rVal)
            continue;

        /* Open Session for slot, if fails continue with next slot */
        rVal = CALL_PKCS11_API(C_OpenSession, pGemModule->phySlotId + i, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &tmpSession);
        if (CKR_OK != rVal)
            continue;

        /* Login using SO Pin */
        rVal = CALL_PKCS11_API(C_Login, tmpSession, CKU_SO, pSoPin, SO_PIN_LEN);
        if (CKR_OK != rVal)
        {
            if ((CKR_PIN_INCORRECT == rVal) || (CKR_PIN_INVALID == rVal))
            {
                GDEBUG_PRINT("#### SO PIN Authenticaton Fail, PLS CHECK SO PIN.");
                GDEBUG_PRINT("IF AUTHENTICATION FAILS MORE THAN 3 TIMES, IT WILL BLOCK SE ####");
            }

            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_InitPIN, tmpSession, (CK_CHAR *)pinCode, DEFAULT_USER_PIN_LEN);

        /* logout */
        CALL_PKCS11_API(C_Logout, tmpSession);

        /* Close the Session */
        CALL_PKCS11_API(C_CloseSession, tmpSession);
    }

    /* Resetting the pkcs11 library after reset of module */
    CALL_PKCS11_API(C_Finalize, NULL_PTR);
    CALL_PKCS11_API(C_Initialize, NULL_PTR);

exit:
    if (TRUE == isSessionClosed)
    {
        rVal = CALL_PKCS11_API(C_OpenSession, pGemModule->phySlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                    PKCS11_notificationCallback, &pGemModule->moduleSession);
        if (CKR_OK != rVal)
            status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_TOKEN__
MSTATUS SMP_API(PKCS11, provisionTokens,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes,
        TAP_EntityList *pTokenIdList
)
{
    ubyte4 i=0;
    CK_CHAR* pOrigPin = NULL;
    CK_CHAR* pNewPin = NULL;
    ubyte4 pinLen = 0;
    ubyte4 newPinLen = 0;
    CK_RV rVal = CKR_OK;
    MSTATUS status = OK;

    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);

    TAP_EntityCredentialList* pCredentialUse = NULL;
    TAP_EntityCredential* pEntityCredUse = NULL;
    TAP_Credential* pCredUse = NULL;

    TAP_EntityCredentialList* pCredentialSet = NULL;
    TAP_EntityCredential* pEntityCredSet = NULL;
    TAP_Credential* pCredSet = NULL;

    CK_SESSION_HANDLE tmpSession = 0;
    byteBoolean isMutexLocked = FALSE;
    byteBoolean isSessionClosed = FALSE;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (0 == pGemModule->moduleSession) || (NULL == pTokenProvisionAttributes))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    pCredentialUse = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pTokenProvisionAttributes, TAP_ATTR_CREDENTIAL_USAGE, NULL);
    if ((NULL != pCredentialUse) && (MAX_MODULE_SLOTS == pCredentialUse->numCredentials))
    {
        pEntityCredUse = pCredentialUse->pEntityCredentials;
        pCredUse = PKCS11_fetchCredentialFromList(&pEntityCredUse->credentialList,
                            TAP_CREDENTIAL_CONTEXT_USER);
        if (NULL != pCredUse)
        {
            if ((NULL != pCredUse->credentialData.pBuffer) && (0 < pCredUse->credentialData.bufferLen))
            {
                /* Logout from the current Login first */
                rVal = PKCS11_logoutAllModuleSessions(pGemModule);

                /* Login for USER of PIN#1 */
                rVal = CALL_PKCS11_API(C_Login, pGemModule->moduleSession, CKU_USER,
                                pCredUse->credentialData.pBuffer, pCredUse->credentialData.bufferLen);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }
                pGemModule->isLoggedIn = TRUE;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    pCredentialSet = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pTokenProvisionAttributes, TAP_ATTR_CREDENTIAL_SET, NULL);
    if ((NULL != pCredentialSet) && (MAX_MODULE_SLOTS == pCredentialSet->numCredentials))
    {
        pEntityCredSet = pCredentialSet->pEntityCredentials;
        pCredSet = PKCS11_fetchCredentialFromList(&pEntityCredSet->credentialList,
                            TAP_CREDENTIAL_CONTEXT_USER);
        if (NULL == pCredSet)
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    /* Close all sessions and re-open module session before exit */
    rVal = PKCS11_closeAllModuleSessions(pGemModule);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }
    isSessionClosed = TRUE;

    /* Resetting the pkcs11 library after provisioning tokens */
    CALL_PKCS11_API(C_Finalize, NULL_PTR);
    CALL_PKCS11_API(C_Initialize, NULL_PTR);

    for (i=TOKEN_0; i<=TOKEN_5; i++)
    {
        /* Fetch the Pins */
        pCredUse = PKCS11_fetchCredentialFromList(&pEntityCredUse[i].credentialList,
                        TAP_CREDENTIAL_CONTEXT_USER);
        if (NULL == pCredUse)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            /* continue provisioning next token */
            continue;
        }

        /* Fetch the Pins */
        pCredSet = PKCS11_fetchCredentialFromList(&pEntityCredSet[i].credentialList,
                        TAP_CREDENTIAL_CONTEXT_USER);
        if (NULL == pCredSet)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            /* continue provisioning next token */
            continue;
        }

        pOrigPin = pCredUse->credentialData.pBuffer;
        pinLen = pCredUse->credentialData.bufferLen;
        pNewPin = pCredSet->credentialData.pBuffer;
        newPinLen = pCredSet->credentialData.bufferLen;

        if ((NULL == pOrigPin) || (0 == pinLen) || (NULL == pNewPin) || (0 == newPinLen))
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            /* continue provisioning next token */
            continue;
        }

        rVal = CALL_PKCS11_API(C_OpenSession, (CK_SLOT_ID) i, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &tmpSession);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            /* continue provisioning next token */
            continue;
        }

        rVal = CALL_PKCS11_API(C_Login, tmpSession, CKU_USER, pOrigPin, pinLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            /* continue provisioning next token */
            continue;
        }

        /* Set the New Pin */
        rVal = CALL_PKCS11_API(C_SetPIN, tmpSession, pOrigPin, pinLen, pNewPin, newPinLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
        }

        CALL_PKCS11_API(C_Logout, tmpSession);
        CALL_PKCS11_API(C_CloseSession, tmpSession);
    }

exit:
    if (TRUE == isSessionClosed)
    {
        rVal = CALL_PKCS11_API(C_OpenSession, pGemModule->phySlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                    PKCS11_notificationCallback, &pGemModule->moduleSession);
        if (CKR_OK != rVal)
            status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

    if (OK != status)
    {
        if (TRUE == pGemModule->isLoggedIn)
        {
            CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
            pGemModule->isLoggedIn = FALSE;
        }
    }

null_exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_TOKEN__
MSTATUS SMP_API(PKCS11, resetToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes
)
{
    CK_CHAR* pOrigPin = NULL;
    CK_CHAR* pNewPin = NULL;
    ubyte4 pinLen = 0;
    ubyte4 newPinLen = 0;
    CK_RV rVal = CKR_OK;
    MSTATUS status = OK;

    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);

    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_Credential* pCred = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;
    byteBoolean isLocalLoggedIn = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (0 == pGemModule->moduleSession) || (NULL == pTokenProvisionAttributes))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    /* Fetch the Usage pin */
    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pTokenProvisionAttributes, TAP_ATTR_CREDENTIAL_USAGE, NULL);
    if (NULL == pCredentials)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }
    pCred = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList, TAP_CREDENTIAL_CONTEXT_USER);
    if (NULL == pCred)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }
    pOrigPin = pCred->credentialData.pBuffer;
    pinLen = pCred->credentialData.bufferLen;

    /* Fetch the Set pin */
    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pTokenProvisionAttributes, TAP_ATTR_CREDENTIAL_SET, NULL);
    if (NULL != pCredentials)
    {
        pCred = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList, TAP_CREDENTIAL_CONTEXT_USER);
        if (NULL == pCred)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }

        pNewPin = pCred->credentialData.pBuffer;
        newPinLen = pCred->credentialData.bufferLen;
    }

    if ((NULL == pOrigPin) || (0 == pinLen))
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    if (FALSE == pGemToken->isLoggedIn)
    {
        rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pOrigPin, pinLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }
        isLocalLoggedIn = TRUE;
    }

    status = PKCS11_deleteAllObjects(pGemModule, pGemToken);
    if (OK != status)
        goto exit;

    if ((NULL != pNewPin) && (0 != newPinLen))
    {
        /* Set the New Pin */
        rVal = CALL_PKCS11_API(C_SetPIN, pGemToken->tokenSession, pOrigPin, pinLen, pNewPin, newPinLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }
        CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
        isLocalLoggedIn = FALSE;
        pGemToken->isLoggedIn = FALSE;
    }

exit:
    if (TRUE == isLocalLoggedIn)
    {
        CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
    }

null_exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_TOKEN__
MSTATUS SMP_API(PKCS11, deleteToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes
)
{
    CK_CHAR label[MAX_LABEL_DESC_SZ];
    ubyte4 pinLen = 0;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_CHAR* pSoPin = NULL;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);

    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_EntityCredential* pEntityCred = NULL;
    TAP_Credential* pCredential = NULL;
    byteBoolean isSessionClosed = FALSE;
    byteBoolean isMutexLocked = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pTokenProvisionAttributes))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    pCredentials = (TAP_EntityCredentialList *) PKCS11_fetchAttributeFromList(
                            pTokenProvisionAttributes, TAP_ATTR_CREDENTIAL, NULL);
    if (NULL == pCredentials)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    pEntityCred = pCredentials->pEntityCredentials;
    pCredential = PKCS11_fetchCredentialFromList(&pEntityCred->credentialList,
                        TAP_CREDENTIAL_CONTEXT_OWNER);
    if ((NULL == pCredential) || (NULL == pCredential->credentialData.pBuffer) ||
            (SO_PIN_LEN != pCredential->credentialData.bufferLen))
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    pSoPin = pCredential->credentialData.pBuffer;
    pinLen = pCredential->credentialData.bufferLen;

    /* Close all sessions and re-open module session before exit */
    rVal = PKCS11_closeAllModuleSessions(pGemModule);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }
    isSessionClosed = TRUE;

    DIGI_MEMSET(label, ' ', MAX_LABEL_DESC_SZ);
    rVal = CALL_PKCS11_API(C_InitToken, (CK_SLOT_ID) pGemToken->tokenId, pSoPin, pinLen, label);
    if (CKR_OK != rVal)
    {
        if ((CKR_PIN_INCORRECT == rVal) || (CKR_PIN_INVALID == rVal))
        {
            GDEBUG_PRINT("#### SO PIN Authenticaton Fail, PLS CHECK SO PIN.");
            GDEBUG_PRINT("IF AUTHENTICATION FAILS MORE THAN 3 TIMES, IT WILL BLOCK SE ####");
        }
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

    /* Resetting the pkcs11 library after reset of module */
    CALL_PKCS11_API(C_Finalize, NULL_PTR);
    CALL_PKCS11_API(C_Initialize, NULL_PTR);

exit:
    if (TRUE == isSessionClosed)
    {
        rVal = CALL_PKCS11_API(C_OpenSession, pGemModule->phySlotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                    PKCS11_notificationCallback, &pGemModule->moduleSession);
        if (CKR_OK != rVal)
            status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
MSTATUS SMP_API(PKCS11, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes* pModuleAttributes,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
)
{
    Pkcs11_Module* pGemModule = NULL;
    Pkcs11_Module* pGemPrevModule = NULL;
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif
    byteBoolean isMutexLocked = FALSE;
    Pkcs11_ModuleList* pModList = gModListHead;

    MOC_UNUSED(pModuleAttributes);

    if (NULL == pModList)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    if (moduleId == EMULATED_MODULE_ID)
    {
        PKCS11_FillError(NULL, &status, ERR_NOT_IMPLEMENTED, "ERR_NOT_IMPLEMENTED");
        goto exit;
    }

    while ((NULL != pModList) && (pModList->moduleId != moduleId))
        pModList = pModList->pNext;

    if (NULL == pModList)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if (NULL == pModList->pModuleHead)
    {
        pGemModule = pModList->pModuleHead = MALLOC(sizeof(Pkcs11_Module));
    }
    else
    {
        pGemModule = pModList->pModuleHead;
        while (NULL != pGemModule)
        {
            pGemPrevModule = pGemModule;
            pGemModule = pGemModule->pNext;
        }
        pGemModule = pGemPrevModule->pNext = MALLOC(sizeof(Pkcs11_Module));
    }

    if (NULL == pGemModule)
    {
        PKCS11_FillError(NULL, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        goto exit;
    }

    pGemModule->phySlotId = pModList->phySlotId;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pGemModule->libType = pModList->libType;
    pFuncTable = pGemModule->pFuncTable = pModList->pFuncTable;
#endif
    pGemModule->moduleSession = 1;
    pGemModule->isLoggedIn = FALSE;
    pGemModule->pTokenHead = NULL;
    pGemModule->pNext = NULL;
    DIGI_MEMSET((ubyte *)&pGemModule->error, 0, sizeof(pGemModule->error));
    pGemModule->error.tapErrorString.pBuffer = MALLOC(MAX_ERROR_BUFFER);
    if (NULL == pGemModule->error.tapErrorString.pBuffer)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        goto exit;
    }
 
    *pModuleHandle = (TAP_ModuleHandle)((uintptr)pGemModule);

exit:
    if (OK != status)
    {
        if (NULL != pGemModule)
        {
            if (&pGemModule->moduleSession)
            {
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
                if (NULL != pFuncTable)
#endif
                    CALL_PKCS11_API(C_CloseSession, pGemModule->moduleSession);

                pGemModule->moduleSession = 0;
            }

            if (NULL != pGemPrevModule)
                pGemPrevModule->pNext = NULL;

            if (NULL != pGemModule->error.tapErrorString.pBuffer)
                FREE(pGemModule->error.tapErrorString.pBuffer);

            FREE(pGemModule);
        }
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
MSTATUS SMP_API(PKCS11, uninitModule,
        TAP_ModuleHandle moduleHandle
)
{
    MSTATUS status = OK;
    Pkcs11_ModuleList* pModList = NULL;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Module* pModule = NULL;
    Pkcs11_Module* pPrevMod = NULL;
    Pkcs11_Token* pToken = NULL;
    Pkcs11_Token* pNextToken = NULL;
    Pkcs11_Object* pObject = NULL;
    Pkcs11_Object* pNextObj = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (0 == pGemModule->moduleSession))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* First find to which modulelist does this module belongs */
    pModList = gModListHead;
    while ((NULL != pModList) && (pModList->phySlotId != pGemModule->phySlotId))
    {
        pModList = pModList->pNext;
    }

    if (NULL != pModList)
    {
        /* Now find the module in the list */
        pPrevMod = pModule = pModList->pModuleHead;
        while ((NULL != pModule) && (pModule != pGemModule))
        {
            pPrevMod = pModule;
            pModule = pModule->pNext;
        }

        if (NULL != pModule)
        {
            /* Remove the module from the list */
            if (pModule == pModList->pModuleHead)
                pModList->pModuleHead = pModule->pNext;
            else
                pPrevMod->pNext = pModule->pNext;

            /* Free Tokens and Objects */
            pToken = pModule->pTokenHead;
            while (NULL != pToken)
            {
                /* Free all the Objects in the token */
                pObject = pToken->pObjectHead;
                while (NULL != pObject)
                {
                    pNextObj = pObject->pNext;
                    if (NULL != pObject->objectId.pBuffer)
                    {
                        (void) DIGI_MEMSET_FREE(&pObject->objectId.pBuffer, pObject->objectId.bufferLen);
                        pObject->objectId.bufferLen = 0;
                    }
                    FREE(pObject);
                    pObject = pNextObj;
                }

                if (TRUE == pToken->isLoggedIn)
                {
                    CALL_PKCS11_API(C_Logout, pToken->tokenSession);
                }

                CALL_PKCS11_API(C_CloseSession, pToken->tokenSession);
                pToken->tokenSession = 0;

                pNextToken = pToken->pNext;
                FREE(pToken);
                pToken = pNextToken;
            }

            if (TRUE == pModule->isLoggedIn)
            {
                CALL_PKCS11_API(C_Logout, pModule->moduleSession);
            }

            CALL_PKCS11_API(C_CloseSession, pModule->moduleSession);

            pModule->moduleSession = 0;

            if (NULL != pModule->error.tapErrorString.pBuffer)
                FREE(pModule->error.tapErrorString.pBuffer);

            FREE(pModule);
        }
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__
MSTATUS SMP_API(PKCS11, associateModuleCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_EntityCredentialList *pCredentials
)
{
    return OK;
#if 0
    /* commented out for if we login here we face an error at initToken */
    
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) moduleHandle;
    TAP_Credential* pCredential = NULL;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;
    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (0 == pGemModule->moduleSession))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (NULL != pCredentials &&  NULL != pCredentials->pEntityCredentials)
    {
        if (FALSE == pGemModule->isLoggedIn)
        {
            pCredential = PKCS11_fetchCredentialFromEntityList(pCredentials, TAP_CREDENTIAL_CONTEXT_OWNER);
            if (NULL != pCredential)
            {
                if ((NULL != pCredential->credentialData.pBuffer) && (0 < pCredential->credentialData.bufferLen))
                {
                    rVal = CALL_PKCS11_API(C_Login, pGemModule->moduleSession, CKU_USER, pCredential->credentialData.pBuffer, SO_PIN_LEN);
                    if (rVal)
                    {
                        status = PKCS11_nanosmpErr(pGemModule, rVal);
                        goto exit;
                    }

                    pGemModule->isLoggedIn = TRUE;
                }
                else
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                    goto exit;
                }
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }
    else
    {
        if (TRUE == pGemModule->isLoggedIn)
        {
            rVal = CALL_PKCS11_API(C_Logout, pGemModule->moduleSession);
            pGemModule->isLoggedIn = FALSE;
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }
exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
#endif
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
MSTATUS SMP_API(PKCS11, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle *pTokenHandle
)
{
    TAP_Credential* pCredential = NULL;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = NULL;
    Pkcs11_Token* pPrevToken = NULL;
    Pkcs11_Token* pTmpToken = NULL;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    byteBoolean found = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if (NULL == pGemModule)
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    if (NULL == pGemModule->pTokenHead)
    {
        pGemToken = pGemModule->pTokenHead = MALLOC(sizeof(Pkcs11_Token));
    }
    else
    {
        pGemToken = pGemModule->pTokenHead;
        while (NULL != pGemToken)
        {
            if (pGemToken->tokenId == tokenId)
            {
                found = TRUE;
                break;
            }

            pPrevToken = pGemToken;
            pGemToken = pGemToken->pNext;
        }

        if (FALSE == found)
        {
            pGemToken = pPrevToken->pNext = MALLOC(sizeof(Pkcs11_Token));
        }
    }

    if (NULL == pGemToken)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        goto exit;
    }

    if (FALSE == found)
    {
        pGemToken->tokenSession = 0;
        pGemToken->tokenId = tokenId;
        pGemToken->isLoggedIn = FALSE;
        pGemToken->pObjectHead = NULL;
        pGemToken->pNext = NULL;
        pGemToken->credential.pBuffer = NULL;
        pGemToken->credential.bufferLen = 0;

        /* open a session */
        rVal = CALL_PKCS11_API(C_OpenSession, (CK_SLOT_ID) tokenId, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                    NULL, PKCS11_notificationCallback, &pGemToken->tokenSession);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }

        if (NULL != pCredentials &&  NULL != pCredentials->pEntityCredentials)
        {
            pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                                TAP_CREDENTIAL_CONTEXT_USER);
            if (NULL != pCredential)
            {
                if ((NULL != pCredential->credentialData.pBuffer) && (0 < pCredential->credentialData.bufferLen))
                {
                    rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);

                    /* If the user is already logged in then proceed. */
                    if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                    {
                        rVal = CKR_OK;
                    }

                    if (rVal)
                    {
                        status = PKCS11_nanosmpErr(pGemModule, rVal);
                        goto exit;
                    }

                    pGemToken->isLoggedIn = TRUE;
                }
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
    }

    /* Return the token handle */
    *pTokenHandle = (TAP_TokenHandle) ((uintptr)pGemToken);

exit:
    if (OK != status)
    {
        if ((NULL != pGemToken) && (&pGemToken->tokenSession))
        {
            CALL_PKCS11_API(C_CloseSession, pGemToken->tokenSession);
            pGemToken->tokenSession = 0;
        }

        if (NULL != pGemToken)
        {
            if (pGemToken == pGemModule->pTokenHead)
            {
                pGemModule->pTokenHead = NULL;
            }
            else
            {
                pTmpToken = pGemModule->pTokenHead;
                while ((NULL != pTmpToken) && (pTmpToken != pGemToken))
                {
                    pPrevToken = pTmpToken;
                    pTmpToken = pTmpToken->pNext;
                }

                if (NULL != pTmpToken)
                    pPrevToken->pNext = NULL;
            }
            FREE(pGemToken);
        }
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
MSTATUS SMP_API(PKCS11, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
)
{
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Token* pPrevToken = NULL;
    Pkcs11_Token* pToken = NULL;
    Pkcs11_Object* pObject = NULL;
    Pkcs11_Object* pNextObj = NULL;
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    pPrevToken = pToken = pGemModule->pTokenHead;
    while ((NULL != pToken) && (pToken != pGemToken))
    {
        pPrevToken = pToken;
        pToken = pToken->pNext;
    }

    /* only delete the token if there are no objects left in it */
    if (NULL != pToken && NULL == pToken->pObjectHead)
    {
        /* if there are no*/

        /* Remove the token from the list */
        if (pToken == pGemModule->pTokenHead)
            pGemModule->pTokenHead = pToken->pNext;
        else
            pPrevToken->pNext = pToken->pNext;

        if (TRUE == pToken->isLoggedIn)
        {
            CALL_PKCS11_API(C_Logout, pToken->tokenSession);
        }

        CALL_PKCS11_API(C_CloseSession, pToken->tokenSession);
        pToken->tokenSession = 0;

        FREE(pToken);
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS__
MSTATUS SMP_API(PKCS11, associateTokenCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_EntityCredentialList *pCredentials
)
{
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    TAP_Credential* pCredential = NULL;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (0 == pGemToken->tokenSession))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (NULL != pCredentials)
    {
        if (FALSE == pGemToken->isLoggedIn)
        {
            pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                                TAP_CREDENTIAL_CONTEXT_USER);
            if (NULL != pCredential)
            {
                rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);

                /* If the user is already logged in then proceed. */
                if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                {
                    rVal = CKR_OK;
                }

                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                pGemToken->isLoggedIn = TRUE;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }
    else
    {
        if (TRUE == pGemToken->isLoggedIn)
        {
            rVal = CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
            pGemToken->isLoggedIn = FALSE;
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
MSTATUS SMP_API(PKCS11, initObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributesOut
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Object* pNewObject = NULL;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pObject = NULL;
    TAP_Credential* pCredential = NULL;
    TAP_Buffer objectId = {0};
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    TAP_ObjectAttributes queryAttrs = {0};
    byteBoolean objIdAlloc = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    if (FALSE == pGemToken->isLoggedIn)
    {
        if ((NULL != pCredentials) && (NULL != pCredentials->pEntityCredentials))
        {
            pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                                TAP_CREDENTIAL_CONTEXT_USER);
            if (NULL != pCredential)
            {
                rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);

                /* If the user is already logged in then proceed. */
                if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                {
                    rVal = CKR_OK;
                }

                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                pGemToken->isLoggedIn = TRUE;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
    }

    if (pObjectAttributes && pObjectAttributes->listLen)
    {
        pAttribute = pObjectAttributes->pAttributeList;

        while (listCount < pObjectAttributes->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_OBJECT_ID_BYTESTRING:

                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid byte string ID structure length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    objectId.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    objectId.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }
    
    /* If we didn't find an objectId attribute use the ulong objectIdIn instead */
    if (NULL == objectId.pBuffer || 0 == objectId.bufferLen)
    {
        if (0 == objectIdIn)
        {
            DB_PRINT("%s.%d Failed, id not properly provided.\n",
                        __FUNCTION__, __LINE__);
            PKCS11_FillError(&pGemModule->error, &status, ERR_NOT_FOUND, "ERR_NOT_FOUND");
            goto exit;
        }

        status = copyUlongIdToBuffer(&objectId, objectIdIn);
        if (OK != status)
            goto exit;

        objIdAlloc = TRUE;
    }

    /* First find if the object is already in the list */
    if (NULL != pGemToken->pObjectHead)
    {
        pObject = pGemToken->pObjectHead;
        while (NULL != pObject)
        {
            if (objectId.bufferLen == pObject->objectId.bufferLen)
            {
                sbyte4 cmp = -1;

                status = DIGI_MEMCMP(objectId.pBuffer, pObject->objectId.pBuffer, pObject->objectId.bufferLen, &cmp);
                if (OK != status)
                    goto exit;

                if (!cmp)
                    break;
            }

            pObject = pObject->pNext;
        }

        if (NULL != pObject)
        {
            *pObjectHandle = (TAP_ObjectHandle)((uintptr)pObject);
            pObject->refCount++;

            if (NULL != pObjectIdOut)
            {
                copyBufferIdToUlong(pObjectIdOut, pObject->objectId);
            }
            goto exit;
        }
    }

    /* Find object in persistent storage */
  
    pNewObject = PKCS11_findAndAllocObject(pGemModule, pGemToken, objectId);
    if (NULL != pNewObject)
    {
        PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);

        /* return the object Id in output */
        *pObjectHandle = (TAP_ObjectHandle)((uintptr)pNewObject);
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_NOT_FOUND, "ERR_NOT_FOUND");
        goto exit;
    }

    /* query for key info used to fill the TAP_Key structure */

    queryAttrs.listLen = 3;
    status = DIGI_MALLOC((void **)&queryAttrs.pAttributeList, sizeof(TAP_Attribute) * 3);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed DIGI_MALLOC.\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }
    
    queryAttrs.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
    queryAttrs.pAttributeList[1].type = TAP_ATTR_KEY_SIZE;
    queryAttrs.pAttributeList[2].type = TAP_ATTR_CURVE;

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    CALL_SMP_API(PKCS11, getObjectInfo, moduleHandle, tokenHandle, (TAP_ObjectHandle) ((uintptr) pNewObject), &queryAttrs, pObjectAttributesOut);

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if (NULL != pObjectIdOut)
    {
        copyBufferIdToUlong(pObjectIdOut, pNewObject->objectId);
    }

exit:
    if (OK != status)
    {
        if ((NULL != pCredentials) && (pGemToken->isLoggedIn == TRUE))
        {
            (void) CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
        }
    }

    if (objIdAlloc && NULL != objectId.pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&objectId.pBuffer, objectId.bufferLen);
        objectId.bufferLen = 0;
    }

    if (NULL != queryAttrs.pAttributeList)
    {
        DIGI_FREE((void **)&queryAttrs.pAttributeList);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORT_OBJECT__
MSTATUS SMP_API(PKCS11, importObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Blob *pObjectBuffer,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle
)
{
    MSTATUS status = OK;
    Pkcs11_Module *pGemModule = (Pkcs11_Module*)((uintptr)moduleHandle);
    Pkcs11_Token *pGemToken = (Pkcs11_Token*)((uintptr)tokenHandle);
    Pkcs11_Object *pGemObject = NULL;
    byteBoolean isMutexLocked = FALSE;
    TAP_Buffer objectId = {0};
    CK_OBJECT_HANDLE prvHandle = 0;
    CK_OBJECT_HANDLE pubHandle = 0;
    ubyte4 offset = 0;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pObjectBuffer) ||
        (NULL == pObjectBuffer->blob.pBuffer) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input argument. pGemModule=%p,"
                 "pGemToken=%p, status=%d\n",
                 __FUNCTION__, __LINE__, pGemModule, pGemToken, status);
        goto exit;
    }
    if (TAP_BLOB_FORMAT_MOCANA != pObjectBuffer->format)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Unsupported object format %d, "
                "status = %d\n",
                __FUNCTION__, __LINE__, pObjectBuffer->format,
                (int)status);
        goto exit;
    }

    if (TAP_BLOB_ENCODING_BINARY != pObjectBuffer->encoding)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Unsupported object encoding %d, "
                "status = %d\n",
                __FUNCTION__, __LINE__, pObjectBuffer->encoding,
                (int)status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Buffer, TAP_SD_OUT,
                            pObjectBuffer->blob.pBuffer, pObjectBuffer->blob.bufferLen,
                            (void*)&objectId, sizeof(objectId), &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%s Failed to deserailze objectIBuffer. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (OK != (status = PKCS11_getObjectHandles(pGemModule, pGemToken, objectId, &prvHandle, &pubHandle)))
    {
        DB_PRINT("%s.%d Failed find the handle with object id. status =%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)&pGemObject, 1, sizeof(Pkcs11_Object))))
    {
        DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pGemObject->refCount = 1;
    pGemObject->pNext = NULL;
    PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pGemObject);

    /* Store the object handles */
    pGemObject->pubObject = pubHandle;
    pGemObject->prvObject = prvHandle;

    if (OK != (status = TAP_UTILS_copyBuffer(&pGemObject->objectId, &objectId)))
    {
        DB_PRINT("%s.%d Failed to copy buffer. status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    *pObjectHandle = (TAP_ObjectHandle)((uintptr)pGemObject);

exit:

    if (NULL != objectId.pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&objectId.pBuffer, objectId.bufferLen);
        objectId.bufferLen = 0;
    }
    
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_OBJECT__
MSTATUS SMP_API(PKCS11, uninitObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

    PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pGemObject);

null_exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_EVICT_OBJECT__
MSTATUS SMP_API(PKCS11, evictObject,
        TAP_ModuleHandle moduleHandle,
        TAP_Buffer *pObjectId,
        TAP_AttributeList *pAttributeList
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_PERSIST_OBJECT__
MSTATUS SMP_API(PKCS11, persistObject,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pObjectId
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS__
MSTATUS SMP_API(PKCS11, associateObjectCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_EntityCredentialList *pCredentials
)
{
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    TAP_Credential* pCredential = NULL;
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemToken) || (0 == pGemToken->tokenSession))
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = ((Pkcs11_Module *)((uintptr)moduleHandle))->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (NULL != pCredentials)
    {
        if (FALSE == pGemToken->isLoggedIn)
        {
            pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                                TAP_CREDENTIAL_CONTEXT_USER);
            if (NULL != pCredential)
            {
                rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);

                /* If the user is already logged in then proceed. */
                if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                {
                    rVal = CKR_OK;
                }

                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                pGemToken->isLoggedIn = TRUE;
            }
            else
            {
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                goto exit;
            }
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }
    else
    {
        if (TRUE == pGemToken->isLoggedIn)
        {
            rVal = CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
            pGemToken->isLoggedIn = FALSE;
        }
        else
        {
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        }
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
static MSTATUS
PKCS11_verifyInit(Pkcs11_Module *pGemModule,
                   Pkcs11_Token *pGemToken,
                   Pkcs11_Object *pGemObject,
                   TAP_MechanismAttributes *pMechanism)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    TAP_SIG_SCHEME *pSigScheme = NULL;
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_PSS_PARAMS pssParams = {0};
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;
#endif
    /* null checks already done */

    pSigScheme = (TAP_SIG_SCHEME*)PKCS11_fetchAttributeFromList(pMechanism, TAP_ATTR_SIG_SCHEME, NULL);

    switch(*pSigScheme)
    {
        case TAP_SIG_SCHEME_PKCS1_5:
            mechanism.mechanism = CKM_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PSS_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA_1;
            pssParams.mgf = CKG_MGF1_SHA1;
            pssParams.sLen = SHA1_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA256;
            pssParams.mgf = CKG_MGF1_SHA256;
            pssParams.sLen = SHA256_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA1:
            mechanism.mechanism = CKM_ECDSA_SHA1;
            break;
        default:
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            goto exit;

    }

    rVal = CALL_PKCS11_API(C_VerifyInit, pGemToken->tokenSession, &mechanism, pGemObject->pubObject);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY__
MSTATUS SMP_API(PKCS11, verify,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pDigest,
        TAP_Signature *pSignature,
        byteBoolean *pSignatureValid
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object *pGemObject = (Pkcs11_Object*)((uintptr)keyHandle);
    CK_KEY_TYPE keyType = CKK_RSA;
    ubyte *pBuffer = NULL;
    ubyte *pInSignature = NULL;
    ubyte4 signatureLen = 0;
    TAP_KEY_ALGORITHM keyAlgo = TAP_KEY_ALGORITHM_UNDEFINED;
    intBoolean sigretval = 0;
    AsymmetricKey asymKey = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_Attribute *pAttribute = NULL;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    hwAccelDescr hwAccelCtx = 0;
    static ubyte4 oidLen = SHA256_OID_LEN;
    ubyte *pResultBuf = NULL;
    ubyte4 resultBufSize = 0;
    sbyte4 cmpResult = 1;
    ubyte4 listCount = 0;
    byteBoolean isDataNotDigest = FALSE;
    CK_ATTRIBUTE keyTypeTemplate[] =
            {
                    {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
            };
    CK_ATTRIBUTE eccPubTemplate[] =
            {
                    {CKA_EC_PARAMS, NULL_PTR, 0}
            };

    byteBoolean isMutexLocked = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    ubyte*          pDigestBuffer = 0;
    ubyte4          digestBufferLen;
    DER_ITEMPTR     pSequence = 0;
    TAP_SIG_SCHEME *pSigScheme = NULL;
    CK_ULONG        saltLen = 0;
    byteBoolean     saltProvided = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pDigest) ||
        (NULL == pSignature) || (NULL == pGemObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input argument pGemModule=%p,"
                 "pGemToken=%p pGemObject=%p status=%d\n",
                 __FUNCTION__, __LINE__, pGemModule, pGemToken, pGemObject,
                 status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (CERT_MAXDIGESTSIZE < pDigest->bufferLen )
    {
        status = ERR_TAP_INVALID_KEY_SIZE;
        DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                 __FUNCTION__, __LINE__, pDigest->bufferLen);
        goto exit;
    }

    status = DIGI_MALLOC ( (void **)&pDigestBuffer, CERT_MAXDIGESTSIZE);
    if (OK != status)
        goto exit;

    /* copy the Digest info */
    (void) DIGI_MEMSET( pDigestBuffer, 0, CERT_MAXDIGESTSIZE);
    status = DIGI_MEMCPY( pDigestBuffer, pDigest->pBuffer, (sbyte4)pDigest->bufferLen);
    if (OK != status)
        goto exit;

    digestBufferLen = pDigest->bufferLen;

    *pSignatureValid = FALSE;
#ifdef PKCS11_PROFILING
    gettimeofday(&startTv, &tz);
#endif

    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_SIG_SCHEME:
                    if ((NULL == pAttribute->pStructOfType) ||
                        (sizeof(TAP_SIG_SCHEME) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                 __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                 pAttribute->length);
                        goto exit;
                    }
                    sigScheme = *((TAP_SIG_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                        (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                 __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                 pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;
                case TAP_ATTR_IS_DATA_NOT_DIGEST:
                    {
                        if ((NULL == pAttribute->pStructOfType) ||
                                (sizeof(byteBoolean) != pAttribute->length))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                    __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                    pAttribute->length);
                            goto exit;
                        }
                        isDataNotDigest = *(byteBoolean *)(pAttribute->pStructOfType);
                    }
                    break;

                case TAP_ATTR_SALT_LEN:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        saltLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                        if ((CK_ULONG)-1 != saltLen)
                        {
                            saltProvided = TRUE;
                        }
                    }
                    break;
                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if (TAP_OP_EXEC_FLAG_HW != opExecFlag)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Software operation not supported at SMP layer. status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, keyTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (TRUE == isDataNotDigest)
    {
        if (OK != (status = PKCS11_verifyInit(pGemModule, pGemToken, pGemObject, pMechanism)))
        {
            DB_PRINT("%s.%d Failed to initialize verify. status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pDigestBuffer = pDigest->pBuffer;
        digestBufferLen = pDigest->bufferLen;
    }
    else
    {
        const ubyte*    hashAlgoOID = 0;
        ubyte4          bufferLen;
        hashAlgoOID  = sha256_OID;
        CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
        CK_RSA_PKCS_PSS_PARAMS pssParams = {0};

        switch(sigScheme)
        {
            case TAP_SIG_SCHEME_PKCS1_5:
            case TAP_SIG_SCHEME_PKCS1_5_SHA256:
                mechanism.mechanism = CKM_RSA_PKCS;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA1:
                mechanism.mechanism = CKM_SHA1_RSA_PKCS;
                break;
            case TAP_SIG_SCHEME_PSS_SHA1:
                mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA_1;
                pssParams.mgf = CKG_MGF1_SHA1;
                pssParams.sLen = saltProvided ? saltLen : SHA1_HASH_LENGTH;
                break;
            case TAP_SIG_SCHEME_PSS_SHA256:
                mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA256;
                pssParams.mgf = CKG_MGF1_SHA256;
                pssParams.sLen = saltProvided ? saltLen : SHA256_HASH_LENGTH;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA1:
                mechanism.mechanism = CKM_ECDSA_SHA1;
                break;
            default:
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                goto exit;

        }

        rVal = CALL_PKCS11_API(C_VerifyInit, pGemToken->tokenSession, &mechanism, pGemObject->pubObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }

        /* construct a new ASN.1 DER encoding with this */
        if (OK > (status = DER_AddSequence(NULL, &pSequence)))
            goto exit;

        if (OK > (status = DER_StoreAlgoOID(pSequence, hashAlgoOID, TRUE)))
            goto exit;

        if (OK > (status = DER_AddItem(pSequence, OCTETSTRING, pDigest->bufferLen, pDigest->pBuffer, NULL)))
            goto exit;

        if (OK > (status = DER_Serialize(pSequence, &pBuffer, &bufferLen)))
            goto exit;

        if (CERT_MAXDIGESTSIZE < bufferLen )
        {
            status = ERR_TAP_INVALID_KEY_SIZE;
            DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                    __FUNCTION__, __LINE__, bufferLen);
            goto exit;
        }

        (void) DIGI_MEMCPY( pDigestBuffer, pBuffer, bufferLen);
        digestBufferLen = bufferLen;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, keyTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (keyType)
    {
        case CKK_RSA:
            keyAlgo = TAP_KEY_ALGORITHM_RSA;
            pInSignature = pSignature->signature.rsaSignature.pSignature;
            signatureLen = pSignature->signature.rsaSignature.signatureLen;
            break;
#ifdef __ENABLE_DIGICERT_ECC__
        case CKK_EC:
        {
            ubyte4 signLen = 0;
            ubyte4 pad = 0;

            keyAlgo = TAP_KEY_ALGORITHM_ECC;
            /* Get the EC params Value of Public Key */
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                goto exit;
            }
            /* Allocate memory for curve id */
            if (OK != (status = DIGI_CALLOC((void**)&eccPubTemplate[0].pValue, 1, eccPubTemplate[0].ulValueLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            /* Check the curveId */
            if (0x06 != *((ubyte *)eccPubTemplate[0].pValue))
            {
                status = ERR_TAP_INVALID_CURVE_ID;
                DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                            __FUNCTION__, __LINE__, status);
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_ECC_P192__
            if (EqualOID(eccOid192 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 48;  /* 2 * byte length of field element */
            }
            else
#endif
            if (EqualOID(eccOid224 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 56;
            }
            else if (EqualOID(eccOid256 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 64;
            }
            else if (EqualOID(eccOid384 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 96;
            }
            else if (EqualOID(eccOid521 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 132;
            }
            else
            {
                status = ERR_TAP_INVALID_CURVE_ID;
                DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            if (OK != (status = DIGI_CALLOC((void**)&pInSignature, 1, signLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            pad = signLen/2 - pSignature->signature.eccSignature.rDataLen;
            if (OK != (status = DIGI_MEMCPY(pSignature+pad, pSignature->signature.eccSignature.pRData,
                                           pSignature->signature.eccSignature.rDataLen)))
            {
                DB_PRINT("%s.%d Failed to copy r value. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            pad = pad + (signLen/2 - pSignature->signature.eccSignature.sDataLen);
            if (OK != (status = DIGI_MEMCPY(pSignature + pad + pSignature->signature.eccSignature.rDataLen,
                                           pSignature->signature.eccSignature.pSData,
                                           pSignature->signature.eccSignature.sDataLen)))
            {
                DB_PRINT("%s.%d Failed to copy s value. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */
        default:
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    rVal = CALL_PKCS11_API(C_Verify, pGemToken->tokenSession, pDigestBuffer, digestBufferLen,
                    pInSignature, signatureLen);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed in C_Verify API. status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }
#ifdef PKCS11_PROFILING
    {
        ubyte4 diff;
        gettimeofday(&endTv, &tz);

        diffTime = endTv.tv_sec - startTv.tv_sec;
        if (diffTime)
        {
            diffTime *= 1000000;
            diffTime += endTv.tv_usec;
            diffTime -= startTv.tv_usec;
        }
        else
        {
            diffTime = endTv.tv_usec - startTv.tv_usec;
        }

        diffSzInMb = (double)pDigest->bufferLen / (1024*1024);
        diffTimeInSec = (double)diffTime / 1000000;
        diff = (ubyte4) (diffSzInMb / diffTimeInSec);
    }
#endif


    *pSignatureValid = TRUE;

exit:
    if (NULL != pBuffer)
        DIGI_FREE((void **)&pBuffer);
    if (NULL != pDigestBuffer)
        DIGI_FREE((void **)&pDigestBuffer);
    if (NULL != pSequence)
        TREE_DeleteTreeItem((TreeItem * ) pSequence);
    if (isDataNotDigest == FALSE)
    {
        DIGI_FREE((void**)&pDigestBuffer);
    }
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    if (keyAlgo == TAP_KEY_ALGORITHM_ECC)
    {
        if (NULL != pInSignature)
            DIGI_FREE((void**)&pInSignature);

        if (NULL != eccPubTemplate[0].pValue)
        {
            DIGI_FREE((void**)&eccPubTemplate[0].pValue);
        }
    }
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
MSTATUS SMP_API(PKCS11, verifyInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
)
{
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (0 == pGemObject->pubObject) || (NULL == pMechanism))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    status = PKCS11_verifyInit(pGemModule, pGemToken, pGemObject, pMechanism);

exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_UPDATE__
MSTATUS SMP_API(PKCS11, verifyUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pBuffer))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_VerifyUpdate, pGemToken->tokenSession, pBuffer->pBuffer, pBuffer->bufferLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto null_exit;
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_FINAL__
MSTATUS SMP_API(PKCS11, verifyFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Signature *pSignature,
        byteBoolean *pSignatureValid
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    ubyte* signBuf = NULL;
    ulong signLen = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pSignature))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

    *pSignatureValid = FALSE;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    signBuf = pSignature->signature.rsaSignature.pSignature;
    signLen = pSignature->signature.rsaSignature.signatureLen;
    rVal = CALL_PKCS11_API(C_VerifyFinal, pGemToken->tokenSession, signBuf, signLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto null_exit;
    }

    *pSignatureValid = TRUE;

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
MSTATUS SMP_API(PKCS11, signDigest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pDigest,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    ubyte *pBuffer = NULL;
    ubyte4 bufferLen;
    ubyte *pSignBuf = NULL;
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_PSS_PARAMS pssParams = {0};

    ulong signLen = 0;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG ulBitLength = 0;
    TAP_KEY_ALGORITHM keyAlgo = TAP_KEY_ALGORITHM_UNDEFINED;

    TAP_SymSignature *pSymSignature = NULL;
    TAP_RSASignature *pRsaSignature = NULL;
    TAP_ECCSignature *pEccSignature = NULL;

    CK_ATTRIBUTE keyTypeTemplate[] =
            {
                    {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
            };
    CK_ATTRIBUTE rsaPubTemplate[] =
            {
                    { CKA_MODULUS_BITS, &ulBitLength, sizeof(ulBitLength) }
            };
    CK_ATTRIBUTE eccPubTemplate[] =
            {
                    {CKA_EC_PARAMS, NULL_PTR, 0},
            };
    byteBoolean isMutexLocked = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    ubyte*          pDigestBuffer = 0;
    ubyte4          digestBufferLen;
    DER_ITEMPTR     pSequence = 0;
    TAP_Attribute  *pAttribute = NULL;
    ubyte4          listCount = 0;
    CK_ULONG        saltLen = 0;
    byteBoolean     saltProvided = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject)
        || (NULL == ppSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif
    if (CERT_MAXDIGESTSIZE < pDigest->bufferLen )
    {
        status = ERR_TAP_INVALID_KEY_SIZE;
        DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                 __FUNCTION__, __LINE__, pDigest->bufferLen);
        goto exit;
    }

    *ppSignature = NULL;

    /* If attributes are provided, use them */
    if (pSignatureAttributes && pSignatureAttributes->listLen)
    {
        pAttribute = pSignatureAttributes->pAttributeList;

        while (listCount < pSignatureAttributes->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_SALT_LEN:
                    if ((sizeof(ubyte4) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                 __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    saltLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    saltProvided = TRUE;
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, keyTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch(type)
    {
        case TAP_SIG_SCHEME_NONE:
            if(CKK_RSA == keyType)
            {
                mechanism.mechanism = CKM_RSA_X_509;
                break;
            }
#ifdef __ENABLE_DIGICERT_ECC__
            else if (CKK_EC == keyType)
            {
                mechanism.mechanism = CKM_ECDSA;
            }
#endif
            else
            {
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",  __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;
        case TAP_SIG_SCHEME_PKCS1_5:
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
        case TAP_SIG_SCHEME_PKCS1_5_SHA224:
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
        case TAP_SIG_SCHEME_PKCS1_5_SHA384:
        case TAP_SIG_SCHEME_PKCS1_5_SHA512:
            mechanism.mechanism = CKM_RSA_PKCS;
            {
                const ubyte*    hashAlgoOID = 0;
                hashAlgoOID  = sha256_OID;
                if (TAP_SIG_SCHEME_PKCS1_5_SHA1 == type)
                {
                    hashAlgoOID = sha1_OID;
                }
                else if (TAP_SIG_SCHEME_PKCS1_5_SHA224 == type)
                {
                    hashAlgoOID = sha224_OID;
                }
                else if (TAP_SIG_SCHEME_PKCS1_5_SHA384 == type)
                {
                    hashAlgoOID = sha384_OID;
                }
                else if (TAP_SIG_SCHEME_PKCS1_5_SHA512 == type)
                {
                    hashAlgoOID = sha512_OID;
                }

                /* construct a new ASN.1 DER encoding with this */
                if (OK > (status = DER_AddSequence(NULL, &pSequence)))
                    goto exit;

                if (OK > (status = DER_StoreAlgoOID(pSequence, hashAlgoOID, TRUE)))
                    goto exit;

                if (OK > (status = DER_AddItem(pSequence, OCTETSTRING, pDigest->bufferLen, pDigest->pBuffer, NULL)))
                    goto exit;

                if (OK > (status = DER_Serialize(pSequence, &pBuffer, &bufferLen)))
                    goto exit;
            }

            break;
        case TAP_SIG_SCHEME_PSS_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA_1;
            pssParams.mgf = CKG_MGF1_SHA1;
            pssParams.sLen = saltProvided ? saltLen : SHA1_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA256;
            pssParams.mgf = CKG_MGF1_SHA256;
            pssParams.sLen = saltProvided ? saltLen : SHA256_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA1:
        case TAP_SIG_SCHEME_ECDSA_SHA224:
        case TAP_SIG_SCHEME_ECDSA_SHA256:
        case TAP_SIG_SCHEME_ECDSA_SHA384:
        case TAP_SIG_SCHEME_ECDSA_SHA512:
            mechanism.mechanism = CKM_ECDSA;
            break;
        default:
            status = ERR_TAP_INVALID_SCHEME;
            DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                     __FUNCTION__,__LINE__, (int)status,
                     status);
            goto exit;
    }

    if (NULL != pBuffer)
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pDigestBuffer, bufferLen, pBuffer, bufferLen);
        if (OK != status)
        {
            goto exit;
        }
        digestBufferLen = bufferLen;
    }
    else
    {
        status = DIGI_MALLOC_MEMCPY(
            (void **) &pDigestBuffer, pDigest->bufferLen, pDigest->pBuffer,
            pDigest->bufferLen);
        if (OK != status)
        {
            goto exit;
        }
        digestBufferLen = pDigest->bufferLen;
    }

    rVal = CALL_PKCS11_API(C_SignInit, pGemToken->tokenSession, &mechanism, pGemObject->prvObject);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed in C_SignInit status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (keyType)
    {
        case CKK_RSA:
        {
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            signLen = ulBitLength/8;
            if (OK != (status = DIGI_CALLOC((void**)&pSignBuf,
                                           1, signLen+1)))
            {
                DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            keyAlgo = TAP_KEY_ALGORITHM_RSA;
        }
            break;
#ifdef __ENABLE_DIGICERT_ECC__
        case CKK_EC:
        {
            /* Get the EC params Value of Public Key */
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                goto exit;
            }
            /* Allocate memory for curve id */
            if (OK != (status = DIGI_CALLOC((void**)&eccPubTemplate[0].pValue, 1, eccPubTemplate[0].ulValueLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            /* Check the curveId */
            if (0x06 != *((ubyte *)eccPubTemplate[0].pValue))
            {
                status = ERR_TAP_INVALID_CURVE_ID;
                DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                            __FUNCTION__, __LINE__, status);
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_ECC_P192__
            if (EqualOID(eccOid192 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 48;  /* 2 * byte length of field element */
            }
            else
#endif
            if (EqualOID(eccOid224 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 56;
            }
            else if (EqualOID(eccOid256 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 64;
            }
            else if (EqualOID(eccOid384 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 96;
            }
            else if (EqualOID(eccOid521 + 1, eccPubTemplate[0].pValue + 1))
            {
                signLen = 132;
            }
            else
            {
                status = ERR_TAP_INVALID_CURVE_ID;
                DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            if (OK != (status = DIGI_CALLOC((void**)&pSignBuf,
                                           1, signLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            keyAlgo = TAP_KEY_ALGORITHM_ECC;
        }
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */
        default:
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

#ifdef PKCS11_PROFILING
    gettimeofday(&startTv, &tz);
#endif

    rVal = CALL_PKCS11_API(C_Sign, pGemToken->tokenSession, pDigestBuffer, digestBufferLen, pSignBuf, &signLen);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_Sign API failed. status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }
#ifdef PKCS11_PROFILING
    {
        ubyte4 diff;
        gettimeofday(&endTv, &tz);

        diffTime = endTv.tv_sec - startTv.tv_sec;
        if (diffTime)
        {
            diffTime *= 1000000;
            diffTime += endTv.tv_usec;
            diffTime -= startTv.tv_usec;
        }
        else
        {
            diffTime = endTv.tv_usec - startTv.tv_usec;
        }

        diffSzInMb = (double)pDigest->bufferLen / (1024*1024);
        diffTimeInSec = (double)diffTime / 1000000;
        diff = (ubyte4) (diffSzInMb / diffTimeInSec);
    }
#endif

    if (OK != (status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature))))
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                 "signature structure, status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    (*ppSignature)->isDEREncoded = FALSE;

    switch(keyType)
    {
        case CKK_RSA:
            (*ppSignature)->signature.rsaSignature.pSignature = pSignBuf;
            (*ppSignature)->signature.rsaSignature.signatureLen = signLen;
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            pSignBuf = NULL;
            break;
        case CKK_EC:
        {
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            (*ppSignature)->signature.eccSignature.rDataLen = signLen/2;
            (*ppSignature)->signature.eccSignature.sDataLen = signLen/2;
            if (OK != (status = DIGI_CALLOC((void**)&(*ppSignature)->signature.eccSignature.pRData,
                                           1, (*ppSignature)->signature.eccSignature.rDataLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            if (OK != (status = DIGI_CALLOC((void**)&(*ppSignature)->signature.eccSignature.pSData,
                                           1, (*ppSignature)->signature.eccSignature.sDataLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)(*ppSignature)->signature.eccSignature.pRData,
                                           pSignBuf,
                                           (*ppSignature)->signature.eccSignature.rDataLen)))
            {
                DB_PRINT("%s.%d Failed to copy the sign buffer status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
            if (OK != (status = DIGI_MEMCPY((ubyte*)(*ppSignature)->signature.eccSignature.pSData,
                                           pSignBuf+(*ppSignature)->signature.eccSignature.rDataLen,
                                           (*ppSignature)->signature.eccSignature.sDataLen)))
            {
                DB_PRINT("%s.%d Failed to copy the sign buffer status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
        break;
    }
exit:

    if (NULL != pSequence)
        TREE_DeleteTreeItem((TreeItem * ) pSequence);
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    if (NULL != pBuffer)
        DIGI_FREE((void**)&pBuffer);
    if (NULL != pDigestBuffer)
        DIGI_FREE((void**)&pDigestBuffer);
    if (NULL != pSignBuf)
        DIGI_FREE((void**)&pSignBuf);
    if (NULL != eccPubTemplate[0].pValue)
    {
        DIGI_FREE((void**)&eccPubTemplate[0].pValue);
    }
    if (OK != status)
    {
        if (ppSignature && *ppSignature)
        {
            if (TAP_KEY_ALGORITHM_RSA == keyAlgo)
            {
                if (NULL != (*ppSignature)->signature.rsaSignature.pSignature)
                {
                    DIGI_FREE((void*)&(*ppSignature)->signature.rsaSignature.pSignature);
                }
            }
            else if (TAP_KEY_ALGORITHM_ECC == keyAlgo)
            {
                if (NULL != (*ppSignature)->signature.eccSignature.pRData)
                {
                    DIGI_FREE((void**)&(*ppSignature)->signature.eccSignature.pRData);
                }
                if (NULL != (*ppSignature)->signature.eccSignature.pSData)
                {
                    DIGI_FREE((void**)&(*ppSignature)->signature.eccSignature.pSData);
                }
            }
            DIGI_FREE((void**)ppSignature);
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
static MSTATUS
PKCS11_signInit(Pkcs11_Module *pGemModule,
                 Pkcs11_Token *pGemToken,
                 Pkcs11_Object *pGemObject,
                 TAP_SIG_SCHEME type)
{
    MSTATUS status = OK;
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
    CK_RSA_PKCS_PSS_PARAMS pssParams = {0};
    CK_RV rVal = CKR_OK;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = pGemModule->pFuncTable;
#endif

    /* null checks already done */

    switch(type)
    {
        case TAP_SIG_SCHEME_PKCS1_5:
            mechanism.mechanism = CKM_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA224:
            mechanism.mechanism = CKM_SHA224_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA384:
            mechanism.mechanism = CKM_SHA384_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA512:
            mechanism.mechanism = CKM_SHA512_RSA_PKCS;
            break;
        case TAP_SIG_SCHEME_PSS_SHA1:
            mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA_1;
            pssParams.mgf = CKG_MGF1_SHA1;
            pssParams.sLen = SHA1_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA224:
            mechanism.mechanism = CKM_SHA224_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA224;
            pssParams.mgf = CKG_MGF1_SHA224;
            pssParams.sLen = SHA224_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA256:
            mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA256;
            pssParams.mgf = CKG_MGF1_SHA256;
            pssParams.sLen = SHA256_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA384:
            mechanism.mechanism = CKM_SHA384_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA384;
            pssParams.mgf = CKG_MGF1_SHA384;
            pssParams.sLen = SHA384_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_PSS_SHA512:
            mechanism.mechanism = CKM_SHA512_RSA_PKCS_PSS;
            mechanism.pParameter = &pssParams;
            mechanism.ulParameterLen = sizeof(pssParams);
            pssParams.hashAlg = CKM_SHA512;
            pssParams.mgf = CKG_MGF1_SHA512;
            pssParams.sLen = SHA512_HASH_LENGTH;
            break;
        case TAP_SIG_SCHEME_HMAC_SHA1:
            mechanism.mechanism = CKM_SHA_1_HMAC;
            break;
        case TAP_SIG_SCHEME_HMAC_SHA224:
            mechanism.mechanism = CKM_SHA224_HMAC;
            break;
        case TAP_SIG_SCHEME_HMAC_SHA256:
            mechanism.mechanism = CKM_SHA256_HMAC;
            break;
        case TAP_SIG_SCHEME_HMAC_SHA384:
            mechanism.mechanism = CKM_SHA384_HMAC;
            break;
        case TAP_SIG_SCHEME_HMAC_SHA512:
            mechanism.mechanism = CKM_SHA512_HMAC;
            break;
        case TAP_SIG_SCHEME_NONE:
        /* Will assume ECC for now and that this is ok */
        case TAP_SIG_SCHEME_ECDSA_SHA1:
        /* we will software hash anyway, smp may not support mechanism.mechanism = CKM_ECDSA_SHA1; */
        case TAP_SIG_SCHEME_ECDSA_SHA224:
        case TAP_SIG_SCHEME_ECDSA_SHA256:
        case TAP_SIG_SCHEME_ECDSA_SHA384:
        case TAP_SIG_SCHEME_ECDSA_SHA512:
            mechanism.mechanism = CKM_ECDSA;
            break;
        default:
            status = ERR_TAP_INVALID_SCHEME;
            DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                    __FUNCTION__,__LINE__, (int)status,
                    status);
            goto exit;
    }

    rVal = CALL_PKCS11_API(C_SignInit, pGemToken->tokenSession, &mechanism, pGemObject->prvObject);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
MSTATUS SMP_API(PKCS11, signBuffer,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pData,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    ubyte *pSignBuf = NULL;
    ulong signLen = 0;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_ULONG ulBitLength = 0;
    TAP_KEY_ALGORITHM keyAlgo = TAP_KEY_ALGORITHM_UNDEFINED;
    CK_ATTRIBUTE keyTypeTemplate[] =
    {
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
    };
    CK_ATTRIBUTE rsaPubTemplate[] =
    {
        { CKA_MODULUS_BITS, &ulBitLength, sizeof(ulBitLength) }
    };
    CK_ATTRIBUTE eccPubTemplate[] =
    {
        {CKA_EC_PARAMS, NULL_PTR, 0},
    };
    byteBoolean isMutexLocked = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    TAP_Attribute  *pAttribute = NULL;
    ubyte4          listCount = 0;
    CK_ULONG        saltLen = 0;
    byteBoolean     saltProvided = FALSE;
    TAP_Buffer      input = {0};
    ubyte hash[SHA512_HASH_LENGTH] = {0}; /* big enough for any sha size */

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject)
            || (NULL == ppSignature) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    *ppSignature = NULL;

    /* default */
    input.pBuffer = pData->pBuffer;
    input.bufferLen = pData->bufferLen;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* If attributes are provided, use them */
    if (pSignatureAttributes && pSignatureAttributes->listLen)
    {
        pAttribute = pSignatureAttributes->pAttributeList;

        while (listCount < pSignatureAttributes->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_SALT_LEN:
                    if ((sizeof(ubyte4) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                 __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    saltLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    saltProvided = TRUE;
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    /* Do signInit, before sign API */
    if (FALSE == saltProvided)
    {
        /* salt length not provided. PKCS11_signInit will set defaults. */
        if (OK != (status = PKCS11_signInit(pGemModule, pGemToken, pGemObject, type)))
        {
            DB_PRINT("%s.%d sign init failed status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
    else
    {
        /* salt length provided. Initialize sign ourselves */
        CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
        CK_RSA_PKCS_PSS_PARAMS pssParams = {0};

        /* Only support RSA-PSS here. Salt length does not apply to any other
         * algorithms. */
        switch (type)
        {
            case TAP_SIG_SCHEME_PSS_SHA1:
                mechanism.mechanism = CKM_SHA1_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA_1;
                pssParams.mgf = CKG_MGF1_SHA1;
                pssParams.sLen = saltLen;
                break;

            case TAP_SIG_SCHEME_PSS_SHA224:
                mechanism.mechanism = CKM_SHA224_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA224;
                pssParams.mgf = CKG_MGF1_SHA224;
                pssParams.sLen = saltLen;
                break;

            case TAP_SIG_SCHEME_PSS_SHA256:
                mechanism.mechanism = CKM_SHA256_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA256;
                pssParams.mgf = CKG_MGF1_SHA256;
                pssParams.sLen = saltLen;
                break;

            case TAP_SIG_SCHEME_PSS_SHA384:
                mechanism.mechanism = CKM_SHA384_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA384;
                pssParams.mgf = CKG_MGF1_SHA384;
                pssParams.sLen = saltLen;
                break;

            case TAP_SIG_SCHEME_PSS_SHA512:
                mechanism.mechanism = CKM_SHA512_RSA_PKCS_PSS;
                mechanism.pParameter = &pssParams;
                mechanism.ulParameterLen = sizeof(pssParams);
                pssParams.hashAlg = CKM_SHA512;
                pssParams.mgf = CKG_MGF1_SHA512;
                pssParams.sLen = saltLen;
                break;

            default:
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d Invalid scheme when salt provided %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)status,
                        status);
                goto exit;
        }

        rVal = CALL_PKCS11_API(C_SignInit, pGemToken->tokenSession, &mechanism, pGemObject->prvObject);

        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d Failed in C_SignInit status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, keyTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (keyType)
    {
        case CKK_RSA:
            {
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 1);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    DB_PRINT("%s.%d Failed to get attribute value status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if (OK != (status = DIGI_CALLOC((void**)&pSignBuf,
                                1, ulBitLength)))
                {
                    DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                signLen = ulBitLength;
                keyAlgo = TAP_KEY_ALGORITHM_RSA;
            }
            break;
#ifdef __ENABLE_DIGICERT_ECC__
        case CKK_EC:
            {
                /* Get the EC params Value of Public Key */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }
                /* Allocate memory for curve id */
                if (OK != (status = DIGI_CALLOC((void**)&eccPubTemplate[0].pValue, 1, eccPubTemplate[0].ulValueLen)))
                {
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 1);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Check the curveId */
                if (0x06 != *((ubyte *)eccPubTemplate[0].pValue))
                {
                    status = ERR_TAP_INVALID_CURVE_ID;
                    DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

#ifdef __ENABLE_DIGICERT_ECC_P192__
                if (EqualOID(eccOid192 + 1, eccPubTemplate[0].pValue + 1))
                {
                    signLen = 48;  /* 2 * byte length of field element */
                }
                else
#endif
                if (EqualOID(eccOid224 + 1, eccPubTemplate[0].pValue + 1))
                {
                    signLen = 56;
                }
                else if (EqualOID(eccOid256 + 1, eccPubTemplate[0].pValue + 1))
                {
                    signLen = 64;
                }
                else if (EqualOID(eccOid384 + 1, eccPubTemplate[0].pValue + 1))
                {
                    signLen = 96;
                }
                else if (EqualOID(eccOid521 + 1, eccPubTemplate[0].pValue + 1))
                {
                    signLen = 132;
                }
                else
                {
                    status = ERR_TAP_INVALID_CURVE_ID;
                    DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                if (OK != (status = DIGI_CALLOC((void**)&pSignBuf,
                                1, signLen)))
                {
                    DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                keyAlgo = TAP_KEY_ALGORITHM_ECC;

                switch (type)
                {
                    case TAP_SIG_SCHEME_NONE:
                        break;

                    case TAP_SIG_SCHEME_ECDSA_SHA1:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__                        
                        status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#else
                        status = SHA1_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d CRYPTO_INTERFACE_SHA1_completeDigest, status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;                           
                        }
                        input.pBuffer = (ubyte *) hash;
                        input.bufferLen = SHA1_HASH_LENGTH;
                        break;

                    case TAP_SIG_SCHEME_ECDSA_SHA224:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__                        
                        status = CRYPTO_INTERFACE_SHA224_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#else
                        status = SHA224_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d CRYPTO_INTERFACE_SHA224_completeDigest, status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;                           
                        }
                        input.pBuffer = (ubyte *) hash;
                        input.bufferLen = SHA224_HASH_LENGTH;
                        break;

                    case TAP_SIG_SCHEME_ECDSA_SHA256:
                        
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__                        
                        status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#else
                        status = SHA256_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d CRYPTO_INTERFACE_SHA256_completeDigest, status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;                           
                        }
                        input.pBuffer = (ubyte *) hash;
                        input.bufferLen = SHA256_HASH_LENGTH;
                        break;

                    case TAP_SIG_SCHEME_ECDSA_SHA384:
                        
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__                        
                        status = CRYPTO_INTERFACE_SHA384_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#else
                        status = SHA384_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d CRYPTO_INTERFACE_SHA384_completeDigest, status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;                           
                        }
                        input.pBuffer = (ubyte *) hash;
                        input.bufferLen = SHA384_HASH_LENGTH;
                        break;

                    case TAP_SIG_SCHEME_ECDSA_SHA512:
                        
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__                        
                        status = CRYPTO_INTERFACE_SHA512_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#else
                        status = SHA512_completeDigest(MOC_HASH(0) pData->pBuffer, pData->bufferLen, hash);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d CRYPTO_INTERFACE_SHA512_completeDigest, status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;                           
                        }
                        input.pBuffer = (ubyte *) hash;
                        input.bufferLen = SHA512_HASH_LENGTH;
                        break;
                    
                    default:
                        status = ERR_TAP_INVALID_SCHEME;
                        DB_PRINT("%s.%d Invalid key encryption, status = %d\n",__FUNCTION__,__LINE__, (int)status);
                        goto exit;
                }
            }
            break;
#endif /* __ENABLE_DIGICERT_ECC__ */
        case CKK_GENERIC_SECRET:
            {
                signLen = 64;
                status = DIGI_CALLOC((void **)&pSignBuf, 1, signLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
            }
            break;
        default:
            {
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
    }

    rVal = CALL_PKCS11_API(C_Sign, pGemToken->tokenSession, input.pBuffer, input.bufferLen, pSignBuf, &signLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_Sign API failed. status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature))))
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                "signature structure, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch(keyType)
    {
        case CKK_RSA:
            (*ppSignature)->signature.rsaSignature.pSignature = pSignBuf;
            (*ppSignature)->signature.rsaSignature.signatureLen = signLen;
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            pSignBuf = NULL;
            break;
        case CKK_EC:
            {
                (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
                (*ppSignature)->signature.eccSignature.rDataLen = signLen/2;
                (*ppSignature)->signature.eccSignature.sDataLen = signLen/2;
                if (OK != (status = DIGI_CALLOC((void**)&(*ppSignature)->signature.eccSignature.pRData,
                                               1, (*ppSignature)->signature.eccSignature.rDataLen)))
                {
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if (OK != (status = DIGI_CALLOC((void**)&(*ppSignature)->signature.eccSignature.pSData,
                                               1, (*ppSignature)->signature.eccSignature.sDataLen)))
                {
                    DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if (OK != (status = DIGI_MEMCPY((ubyte*)(*ppSignature)->signature.eccSignature.pRData,
                                               pSignBuf,
                                               (*ppSignature)->signature.eccSignature.rDataLen)))
                {
                    DB_PRINT("%s.%d Failed to copy the sign buffer status=%d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if (OK != (status = DIGI_MEMCPY((ubyte*)(*ppSignature)->signature.eccSignature.pSData,
                                               pSignBuf+(*ppSignature)->signature.eccSignature.rDataLen,
                                               (*ppSignature)->signature.eccSignature.sDataLen)))
                {
                    DB_PRINT("%s.%d Failed to copy the sign buffer status=%d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
            }
            break;
        case CKK_GENERIC_SECRET:
            {
                (*ppSignature)->signature.hmacSignature.pSignature = (ubyte *) pSignBuf; pSignBuf = NULL;
                (*ppSignature)->signature.hmacSignature.signatureLen = (ubyte4) signLen;
                (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
                (*ppSignature)->isDEREncoded = FALSE;
            }
        default:
            break;
    }

    (*ppSignature)->isDEREncoded = FALSE;

exit:
    if (TRUE == isMutexLocked)
        (void) RTOS_mutexRelease(gGemMutex);
    if (NULL != pSignBuf)
        (void) DIGI_FREE((void**)&pSignBuf);
    if (NULL != eccPubTemplate[0].pValue)
    {
        (void) DIGI_FREE((void**)&eccPubTemplate[0].pValue);
    }
    if (OK != status)
    {
        if (ppSignature && *ppSignature)
        {
            if (TAP_KEY_ALGORITHM_RSA == keyAlgo)
            {
                if (NULL != (*ppSignature)->signature.rsaSignature.pSignature)
                {
                    (void) DIGI_FREE((void*)&(*ppSignature)->signature.rsaSignature.pSignature);
                }
            }
            else if (TAP_KEY_ALGORITHM_ECC == keyAlgo)
            {
                if (NULL != (*ppSignature)->signature.eccSignature.pRData)
                {
                    (void) DIGI_FREE((void**)&(*ppSignature)->signature.eccSignature.pRData);
                }
                if (NULL != (*ppSignature)->signature.eccSignature.pSData)
                {
                    (void) DIGI_FREE((void**)&(*ppSignature)->signature.eccSignature.pSData);
                }
            }
            (void) DIGI_FREE((void**)ppSignature);
        }
    }

    (void) DIGI_MEMSET(hash, 0x00, SHA512_HASH_LENGTH);

    return status;
}
#endif


#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
MSTATUS SMP_API(PKCS11,signInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_OperationHandle *pOpContext
)
{
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (0 == pGemObject->prvObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. moduleHandle = %p, tokenHandle = %p,"
                 "keyHandle = %p, status = %d\n", __FUNCTION__, __LINE__, moduleHandle,
                 tokenHandle, keyHandle, status);
        goto exit;
    }

    status = PKCS11_signInit(pGemModule, pGemToken, pGemObject, type);

exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_UPDATE__
MSTATUS SMP_API(PKCS11,signUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_SignUpdate, pGemToken->tokenSession, pBuffer->pBuffer, pBuffer->bufferLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_FINAL__
MSTATUS SMP_API(PKCS11,signFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    CK_BYTE_PTR pSignBuf = NULL;
    CK_ULONG signLen = 64; /* big enough for any hmac */
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    /* IMPORTANT: method is for only hmac right now. need to pass in attributes for other sign Algos */
    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject)
            || (NULL == ppSignature))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

    *ppSignature = NULL;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    status = DIGI_CALLOC((void **) &pSignBuf, 1, (ubyte4) signLen);
    if (OK != status)
        goto exit;

    rVal = CALL_PKCS11_API(C_SignFinal, pGemToken->tokenSession, pSignBuf, &signLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature))))
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                 "signature structure, status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    (*ppSignature)->signature.hmacSignature.pSignature = (ubyte *) pSignBuf; pSignBuf = NULL;
    (*ppSignature)->signature.hmacSignature.signatureLen = (ubyte4) signLen;
    (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    (*ppSignature)->isDEREncoded = FALSE;

exit:

    if (NULL != pSignBuf)
    {
        (void) DIGI_MEMSET_FREE((ubyte**) &pSignBuf, (ubyte4) signLen);
    }

    /* ppSignature is last thing to be allocated, no need to clean it up */

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_SIGNATURE_BUFFER__
MSTATUS SMP_API(PKCS11, freeSignatureBuffer,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;

    if ((NULL == ppSignature) || (!*ppSignature))
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

    if ((*ppSignature)->signature.rsaSignature.pSignature)
        FREE((*ppSignature)->signature.rsaSignature.pSignature);

null_exit:
    return status;
}
#endif

static
MSTATUS PKCS11_getP11SymmetricAlgorithm(CK_ULONG keyAlgorithm, ubyte mode, CK_ULONG *pp11AlgId, ubyte4 *pBlockSize)
{
    ubyte alg[MAX_BUFFER_SIZE] = {0};
    MSTATUS status = OK;
    ubyte4 i = 0;

    *pp11AlgId = (CK_ULONG) -1;

    switch (keyAlgorithm)
    {
        case CKK_AES:
            DIGI_STRCBCPY((sbyte*)alg, sizeof(alg), (sbyte*)CKM_AES);
            *pBlockSize = AES_BLOCK_SIZE;
            break;
        case CKK_DES:
            DIGI_STRCBCPY((sbyte*)alg, sizeof(alg), (sbyte*)CKM_DES);
            *pBlockSize = DES_BLOCK_SIZE;
            break;
        case CKK_DES3:
            DIGI_STRCBCPY((sbyte*)alg, sizeof(alg), (sbyte*)CKM_DES3);
            *pBlockSize = THREE_DES_BLOCK_SIZE;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key encryption algorithm, status = %d\n",
                    __FUNCTION__,__LINE__,
                    status);
            goto exit;
    }

    switch (mode)
    {
        case TAP_SYM_KEY_MODE_CBC:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"CBC);
            break;
        case TAP_SYM_KEY_MODE_ECB:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"ECB);
            break;
        case TAP_SYM_KEY_MODE_CTR:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"CTR);
            break;
        case TAP_SYM_KEY_MODE_OFB:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"OFB);
            break;
        case TAP_SYM_KEY_MODE_CFB:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"CFB128);
            break;
        case TAP_SYM_KEY_MODE_GCM:
            DIGI_STRCAT((sbyte*)alg, (sbyte*)"_"GCM);
            break;
        default:
            status = ERR_TAP_INVALID_SYM_MODE;
            DB_PRINT("%s.%d Invalid key encryption mode, status = %d\n",
                    __FUNCTION__,__LINE__,
                    status);
            goto exit;
    }

    for (i = 0; i < (sizeof(gSymAlgTable)/sizeof(P11SymAlgorithm)); i++)
    {
        if (0 == DIGI_STRNICMP((sbyte*)alg, (sbyte*)gSymAlgTable[i].pAlg, DIGI_STRLEN((sbyte*)alg)))
        {
            *pp11AlgId = gSymAlgTable[i].p11AlgId;
            break;
        }
    }


exit:
    return status;
}

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT__
MSTATUS SMP_API(PKCS11, encrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pBuffer,
        TAP_Buffer *pCipherBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    TAP_Attribute *pAttribute = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_PKCS1_5;
    TAP_Buffer ivBuf = {0};
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    TAP_Buffer label = {0};
    ubyte *pEncryptedBuffer = NULL;
    CK_ULONG encryptedBufLen = 0;
    ubyte *ppaddedBuffer = NULL;
    ubyte4 paddedBufferLen = 0;
    ubyte *pPlainText = NULL;
    ubyte4 plainTextLen = 0;
    ubyte4 listCount = 0;
    CK_ULONG tagLen = 0;
    TAP_Buffer aad = {0};
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    CK_OBJECT_CLASS classType = CKO_DATA;
    CK_ATTRIBUTE classTemplate[] = {
        {CKA_CLASS, &classType, sizeof(classType)}
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (0 == pGemObject->pubObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                case TAP_ATTR_ENC_LABEL:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid label structure length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    label.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    label.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;
                case TAP_ATTR_SYM_KEY_MODE:
                    if ((sizeof(TAP_SYM_KEY_MODE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Symmetric key mode. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    break;
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                case TAP_ATTR_TAG_LEN_BITS:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        tagLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    }
                    break;

                case TAP_ATTR_ADDITIONAL_AUTH_DATA:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    aad = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }
    
    if (TAP_OP_EXEC_FLAG_HW != opExecFlag)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Software operation not supported at SMP layer. status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get the type of the key handle. i.e. Asymmetric key or Symmetric Key */
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, classTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

#ifdef PKCS11_PROFILING
        gettimeofday(&startTv, &tz);
#endif
    if (CKO_PUBLIC_KEY == classType || CKO_PRIVATE_KEY == classType)
    {
        CK_ULONG ulBitLength = 0;
        CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
        CK_MECHANISM rsaEnc = { mechanism, NULL_PTR, 0 };
        CK_ATTRIBUTE rsaPubTemplate[] =
        {
            { CKA_MODULUS_BITS, &ulBitLength, sizeof(ulBitLength) }
        };

        switch (encScheme)
        {
            case TAP_ENC_SCHEME_PKCS1_5:
                rsaEnc.mechanism = CKM_RSA_PKCS;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA1:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA_1;
                oaepParams.mgf = CKG_MGF1_SHA1;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA224:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA224;
                oaepParams.mgf = CKG_MGF1_SHA224;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA256:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA256;
                oaepParams.mgf = CKG_MGF1_SHA256;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA384:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA384;
                oaepParams.mgf = CKG_MGF1_SHA384;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA512:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA512;
                oaepParams.mgf = CKG_MGF1_SHA512;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_NONE:
                rsaEnc.mechanism = CKM_RSA_X_509;
                break;
            default:
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)encScheme,
                        status);
                goto exit;
        }

        rVal = CALL_PKCS11_API(C_EncryptInit, pGemToken->tokenSession, &rsaEnc, pGemObject->pubObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_EncryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (OK != (status = DIGI_MALLOC((void**)&pEncryptedBuffer, ulBitLength)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        encryptedBufLen = (CK_ULONG)ulBitLength;
        rVal = CALL_PKCS11_API(C_Encrypt, pGemToken->tokenSession, pBuffer->pBuffer, pBuffer->bufferLen,
                     pEncryptedBuffer, &encryptedBufLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Encrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else if (CKO_SECRET_KEY == classType || CKO_DATA == classType)
    {
        /*Symmetric Key */
        ubyte4 blockSize = 0;
        CK_ULONG remaining = 0;
        CK_ULONG ulEncryptedDataLen;
        CK_ULONG p11AlgType;
        CK_MECHANISM_TYPE mechanism = CKM_AES_CBC;
        CK_KEY_TYPE keyType = CKK_AES;
        CK_AES_CTR_PARAMS ctrParams = {0};
        CK_GCM_PARAMS gcmParams = {0};
        CK_MECHANISM symMechanism = { mechanism, ivBuf.pBuffer, ivBuf.bufferLen };
        CK_ATTRIBUTE algTemplate[] =
        {
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
        };

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, algTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = PKCS11_getP11SymmetricAlgorithm(keyType, symMode, &p11AlgType, &blockSize);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        if ((CK_ULONG) -1 == p11AlgType)
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        symMechanism.mechanism = p11AlgType;

        if (CKM_AES_CTR == symMechanism.mechanism)
        {
            status = ERR_INVALID_INPUT;
            if (16 != ivBuf.bufferLen)
            {
                goto exit;
            }

            /* CloudHSM does not like anything above 32 bits */
            ctrParams.ulCounterBits = 32;

            status = DIGI_MEMCPY (
                (void *)ctrParams.cb, (void *)ivBuf.pBuffer, 16);
            if (OK != status)
                goto exit;

            symMechanism.pParameter = (void *)&ctrParams;
            symMechanism.ulParameterLen = sizeof(CK_AES_CTR_PARAMS);
        }
        else if(CKM_AES_GCM == symMechanism.mechanism)
        {
#if defined(__ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__)
            if (LIBTYPE_CLOUDHSM == pGemModule->libType)
#endif
#if defined(__ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__) || defined(__ENABLE_DIGICERT_CLOUDHSM_SUPPORT__)
            {
                /* For cloudhsm, they will write over the IV buffer with a new 12 byte
                 * nonce. They require the input ulIvBits to be zero, input bufferLen to
                 * be 12, and a zerod IV buffer. */
                if (12 != ivBuf.bufferLen)
                {
                    status = ERR_INVALID_INPUT;
                    goto exit;
                }

                DIGI_MEMSET(ivBuf.pBuffer, 0, ivBuf.bufferLen);
                gcmParams.ulIvBits = 0;
            }
#endif
#if defined(__ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__)
            else
#endif
#if !defined(__ENABLE_DIGICERT_CLOUDHSM_SUPPORT__)
            {
                gcmParams.ulIvBits = (CK_ULONG)(ivBuf.bufferLen * 8);
            }
#endif
            gcmParams.pIv = (CK_BYTE_PTR)ivBuf.pBuffer;
            gcmParams.ulIvLen = (CK_ULONG)ivBuf.bufferLen;
            gcmParams.ulTagBits = (CK_ULONG)tagLen;
            gcmParams.pAAD = (CK_BYTE_PTR)aad.pBuffer;
            gcmParams.ulAADLen = (CK_ULONG)aad.bufferLen;

            symMechanism.pParameter = (void *)&gcmParams;
            symMechanism.ulParameterLen = sizeof(CK_GCM_PARAMS);
        }

        rVal = CALL_PKCS11_API(C_EncryptInit, pGemToken->tokenSession, &symMechanism, pGemObject->pubObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_EncryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        /*Padding is required */
        remaining = pBuffer->bufferLen % blockSize;
        if (0 != remaining)
        {
            ubyte4 i = 0;
            /* Do PKCS#7 padding of the input*/
            if (OK != (status = DIGI_CALLOC((void**)&ppaddedBuffer, 1, (pBuffer->bufferLen + blockSize - remaining))))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            if (OK != (status = DIGI_MEMCPY((ubyte*)ppaddedBuffer, pBuffer->pBuffer, pBuffer->bufferLen)))
            {
                DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                         __FUNCTION__, __LINE__, status);
                goto exit;
            }

            for (i = 0; i < (blockSize - remaining); i++)
            {
                ppaddedBuffer[pBuffer->bufferLen + i] = (blockSize - remaining);
            }
            plainTextLen = paddedBufferLen = (pBuffer->bufferLen + blockSize - remaining);
            pPlainText = ppaddedBuffer;
        }
        else
        {
            pPlainText = pBuffer->pBuffer;
            plainTextLen = pBuffer->bufferLen;
        }

        rVal = CALL_PKCS11_API(C_Encrypt, pGemToken->tokenSession, pPlainText, plainTextLen,
                NULL_PTR, &ulEncryptedDataLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Encrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (OK != (status = DIGI_MALLOC((void**)&pEncryptedBuffer, ulEncryptedDataLen)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        encryptedBufLen = (CK_ULONG)ulEncryptedDataLen;
        rVal = CALL_PKCS11_API(C_Encrypt, pGemToken->tokenSession, pPlainText, plainTextLen,
                pEncryptedBuffer, &encryptedBufLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Encrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = ERR_TAP_UNSUPPORTED;
    }

#ifdef PKCS11_PROFILING
    {
        ubyte4 diff;
        gettimeofday(&endTv, &tz);

        diffTime = endTv.tv_sec - startTv.tv_sec;
        if (diffTime)
        {
            diffTime *= 1000000;
            diffTime += endTv.tv_usec;
            diffTime -= startTv.tv_usec;
        }
        else
        {
            diffTime = endTv.tv_usec - startTv.tv_usec;
        }

        diffSzInMb = (double)pBuffer->bufferLen / (1024*1024);
        diffTimeInSec = (double)diffTime / 1000000;
        diff = (ubyte4) (diffSzInMb / diffTimeInSec);
    }
#endif
    pCipherBuffer->pBuffer = pEncryptedBuffer;
    pCipherBuffer->bufferLen = (ubyte4)encryptedBufLen;
    pEncryptedBuffer = NULL;


exit:
    if (ppaddedBuffer != NULL)
        DIGI_FREE((void**)&ppaddedBuffer);
    if (pEncryptedBuffer != NULL)
        DIGI_FREE((void**)&pEncryptedBuffer);

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_INIT__
MSTATUS SMP_API(PKCS11, encryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    TAP_Attribute *pAttribute = NULL;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    ubyte4 listCount = 0;
    CK_ULONG tagLen = 0;
    TAP_Buffer ivBuf = {0};
    TAP_Buffer aad = {0};
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    CK_OBJECT_CLASS classType = CKO_DATA;
    CK_ATTRIBUTE classTemplate[] = {
        {CKA_CLASS, &classType, sizeof(classType)}
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif
    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (0 == pGemObject->pubObject))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if ((sizeof(TAP_SYM_KEY_MODE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Symmetric key mode. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    break;
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;
                case TAP_ATTR_TAG_LEN_BITS:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        tagLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    }
                    break;

                case TAP_ATTR_ADDITIONAL_AUTH_DATA:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    aad = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }
    
    if (TAP_OP_EXEC_FLAG_HW != opExecFlag)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Software operation not supported at SMP layer. status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get the type of the key handle. i.e. Asymmetric key or Symmetric Key */
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, classTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (CKO_PUBLIC_KEY == classType || CKO_PRIVATE_KEY == classType)
    {
        CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
        CK_MECHANISM rsaEnc = { mechanism, NULL_PTR, 0 };

        switch (encScheme)
        {
            case TAP_ENC_SCHEME_PKCS1_5:
                rsaEnc.mechanism = CKM_RSA_PKCS;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA1:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA_1;
                oaepParams.mgf = CKG_MGF1_SHA1;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA224:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA224;
                oaepParams.mgf = CKG_MGF1_SHA224;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA256:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA256;
                oaepParams.mgf = CKG_MGF1_SHA256;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA384:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA384;
                oaepParams.mgf = CKG_MGF1_SHA384;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA512:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA512;
                oaepParams.mgf = CKG_MGF1_SHA512;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_NONE:
                rsaEnc.mechanism = CKM_RSA_X_509;
                break;
            default:
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)encScheme,
                        status);
                goto exit;
        }
        rVal = CALL_PKCS11_API(C_EncryptInit, pGemToken->tokenSession, &rsaEnc, pGemObject->pubObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_EncryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else if (CKO_SECRET_KEY == classType || CKO_DATA == classType)
    {
        ubyte4 blockSize = 0;
        CK_ULONG p11AlgType;
        CK_KEY_TYPE keyType = CKK_AES;
        CK_MECHANISM_TYPE mechanism = CKM_AES_CBC;
        CK_AES_CTR_PARAMS ctrParams = {0};
        CK_GCM_PARAMS gcmParams = {0};
        CK_MECHANISM symMechanism = { mechanism, ivBuf.pBuffer, ivBuf.bufferLen };
        CK_ATTRIBUTE algTemplate[] =
        {
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
        };

        /* Get the key type in case this isnt AES */
        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, algTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_EncryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = PKCS11_getP11SymmetricAlgorithm(keyType, symMode, &p11AlgType, &blockSize);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        if ((CK_ULONG) -1 == p11AlgType)
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        symMechanism.mechanism = p11AlgType;
        if (CKM_AES_CTR == symMechanism.mechanism)
        {
            status = ERR_INVALID_INPUT;
            if (16 != ivBuf.bufferLen)
            {
                goto exit;
            }

            /* CloudHSM does not like anything above 32 bits */
            ctrParams.ulCounterBits = 8;

            status = DIGI_MEMCPY (
                (void *)ctrParams.cb, (void *)ivBuf.pBuffer, 16);
            if (OK != status)
                goto exit;

            symMechanism.pParameter = (void *)&ctrParams;
            symMechanism.ulParameterLen = sizeof(CK_AES_CTR_PARAMS);
        }
        else if(CKM_AES_GCM == symMechanism.mechanism)
        {
            gcmParams.pIv = (CK_BYTE_PTR)ivBuf.pBuffer;
            gcmParams.ulIvLen = (CK_ULONG)ivBuf.bufferLen;
            gcmParams.ulIvBits = (CK_ULONG)(ivBuf.bufferLen * 8);
            gcmParams.ulTagBits = (CK_ULONG)tagLen;
            gcmParams.pAAD = (CK_BYTE_PTR)aad.pBuffer;
            gcmParams.ulAADLen = (CK_ULONG)aad.bufferLen;

            symMechanism.pParameter = (void *)&gcmParams;
            symMechanism.ulParameterLen = sizeof(CK_GCM_PARAMS);
        }

        rVal = CALL_PKCS11_API(C_EncryptInit, pGemToken->tokenSession, &symMechanism, pGemObject->pubObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_EncryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = ERR_TAP_UNSUPPORTED;
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_UPDATE__
MSTATUS SMP_API(PKCS11, encryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext,
        TAP_Buffer *pCipherBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    byteBoolean isMutexLocked = FALSE;
    CK_ULONG maxOutputLen = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (NULL == pCipherBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_EncryptUpdate, pGemToken->tokenSession, pBuffer->pBuffer,
                           pBuffer->bufferLen, NULL_PTR, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_EncryptUpdate Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)&pCipherBuffer->pBuffer, 1,
                             maxOutputLen)))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_EncryptUpdate, pGemToken->tokenSession, pBuffer->pBuffer,
                           pBuffer->bufferLen, pCipherBuffer->pBuffer, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_EncryptUpdate Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pCipherBuffer->bufferLen = (ubyte4) maxOutputLen;

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_FINAL__
MSTATUS SMP_API(PKCS11, encryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pCipherBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    byteBoolean isMutexLocked = FALSE;
    ubyte *pBuffer = NULL;
    CK_ULONG maxOutputLen = 0;
    CK_BYTE *pDummy = (CK_BYTE *) "a";
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (NULL == pCipherBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_EncryptFinal, pGemToken->tokenSession, NULL_PTR, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_EncryptFinal Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    if (maxOutputLen)
    {
        if (OK != (status = DIGI_CALLOC((void**)&pCipherBuffer->pBuffer, 1,
                                maxOutputLen)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBuffer = pCipherBuffer->pBuffer;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_PKCS11_TEE__
        /* For the TEE implementation, if the outputLen is zero then the operation is
         * considered finalized and any additional call to EncryptFinal will yield an error */
        pCipherBuffer->bufferLen = (ubyte4) maxOutputLen;
        status = OK;
        goto exit;
#endif
        /* Passing a NULL pointer does not necessarily finalize a cipher operation,
         * so pass in a dummy pointer with a *pUlEncryptedPartLen = 0 */
        pBuffer = pDummy;
    }

    rVal = CALL_PKCS11_API(C_EncryptFinal, pGemToken->tokenSession, pBuffer, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_EncryptFinal Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pCipherBuffer->bufferLen = (ubyte4) maxOutputLen;

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT__
MSTATUS SMP_API(PKCS11, decrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pCipherBuffer,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    TAP_Attribute *pAttribute = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_PKCS1_5;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    TAP_Buffer label = {0};
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    ubyte *pDecryptedBuffer = NULL;
    CK_ULONG decryptedBufLen = 0;
    ubyte4 listCount = 0;
    CK_ULONG tagLen = 0;
    TAP_Buffer ivBuf = {0};
    TAP_Buffer aad = {0};
    CK_OBJECT_CLASS classType = CKO_DATA;
    CK_ATTRIBUTE classTemplate[] = {
        {CKA_CLASS, &classType, sizeof(classType)}
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) ||
        (NULL == pGemObject) || (0 == pGemObject->prvObject) ||
        (0 == pGemToken->tokenSession))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                case TAP_ATTR_ENC_LABEL:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid label structure length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    label.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    label.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;
                case TAP_ATTR_SYM_KEY_MODE:
                    if ((sizeof(TAP_SYM_KEY_MODE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Symmetric key mode. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    break;
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                case TAP_ATTR_TAG_LEN_BITS:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        tagLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    }
                    break;

                case TAP_ATTR_ADDITIONAL_AUTH_DATA:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    aad = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }
    
    if (TAP_OP_EXEC_FLAG_HW != opExecFlag)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Software operation not supported at SMP layer. status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get the type of the key handle. i.e. Asymmetric key or Symmetric Key */
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, classTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

#ifdef PKCS11_PROFILING
    gettimeofday(&startTv, &tz);
#endif

    if (CKO_PUBLIC_KEY == classType || CKO_PRIVATE_KEY == classType)
    {
        CK_ULONG ulBitLength = 0;
        CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
        CK_MECHANISM rsaEnc = { mechanism, NULL_PTR, 0 };
        CK_ATTRIBUTE rsaPubTemplate[] =
        {
            { CKA_MODULUS_BITS, &ulBitLength, sizeof(ulBitLength) }
        };

        switch (encScheme)
        {
            case TAP_ENC_SCHEME_PKCS1_5:
                rsaEnc.mechanism = CKM_RSA_PKCS;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA1:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA_1;
                oaepParams.mgf = CKG_MGF1_SHA1;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA224:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA224;
                oaepParams.mgf = CKG_MGF1_SHA224;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA256:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA256;
                oaepParams.mgf = CKG_MGF1_SHA256;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA384:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA384;
                oaepParams.mgf = CKG_MGF1_SHA384;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA512:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA512;
                oaepParams.mgf = CKG_MGF1_SHA512;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                break;
            case TAP_ENC_SCHEME_NONE:
                rsaEnc.mechanism = CKM_RSA_X_509;
                break;
            default:
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)encScheme,
                        status);
                goto exit;
        }

        /* IDGo800 Mentions that Only RSA public keys are supported either as session objects or
           token objects. */
        rVal = CALL_PKCS11_API(C_DecryptInit, pGemToken->tokenSession, &rsaEnc, pGemObject->prvObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_DecryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }


        if (OK != (status = DIGI_MALLOC((void**)&pDecryptedBuffer, ulBitLength)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        decryptedBufLen = (CK_ULONG)ulBitLength;
        rVal = CALL_PKCS11_API(C_Decrypt, pGemToken->tokenSession, pCipherBuffer->pBuffer, pCipherBuffer->bufferLen,
                     pDecryptedBuffer, &decryptedBufLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Decrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else if (CKO_SECRET_KEY == classType || CKO_DATA == classType)
    {
        /*Symmetric Key */
        CK_MECHANISM_TYPE mechanism = CKM_AES_CBC;
        CK_KEY_TYPE keyType = CKK_AES;
        ubyte4 blockSize = 0;
        CK_ULONG p11AlgType;
        ubyte4 i = 0;
        CK_ULONG ulDecryptedDataLen;
        CK_AES_CTR_PARAMS ctrParams = {0};
        CK_GCM_PARAMS gcmParams = {0};
        CK_MECHANISM symMechanism = { mechanism, ivBuf.pBuffer, ivBuf.bufferLen };
        CK_ATTRIBUTE algTemplate[] =
        {
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
        };

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, algTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = PKCS11_getP11SymmetricAlgorithm(keyType, symMode, &p11AlgType, &blockSize);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        if ((CK_ULONG) -1 == p11AlgType)
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }
        symMechanism.mechanism = p11AlgType;

        if (CKM_AES_CTR == symMechanism.mechanism)
        {
            status = ERR_INVALID_INPUT;
            if (16 != ivBuf.bufferLen)
            {
                goto exit;
            }

            /* CloudHSM does not like anything above 32 bits */
            ctrParams.ulCounterBits = 32;

            status = DIGI_MEMCPY (
                (void *)ctrParams.cb, (void *)ivBuf.pBuffer, 16);
            if (OK != status)
                goto exit;

            symMechanism.pParameter = (void *)&ctrParams;
            symMechanism.ulParameterLen = sizeof(CK_AES_CTR_PARAMS);
        }
        else if(CKM_AES_GCM == symMechanism.mechanism)
        {
            gcmParams.pIv = (CK_BYTE_PTR)ivBuf.pBuffer;
            gcmParams.ulIvLen = (CK_ULONG)ivBuf.bufferLen;
            gcmParams.ulIvBits = (CK_ULONG)(ivBuf.bufferLen * 8);
            gcmParams.ulTagBits = (CK_ULONG)tagLen;
            gcmParams.pAAD = (CK_BYTE_PTR)aad.pBuffer;
            gcmParams.ulAADLen = (CK_ULONG)aad.bufferLen;

            symMechanism.pParameter = (void *)&gcmParams;
            symMechanism.ulParameterLen = sizeof(CK_GCM_PARAMS);
        }

        rVal = CALL_PKCS11_API(C_DecryptInit, pGemToken->tokenSession, &symMechanism, pGemObject->prvObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_DecryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_Decrypt, pGemToken->tokenSession, pCipherBuffer->pBuffer, pCipherBuffer->bufferLen,
                NULL_PTR, &ulDecryptedDataLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Decrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (OK != (status = DIGI_MALLOC((void**)&pDecryptedBuffer, ulDecryptedDataLen)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        decryptedBufLen = (CK_ULONG)ulDecryptedDataLen;
        rVal = CALL_PKCS11_API(C_Decrypt, pGemToken->tokenSession, pCipherBuffer->pBuffer, pCipherBuffer->bufferLen,
                pDecryptedBuffer, &decryptedBufLen);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_Encrypt Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        /* Remove PKCS#7 padding if any*/
        ubyte pad = 0;
        pad = pDecryptedBuffer[decryptedBufLen-1];
        for (i = decryptedBufLen-1; i > (decryptedBufLen-1-pad); --i)
        {
            if (pad != pDecryptedBuffer[i])
            {
                break;
            }
        }

        if (i == decryptedBufLen-1-pad)
            decryptedBufLen = decryptedBufLen - (ubyte4)pad;

    }
    else
    {
        status = ERR_TAP_UNSUPPORTED;
    }

#ifdef PKCS11_PROFILING
    {
        ubyte4 diff;
        gettimeofday(&endTv, &tz);

        diffTime = endTv.tv_sec - startTv.tv_sec;
        if (diffTime)
        {
            diffTime *= 1000000;
            diffTime += endTv.tv_usec;
            diffTime -= startTv.tv_usec;
        }
        else
        {
            diffTime = endTv.tv_usec - startTv.tv_usec;
        }

        diffSzInMb = (double)pBuffer->bufferLen / (1024*1024);
        diffTimeInSec = (double)diffTime / 1000000;
        diff = (ubyte4) (diffSzInMb / diffTimeInSec);
    }
#endif
    if (OK != (status = DIGI_CALLOC((void**)&pBuffer->pBuffer, 1, (ubyte4)decryptedBufLen)))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    if (OK != (status = DIGI_MEMCPY((ubyte*)pBuffer->pBuffer, pDecryptedBuffer, (ubyte4)decryptedBufLen)))
    {
        DB_PRINT("%s.%d Failed to copy buffer. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pBuffer->bufferLen = (ubyte4)decryptedBufLen;

exit:
    if (NULL != pDecryptedBuffer)
        DIGI_FREE((void**)&pDecryptedBuffer);
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_INIT__
MSTATUS SMP_API(PKCS11, decryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    TAP_Attribute *pAttribute = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    ubyte4 listCount = 0;
    CK_ULONG tagLen = 0;
    TAP_Buffer ivBuf = {0};
    TAP_Buffer aad = {0};
    CK_OBJECT_CLASS classType = CKO_DATA;
    CK_ATTRIBUTE classTemplate[] = {
        {CKA_CLASS, &classType, sizeof(classType)}
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) ||
        (NULL == pGemObject) || (0 == pGemObject->prvObject) ||
        (0 == pGemToken->tokenSession))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if ((sizeof(TAP_SYM_KEY_MODE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Symmetric key mode. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    break;
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;
                case TAP_ATTR_TAG_LEN_BITS:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid salt length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        tagLen = (CK_ULONG) *((ubyte4 *)(pAttribute->pStructOfType));
                    }
                    break;

                case TAP_ATTR_ADDITIONAL_AUTH_DATA:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    aad = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if (TAP_OP_EXEC_FLAG_HW != opExecFlag)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Software operation not supported at SMP layer. status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get the type of the key handle. i.e. Asymmetric key or Symmetric Key */
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, classTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (CKO_PUBLIC_KEY == classType || CKO_PRIVATE_KEY == classType)
    {
        CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
        CK_MECHANISM_TYPE mechanism = CKM_RSA_PKCS;
        CK_MECHANISM rsaEnc = { mechanism, NULL_PTR, 0 };

        switch (encScheme)
        {
            case TAP_ENC_SCHEME_PKCS1_5:
                rsaEnc.mechanism = CKM_RSA_PKCS;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA1:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA_1;
                oaepParams.mgf = CKG_MGF1_SHA1;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_OAEP_SHA224:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA224;
                oaepParams.mgf = CKG_MGF1_SHA224;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
           case TAP_ENC_SCHEME_OAEP_SHA256:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA256;
                oaepParams.mgf = CKG_MGF1_SHA256;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
           case TAP_ENC_SCHEME_OAEP_SHA384:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA384;
                oaepParams.mgf = CKG_MGF1_SHA384;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
           case TAP_ENC_SCHEME_OAEP_SHA512:
                rsaEnc.mechanism = CKM_RSA_PKCS_OAEP;
                rsaEnc.pParameter = &oaepParams;
                rsaEnc.ulParameterLen = sizeof(oaepParams);
                oaepParams.hashAlg = CKM_SHA512;
                oaepParams.mgf = CKG_MGF1_SHA512;
                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = NULL;
                oaepParams.ulSourceDataLen = 0;
                break;
            case TAP_ENC_SCHEME_NONE:
                rsaEnc.mechanism = CKM_RSA_X_509;
                break;
            default:
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)encScheme,
                        status);
                goto exit;
        }

        rVal = CALL_PKCS11_API(C_DecryptInit, pGemToken->tokenSession, &rsaEnc, pGemObject->prvObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_DecryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else if (CKO_SECRET_KEY == classType || CKO_DATA == classType)
    {
        /*Symmetric Key */
        CK_MECHANISM_TYPE mechanism = CKM_AES_CBC;
        CK_KEY_TYPE keyType = CKK_AES;
        ubyte4 blockSize = 0;
        CK_ULONG p11AlgType;
        CK_AES_CTR_PARAMS ctrParams = {0};
        CK_GCM_PARAMS gcmParams = {0};
        CK_MECHANISM symMechanism = { mechanism, ivBuf.pBuffer, ivBuf.bufferLen };
        CK_ATTRIBUTE algTemplate[] =
        {
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)}
        };

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, algTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_GetAttributeValue Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = PKCS11_getP11SymmetricAlgorithm(keyType, symMode, &p11AlgType, &blockSize);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        if ((CK_ULONG) -1 == p11AlgType)
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Failed to get the Algorithm. status=%d\n",
                     __FUNCTION__, __LINE__, status);
            goto exit;
        }

        symMechanism.mechanism = p11AlgType;
        if (CKM_AES_CTR == symMechanism.mechanism)
        {
            status = ERR_INVALID_INPUT;
            if (16 != ivBuf.bufferLen)
            {
                goto exit;
            }

            /* CloudHSM does not like anything above 32 bits */
            ctrParams.ulCounterBits = 32;

            status = DIGI_MEMCPY (
                (void *)ctrParams.cb, (void *)ivBuf.pBuffer, 16);
            if (OK != status)
                goto exit;

            symMechanism.pParameter = (void *)&ctrParams;
            symMechanism.ulParameterLen = sizeof(CK_AES_CTR_PARAMS);
        }
        else if(CKM_AES_GCM == symMechanism.mechanism)
        {
            gcmParams.pIv = (CK_BYTE_PTR)ivBuf.pBuffer;
            gcmParams.ulIvLen = (CK_ULONG)ivBuf.bufferLen;
            gcmParams.ulIvBits = (CK_ULONG)(ivBuf.bufferLen * 8);
            gcmParams.ulTagBits = (CK_ULONG)tagLen;
            gcmParams.pAAD = (CK_BYTE_PTR)aad.pBuffer;
            gcmParams.ulAADLen = (CK_ULONG)aad.bufferLen;

            symMechanism.pParameter = (void *)&gcmParams;
            symMechanism.ulParameterLen = sizeof(CK_GCM_PARAMS);
        }

        rVal = CALL_PKCS11_API(C_DecryptInit, pGemToken->tokenSession, &symMechanism, pGemObject->prvObject);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d C_DecryptInit Failed. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = ERR_TAP_UNSUPPORTED;
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_UPDATE__
MSTATUS SMP_API(PKCS11, decryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pCipherBuffer,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    byteBoolean isMutexLocked = FALSE;
    CK_ULONG maxOutputLen = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (NULL == pCipherBuffer) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_DecryptUpdate, pGemToken->tokenSession, pCipherBuffer->pBuffer,
                           pCipherBuffer->bufferLen, NULL_PTR, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_DecryptUpdate Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)&pBuffer->pBuffer, 1,
                             maxOutputLen)))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_DecryptUpdate, pGemToken->tokenSession, pCipherBuffer->pBuffer,
                           pCipherBuffer->bufferLen, pBuffer->pBuffer, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_DecryptUpdate Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pBuffer->bufferLen = (ubyte4) maxOutputLen;

    /* AES-GCM may have written zero bytes of data. If so then free
     * the allocated buffer */
    if ( (NULL != pBuffer->pBuffer) && (0 == pBuffer->bufferLen) )
    {
        DIGI_FREE((void **)&(pBuffer->pBuffer));
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_FINAL__
MSTATUS SMP_API(PKCS11, decryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    byteBoolean isMutexLocked = FALSE;
    CK_ULONG maxOutputLen = 0;
    CK_BYTE *pDummy = (CK_BYTE *) "a";
    CK_BYTE *pBufToUse = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
    {
        DB_PRINT("%s.%d Mutex wait Failed status:%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) ||
          (NULL == pBuffer) || (0 == pGemToken->tokenSession))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input. status:%d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_DecryptFinal, pGemToken->tokenSession, NULL_PTR, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_DecryptFinal Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    if (maxOutputLen)
    {
        if (OK != (status = DIGI_CALLOC((void**)&pBuffer->pBuffer, 1,
                                maxOutputLen)))
        {
            DB_PRINT("%s.%d Failed to allocate memory. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBufToUse = pBuffer->pBuffer;
    }
    else
    {
#ifdef __ENABLE_DIGICERT_PKCS11_TEE__
        /* For the TEE PKCS11 implementation, if the outputLen is zero then the operation is
         * considered finalized and any additional call to EncryptFinal will yield an error */
        pBuffer->bufferLen = (ubyte4) maxOutputLen;
        status = OK;
        goto exit;
#endif
        /* Passing a NULL pointer does not necessarily finalize a cipher operation,
         * so pass in a dummy pointer with a *pUlEncryptedPartLen = 0 */
        pBufToUse = pDummy;
    }

    rVal = CALL_PKCS11_API(C_DecryptFinal, pGemToken->tokenSession, pBufToUse, &maxOutputLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_DecryptFinal Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pBuffer->bufferLen = (ubyte4) maxOutputLen;

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST__
MSTATUS SMP_API(PKCS11, digest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pInputBuffer,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    ulong len = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pInputBuffer) || (NULL == pBuffer))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

#ifdef PKCS11_PROFILING
    gettimeofday(&startTv, &tz);
#endif
    /* Required for ulong */
    len = pBuffer->bufferLen;
    rVal = CALL_PKCS11_API(C_Digest, pGemToken->tokenSession, pInputBuffer->pBuffer, pInputBuffer->bufferLen, pBuffer->pBuffer, &len);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto null_exit;
    }
    pBuffer->bufferLen = len;

#ifdef PKCS11_PROFILING
    gettimeofday(&endTv, &tz);

    diffTime = endTv.tv_sec - startTv.tv_sec;
    if (diffTime)
    {
        diffTime *= 1000000;
        diffTime += endTv.tv_usec;
        diffTime -= startTv.tv_usec;
    }
    else
    {
        diffTime = endTv.tv_usec - startTv.tv_usec;
    }

    diffSzInMb = (double)pInputBuffer->bufferLen / (1024*1024);
    diffTimeInSec = (double)diffTime / 1000000;
    pInputBuffer->bufferLen = (ubyte4) (diffSzInMb / diffTimeInSec);
#endif


null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_INIT__
MSTATUS SMP_API(PKCS11,digestInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    TAP_HASH_ALG mechType;

    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    CK_MECHANISM mechanism = { 0, NULL_PTR, 0 };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pMechanism))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    mechType = *((TAP_HASH_ALG *)pMechanism->pAttributeList->pStructOfType);

    switch(mechType)
    {
        case TAP_HASH_ALG_SHA1:
            mechanism.mechanism = CKM_SHA_1;
            break;

         case TAP_HASH_ALG_SHA224:
            mechanism.mechanism = CKM_SHA224;
            break;

        case TAP_HASH_ALG_SHA256:
            mechanism.mechanism = CKM_SHA256;
            break;

        case TAP_HASH_ALG_SHA384:
            mechanism.mechanism = CKM_SHA384;
            break;

        case TAP_HASH_ALG_SHA512:
            mechanism.mechanism = CKM_SHA512;
            break;

        case TAP_HASH_ALG_NONE:
            mechanism.mechanism = CKM_MD5;
            break;

        default:
            PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
            goto null_exit;
    }

    rVal = CALL_PKCS11_API(C_DigestInit, pGemToken->tokenSession, &mechanism);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_UPDATE__
MSTATUS SMP_API(PKCS11, digestUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pBuffer))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_DigestUpdate, pGemToken->tokenSession, pBuffer->pBuffer, pBuffer->bufferLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto null_exit;
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_FINAL__
MSTATUS SMP_API(PKCS11, digestFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    ulong len = 0;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pBuffer))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    /* Required for ulong */
    len = pBuffer->bufferLen;
    rVal = CALL_PKCS11_API(C_DigestFinal, pGemToken->tokenSession, pBuffer->pBuffer, &len);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto null_exit;
    }
    pBuffer->bufferLen = len;

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_RANDOM__
MSTATUS SMP_API(PKCS11, getRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest,
        ubyte4 bytesRequested,
        TAP_Buffer *pRandom
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (!bytesRequested) || (NULL == pRandom))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    pRandom->pBuffer = MALLOC(bytesRequested);
    pRandom->bufferLen = bytesRequested;
    rVal = CALL_PKCS11_API(C_GenerateRandom, pGemToken->tokenSession, pRandom->pBuffer, bytesRequested);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

null_exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_STIR_RANDOM__
MSTATUS SMP_API(PKCS11, stirRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TRUSTED_DATA__
MSTATUS SMP_API(PKCS11, getTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_Buffer *pDataValue
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UPDATE_TRUSTED_DATA__
MSTATUS SMP_API(PKCS11, updateTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_TRUSTED_DATA_OPERATION trustedDataOp,
        TAP_Buffer *pDataValue,
        TAP_Buffer *pUpdatedDataValue
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
MSTATUS SMP_API(PKCS11, sealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToSeal,
        TAP_Buffer *pDataOut
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
MSTATUS SMP_API(PKCS11, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
MSTATUS SMP_API(PKCS11, setPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PolicyStorageAttributes *pPolicyAttributes,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);
    byteBoolean isLocalLoggedIn = FALSE;
    TAP_Credential* pCredential = NULL;
    TAP_EntityCredentialList* pCredentials = NULL;

    CK_OBJECT_CLASS data_class = ~0;
    CK_ATTRIBUTE objTypeTemplate = {CKA_CLASS, &data_class, sizeof(CK_OBJECT_CLASS)};
    CK_ATTRIBUTE dataTemplate = {CKA_VALUE, NULL, 0};
    byteBoolean isMutexLocked = FALSE;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (NULL == pData))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    dataTemplate.pValue = pData->pBuffer;
    dataTemplate.ulValueLen = pData->bufferLen;

    /*Secure data only supported on Token_0 of pkcs11 module */
    if (TOKEN_0 != pGemToken->tokenId)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    if (FALSE == pGemToken->isLoggedIn)
    {
        if (pOpAttributes)
        {
            pCredentials = (TAP_EntityCredentialList*)PKCS11_fetchAttributeFromList(pOpAttributes, TAP_ATTR_CREDENTIAL, NULL);
            if (NULL != pCredentials)
            {
                pCredential = PKCS11_fetchCredentialFromList(
                                    &pCredentials->pEntityCredentials->credentialList, TAP_CREDENTIAL_CONTEXT_USER);

                if (NULL != pCredential)
                {
                    if (NULL != pCredential->credentialData.pBuffer)
                    {
                        rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer,
                                pCredential->credentialData.bufferLen);

                        /* If the user is already logged in then proceed. */
                        if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                        {
                            rVal = CKR_OK;
                        }

                        if (CKR_OK != rVal)
                        {
                            status = PKCS11_nanosmpErr(pGemModule, rVal);
                            goto exit;
                        }
                        isLocalLoggedIn = TRUE;
                        pGemToken->isLoggedIn = TRUE;
                    }
                }
            }
        }
    }

    if (FALSE == pGemToken->isLoggedIn)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, &objTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    if (CKO_DATA != data_class)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_SetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, &dataTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
    }

exit:
    if (TRUE == isLocalLoggedIn)
    {
        CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
        pGemToken->isLoggedIn = FALSE;
        isLocalLoggedIn = FALSE;
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
MSTATUS SMP_API(PKCS11, getPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);
    byteBoolean isLocalLoggedIn = FALSE;
    TAP_Credential* pCredential = NULL;
    TAP_EntityCredentialList* pCredentials = NULL;

    CK_OBJECT_CLASS data_class = ~0;
    CK_ATTRIBUTE objTypeTemplate = {CKA_CLASS, &data_class, sizeof(CK_OBJECT_CLASS)};

    CK_ATTRIBUTE dataTemplate = {CKA_VALUE, NULL, 0};
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || (NULL == pData))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    /*Secure data only supported on Token_0 of pkcs11 module */
    if (TOKEN_0 != pGemToken->tokenId)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    if (FALSE == pGemToken->isLoggedIn)
    {
        if (NULL != pOpAttributes)
        {
            pCredentials = (TAP_EntityCredentialList*)PKCS11_fetchAttributeFromList(pOpAttributes, TAP_ATTR_CREDENTIAL, NULL);
            if (NULL != pCredentials)
            {
                pCredential = PKCS11_fetchCredentialFromList(
                                    &pCredentials->pEntityCredentials->credentialList, TAP_CREDENTIAL_CONTEXT_USER);

                if (NULL != pCredential)
                {
                    if (NULL != pCredential->credentialData.pBuffer)
                    {
                        rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer,
                                pCredential->credentialData.bufferLen);

                        /* If the user is already logged in then proceed. */
                        if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                        {
                            rVal = CKR_OK;
                        }

                        if (CKR_OK != rVal)
                        {
                            status = PKCS11_nanosmpErr(pGemModule, rVal);
                            goto exit;
                        }
                        isLocalLoggedIn = TRUE;
                        pGemToken->isLoggedIn = TRUE;
                    }
                }
            }
        }
    }

    if (FALSE == pGemToken->isLoggedIn)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, &objTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        goto exit;
    }

    if (CKO_DATA == data_class)
    {
        dataTemplate.pValue = MALLOC(MAX_DATA_STORAGE);
        dataTemplate.ulValueLen = MAX_DATA_STORAGE;
        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->prvObject, &dataTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
    }

    pData->pBuffer = dataTemplate.pValue;
    pData->bufferLen = dataTemplate.ulValueLen;

exit:
    if (TRUE == isLocalLoggedIn)
    {
        CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);

        pGemToken->isLoggedIn = FALSE;
        isLocalLoggedIn = FALSE;
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS__

#ifdef __ENABLE_DIGICERT_SMP_PKCS11_FULLCMC__
TPM2_AK_CSR_INFO CsrInfo = {0};
#endif

MSTATUS
SMP_API(PKCS11, getCertificateRequestValidationAttrs,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pBase64Blob

)
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_SMP_PKCS11_FULLCMC__
    ubyte *pCsrInfoSerialized = NULL;
    TPM2_AK_CSR_INFO  *pCsrInfo = NULL;
    ubyte4 serializationOffset = 0;
    TAP_PublicKey *pPubKey = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (0 == objectHandle) || (NULL == pBase64Blob))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, tokenHandle = %p,"
                "objectHandle = %p, pBase64Blob = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle,
                objectHandle, pBase64Blob);
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = ((Pkcs11_Module*)((uintptr)moduleHandle))->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    pCsrInfo = &CsrInfo;
    DIGI_MEMSET((ubyte *)pCsrInfo, 0,  sizeof(TPM2_AK_CSR_INFO));
    /*
     * At worst, the serialized size is the same as the structure size. allocate memory
     */
    if (OK != (status = DIGI_CALLOC((void **)&pCsrInfoSerialized, 1, sizeof(TPM2_AK_CSR_INFO))))
    {
        DB_PRINT("%s.%d Failed to allocate memory for serialized CSR info, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
/*    RANDOM_numberGenerator(g_pRandomContext, pCsrInfo, sizeof(*pCsrInfo)); */
    pCsrInfo->ekObjectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT |
                       TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_FIXEDTPM ;
    pCsrInfo->akPublicArea.objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT |
                       TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_FIXEDTPM ;
    pCsrInfo->akPublicArea.type = TPM2_ALG_RSA ;
    pCsrInfo->ekNameAlg = TPM2_ALG_SHA256;
    pCsrInfo->akPublicArea.nameAlg = TPM2_ALG_SHA256;
    CALL_SMP_API(PKCS11,getPublicKey,moduleHandle, tokenHandle, objectHandle, &pPubKey) ;
    if(OK != status)
    {
        DB_PRINT("%s.%d Failed to get the public key, status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pCsrInfo->akPublicArea.unique.rsa.buffer, pPubKey->publicKey.rsaKey.pModulus, pPubKey->publicKey.rsaKey.modulusLen);
    if(OK != status)
    {
        DB_PRINT("%s.%d Failed to get the public key, status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pCsrInfo->akPublicArea.unique.rsa.size = pPubKey->publicKey.rsaKey.modulusLen;
    pCsrInfo->akPublicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    pCsrInfo->akPublicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
 /*   pCsrInfo->akPublicArea.parameters.rsaDetail.scheme.details = TPM2_ALG_NULL; */

    if (OK != (status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_AK_CSR_INFO,
            TAP_SD_IN,
            (ubyte *)pCsrInfo, sizeof(TPM2_AK_CSR_INFO),
            pCsrInfoSerialized, sizeof(TPM2_AK_CSR_INFO),
            &serializationOffset)))
    {
        DB_PRINT("%s.%d Failed to serialize csr info, status  = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }


    if (OK != (status = BASE64_encodeMessage((ubyte *)pCsrInfoSerialized, serializationOffset,
            (ubyte **)&(pBase64Blob->blob.pBuffer), &(pBase64Blob->blob.bufferLen))))
    {
        DB_PRINT("%s.%d Failed to base64 encode serialized csr info, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
exit:

    if (pCsrInfoSerialized)
        shredMemory((ubyte **)&pCsrInfoSerialized, sizeof(TPM2_AK_CSR_INFO), TRUE);

    if(pPubKey)
       CALL_SMP_API(PKCS11, freePublicKey, &pPubKey) ;

null_exit:
#else
    status = ERR_NOT_IMPLEMENTED;
#endif
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNWRAP_KEY_VALIDATED_SECRET__


MSTATUS SMP_API(PKCS11, unWrapKeyValidatedSecret,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectHandle rtKeyHandle,
        TAP_Blob *pBlob,
        TAP_Buffer *pSecret
)
{
    MSTATUS status = OK;
#ifdef __ENABLE_DIGICERT_SMP_PKCS11_FULLCMC__
    ubyte *pDecodedBlob = NULL;
    ubyte4 decodedBlobLen = 0;
    ubyte4 offset = 0;
    ubyte*      pKeyBlob = NULL;
    ubyte4      keyBlobLen;
    ubyte *pPlainSecret = NULL;
    ubyte *pEncryptKey = NULL;
    TPM2_AK_CSR_INFO  *pCsrInfo = NULL;
    ubyte4 secretLen = 0;
    AsymmetricKey asymKey={0};
    TPM2B_NAME akName = {0};
    TPM2B_DIGEST symKey = {0};
    TPM2B_DIGEST hmacKey = {0};
    TPM2_MAKE_CREDENTIAL_RSP_PARAMS rspParams = {0};
    BulkCtx aesCfbCtx = NULL;
    ubyte ivEncrypt[16] = {0};
    ubyte encryptKey[128] = {0};
    ubyte4 roundedSize = 0;
    ubyte pTemp[2] = {0};
    ubyte2 tempSecLen = 0;

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (0 == objectHandle)  ||
            (NULL == pBlob) || (NULL == pSecret))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, tokenHandle = %p, "
                "objectHandle = %p, rtKeyHandle = %p, pBlob = %p, "
                "pSecret = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle,
                objectHandle, rtKeyHandle, pBlob, pSecret);
        goto exit;
    }

    if (  (NULL == pBlob->blob.pBuffer)
       || (0 >= pBlob->blob.bufferLen) )
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid input, secret to unwrap cannot be empty. "
                "buffer = %p, buffer length= %d\n",
                __FUNCTION__, __LINE__,
                pBlob->blob.pBuffer, pBlob->blob.bufferLen);
        goto exit;
    }

    if (OK != (status = BASE64_decodeMessage((const ubyte*)pBlob->blob.pBuffer,
            pBlob->blob.bufferLen, &pDecodedBlob, &decodedBlobLen)))
    {
        DB_PRINT("%s.%d Failed to decode base64 blob, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    if (OK != (status = SAPI2_SERIALIZE_serialize(
            SAPI2_ST_TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS,
            TAP_SD_OUT,
            pDecodedBlob,
            decodedBlobLen,
            (ubyte *)&(rspParams),
            sizeof rspParams,
            &offset)))
    {
        DB_PRINT("%s.%d Failed to deserialize decoded base64 blob, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (OK > (status = DIGICERT_readFile(MOC_SMP_PKCS11_RT_KEY,
                                       &pKeyBlob,
                                       &keyBlobLen)))
    {
        DB_PRINT("%s.%d failed to read server key. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = CRYPTO_initAsymmetricKey (&asymKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d failed to init asymmetric key. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    status = CRYPTO_deserializeAsymKey (
                pKeyBlob, keyBlobLen, NULL, &asymKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d failed to deserialize the root trust key. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    status = CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(MOC_RSA(0) (const RSAKey *)asymKey.key.pRSA,sha256withRSAEncryption,MOC_PKCS1_ALG_MGF1,sha256withRSAEncryption, (const unsigned char *)(rspParams.secret.secret), rspParams.secret.size,(ubyte *)"IDENTITY",sizeof("IDENTITY"),
          &pPlainSecret, &secretLen);
#else
    status = PKCS1_rsaesOaepDecrypt(MOC_RSA(0) (const RSAKey *)asymKey.key.pRSA,sha256withRSAEncryption,PKCS1_MGF1_FUNC, (const unsigned char *)(rspParams.secret.secret), rspParams.secret.size,(ubyte *)"IDENTITY",sizeof("IDENTITY"),
          &pPlainSecret, &secretLen);
#endif
    if (OK != status)
    {
        DB_PRINT("%s.%d failed to decrypt the root trust key. status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pCsrInfo = &CsrInfo;
    /*
     * Use dummy transient handle for getting object name.
     */
    if (OK != SAPI2_UTILS_getObjectName(TPM2_TRANSIENT_FIRST,
            &(pCsrInfo->akPublicArea), &(akName)))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed to get AK name.\n", __FUNCTION__,
                __LINE__);
        goto exit;
    }
    /*
     * Use seed to generate symKey and HMAC key.
     */
    symKey.size = 16;
    hmacKey.size = secretLen;
    if (OK != SAPI2_UTILS_TPM2_KDFA(pCsrInfo->ekNameAlg,
            pPlainSecret, secretLen,
            "STORAGE", akName.name, akName.size,
            NULL, 0,
            symKey.buffer, symKey.size))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed KDFA for encryption key\n", __FUNCTION__,
                            __LINE__);
        goto exit;
    }
    if (OK != SAPI2_UTILS_TPM2_KDFA(pCsrInfo->ekNameAlg,
            pPlainSecret, secretLen,
            "INTEGRITY", NULL, 0, NULL, 0,
            hmacKey.buffer, hmacKey.size))
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Failed KDFA for hmac key\n", __FUNCTION__,
                            __LINE__);
        goto exit;
    }
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    aesCfbCtx = CRYPTO_INTERFACE_CreateAESCFBCtx(MOC_SYM(NULL) symKey.buffer, symKey.size, FALSE);
#else
    aesCfbCtx = CreateAESCFBCtx(MOC_SYM(NULL) symKey.buffer, symKey.size, FALSE);
#endif
    if (NULL == aesCfbCtx)
    {
        status = ERR_CRYPTO;
        DB_PRINT("%s.%d Failed to create AES context\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }
    pEncryptKey = (ubyte *)rspParams.credentialBlob.credential+34;
    (void) DIGI_MEMSET(encryptKey, 0, sizeof encryptKey);
    secretLen = rspParams.credentialBlob.size-34;
    (void) DIGI_MEMCPY(encryptKey, pEncryptKey, secretLen);
    roundedSize = (secretLen  + AES_BLOCK_SIZE - 1) & ~(AES_BLOCK_SIZE - 1);

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (OK != (status = CRYPTO_INTERFACE_DoAES(MOC_SYM(NULL) aesCfbCtx, (ubyte *)encryptKey, roundedSize, FALSE, ivEncrypt)))
#else
    if (OK != (status = DoAES(MOC_SYM(NULL) aesCfbCtx, (ubyte *)encryptKey, roundedSize, FALSE, ivEncrypt)))
#endif
    {
        DB_PRINT("%s.%d Failed to CFB encrypt\n", __FUNCTION__,
                        __LINE__);
        goto exit;
    }
    (void) DIGI_FREE((void **)&pPlainSecret) ;
    tempSecLen = *((ubyte2 *)encryptKey);

    DIGI_HTONS(pTemp, tempSecLen);
    tempSecLen = *((ubyte2 *)pTemp);
    secretLen = (ubyte4) tempSecLen;

    status = DIGI_CALLOC((void **)&pPlainSecret, 1, secretLen);
    if (OK != status)
        goto exit;
    
    (void) DIGI_MEMCPY(pPlainSecret, encryptKey+2, secretLen);
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    (void) CRYPTO_INTERFACE_DeleteAESCtx(MOC_SYM(NULL) &(aesCfbCtx));
#else
    (void) DeleteAESCtx(MOC_SYM(NULL) &(aesCfbCtx));
#endif

    pSecret->pBuffer = pPlainSecret ;
    pSecret->bufferLen = secretLen;

exit:
    if (pDecodedBlob && (decodedBlobLen != 0))
        shredMemory((ubyte **)&pDecodedBlob, decodedBlobLen, TRUE);
    if (pKeyBlob && keyBlobLen)
    {
        shredMemory((ubyte **)&pKeyBlob, keyBlobLen, TRUE);
    }
    (void) CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
#else
    status = ERR_NOT_IMPLEMENTED;
#endif
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SMP_GET_QUOTE__
MSTATUS SMP_API(PKCS11, getQuote,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_TRUSTED_DATA_TYPE type,
        TAP_TrustedDataInfo *pInfo,
        TAP_Buffer *pNonce,
        TAP_AttributeList *pReserved,
        TAP_Blob *pQuoteData,
        TAP_Signature **ppQuoteSignature
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_ASYMMETRIC_KEY__
MSTATUS SMP_API(PKCS11, createAsymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*)((uintptr) moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pNewObject = NULL;
    CK_OBJECT_HANDLE prvHandle = 0;
    CK_OBJECT_HANDLE pubHandle = 0;
    CK_BBOOL isTrue = TRUE;
    CK_BYTE pbPubExp[] = { 0x01, 0x00, 0x01 }; /* 65537 in bytes */
    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS prvClass = CKO_PRIVATE_KEY;
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_2048;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_PKCS1_5;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_ECC_CURVE eccCurve =  TAP_ECC_CURVE_NIST_P192;
    TAP_KEY_CMK keyCmk = TAP_KEY_CMK_DISABLE;
    TAP_ObjectCapabilityAttributes *pKeyObjectAttributes = (TAP_ObjectCapabilityAttributes*) pObjectAttributes;
    ubyte4 count = 0;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    CK_ULONG ulBitlength = 0;
    TAP_Credential* pCredential = NULL;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    TAP_EntityCredentialList* pCredentials = NULL;
    CK_BBOOL decryptUsage = FALSE;
    CK_BBOOL signUsage = FALSE;
    CK_VOID_PTR pOid = NULL;
    CK_ULONG oidLen = 0;
    int numPubKeyAttrs = 4;
    int numPrivKeyAttrs = 7;
    sbyte4 cmp = 0;
    ubyte useNewId = FALSE;
    CK_UTF8CHAR label[MAX_ID_BYTE_SIZE] = {0};
    CK_ATTRIBUTE idTemplate[] =
    {
        {CKA_ID, NULL, 0}
    };

    CK_ATTRIBUTE publicKeyTemplate[20] =
    {
        { CKA_CLASS, &pubClass, sizeof(pubClass) },
        { CKA_TOKEN, &isTrue, sizeof(isTrue) },
        { CKA_ID, &label, sizeof(label)-1 },
        { CKA_LABEL, NULL, 0 },
    };
    CK_ATTRIBUTE privateKeyTemplate[20] =
    {
        { CKA_CLASS, &prvClass, sizeof(prvClass) },
        { CKA_TOKEN, &isTrue, sizeof(isTrue) },
        { CKA_PRIVATE, &isTrue, sizeof(isTrue) },
        { CKA_SENSITIVE, &isTrue, sizeof(isTrue) },
        { CKA_ID, &label, sizeof(label)-1 },
        { CKA_LABEL, NULL, 0 },
        { CKA_EXTRACTABLE, &keyCmk, sizeof(TAP_KEY_CMK) },
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pKeyAttributeList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle);
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_KEY_USAGE:
                    if (sizeof(TAP_KEY_USAGE) == pAttribute->length)
                        keyUsage = *((TAP_KEY_USAGE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key usage length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    switch(keyUsage)
                    {
                        case TAP_KEY_USAGE_SIGNING:
                            {
                                signUsage = TRUE;
                                break;
                            }  /* TAP_KEY_USAGE_SIGNING */
                        case TAP_KEY_USAGE_ATTESTATION:
                            {
                                signUsage = TRUE;
                                break;
                            }  /* TAP_KEY_USAGE_ATTESTATION */

                        case TAP_KEY_USAGE_DECRYPT:
                            {
                                decryptUsage = TRUE;
                                break;
                            }  /* TAP_KEY_USAGE_DECRYPT */

                        case TAP_KEY_USAGE_STORAGE:
                            {
                                status = ERR_TAP;
                                goto exit;
                            }  /* TAP_KEY_USAGE_STORAGE */

                        case TAP_KEY_USAGE_GENERAL:
                            {
                               signUsage = TRUE;
                               decryptUsage = TRUE;
                               break;
                            }  /* TAP_KEY_USAGE_GENERAL */
                        default:
                            {
                                status = ERR_TAP;
                                goto exit;
                            }
                    }  /* keyUsage */
                    break;
                case TAP_ATTR_KEY_CMK:
                    if (sizeof(TAP_KEY_CMK) == pAttribute->length)
                        keyCmk = *((TAP_KEY_CMK *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key cmk length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;
                case TAP_ATTR_CREDENTIAL:
                    if ((sizeof(TAP_CredentialList) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        DB_PRINT("%s.%d Invalid attribute value, length = %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        status = ERR_INVALID_ARG;
                        goto exit;
                    }

                    pCredentials = (TAP_EntityCredentialList*)pAttribute->pStructOfType;
                    break;

                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_ENC_SCHEME:
                    if (sizeof(TAP_ENC_SCHEME) == pAttribute->length)
                        encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key encryption scheme structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SIG_SCHEME:
                    if (sizeof(TAP_SIG_SCHEME) == pAttribute->length)
                        sigScheme = *((TAP_SIG_SCHEME *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key signing scheme structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_CURVE:
                    if (sizeof(TAP_ECC_CURVE) == pAttribute->length)
                        eccCurve = *((TAP_ECC_CURVE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key curve structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;
            }
        }
    }

    if (NULL != pCredentials)
    {
        pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                            TAP_CREDENTIAL_CONTEXT_OWNER);
        if (NULL != pCredential)
        {
            if (NULL != pCredential->credentialData.pBuffer)
            {
                pGemToken->credential.pBuffer = pCredential->credentialData.pBuffer;
                pGemToken->credential.bufferLen = pCredential->credentialData.bufferLen;
            }
        }
    }

    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            {
                switch(keySize)
                {
                    case TAP_KEY_SIZE_UNDEFINED:
                        ulBitlength = PKCS11_DEFAULT_KEY_SZ;
                        break;

                    case TAP_KEY_SIZE_1024:
                        ulBitlength = 1024;
                        break;

                    case TAP_KEY_SIZE_2048:
                        ulBitlength = 2048;
                        break;

                    case TAP_KEY_SIZE_3072:
                        ulBitlength = 3072;
                        break;

                    case TAP_KEY_SIZE_4096:
                        ulBitlength = 4096;
                        break;
                }
                mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_MODULUS_BITS, &ulBitlength, sizeof(ulBitlength));
                numPubKeyAttrs++;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_PUBLIC_EXPONENT, pbPubExp, sizeof(pbPubExp));
                numPubKeyAttrs++;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                numPubKeyAttrs++;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_VERIFY, &signUsage, sizeof(signUsage));
                numPubKeyAttrs++;

                INSERT_ATTRIBUTE(privateKeyTemplate[numPrivKeyAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                numPrivKeyAttrs++;
                INSERT_ATTRIBUTE(privateKeyTemplate[numPrivKeyAttrs], CKA_SIGN, &signUsage, sizeof(signUsage));
                numPrivKeyAttrs++;
            }
            break;
        case TAP_KEY_ALGORITHM_ECC:
            {
                switch(eccCurve)
                {
                    case TAP_ECC_CURVE_NONE:
                        break;

                    case TAP_ECC_CURVE_NIST_P192:
                        pOid = (CK_VOID_PTR)eccOid192;
                        oidLen = sizeof(eccOid192);
                        break;

                    case TAP_ECC_CURVE_NIST_P224:
                        pOid = (CK_VOID_PTR)eccOid224;
                        oidLen = sizeof(eccOid224);
                        break;

                    case TAP_ECC_CURVE_NIST_P256:
                        pOid = (CK_VOID_PTR)eccOid256;
                        oidLen = sizeof(eccOid256);
                        break;

                    case TAP_ECC_CURVE_NIST_P384:
                        pOid = (CK_VOID_PTR)eccOid384;
                        oidLen = sizeof(eccOid384);
                        break;

                    case TAP_ECC_CURVE_NIST_P521:
                        pOid = (CK_VOID_PTR)eccOid521;
                        oidLen = sizeof(eccOid521);
                        break;
                }
                mechanism.mechanism = CKM_EC_KEY_PAIR_GEN;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_VERIFY, &signUsage, sizeof(signUsage));
                numPubKeyAttrs++;
                INSERT_ATTRIBUTE(publicKeyTemplate[numPubKeyAttrs], CKA_EC_PARAMS, pOid, oidLen);
                numPubKeyAttrs++;

                INSERT_ATTRIBUTE(privateKeyTemplate[numPrivKeyAttrs], CKA_SIGN, &signUsage, sizeof(signUsage));
                numPrivKeyAttrs++;
            }
            break;

        default:
            {
                status = ERR_TAP_INVALID_ALGORITHM;
                DB_PRINT("%s.%d Unsupported Alogrithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

    }

    if (OK != (status = DIGI_CALLOC((void**)&pNewObject, 1, sizeof(Pkcs11_Object))))
    {
        DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Query the HSM to find an available CKA_ID */
    pNewObject->objectId = PKCS11_generateNextObjectId(pGemModule, pGemToken, CKO_PRIVATE_KEY);
    
    status = DIGI_MEMCPY((ubyte *) label, pNewObject->objectId.pBuffer, pNewObject->objectId.bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Was not able to create/copy objectId, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    publicKeyTemplate[2].ulValueLen = pNewObject->objectId.bufferLen;
    privateKeyTemplate[4].ulValueLen = pNewObject->objectId.bufferLen;

    /* Generate a new label for this public key using its ID */
    status = PKCS11_createKeyLabelAlloc (
        (const sbyte *) MOC_DEFAULT_LABEL_PREFIX, (const sbyte *)MOC_LABEL_PUB, keyAlgorithm,
        (TAP_RAW_KEY_SIZE) keySize, eccCurve, pNewObject->objectId, (sbyte **)&(publicKeyTemplate[3].pValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create key label = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    publicKeyTemplate[3].ulValueLen = DIGI_STRLEN((const sbyte *)(publicKeyTemplate[3].pValue));

    /* Generate a new label for this private key using its ID */
    status = PKCS11_createKeyLabelAlloc (
        (const sbyte *) MOC_DEFAULT_LABEL_PREFIX, (const sbyte *)MOC_LABEL_PRIV, keyAlgorithm,
        (TAP_RAW_KEY_SIZE) keySize, eccCurve, pNewObject->objectId, (sbyte **)&(privateKeyTemplate[5].pValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create key label = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    privateKeyTemplate[5].ulValueLen = DIGI_STRLEN((const sbyte *)(privateKeyTemplate[5].pValue));

    rVal = CALL_PKCS11_API(C_GenerateKeyPair, pGemToken->tokenSession, &mechanism, publicKeyTemplate,
            numPubKeyAttrs, privateKeyTemplate,
            numPrivKeyAttrs, &pubHandle, &prvHandle);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to Generate key pair status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Check the new keys ID value, the HSM may have ignored our ID input and set
     * their own. Note the Digicert SSM has this behavior */
    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, prvHandle, idTemplate, 1);
    if (CKR_OK == rVal)
    {
        /* If we got the length, allocate a buffer and retrieve the value */
        status = DIGI_MALLOC((void **)&idTemplate[0].pValue, idTemplate[0].ulValueLen + 1);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed DIGI_MALLOC = %d\n", __FUNCTION__, __LINE__, status);
            goto exit;
        }

        rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, prvHandle, idTemplate, 1);
        if (CKR_OK == rVal)
        {
            /* If the lengths dont match, no need to check buffer contents */
            if (pNewObject->objectId.bufferLen != idTemplate[0].ulValueLen)
            {
                useNewId = TRUE;
            }
            else
            {
                /* Got an ID value, check against the original */
                status = DIGI_MEMCMP (
                    pNewObject->objectId.pBuffer, idTemplate[0].pValue, 
                    (usize)idTemplate[0].ulValueLen, &cmp);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed memcmp = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* 8 byte ID did not match our input, use theirs instead */
                if (0 != cmp)
                {
                    useNewId = TRUE;
                }
            }
        }
    }

    if (TRUE == useNewId)
    {
        /* Free the existing buffer */
        if (NULL != pNewObject->objectId.pBuffer)
        {
            status = DIGI_FREE((void **)&pNewObject->objectId.pBuffer);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed DIGI_FREE = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }

        if (NULL == idTemplate[0].pValue)
        {
            status = ERR_INTERNAL_ERROR;
            DB_PRINT("Error expected value is NULL\n");
            goto exit;
        }

        /* Transfer the pointer ownership */
        pNewObject->objectId.pBuffer = idTemplate[0].pValue;
        pNewObject->objectId.bufferLen = idTemplate[0].ulValueLen;
        idTemplate[0].pValue = NULL;
    }

    /* Store the object handles */
    pNewObject->pubObject = pubHandle;
    pNewObject->prvObject = prvHandle;

    if (pKeyObjectAttributes)
    {
        /* Put together TAP Attribute list of the parameters used to create
           this key
         */
        if (NULL != pKeyObjectAttributes->pAttributeList)
        {
            status = TAP_UTILS_freeAttributeList(pKeyObjectAttributes);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free memory for key attribute list, status = %d\n", __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        numCreatedKeyAttributes = 8;
        pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;
        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
        pCreatedKeyAttributes->length = sizeof(keyUsage);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for keyUsage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy keyUsage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_ALGORITHM;
        pCreatedKeyAttributes->length = sizeof(keyAlgorithm);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyAlgorithm,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_ENC_SCHEME;
        pCreatedKeyAttributes->length = sizeof(encScheme);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(encScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for encScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &encScheme,
                sizeof(encScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy encScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SIG_SCHEME;
        pCreatedKeyAttributes->length = sizeof(sigScheme);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(sigScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &sigScheme,
                sizeof(sigScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        if (TAP_KEY_ALGORITHM_RSA == keyAlgorithm)
        {
            pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(keySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for keySize attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy keySize attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        else
        {
            pCreatedKeyAttributes->type = TAP_ATTR_CURVE;
            pCreatedKeyAttributes->length = sizeof(eccCurve);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(eccCurve));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for eccCurve attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &eccCurve,
                    sizeof(eccCurve));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy eccCurve attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_OBJECT_ID_BYTESTRING;
        pCreatedKeyAttributes->length = sizeof(TAP_Buffer);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Buffer));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = DIGI_MALLOC (
            (void **)&((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->pBuffer,  pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = DIGI_MEMCPY (
            ((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->pBuffer,
            pNewObject->objectId.pBuffer,
            pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy data"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        ((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->bufferLen = pNewObject->objectId.bufferLen;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SERIALIZED_OBJECT_BLOB;
        pCreatedKeyAttributes->length = sizeof(TAP_Blob);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Blob));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        /* Send back a serialized object blob */
        CALL_SMP_API(PKCS11, exportObject, moduleHandle, tokenHandle, (TAP_ObjectHandle) ((uintptr) pNewObject), pCreatedKeyAttributes->pStructOfType);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to serialize attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }    

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        /* Last entry */
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    pNewObject->refCount = 1;
    pNewObject->pNext = NULL;
    PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);

    if (NULL != pObjectIdOut)
    {
        if (TRUE == useNewId)
        {
            *pObjectIdOut = 0;
        }
        else
        {
            copyBufferIdToUlong(pObjectIdOut, pNewObject->objectId);
        }
    }

    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pNewObject); pNewObject = NULL;

exit:

    if (NULL != publicKeyTemplate[3].pValue)
    {
        DIGI_FREE((void **)&(publicKeyTemplate[3].pValue));
    }
    if (NULL != privateKeyTemplate[5].pValue)
    {
        DIGI_FREE((void **)&(privateKeyTemplate[5].pValue));
    }
    if (NULL != idTemplate[0].pValue )
    {
        DIGI_FREE((void **)&(idTemplate[0].pValue));
    }

    if (NULL != pNewObject)
    {
        (void) PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pNewObject);
    }

    pGemToken->credential.pBuffer = NULL;
    pGemToken->credential.bufferLen = 0;

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__
MSTATUS SMP_API(PKCS11, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppublicKey
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    MAsn1Element *pArray = NULL;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);
    CK_KEY_TYPE keyType = CKK_RSA;
    byteBoolean isMutexLocked = FALSE;
    CK_ULONG exponentLen = 0;
    CK_ATTRIBUTE keyTypeTemplate[] =
    {
        {CKA_KEY_TYPE, &keyType, sizeof(CK_KEY_TYPE)}
    };
    CK_ATTRIBUTE rsaPubTemplate[] =
    {
        {CKA_MODULUS, NULL_PTR, 0},
        {CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
    };
    CK_ATTRIBUTE eccPubTemplate[] =
    {
        {CKA_EC_PARAMS, NULL_PTR, 0},
        {CKA_EC_POINT, NULL_PTR, 0}
    };
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid  input pGemModule=%p,"
                 "pGemToken=%p, pGemObject=%p\n", __FUNCTION__, __LINE__,
                 pGemModule, pGemToken, pGemObject);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, keyTypeTemplate, 1);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to get Attribute value. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (keyType)
    {
        case CKK_RSA:
            {
                /* Get the Modulus Value of Public Key */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 2);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                /* Allocate for modulus */
                if (OK != (status = DIGI_CALLOC((void**)&rsaPubTemplate[0].pValue, 1, rsaPubTemplate[0].ulValueLen)))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                /* The exponent will later be cast as a ubyte4, so make sure its at least large enough for that */
                exponentLen = rsaPubTemplate[1].ulValueLen;
                if (exponentLen < 4)
                    exponentLen = 4;

                if (OK != (status = DIGI_CALLOC((void**)&rsaPubTemplate[1].pValue, 1, exponentLen)))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                if (OK != (status = DIGI_CALLOC((void**)ppublicKey, 1, sizeof(**ppublicKey))))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                /* Get the Modulus Value of Public Key */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, rsaPubTemplate, 2);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                (*ppublicKey)->publicKey.rsaKey.pModulus = rsaPubTemplate[0].pValue;
                (*ppublicKey)->publicKey.rsaKey.pExponent = rsaPubTemplate[1].pValue;

                (*ppublicKey)->publicKey.rsaKey.modulusLen = rsaPubTemplate[0].ulValueLen;
                (*ppublicKey)->publicKey.rsaKey.exponentLen = (rsaPubTemplate[1].ulValueLen == 3)? 4: rsaPubTemplate[1].ulValueLen;
                (*ppublicKey)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;

            }
            break;
        case CKK_ECDSA:
            {
                ubyte4 bytesRead = 0;
                MAsn1TypeAndCount pTemplate[1] = {
                    { MASN1_TYPE_OCTET_STRING, 0 }
                };
                sbyte4 ptLen = 0;

                /* Get the EC params Value of Public Key */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 2);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                /* Allocate memory for curve id */
                if (OK != (status = DIGI_CALLOC((void**)&eccPubTemplate[0].pValue, 1, eccPubTemplate[0].ulValueLen)))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                /* Allocate memory for EC Point */
                if (OK != (status = DIGI_CALLOC((void**)&eccPubTemplate[1].pValue, 1, eccPubTemplate[1].ulValueLen)))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                if (OK != (status = DIGI_CALLOC((void**)ppublicKey, 1, sizeof(**ppublicKey))))
                {
                    PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
                    goto exit;
                }

                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, eccPubTemplate, 2);
                if (CKR_OK != rVal)
                {
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
                    goto exit;
                }

                /* Fill the curve id */
                if (0x06 != *((ubyte *)eccPubTemplate[0].pValue))
                {
                    status = ERR_TAP_INVALID_CURVE_ID;
                    DB_PRINT("%s.%d Unsupported EC curve status:%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                if (EqualOID(eccOid192 + 1, eccPubTemplate[0].pValue + 1))
                {
                    (*ppublicKey)->publicKey.eccKey.curveId = TAP_ECC_CURVE_NIST_P192;
                }
                else if (EqualOID(eccOid224 + 1, eccPubTemplate[0].pValue + 1))
                {
                    (*ppublicKey)->publicKey.eccKey.curveId = TAP_ECC_CURVE_NIST_P224;
                }
                else if (EqualOID(eccOid256 + 1, eccPubTemplate[0].pValue + 1))
                {
                    (*ppublicKey)->publicKey.eccKey.curveId = TAP_ECC_CURVE_NIST_P256;
                }
                else if (EqualOID(eccOid384 + 1, eccPubTemplate[0].pValue + 1))
                {
                    (*ppublicKey)->publicKey.eccKey.curveId = TAP_ECC_CURVE_NIST_P384;
                }
                else if (EqualOID(eccOid521 + 1, eccPubTemplate[0].pValue + 1))
                {
                    (*ppublicKey)->publicKey.eccKey.curveId = TAP_ECC_CURVE_NIST_P521;
                }
                else
                {
                    status = ERR_TAP_INVALID_CURVE_ID;;
                    goto exit;
                }

				status = MAsn1CreateElementArray (
						pTemplate, 1, MASN1_FNCT_DECODE, NULL, &pArray);
				if (OK != status)
					goto exit;

				status = MAsn1Decode (
						eccPubTemplate[1].pValue, eccPubTemplate[1].ulValueLen, pArray, &bytesRead);
				if (OK != status)
					goto exit;
                /* Pkcs11: Only uncompressed format is supported for the point's representation */
                if (pArray[0].value.pValue[0] == 0x03 || pArray[0].value.pValue[0] == 0x02)
                { /* key is in compressed format */
                    goto exit;
                }

                /* key is in uncompressed format 0x04 */
                ptLen = (pArray[0].valueLen-1)/2; /*Ignore the first byte 0x04 */
                (*ppublicKey)->publicKey.eccKey.pubXLen = ptLen;
                (*ppublicKey)->publicKey.eccKey.pubYLen = ptLen;

                if (OK != (status = DIGI_CALLOC((void*)&((*ppublicKey)->publicKey.eccKey.pPubX), 1,
                                       ptLen)))
                {
                    goto exit;
                }

                if (OK != (status = DIGI_CALLOC((void*)&((*ppublicKey)->publicKey.eccKey.pPubY), 1,
                                       ptLen)))
                {
                    goto exit;
                }

                if (OK != (status = DIGI_MEMCPY((*ppublicKey)->publicKey.eccKey.pPubX, (pArray[0].value.pValue)+1, ptLen)))
                {
                    goto exit;
                }
                if (OK != (status = DIGI_MEMCPY((*ppublicKey)->publicKey.eccKey.pPubY, pArray[0].value.pValue+ptLen+1, ptLen)))
                {
                    goto exit;
                }
                (*ppublicKey)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            }
            break;
        default:
            break;
    }

null_exit:
exit:
    if (NULL != eccPubTemplate[0].pValue)
    {
        DIGI_FREE((void **)&(eccPubTemplate[0].pValue));
    }
    if (NULL != eccPubTemplate[1].pValue)
    {
        DIGI_FREE((void **)&(eccPubTemplate[1].pValue));
    }
    if (NULL != pArray)
    {
        MAsn1FreeElementArray(&pArray);
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_PUBLIC_KEY__
MSTATUS SMP_API(PKCS11,freePublicKey,
        TAP_PublicKey **ppublicKey
)
{
    MSTATUS status = OK;

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;
    if ((NULL == ppublicKey) || (NULL == *ppublicKey))
    {
        PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

    if ((*ppublicKey)->publicKey.rsaKey.pModulus)
    {
        FREE((*ppublicKey)->publicKey.rsaKey.pModulus);
        (*ppublicKey)->publicKey.rsaKey.pModulus = NULL;
    }

    if ((*ppublicKey)->publicKey.rsaKey.pExponent)
    {
        FREE((*ppublicKey)->publicKey.rsaKey.pExponent);
        (*ppublicKey)->publicKey.rsaKey.pExponent = NULL;
    }

null_exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_SYMMETRIC_KEY__
MSTATUS SMP_API(PKCS11, createSymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    CK_RV rVal = 0;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pNewObject = NULL;
    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_Attribute *pAttribute = NULL;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Credential* pCredential = NULL;
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_SYM_DEFAULT;
    TAP_RAW_KEY_SIZE rawKeySize = 0;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    CK_OBJECT_HANDLE keyHandle = 0;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL decryptUsage = FALSE;
    CK_BBOOL signUsage = FALSE;
    CK_BBOOL isTrue = TRUE;
    TAP_KEY_CMK keyCmk = TAP_KEY_CMK_DISABLE;
    CK_ULONG keyLength = 0;
    CK_MECHANISM mechanism = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_KEY_TYPE keyType = CKK_AES;
    ubyte4 count = 0;
    CK_UTF8CHAR label[MAX_ID_BYTE_SIZE] = {0};
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    CK_ATTRIBUTE keyTemplate[20] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_TOKEN, &isTrue, sizeof(isTrue)},
        {CKA_ID, label, sizeof(label) - 1},
        {CKA_LABEL, NULL, 0},
        {CKA_EXTRACTABLE, &keyCmk, sizeof(TAP_KEY_CMK)},
    };

    int numAttrs = 5;
    byteBoolean isMutexLocked = FALSE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pKeyAttributeList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_KEY_USAGE:
                    if (sizeof(TAP_KEY_USAGE) == pAttribute->length)
                        keyUsage = *((TAP_KEY_USAGE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key usage length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    switch(keyUsage)
                    {
                        case TAP_KEY_USAGE_UNDEFINED:
                        case TAP_KEY_USAGE_GENERAL:
                            {
                                signUsage = TRUE;
                                decryptUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_DECRYPT:
                            {
                                decryptUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_SIGNING:
                            {
                                signUsage = TRUE;
                                break;
                            }
                        default:
                            {
                                status = ERR_TAP;
                                goto exit;
                            }
                    }  /* keyUsage */

                    break;

                case TAP_ATTR_CREDENTIAL_SET:
                    if ((sizeof(TAP_CredentialList) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        DB_PRINT("%s.%d Invalid attribute value, length = %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        status = ERR_INVALID_ARG;
                        goto exit;
                    }

                    pCredentials = (TAP_EntityCredentialList*)pAttribute->pStructOfType;
                    break;
                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_RAW_KEY_SIZE:
                    if (sizeof(TAP_RAW_KEY_SIZE) == pAttribute->length)
                        rawKeySize = *((TAP_RAW_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid raw key size structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }

                    if (rawKeySize > RAW_KEY_MAX_LEN)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid raw key size %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                rawKeySize, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_HASH_ALG:
                    if (sizeof(TAP_HASH_ALG) == pAttribute->length)
                        hashAlg = *((TAP_HASH_ALG *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key hash structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if (sizeof(TAP_SYM_KEY_MODE) == pAttribute->length)
                        symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid sym key mode structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }
                    break;
                
                case TAP_ATTR_KEY_CMK:
                    if (sizeof(TAP_KEY_CMK) == pAttribute->length)
                        keyCmk = *((TAP_KEY_CMK *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key cmk length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;
            }
        }
    }

    if (NULL != pCredentials)
    {
        pCredential = PKCS11_fetchCredentialFromList(&pCredentials->pEntityCredentials->credentialList,
                            TAP_CREDENTIAL_CONTEXT_OWNER);
        if (NULL != pCredential)
        {
            if (NULL != pCredential->credentialData.pBuffer)
            {
                pGemToken->credential.pBuffer = pCredential->credentialData.pBuffer;
                pGemToken->credential.bufferLen = pCredential->credentialData.bufferLen;
            }
        }
    }

    /* Check if the mechanism is supported */
    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
            {
                switch(keySize)
                {
                    case TAP_KEY_SIZE_UNDEFINED:
                        keyLength = PKCS11_DEFAULT_KEY_SZ;
                        break;

                    case TAP_KEY_SIZE_128:
                        keyLength = 128/8;
                        break;

                    case TAP_KEY_SIZE_192:
                        keyLength = 192/8;
                        break;

                    case TAP_KEY_SIZE_256:
                        keyLength = 256/8;
                        break;
                    default:
                        status = ERR_TAP;
                        goto exit;
                }
                keyType = CKK_AES;
                mechanism.mechanism = CKM_AES_KEY_GEN;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE_LEN, &keyLength, sizeof(keyLength));
                numAttrs++;
            }
            break;
        case TAP_KEY_ALGORITHM_DES:
            {
                keyType = CKK_DES;
                mechanism.mechanism = CKM_DES_KEY_GEN;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
            }
            break;
        case TAP_KEY_ALGORITHM_TDES:
            {
                keyType = CKK_DES3;
                mechanism.mechanism = CKM_DES3_KEY_GEN;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                numAttrs++;
            }
            break;
        case TAP_KEY_ALGORITHM_HMAC:
            {
                keyType = CKK_GENERIC_SECRET;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                numAttrs++;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_SIGN, &signUsage, sizeof(signUsage));
                numAttrs++;
                keyLength = (CK_ULONG) rawKeySize;
                mechanism.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
                INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE_LEN, &keyLength, sizeof(keyLength));
                numAttrs++;
            }
            break;
        default:
            {
                status = ERR_TAP_INVALID_ALGORITHM;
                DB_PRINT("%s.%d Unsupported Alogrithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;
    }

    if (OK != (status = DIGI_CALLOC((void**)&pNewObject, 1, sizeof(Pkcs11_Object))))
    {
        DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Query the HSM to find an available CKA_ID */
    pNewObject->objectId = PKCS11_generateNextObjectId(pGemModule, pGemToken, CKO_SECRET_KEY);
    
    status = DIGI_MEMCPY((ubyte *) label, pNewObject->objectId.pBuffer, pNewObject->objectId.bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Was not able to create/copy objectId, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    keyTemplate[2].ulValueLen = pNewObject->objectId.bufferLen;
    
    /* Generate a new label for this private key using its ID */
    status = PKCS11_createKeyLabelAlloc (
        (const sbyte *) MOC_DEFAULT_LABEL_PREFIX, (const sbyte *)MOC_LABEL_SYM, keyAlgorithm,
        (TAP_KEY_ALGORITHM_HMAC == keyAlgorithm ? rawKeySize : (TAP_RAW_KEY_SIZE) keySize), 0, pNewObject->objectId, (sbyte **)&(keyTemplate[3].pValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create key label = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }
    keyTemplate[3].ulValueLen = DIGI_STRLEN((const sbyte *)(keyTemplate[3].pValue));

    rVal = CALL_PKCS11_API(C_GenerateKey, pGemToken->tokenSession, &mechanism, keyTemplate, numAttrs, &keyHandle);

    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to Generate key status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pKeyObjectAttributes)
    {
        /* Put together TAP Attribute list of the parameters used to create
           this key
         */
        if (NULL != pKeyObjectAttributes->pAttributeList)
        {
            status = TAP_UTILS_freeAttributeList(pKeyObjectAttributes);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free memory for key attribute list, status = %d\n", __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        numCreatedKeyAttributes = 7;
        pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_ALGORITHM;
        pCreatedKeyAttributes->length = sizeof(keyAlgorithm);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyAlgorithm,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
        pCreatedKeyAttributes->length = sizeof(keyUsage);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (TAP_KEY_USAGE_DECRYPT == keyUsage)
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_SYM_KEY_MODE;
            pCreatedKeyAttributes->length = sizeof(symMode);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for sym mode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &symMode,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy symMode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(keySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        else /* TAP_KEY_USAGE_SIGNING == keyUsage */
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_HASH_ALG;
            pCreatedKeyAttributes->length = sizeof(hashAlg);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &hashAlg,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_RAW_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(rawKeySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(rawKeySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for raw key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &rawKeySize,
                    sizeof(rawKeySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy raw key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_OBJECT_ID_BYTESTRING;
        pCreatedKeyAttributes->length = sizeof(TAP_Buffer);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Buffer));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = DIGI_MALLOC (
            (void **)&((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->pBuffer, 
            pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = DIGI_MEMCPY (
            ((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->pBuffer,
            pNewObject->objectId.pBuffer,
            pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy data"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        ((TAP_Buffer *)pCreatedKeyAttributes->pStructOfType)->bufferLen = pNewObject->objectId.bufferLen;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SERIALIZED_OBJECT_BLOB;
        pCreatedKeyAttributes->length = sizeof(TAP_Blob);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Blob));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object Blob attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        /* Send back a serialized object blob */
        CALL_SMP_API(PKCS11, exportObject, moduleHandle, tokenHandle, (TAP_ObjectHandle) ((uintptr) pNewObject), pCreatedKeyAttributes->pStructOfType);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to serialize attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        } 

        /* Last entry */
        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    /* Store the object handles */
    pNewObject->refCount = 1;
    pNewObject->pubObject = keyHandle;
    pNewObject->prvObject = keyHandle;

    pNewObject->pNext = NULL;
    PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);
    
    if (NULL != pObjectIdOut)
    {
        copyBufferIdToUlong(pObjectIdOut, pNewObject->objectId);
    }

    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pNewObject); pNewObject = NULL;

exit:

    if (NULL != pNewObject)
    {
        (void) PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pNewObject);
    }
    
    if (NULL != keyTemplate[3].pValue)
    {
        DIGI_FREE((void **)&(keyTemplate[3].pValue));
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_EXPORT_OBJECT__
MSTATUS SMP_API(PKCS11, exportObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pExportedObject
)
{
    MSTATUS status = OK;
    Pkcs11_Module *pGemModule = (Pkcs11_Module*)((uintptr)moduleHandle);
    Pkcs11_Token *pGemToken = (Pkcs11_Token*)((uintptr)tokenHandle);
    Pkcs11_Object *pGemObject = (Pkcs11_Object*)((uintptr)objectHandle);
    ubyte4 offset = 0;
    ubyte4 serSize = 0;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) ||
        (NULL == pExportedObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input argument. pGemModule=%p,"
                 "pGemToken=%p, status=%d\n",
                 __FUNCTION__, __LINE__, pGemModule, pGemToken, status);
        goto exit;
    }

    serSize = 4; /* at least the buffer len */

    if (pGemObject->objectId.pBuffer == NULL || 0 == pGemObject->objectId.bufferLen)
    {
        status = ERR_TAP_INVALID_HANDLE;
        DB_PRINT("%s.%d ObjectId with value as 0 is not supported status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    serSize += pGemObject->objectId.bufferLen; /* len followed by value */

    if (OK != (status = DIGI_CALLOC((void**)&pExportedObject->blob.pBuffer, 1, serSize)))
    {
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pExportedObject->blob.bufferLen = serSize;

    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Buffer, TAP_SD_IN,
                            (void*)&pGemObject->objectId, sizeof(pGemObject->objectId),
                            pExportedObject->blob.pBuffer, pExportedObject->blob.bufferLen, &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%s Failed to serailze objectId. status=%d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pExportedObject->format = TAP_BLOB_FORMAT_MOCANA;
    pExportedObject->encoding= TAP_BLOB_ENCODING_BINARY;

exit:
    if (OK != status)
    {
        if (NULL != pExportedObject && NULL != pExportedObject->blob.pBuffer)
            (void) DIGI_FREE((void**)&pExportedObject->blob.pBuffer);
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SERIALIZE_OBJECT__
MSTATUS SMP_API(PKCS11, serializeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_Blob *pSerializedObject
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    CK_KEY_TYPE keyType = 0;
    CK_ULONG bitLen = 0;
    CK_ATTRIBUTE modAttr = {CKA_MODULUS, NULL, 0};
    CK_ATTRIBUTE objAttr[] = {
            { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
            { CKA_MODULUS_BITS, &bitLen, sizeof(bitLen) },

    };
    TAP_Buffer* pSerializeBuffer = NULL;
    TAP_Buffer objectIdBuffer = {0};

    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = NULL;
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pSerializedObject))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    status = copyUlongIdToBuffer(&objectIdBuffer, objectId);
    if (OK != status)
    {
        goto exit;
    }

    /* First find if the object is already in the list */
    if (NULL != pGemToken->pObjectHead)
    {
        pGemObject = pGemToken->pObjectHead;
        while (NULL != pGemObject)
        {
            if (objectIdBuffer.bufferLen == pGemObject->objectId.bufferLen)
            {
                sbyte4 cmp = -1;

                status = DIGI_MEMCMP(
                    objectIdBuffer.pBuffer, pGemObject->objectId.pBuffer,
                    pGemObject->objectId.bufferLen, &cmp);
                if (OK != status)
                    goto exit;

                if (!cmp)
                    break;
            }

            pGemObject = pGemObject->pNext;
        }
    }

    if (NULL == pGemObject)
    {
        /* Find object in persistent storage */
        pGemObject = PKCS11_findAndAllocObject(pGemModule, pGemToken, objectIdBuffer);
    }

    if (NULL != pGemObject)
    {
        if (0 < pGemObject->pubObject)
        {
            /* Fetch the object type and length */
            rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, objAttr, sizeof(objAttr) / sizeof(CK_ATTRIBUTE));
            if (CKR_OK != rVal)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                goto exit;
            }

            if ((CKK_RSA == keyType) && ((1024 == bitLen) || (2048 == bitLen) || (3072 == bitLen) || (4096 == bitLen)))
            {
                pSerializeBuffer = &pSerializedObject->blob;
                pSerializeBuffer->bufferLen = bitLen >> 3;
                pSerializeBuffer->pBuffer = MALLOC(pSerializeBuffer->bufferLen);

                modAttr.pValue = pSerializeBuffer->pBuffer;
                modAttr.ulValueLen = pSerializeBuffer->bufferLen;

                /* Fetch the Modulus */
                rVal = CALL_PKCS11_API(C_GetAttributeValue, pGemToken->tokenSession, pGemObject->pubObject, &modAttr, 1);
                if (CKR_OK != rVal)
                    status = PKCS11_nanosmpErr(pGemModule, rVal);
            }
        }
    }
    else
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
    }

null_exit:
exit:
    if (NULL != objectIdBuffer.pBuffer)
        (void) DIGI_MEMSET_FREE(&objectIdBuffer.pBuffer, objectIdBuffer.bufferLen);
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_OBJECT__
MSTATUS SMP_API(PKCS11, createObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectHandle *pHandle
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    ubyte4 tokenVal = 1;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    CK_OBJECT_HANDLE objHandle = 0;
    TAP_Attribute *pAttribute = NULL;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_UNDEFINED;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_SYM_DEFAULT;
    TAP_RAW_KEY_SIZE rawKeySize = 0;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    Pkcs11_Object* pNewObject = NULL;
    CK_ULONG keyId = 0;
    CK_BBOOL isTrue = TRUE;
    CK_BBOOL token = TRUE;
    CK_BBOOL decryptUsage = FALSE;
    CK_BBOOL signUsage = FALSE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS objClass = CKO_DATA;
    TAP_Credential* pCredential = NULL;
    TAP_EntityCredentialList* pCredentials = NULL;
    TAP_Buffer keyData = {0};
    CK_UTF8CHAR label[MAX_ID_BYTE_SIZE] = {0};
    ubyte4 count = 0;
    ubyte4 numAttrs = 4;
    ubyte *pE = NULL;
    ubyte4 eLen = 0;
    ubyte *pN = NULL;
    ubyte4 nLen = 0;
    ubyte *pIter = NULL;

    CK_ATTRIBUTE idTemplate[] =
    {
        {CKA_LABEL, label, sizeof(label)-1},
    };

    CK_ATTRIBUTE Template[] = {
        {CKA_CLASS, &objClass, sizeof(CK_OBJECT_CLASS)} ,
        {CKA_TOKEN, &isTrue, sizeof(CK_BBOOL)} ,
        {CKA_PRIVATE, &isTrue, sizeof(CK_BBOOL)} ,
    };

    CK_ATTRIBUTE keyTemplate[20] =
    {
        {CKA_CLASS, &objClass, sizeof(objClass)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_ID, label, sizeof(label) - 1},
        {CKA_LABEL, NULL, 0},
    };

    CK_ULONG ulCount = sizeof(Template) / sizeof(CK_ATTRIBUTE);
    byteBoolean isLocalLoggedIn = FALSE;

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pKeyAttributeList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle);
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_KEY_USAGE:
                    if (sizeof(TAP_KEY_USAGE) == pAttribute->length)
                        keyUsage = *((TAP_KEY_USAGE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key usage length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    switch(keyUsage)
                    {
                        case TAP_KEY_USAGE_UNDEFINED:
                        case TAP_KEY_USAGE_GENERAL:
                            {
                                decryptUsage = TRUE;
                                signUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_DECRYPT:
                            {
                                decryptUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_SIGNING:
                            {
                                signUsage = TRUE;
                                break;
                            }
                        default:
                            {
                                status = ERR_TAP;
                                goto exit;
                            }
                    }  /* keyUsage */

                    break;

                case TAP_ATTR_CREDENTIAL_SET:
                    if ((sizeof(TAP_CredentialList) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        DB_PRINT("%s.%d Invalid attribute value, length = %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        status = ERR_INVALID_ARG;
                        goto exit;
                    }

                    pCredentials = (TAP_EntityCredentialList*)pAttribute->pStructOfType;
                    break;

                case TAP_ATTR_HASH_ALG:
                    if (sizeof(TAP_HASH_ALG) == pAttribute->length)
                        hashAlg = *((TAP_HASH_ALG *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key hash structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if (sizeof(TAP_SYM_KEY_MODE) == pAttribute->length)
                        symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid sym key mode structure length %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_TOKEN_OBJECT:
                    {
                        if ((sizeof(ubyte4) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid token attribute length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        tokenVal = *((ubyte4 *)(pAttribute->pStructOfType));
                        if (0 == tokenVal)
                            token = FALSE;
                    }
                    break;

                case TAP_ATTR_OBJECT_VALUE:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    keyData = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;
            }
        }
    }

    if (NULL != pCredentials)
    {
        if (FALSE == pGemToken->isLoggedIn)
        {
            pCredential = PKCS11_fetchCredentialFromList(
                                &pCredentials->pEntityCredentials->credentialList, TAP_CREDENTIAL_CONTEXT_USER);

            if (NULL != pCredential)
            {
                if (NULL != pCredential->credentialData.pBuffer)
                {
                    rVal = CALL_PKCS11_API(C_Login, pGemToken->tokenSession, CKU_USER, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);

                    /* If the user is already logged in then proceed. */
                    if (CKR_USER_ALREADY_LOGGED_IN == rVal)
                    {
                        rVal = CKR_OK;
                    }


                    if (CKR_OK != rVal)
                    {
                        status = PKCS11_nanosmpErr(pGemModule, rVal);
                        DB_PRINT("%s.%d Failed to Login status = %d\n",
                                __FUNCTION__,__LINE__, status);
                        goto exit;
                    }
                    isLocalLoggedIn = TRUE;
                    pGemToken->isLoggedIn = TRUE;
                }
            }
        }
    }

    if (TAP_KEY_ALGORITHM_UNDEFINED != keyAlgorithm)
    {
        if (NULL == keyData.pBuffer)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        switch(keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_AES:
                {
                    objClass = CKO_SECRET_KEY;
                    keyType = CKK_AES;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE, keyData.pBuffer, keyData.bufferLen);
                    numAttrs++;

                    switch(keyData.bufferLen)
                    {
                        case 16:
                            keySize = TAP_KEY_SIZE_128;
                            break;

                        case 24:
                            keySize = TAP_KEY_SIZE_192;
                            break;

                        case 32:
                            keySize = TAP_KEY_SIZE_256;
                            break;

                        default:
                            status = ERR_INVALID_INPUT;
                            goto exit;
                    }
                }
                break;
            case TAP_KEY_ALGORITHM_DES:
                {
                    objClass = CKO_SECRET_KEY;
                    keyType = CKK_DES;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE, keyData.pBuffer, keyData.bufferLen);
                    numAttrs++;
                }
                break;
            case TAP_KEY_ALGORITHM_TDES:
                {
                    objClass = CKO_SECRET_KEY;
                    keyType = CKK_DES3;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_DECRYPT, &decryptUsage, sizeof(decryptUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE, keyData.pBuffer, keyData.bufferLen);
                    numAttrs++;
                }
                break;
            case TAP_KEY_ALGORITHM_HMAC:
                {
                    objClass = CKO_SECRET_KEY;
                    keyType = CKK_GENERIC_SECRET;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_SIGN, &signUsage, sizeof(signUsage));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_VALUE, keyData.pBuffer, keyData.bufferLen);
                    numAttrs++;

                    rawKeySize = (TAP_RAW_KEY_SIZE) keyData.bufferLen;
                    if (rawKeySize > RAW_KEY_MAX_LEN)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid raw key size %d,"
                                " status = %d\n", __FUNCTION__, __LINE__,
                                rawKeySize, status);
                        goto exit;
                    }
                }
                break;
            case TAP_KEY_ALGORITHM_RSA:
                {
                    objClass = CKO_PUBLIC_KEY;
                    keyType = CKK_RSA;

                    /* We need the public key data */
                    if (NULL == keyData.pBuffer)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Error parsing RSA public key data = %d\n",
                            __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    /* We are expecting format of:
                     * modLen (4 bytes) || modulus || exponentLen (4 bytes) || exponent */
                    pIter = keyData.pBuffer;
                    status = DIGI_MEMCPY((void *)&nLen, (void *)pIter, sizeof(ubyte4));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Error parsing RSA public key data = %d\n",
                            __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    switch(nLen)
                    {
                        case 256:
                            keySize = TAP_KEY_SIZE_2048;
                            break;

                        case 384:
                            keySize = TAP_KEY_SIZE_3072;
                            break;

                        case 512:
                            keySize = TAP_KEY_SIZE_4096;
                            break;

                        default:
                            status = ERR_INVALID_INPUT;
                            goto exit;
                    }

                    if (nLen > keyData.bufferLen)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Error parsing RSA public key data = %d\n",
                            __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    pIter += sizeof(ubyte4);
                    pN = pIter;
                    pIter += nLen;

                    status = DIGI_MEMCPY((void *)&eLen, (void *)pIter, sizeof(ubyte4));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Error parsing RSA public key data = %d\n",
                            __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    if (nLen > keyData.bufferLen - eLen)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Error parsing RSA public key data = %d\n",
                            __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    pIter += sizeof(ubyte4);
                    pE = pIter;

                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_MODULUS, pN, nLen);
                    numAttrs++;
                    INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_PUBLIC_EXPONENT, pE, eLen);
                    numAttrs++;
                }
                break;
            default:
                {
                    status = ERR_TAP_INVALID_ALGORITHM;
                    DB_PRINT("%s.%d Unsupported Alogrithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                break;
        }

        if (OK != (status = DIGI_CALLOC((void**)&pNewObject, 1, sizeof(Pkcs11_Object))))
        {
            DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pNewObject->objectId = PKCS11_generateNextObjectId(pGemModule, pGemToken, CKO_SECRET_KEY);

        status = DIGI_MEMCPY((ubyte *) label, pNewObject->objectId.pBuffer, pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Was not able to create/copy objectId, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        keyTemplate[2].ulValueLen = pNewObject->objectId.bufferLen;
        idTemplate[0].ulValueLen = pNewObject->objectId.bufferLen;

        status = PKCS11_createKeyLabelAlloc (
            (const sbyte *) MOC_DEFAULT_LABEL_PREFIX, (const sbyte *)MOC_LABEL_SYM, keyAlgorithm,
            (TAP_KEY_ALGORITHM_HMAC == keyAlgorithm ? rawKeySize : (TAP_RAW_KEY_SIZE) keySize), 0, pNewObject->objectId, (sbyte **)&(keyTemplate[3].pValue));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to create key label = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
        keyTemplate[3].ulValueLen = DIGI_STRLEN((const sbyte *)(keyTemplate[3].pValue));

        rVal = CALL_PKCS11_API(C_CreateObject, pGemToken->tokenSession, keyTemplate, numAttrs, &objHandle);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d Failed to createObject status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pNewObject->refCount = 1;
        pNewObject->pubObject = objHandle;
        pNewObject->pNext = NULL;
        PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);

        if (pKeyObjectAttributes)
        {
            /* Put together TAP Attribute list of the parameters used to create
            this key
            */
            numCreatedKeyAttributes = 5;

            pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

            status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                    sizeof(TAP_Attribute) * numCreatedKeyAttributes);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            count = 0;

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_KEY_ALGORITHM;
            pCreatedKeyAttributes->length = sizeof(keyAlgorithm);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keyAlgorithm));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for keyAlgorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyAlgorithm,
                    sizeof(keyAlgorithm));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy keyAlgorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
            pCreatedKeyAttributes->length = sizeof(keyUsage);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keyUsage));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for key usage attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                    sizeof(keyUsage));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy key usage attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            if (TAP_KEY_USAGE_DECRYPT == keyUsage)
            {
                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

                pCreatedKeyAttributes->type = TAP_ATTR_SYM_KEY_MODE;
                pCreatedKeyAttributes->length = sizeof(symMode);
                status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(symMode));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for sym mode attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &symMode,
                        sizeof(symMode));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy symMode attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];
                pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
                pCreatedKeyAttributes->length = sizeof(keySize);
                status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(keySize));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for key size attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                        sizeof(keySize));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy key size attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
            }
            else /* TAP_KEY_USAGE_SIGNING == keyUsage */
            {
                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

                pCreatedKeyAttributes->type = TAP_ATTR_HASH_ALG;
                pCreatedKeyAttributes->length = sizeof(hashAlg);
                status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(hashAlg));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for Hash Algorithm attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &hashAlg,
                        sizeof(hashAlg));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy Hash Algorithm attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];
                pCreatedKeyAttributes->type = TAP_ATTR_RAW_KEY_SIZE;
                pCreatedKeyAttributes->length = sizeof(rawKeySize);
                status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(rawKeySize));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for raw key size attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &rawKeySize,
                        sizeof(rawKeySize));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy raw key size attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
            }

            /* Last entry */
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];
            pCreatedKeyAttributes->type = TAP_ATTR_NONE;
            pCreatedKeyAttributes->length = 0;
            pCreatedKeyAttributes->pStructOfType = NULL;
        }
    }
    else
    {
        /* create empty secure data object*/
        rVal = CALL_PKCS11_API(C_CreateObject, pGemToken->tokenSession, Template, ulCount, &objHandle);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d Failed to createObject status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        status = DIGI_CALLOC((void **)&pNewObject, 1, sizeof(Pkcs11_Object));
        if (OK != status)
        {
            status = ERR_MEM_ALLOC_FAIL;
            DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pNewObject->pubObject = 0;
        pNewObject->objectId = PKCS11_generateNextObjectId(pGemModule, pGemToken, CKO_DATA);

        status = DIGI_MEMCPY((ubyte *) label, pNewObject->objectId.pBuffer, pNewObject->objectId.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Was not able to create/copy objectId, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        idTemplate[0].ulValueLen = pNewObject->objectId.bufferLen;

        pNewObject->refCount = 1;
        pNewObject->pNext = NULL;

        PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);

        rVal = CALL_PKCS11_API(C_SetAttributeValue, pGemToken->tokenSession, objHandle, idTemplate, 1);
        if (CKR_OK != rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d Failed to set attribute value. status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }

    if (NULL != pObjectIdOut)
    {
        copyBufferIdToUlong(pObjectIdOut, pNewObject->objectId);
    }

    if (TRUE == isLocalLoggedIn)
    {
        rVal = CALL_PKCS11_API(C_Logout, pGemToken->tokenSession);
        if (rVal)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            goto exit;
        }
        pGemToken->isLoggedIn = FALSE;
    }

    /* Store the object handles */
    pNewObject->prvObject = objHandle;
    *pHandle = (TAP_ObjectHandle)((uintptr)pNewObject); pNewObject = NULL;

exit:

    if (NULL != keyTemplate[3].pValue)
    {
        DIGI_FREE((void **)&(keyTemplate[3].pValue));
    }

    if (NULL != pNewObject)
    {
        (void) PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pNewObject);
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
MSTATUS SMP_API(PKCS11, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p objectHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle, objectHandle);
        goto exit;
    }
    /* Remove only Pkcs11_Object memory */

    PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pGemObject);

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_PURGE_OBJECT__
MSTATUS SMP_API(PKCS11, purgeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)objectHandle);
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p objectHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle, objectHandle);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif
    /* Remove only Pkcs11_Object memory */

    /* Delete Public Object. If the object handles are the same this is a secret key, let the private
     * key deletion code take care of it */
    if ( (0 < pGemObject->pubObject) && (pGemObject->pubObject != pGemObject->prvObject) )
    {
        rVal = CALL_PKCS11_API(C_DestroyObject, pGemToken->tokenSession, pGemObject->pubObject);
        if (rVal != OK)
        {
            status = PKCS11_nanosmpErr(pGemModule, rVal);
            DB_PRINT("%s.%d Failed to destroy public object status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    /*Only public objects can be destroyed unless the normal user is logged in*/
    if (TRUE == pGemToken->isLoggedIn)
    {
        /*Delete Private Object */
        if (0 < pGemObject->prvObject)
        {
            rVal = CALL_PKCS11_API(C_DestroyObject, pGemToken->tokenSession, pGemObject->prvObject);
            if (rVal != OK)
            {
                status = PKCS11_nanosmpErr(pGemModule, rVal);
                DB_PRINT("%s.%d Failed to destroy private object status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
    }

    PKCS11_removeObject(pGemModule, &pGemToken->pObjectHead, pGemObject);

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);

    return status;
}
#endif


#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE__
MSTATUS SMP_API(PKCS11, getRootOfTrustCertificate,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Blob *pCertificate
)
{
    MSTATUS status = OK;

    if ((0 == moduleHandle) || (NULL == pCertificate))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, objectId = %p,"
                "pCertificate = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectId, pCertificate);
        goto exit;
    }


    status = DIGICERT_readFile(MOC_SMP_PKCS11_RT_CERT, &pCertificate->blob.pBuffer,
                      &pCertificate->blob.bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to read root of trust certificate, "
                        "status %d\n",  __FUNCTION__,__LINE__, status);
                goto exit;
    }
    pCertificate->format = TAP_BLOB_FORMAT_DER;
    pCertificate->encoding = TAP_BLOB_ENCODING_BINARY;
exit:

    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE__
MSTATUS SMP_API(PKCS11,getRootOfTrustKeyHandle,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_ObjectHandle *pKeyHandle
)
{
    return OK;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DUPLICATEKEY__
MSTATUS SMP_API(PKCS11,duplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pDuplicateBuf
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    Pkcs11_Object* pGemObject = (Pkcs11_Object*) ((uintptr)keyHandle);
    Pkcs11_Object* pKeyToBeWrapped = NULL;
    TAP_Attribute *pAttribute = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    CK_MECHANISM mechanism = {0};
    TAP_Buffer label = {0};
    TAP_Buffer ivBuf = {0};
    ubyte4 listCount = 0;
    ubyte keyWrapType = 0;
    TAP_Buffer keyToBeWrappedId = {0};
    ubyte *pWrappedKey = NULL;
    CK_ULONG wrappedKeyLen = 0;
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};
#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;

    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto exit;

    isMutexLocked = TRUE;
    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pGemObject) || 
        (0 == pGemObject->pubObject) || (NULL == pDuplicateBuf))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto exit;
    }
#endif

    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;
                
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_ENC_LABEL:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid label structure length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    label.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    label.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;

                case TAP_ATTR_KEY_WRAP_TYPE:
                    {
                        if ((sizeof(ubyte) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid key wrap type of length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        keyWrapType = *(ubyte *)(pAttribute->pStructOfType);
                    }
                    break;
                case TAP_ATTR_KEY_TO_BE_WRAPPED_ID:
                    {
                        if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid wrapping key id of length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        keyToBeWrappedId = *((TAP_Buffer *)(pAttribute->pStructOfType));
                    }
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    switch(keyWrapType)
    {
        case TAP_KEY_WRAP_RSA:
            mechanism.mechanism = CKM_RSA_PKCS;
            break;

        case TAP_KEY_WRAP_RSA_OAEP:
            {
                mechanism.mechanism = CKM_RSA_PKCS_OAEP;
                switch(encScheme)
                {
                    case TAP_ENC_SCHEME_OAEP_SHA1:
                        oaepParams.hashAlg = CKM_SHA_1;
                        oaepParams.mgf = CKG_MGF1_SHA1;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA224:
                        oaepParams.hashAlg = CKM_SHA224;
                        oaepParams.mgf = CKG_MGF1_SHA224;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA256:
                        oaepParams.hashAlg = CKM_SHA256;
                        oaepParams.mgf = CKG_MGF1_SHA256;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA384:
                        oaepParams.hashAlg = CKM_SHA384;
                        oaepParams.mgf = CKG_MGF1_SHA384;
                        break;
                    
                    case TAP_ENC_SCHEME_OAEP_SHA512:
                        oaepParams.hashAlg = CKM_SHA512;
                        oaepParams.mgf = CKG_MGF1_SHA512;
                        break;

                    default:
                        status = ERR_TAP_INVALID_SCHEME;
                        DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                                __FUNCTION__,__LINE__, (int)encScheme,
                                status);
                        goto exit;
                }

                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                mechanism.pParameter = &oaepParams;
                mechanism.ulParameterLen = sizeof(oaepParams);
            }
            break;

        case TAP_KEY_WRAP_AES:
            mechanism.mechanism = CKM_AES_CBC;
            mechanism.pParameter = (CK_VOID_PTR)ivBuf.pBuffer;
            mechanism.ulParameterLen = (CK_ULONG)ivBuf.bufferLen;
            break;

        default:
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid key wrap type\n", __FUNCTION__,__LINE__);
                goto exit;
            }
    }

    /* Establish a handle to the wrapping key by searching using provided ID */
    pKeyToBeWrapped = PKCS11_findAndAllocObject(pGemModule, pGemToken, keyToBeWrappedId);
    if (NULL == pKeyToBeWrapped)
    {
        /* We need to establish handle for operation, fatal error */
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Failed to find wrapping key by provided ID\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    /* Get the wrapped key length */
    rVal = CALL_PKCS11_API(C_WrapKey,
        pGemToken->tokenSession, &mechanism, pGemObject->pubObject, 
        pKeyToBeWrapped->prvObject, NULL, &wrappedKeyLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_WrapKey Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    /* Allocate the buffer that will receive the wrapped key. Known narrowing
     * conversion on 64-bit, wrapped key length will never blow out a ubyte4. */
    status = DIGI_MALLOC((void **)&pWrappedKey, (ubyte4)wrappedKeyLen);
    if (OK != status)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Allocation failure of size %d\n", __FUNCTION__,__LINE__, (int)wrappedKeyLen);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_WrapKey,
        pGemToken->tokenSession, &mechanism, pGemObject->pubObject,
        pKeyToBeWrapped->prvObject, (CK_BYTE_PTR)pWrappedKey, &wrappedKeyLen);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d C_WrapKey Failed. status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pDuplicateBuf->pBuffer = pWrappedKey;
    pDuplicateBuf->bufferLen = (ubyte4)wrappedKeyLen;
    pWrappedKey = NULL;

exit:
    if (NULL != pKeyToBeWrapped)
    {
        if (NULL != pKeyToBeWrapped->objectId.pBuffer)
        {
            DIGI_FREE((void **)&pKeyToBeWrapped->objectId.pBuffer);
            pKeyToBeWrapped->objectId.bufferLen = 0;
        }
        DIGI_FREE((void **)&pKeyToBeWrapped);
    }
    if (NULL != pWrappedKey)
    {
        DIGI_FREE((void **)&pWrappedKey);
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORTDUPLICATEKEY__
MSTATUS SMP_API(PKCS11,importDuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        TAP_Buffer *pDuplicateBuf,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    CK_RV rVal = CKR_OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    Pkcs11_Token* pGemToken = (Pkcs11_Token*) ((uintptr)tokenHandle);
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_UNDEFINED;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_SYM_DEFAULT;
    CK_MECHANISM mechanism = {0};
    TAP_Attribute *pAttribute = NULL;
    ubyte4 numAttrs = 4;
    ubyte4 count = 0;
    CK_ULONG keyId = 0;
    CK_BBOOL isTrue = TRUE;
    CK_BBOOL token = TRUE;
    CK_BBOOL decryptUsage = FALSE;
    CK_BBOOL signUsage = FALSE;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    TAP_Buffer wrappingKeyId = {0};
    ubyte keyWrapType = 0;
    TAP_Buffer ivBuf = {0};
    TAP_Buffer label = {0};
    CK_OBJECT_HANDLE objHandle = 0;
    Pkcs11_Object* pUnwrappingKey = NULL;
    Pkcs11_Object* pNewObject = NULL;
    TAP_ENC_SCHEME encScheme;
    CK_RSA_PKCS_OAEP_PARAMS oaepParams = {0};

    CK_ATTRIBUTE keyTemplate[20] =
    {
        {CKA_CLASS, &objClass, sizeof(objClass)},
        {CKA_TOKEN, &token, sizeof(token)},
        {CKA_ID, NULL, 0},
        {CKA_LABEL, NULL, 0},
    };

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    CK_FUNCTION_LIST_PTR pFuncTable = NULL;
#endif

    byteBoolean isMutexLocked = FALSE;
    if (OK != (status = RTOS_mutexWait(gGemMutex)))
        goto null_exit;

    isMutexLocked = TRUE;

    if ((NULL == pGemModule) || (NULL == pGemToken) || (NULL == pKeyAttributeList) || (NULL == pDuplicateBuf))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle);
        goto null_exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DYNAMIC_LOAD__
    pFuncTable = pGemModule->pFuncTable;
    if (NULL == pFuncTable)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d: Internal Error, NULL pFuncTable.\n",__FUNCTION__, __LINE__);
        goto null_exit;
    }
#endif

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;
                
                case TAP_ATTR_KEY_USAGE:
                    if (sizeof(TAP_KEY_USAGE) == pAttribute->length)
                        keyUsage = *((TAP_KEY_USAGE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key usage length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    switch(keyUsage)
                    {
                        case TAP_KEY_USAGE_UNDEFINED:
                        case TAP_KEY_USAGE_GENERAL:
                            {
                                decryptUsage = TRUE;
                                signUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_DECRYPT:
                            {
                                decryptUsage = TRUE;
                                break;
                            }
                        case TAP_KEY_USAGE_SIGNING:
                            {
                                signUsage = TRUE;
                                break;
                            }
                        default:
                            {
                                status = ERR_TAP;
                                goto exit;
                            }
                    }  /* keyUsage */

                    break;
                
                case TAP_ATTR_BUFFER:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    ivBuf = *((TAP_Buffer *)(pAttribute->pStructOfType));

                    break;
                
                case TAP_ATTR_ENC_LABEL:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid label structure length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    label.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    label.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;

                case TAP_ATTR_KEY_WRAP_TYPE:
                    {
                        if ((sizeof(ubyte) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid key wrap type of length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        keyWrapType = *(ubyte *)(pAttribute->pStructOfType);
                    }
                    break;

                case TAP_ATTR_WRAPPING_KEY_ID:
                    {
                        if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                                (NULL == pAttribute->pStructOfType))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid wrapping key id of length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                            goto exit;
                        }
                        wrappingKeyId = *((TAP_Buffer *)(pAttribute->pStructOfType));
                    }
                    break;
            }
        }
    }

    switch(keyWrapType)
    {
        case TAP_KEY_WRAP_RSA:
            mechanism.mechanism = CKM_RSA_PKCS;
            break;
        
        case TAP_KEY_WRAP_RSA_OAEP:
            {
                mechanism.mechanism = CKM_RSA_PKCS_OAEP;
                switch(encScheme)
                {
                    case TAP_ENC_SCHEME_OAEP_SHA1:
                        oaepParams.hashAlg = CKM_SHA_1;
                        oaepParams.mgf = CKG_MGF1_SHA1;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA224:
                        oaepParams.hashAlg = CKM_SHA224;
                        oaepParams.mgf = CKG_MGF1_SHA224;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA256:
                        oaepParams.hashAlg = CKM_SHA256;
                        oaepParams.mgf = CKG_MGF1_SHA256;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA384:
                        oaepParams.hashAlg = CKM_SHA384;
                        oaepParams.mgf = CKG_MGF1_SHA384;
                        break;

                    case TAP_ENC_SCHEME_OAEP_SHA512:
                        oaepParams.hashAlg = CKM_SHA512;
                        oaepParams.mgf = CKG_MGF1_SHA512;
                        break;

                    default:
                        status = ERR_TAP_INVALID_SCHEME;
                        DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                                __FUNCTION__,__LINE__, (int)encScheme,
                                status);
                        goto exit;
                }

                oaepParams.source = CKZ_DATA_SPECIFIED;
                oaepParams.pSourceData = label.pBuffer;
                oaepParams.ulSourceDataLen = label.bufferLen;
                mechanism.pParameter = &oaepParams;
                mechanism.ulParameterLen = sizeof(oaepParams);
            }
            break;
        
        case TAP_KEY_WRAP_AES:
            mechanism.mechanism = CKM_AES_CBC;
            mechanism.pParameter = (CK_VOID_PTR)ivBuf.pBuffer;
            mechanism.ulParameterLen = (CK_ULONG)ivBuf.bufferLen;
            break;

        default:
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid key wrap type\n", __FUNCTION__,__LINE__);
                goto exit;
            }
    }

    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
        {
            keyType = CKK_AES;
            objClass = CKO_SECRET_KEY;

            INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
            numAttrs++;
            INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_ENCRYPT, &decryptUsage, sizeof(decryptUsage));
            numAttrs++;
            INSERT_ATTRIBUTE(keyTemplate[numAttrs], CKA_KEY_TYPE, &keyType, sizeof(keyType));
            numAttrs++;
        }
        break;

        default:
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid key type for unwrap\n", __FUNCTION__,__LINE__);
                goto exit;
            }
    }

    if (OK != (status = DIGI_MALLOC((void**)&pNewObject, sizeof(Pkcs11_Object))))
    {
        DB_PRINT("%s.%d Failed to allocate memory status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pNewObject->objectId = PKCS11_generateNextObjectId(pGemModule, pGemToken, objClass);

    keyTemplate[2].pValue = (void *)pNewObject->objectId.pBuffer;
    keyTemplate[2].ulValueLen = (CK_ULONG)pNewObject->objectId.bufferLen;

    keySize = TAP_KEY_SIZE_UNDEFINED;

    status = PKCS11_createKeyLabelAlloc (  /* If HMAC keys are later supported, pass in rawKeySize */
        (const sbyte *) MOC_DEFAULT_LABEL_PREFIX, (const sbyte *)MOC_LABEL_SYM, keyAlgorithm,
        (TAP_RAW_KEY_SIZE) keySize, 0, pNewObject->objectId, (sbyte **)&(keyTemplate[3].pValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create key label = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    keyTemplate[3].ulValueLen = DIGI_STRLEN((const sbyte *)(keyTemplate[3].pValue)) + 1;

    /* Establish a handle to the unwrapping key by searching using provided ID */
    pUnwrappingKey = PKCS11_findAndAllocObject(pGemModule, pGemToken, wrappingKeyId);
    if (NULL == pUnwrappingKey)
    {
        /* We need to establish handle for operation, fatal error */
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Failed to find wrapping key by provided ID\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    rVal = CALL_PKCS11_API(C_UnwrapKey,
        pGemToken->tokenSession, &mechanism, pUnwrappingKey->prvObject, pDuplicateBuf->pBuffer,
        pDuplicateBuf->bufferLen, keyTemplate, numAttrs, &objHandle);
    if (CKR_OK != rVal)
    {
        status = PKCS11_nanosmpErr(pGemModule, rVal);
        DB_PRINT("%s.%d Failed to C_UnwrapKey status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pNewObject->refCount = 1;
    pNewObject->pubObject = objHandle;
    pNewObject->prvObject = objHandle;
    pNewObject->pNext = NULL;
    PKCS11_addNewObject(pGemModule, &pGemToken->pObjectHead, pNewObject);

    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pNewObject); pNewObject = NULL;

exit:

    if (NULL != pNewObject)
    {
        if (NULL != pNewObject->objectId.pBuffer)
        {
            (void) DIGI_FREE((void **) &pNewObject->objectId.pBuffer);
            pNewObject->objectId.bufferLen = 0;
        }
        (void) DIGI_FREE((void **) &pNewObject);
    }

    if (NULL != pUnwrappingKey)
    {
        if (NULL != pUnwrappingKey->objectId.pBuffer)
        {
            (void) DIGI_FREE((void **) &pUnwrappingKey->objectId.pBuffer);
            pUnwrappingKey->objectId.bufferLen = 0;
        }
        (void) DIGI_FREE((void **) &pUnwrappingKey);
    }

    if (NULL != keyTemplate[3].pValue)
    {
        DIGI_FREE((void **)&(keyTemplate[3].pValue));
    }

null_exit:

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gGemMutex);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_LAST_ERROR__
MOC_EXTERN MSTATUS SMP_API(PKCS11, getLastError,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ErrorAttributes *pErrorAttributes
)
{
    MSTATUS status = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);

    if ((NULL == pGemModule) || (NULL == pErrorAttributes))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    pErrorAttributes->listLen = 1;
    pErrorAttributes->pAttributeList = MALLOC(sizeof(TAP_Attribute));
    if (NULL == pErrorAttributes->pAttributeList)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        goto exit;
    }

    pErrorAttributes->pAttributeList->type = TAP_ATTR_NONE;
    pErrorAttributes->pAttributeList->length = sizeof(TAP_Error);
    pErrorAttributes->pAttributeList->pStructOfType = (void *) &pGemModule->error;

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST__
MOC_EXTERN MSTATUS SMP_API(PKCS11, selfTest,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestResponseAttributes *pTestResponse
)
{
    MSTATUS status = OK;
    MSTATUS tmpStatus = OK;
    Pkcs11_Module* pGemModule = (Pkcs11_Module*) ((uintptr)moduleHandle);
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle keyHandle = 0;
    TAP_TEST_MODE* pTestMode = NULL;
    TAP_TokenId tokenId = 0;
    TAP_ObjectId objId = 0;
    TAP_EntityList tokenIdList = {0};

    TAP_TokenCapabilityAttributes* pTokenAttributes = NULL;
    TAP_EntityCredentialList *pCredentials = NULL;
    TAP_SignAttributes *pSignatureAttributes = NULL;
    ubyte encScheme = TAP_ENC_SCHEME_OAEP_SHA256;
    ubyte sigScheme = TAP_SIG_SCHEME_PSS_SHA256;
    ubyte keyUsage = TAP_KEY_USAGE_GENERAL;

    ubyte plain[256] = "Buffer to Be Encrypted";
    TAP_Buffer plainText = {DIGI_STRLEN((const sbyte *)plain), plain};

    ubyte cipher[256];
    TAP_Buffer ciphered = {sizeof(cipher), cipher};

    ubyte buffer[] = "BufferSign";
    TAP_Buffer bufferText = {DIGI_STRLEN((const sbyte *)buffer), buffer};

    ubyte decrypt[256];
    TAP_Buffer decrypted = {sizeof(decrypt), decrypt};

    ubyte signBuff[128];
    TAP_Signature* pSignature = MALLOC(sizeof(TAP_Signature));
    byteBoolean isSignatureValid = FALSE;

    TAP_SIG_SCHEME digestType = sigScheme;
    MSTATUS *pStatus = NULL;

    ubyte userPwd[] = RESET_PIN_CODE;
    TAP_Credential cred = {TAP_CREDENTIAL_TYPE_PASSWORD, TAP_CREDENTIAL_FORMAT_PLAINTEXT, TAP_CREDENTIAL_CONTEXT_USER, {4, userPwd}};
    TAP_EntityCredential credentials = {TAP_ENTITY_TYPE_MODULE, 0, TAP_ENTITY_TYPE_TOKEN, 0, {1, &cred}};
    TAP_EntityCredentialList keyCredList = {1, &credentials};

    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_1024;
    TAP_KEY_ALGORITHM rsaAlgoType = TAP_KEY_ALGORITHM_RSA;
    TAP_Attribute rsaKeyAttr[] =
    {
        {TAP_ATTR_KEY_SIZE, sizeof(TAP_KEY_SIZE), &keySize},
        {TAP_ATTR_KEY_USAGE, sizeof(TAP_KEY_USAGE), &keyUsage},
        {TAP_ATTR_KEY_ALGORITHM, sizeof(TAP_KEY_ALGORITHM), &rsaAlgoType},
        {TAP_ATTR_CREDENTIAL, sizeof(TAP_EntityCredentialList), &keyCredList},
        {TAP_ATTR_ENC_SCHEME, sizeof(TAP_ENC_SCHEME), &encScheme},
        {TAP_ATTR_SIG_SCHEME, sizeof(TAP_SIG_SCHEME), &sigScheme}
    };

    TAP_KeyAttributes keyAttributes = {3, rsaKeyAttr};


    if ((NULL == pGemModule) || (NULL == pTestRequest) || (NULL == pTestResponse)
           || (NULL == pTestRequest->pAttributeList)
           || (NULL == pTestRequest->pAttributeList->pStructOfType))
    {
        if (NULL == pGemModule)
            PKCS11_FillError(NULL, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        else
            PKCS11_FillError(&pGemModule->error, &status, ERR_NULL_POINTER, "ERR_NULL_POINTER");
        goto exit;
    }

    CALL_SMP_API(PKCS11, getTokenList, moduleHandle, TAP_TOKEN_TYPE_DEFAULT,
            pTokenAttributes, &tokenIdList);

	GDEBUG_PRINTSTR1INT1("status: ", status);
    GDEBUG_PRINT("\n");
	if (OK != status)
	{
		GDEBUG_PRINT("GetTokenList Failure\n");
        goto exit;
	}

	if ((0 == tokenIdList.entityIdList.numEntities) || (NULL == tokenIdList.entityIdList.pEntityIdList))
	{
		DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
		status = ERR_TAP_NO_TOKEN_AVAILABLE;
		goto exit;
	}
	tokenId = tokenIdList.entityIdList.pEntityIdList[0];
	DIGI_FREE((void **)&tokenIdList.entityIdList.pEntityIdList);

    if (TAP_ATTR_TEST_MODE == pTestRequest->pAttributeList->type)
    {
        pTestMode = (TAP_TEST_MODE *)pTestRequest->pAttributeList->pStructOfType;
        switch (*pTestMode)
        {
            case TAP_TEST_MODE_FULL:
            {
                /* Encrypt / Decrypt */
				TAP_AttributeList encryptAttrList = {0};
                TAP_Attribute encryptAttrs[] = {{TAP_ATTR_ENC_SCHEME, sizeof(TAP_ENC_SCHEME), &encScheme}};

                /* Sign / Verify */
                TAP_AttributeList verifyAttrList = {0};
                TAP_Attribute verifyAttrs[] = {{TAP_ATTR_SIG_SCHEME, sizeof(TAP_SIG_SCHEME), &sigScheme}};

                GDEBUG_PRINT("Init Token\n");
                CALL_SMP_API(PKCS11, initToken, moduleHandle, pTokenAttributes,
                                tokenId, pCredentials, (TAP_TokenHandle *) &tokenHandle);
                GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Init Token Failure\n");
                    break;
                }

                GDEBUG_PRINT("Logging In to Token\n");
                CALL_SMP_API(PKCS11, associateTokenCredentials, moduleHandle,
                                tokenHandle, &keyCredList);
                GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Login Failure\n");
                    break;
                }

                GDEBUG_PRINT("Create Asymmetric Keys\n");
                CALL_SMP_API(PKCS11, createAsymmetricKey, moduleHandle, tokenHandle,
                             &keyAttributes, 0, &objId, NULL, &keyHandle);
                if (OK != status)
                {
                    GDEBUG_PRINT("Create Asymmetric Failure\n");
                    break;
                }

                GDEBUG_PRINTSTR1HEXINT1("Object Created: ", (int)objId);
                GDEBUG_PRINT("\n");

                encryptAttrList.listLen = 1;
                encryptAttrList.pAttributeList = encryptAttrs;

                GDEBUG_PRINT3("Encrypting String: ", plainText.pBuffer, "\n");
                CALL_SMP_API(PKCS11, encrypt, moduleHandle, tokenHandle, keyHandle,
                                &encryptAttrList, &plainText, &ciphered);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Encrypt Failure\n");
                    break;
                }
                GDEBUG_PRINT("Decrypting\n");
                CALL_SMP_API(PKCS11, decrypt, moduleHandle, tokenHandle, keyHandle,
                                &encryptAttrList, &ciphered, &decrypted);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Decrypt Failure\n");
                    break;
                }
                decrypted.pBuffer[decrypted.bufferLen] = '\0';
                GDEBUG_PRINT3("Decrypted String: ", decrypted.pBuffer, "\n");

                /* Sign / Verify */
                GDEBUG_PRINT("Sign init \n");
                pSignature->signature.rsaSignature.pSignature = signBuff;
                pSignature->signature.rsaSignature.signatureLen = sizeof(signBuff);

                GDEBUG_PRINT("Sign\n");
                CALL_SMP_API(PKCS11, signBuffer, moduleHandle, tokenHandle, keyHandle,
                                &bufferText, digestType, pSignatureAttributes, &pSignature);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Sign Failure\n");
                    break;
                }

                verifyAttrList.listLen = 1;
                verifyAttrList.pAttributeList = verifyAttrs;

                GDEBUG_PRINT("Verify\n");
                CALL_SMP_API(PKCS11, verify, moduleHandle, tokenHandle, keyHandle,
                                &verifyAttrList, &bufferText, pSignature, &isSignatureValid);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
                if (OK != status)
                {
                    GDEBUG_PRINT("Verify Failure\n");
                    break;
                }

                if (1 == isSignatureValid)
                    GDEBUG_PRINT("Signature Validity: Succeeded\n");
                else
                    GDEBUG_PRINT("Signature Validity: Failed\n");

                GDEBUG_PRINT("Deleting Object\n");
                CALL_SMP_API(PKCS11, deleteObject, moduleHandle, tokenHandle, keyHandle);
                GDEBUG_PRINT("Object Deleted\n");
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");

                GDEBUG_PRINT("Logging out of to Token\n");
                CALL_SMP_API(PKCS11, associateTokenCredentials, moduleHandle,
                                tokenHandle, NULL);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");

                GDEBUG_PRINT("Uninit Token\n");
                CALL_SMP_API(PKCS11, uninitToken, moduleHandle, tokenHandle);
            	GDEBUG_PRINTSTR1INT1("status: ", status);
                GDEBUG_PRINT("\n");
            }
                break;
            default:
                PKCS11_FillError(&pGemModule->error, &status, ERR_INVALID_ARG, "ERR_INVALID_ARG");
                break;
        }
    }

    if (OK != status)
    {
        tmpStatus = status;
        CALL_SMP_API(PKCS11, deleteObject, moduleHandle, tokenHandle, keyHandle);
        CALL_SMP_API(PKCS11, associateTokenCredentials, moduleHandle,
                       tokenHandle, NULL);
        CALL_SMP_API(PKCS11, uninitToken, moduleHandle, tokenHandle);
        status = tmpStatus;
    }

    pStatus = MALLOC(sizeof(MSTATUS));
    if (NULL == pStatus)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        goto exit;
    }
    *pStatus = status;

    pTestResponse->listLen = 1;
    pTestResponse->pAttributeList = MALLOC(sizeof(TAP_Attribute));
    if (NULL == pTestResponse->pAttributeList)
    {
        PKCS11_FillError(&pGemModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        FREE(pStatus);
        goto exit;
    }

    pTestResponse->pAttributeList->type = TAP_ATTR_TEST_STATUS;
    pTestResponse->pAttributeList->length = sizeof(status);
    pTestResponse->pAttributeList->pStructOfType = pStatus;

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST_POLL__
MOC_EXTERN MSTATUS SMP_API(PKCS11, selfTestPoll,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestContext testContext,
        TAP_TestResponseAttributes *pTestResponse
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_PKCS11__)) */
