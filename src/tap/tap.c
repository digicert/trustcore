/*
 * tap.c
 *
 * @details  This file contains the TAP client side
 *
 * Trust Anchor Platform APIs
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
#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mfmgmt.h"
#include "../common/debug_console.h"
#include "../crypto/cert_store.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "tap.h"
#include "tap_api.h"
#include "tap_common.h"
#include "tap_utils.h"
#include "tap_base_serialize.h"
#include "tap_serialize.h"
#include "../smp/smp_interface.h"
#include "smp_serialize_interface.h"
#include "tap_remote.h"
#include "tap_client_comm.h"
#include "tap_serialize_remote.h"
#include "tap_conf_common.h"

#include "../crypto/pkcs1.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__

#include "../common/mdefs.h"
#include "../common/mstdlib.h"
#include "../crypto/hw_accel.h"
#include "../crypto/sha256.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_sha256.h"
#endif

#include "../data_protection/tap_data_protect.h"
#include "../data_protection/tools/fp_example_seed_callback.h"

/* max size macro matches that in cryptointerface.c */
#define MAX_KEY_BUFFER 1024

#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

/*------------------------------------------------------------------*/
/*  Internal types and  definitions */
/*------------------------------------------------------------------*/

/**
 * @private
 * @internal
 * @var localProviderList Global provider list built during TAP_init and freed in TAP_uninit.
 *                        This structure contains commands supported by the available providers on the local host.
 *                        This is populate in the first call to TAP_init by calling the SMP register functions.
 *                        This is freed in the last call to TAP_uninit by calling the SMP unregister functions.
 */
TAP_ProviderList localProviderList = { 0 };

/**
 * @private
 * @internal
 * @details Internal TAP context structure
 */
typedef struct
{
    /*! context signature */
    ubyte4                           signature;
    /*! security module type; must be value #TAP_PROVIDER value */
    TAP_PROVIDER                     providerType;
    /*! Information to uniquely identify a module.  This contains #TAP_ConnectionInfo. */
    TAP_Module                       module;
    /*! SSL session information for a connection. */
    TAP_SessionInfo                  sessionInfo;
    /*! Policy/Security descriptor */
    TAP_PolicyInfo                  *pPolicyAuthInfo;
    /*! Module handle returned by SMP */
    TAP_ModuleHandle moduleHandle;
} _TAP_Context;

MOC_EXTERN_DATA_DECL TAP_OPERATIONAL_INFO tapClientInfo;

/**
 * @private
 * @internal
 * @var tapRemoteInit Remote TAP initialization complete flag. Does not ensure thread safety, only to prevent multiple initializations.
 */
MOC_EXTERN_DATA_DECL ubyte tapRemoteInitDone;

/**
 * @private
 * @internal
 * @var tapInitDone TAP initialization complete flag. Does not ensure thread safety, only to prevent multiple initializations.
 */
static ubyte tapInitDone = 0;

/**
 * @private
 * @internal
 * @var globalDeferredTokenUnload Inidicates if all token uninitializations should be deferred.
 */
static ubyte globalDeferredTokenUnload = 0;

/* Global structure for TAP_ModuleInfo structures.  Table is populated
   by TAP_init with info returned by module init functions */

#if 0
/* Do we still need/want this with the new architecture? */
TAP_ModuleInfo TAP_moduleInfoList[TAP_PROVIDER_MAX];
#endif

/*------------------------------------------------------------------*/
/*  Internal function definitions */
/*------------------------------------------------------------------*/

MSTATUS TAP_updateAttributeList(TAP_AttributeList *pSrc, TAP_AttributeList *pDest,
        ubyte4 *pAttributeListLen);

MSTATUS TAP_dispatchSMPCommand(TAP_PROVIDER provider, TAP_SessionInfo *pSessionInfo,
                               SMP_CmdReq *pCmdReq, SMP_CmdRsp *pCmdRsp);

MSTATUS TAP_SMP_serializeObject(_TAP_Context *pContext, TAP_OBJECT_TYPE objType, const void *pObject,
                                TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                                TAP_Blob *pObjectBlob, TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_createObject(_TAP_Context *pContext,
                             TAP_TokenHandle *pTokenHandle,
                             TAP_AttributeList *pAttributes,
                             TAP_ObjectId *pObjectIdOut,
                             TAP_ObjectHandle *pObjectHandle);

MSTATUS TAP_SMP_deleteObject(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle);

MSTATUS TAP_SMP_deleteObject_usingAuthContext(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle,
                           TAP_AUTH_CONTEXT_PROPERTY authContext);

MSTATUS TAP_SMP_purgeObject(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle);

MSTATUS TAP_SMP_importObject(TAP_OBJECT_TYPE objType, const void *pObject,
                             TAP_TokenHandle *pTokenHandle,
                             TAP_ObjectCapabilityAttributes *pObjectAttributes,
                             TAP_EntityCredentialList *pCredentials,
                             TAP_Blob *pObjectBlob, TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_initObject(TAP_Context *pTapContext, TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectId *pObjectId,
                           TAP_ObjectCapabilityAttributes *pObjectAttributes,
                           TAP_EntityCredentialList *pCredentials,
                           TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut,
                           TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_uninitObject(_TAP_Context *pContext,
                             TAP_TokenHandle tokenHandle,
                             TAP_ObjectHandle objectHandle);

MSTATUS TAP_SMP_getObjectList(_TAP_Context *pContext,
                              TAP_TokenHandle *pTokenHandle,
                              TAP_AttributeList *pAttributes,
                              TAP_EntityList *pObjectList);

MSTATUS TAP_SMP_getObjectInfo(_TAP_Context *pContext,
                              TAP_TokenHandle *pTokenHandle,
                              TAP_ObjectHandle *pObjectHandle,
                              TAP_ObjectId *pObjectId,
                              TAP_AttributeList *pAttributes,
                              TAP_AttributeList *pObjectAttributes);

MSTATUS TAP_SMP_getTokenList(TAP_Context *pTapContext, TAP_TOKEN_TYPE tokenType,
                         TAP_TokenCapabilityAttributes *pCapabilityAttributes,
                         TAP_EntityList *pTokenList, TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_getTokenInfo(TAP_Context *pTapContext, TAP_TokenId *pTokenId,
                             TAP_TokenCapabilityAttributes *pCapabilitySelection,
                             TAP_TokenCapabilityAttributes *pTokenCapabilities,
                             TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_initToken(TAP_Context *pTapContext, TAP_TokenId *pTokenId,
                          TAP_TokenCapabilityAttributes *pTokenAttributes,
                          TAP_EntityCredentialList *pCredentials,
                          TAP_TokenHandle *pTokenHandle,
                          TAP_ErrorContext *pErrContext);

MSTATUS TAP_SMP_uninitToken(TAP_Context *pTapContext, TAP_TokenHandle *pTokenHandle,
                            TAP_ErrorContext *pErrContext);


MSTATUS TAP_getPublicKey(TAP_Key *pTapKey, TAP_PublicKey *pPublicKey);

/*------------------------------------------------------------------*/
/*  Internal functions */
/*------------------------------------------------------------------*/

MSTATUS TAP_updateAttributeList(TAP_AttributeList *pSrc, TAP_AttributeList *pDest,
        ubyte4 *pAttributeListLen)
{
    MSTATUS status = OK;
    ubyte4 count;

    if ((NULL == pAttributeListLen) || (NULL == pSrc) ||
            (NULL == pDest))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pAttributeListLen = 0;

    pDest->listLen = pSrc->listLen;
    pDest->pAttributeList = pSrc->pAttributeList;

    for (count = 0; count < pDest->listLen; count++)
    {
        *pAttributeListLen += pDest->pAttributeList[count].length;
    }

exit:

    return status;
}

#ifdef __ENABLE_TAP_REMOTE__
/*------------------------------------------------------------------*/

static byteBoolean TAP_localSession(TAP_SessionInfo *pSessionInfo)
{
    byteBoolean bLocalSession = TRUE;

    if (pSessionInfo &&
            pSessionInfo->connInfo.serverName.pBuffer)
        bLocalSession = FALSE;

    return bLocalSession;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_dispatchSMPCommand(TAP_PROVIDER provider, TAP_SessionInfo *pSessionInfo,
                               SMP_CmdReq *pCmdReq, SMP_CmdRsp *pCmdRsp)
{
    MSTATUS status = OK;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_CmdReqHdr cmdReqHdr = {0};
    ubyte4 byteCount = 0;
    ubyte4 reqBufferSize = 0;
    ubyte *pReqBuffer = NULL ;
    ubyte *pResBuffer = NULL ;
    ubyte4 offset = 0;
    byteBoolean bLocalSession = FALSE;
#endif

    if ((NULL == pCmdReq) || (NULL == pCmdRsp) || (NULL == pSessionInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE__
    bLocalSession = TAP_localSession(pSessionInfo);

    if (FALSE == bLocalSession)
    {
        if(!pSessionInfo->sessionInit)
        {
            status = TAP_OpenSession(pSessionInfo);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error while connecting to the TAP server, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));

                goto exit;
            }
        }
    }
    else
#endif
    {
        status = TAP_COMMON_checkCmdSupport(&localProviderList, provider, pCmdReq->cmdCode);
        if (OK != status)
        {
            DB_PRINT("%s.%d Invalid command %d for TAP_PROVIDER %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, pCmdReq->cmdCode, provider, status, MERROR_lookUpErrorCode(status));

            goto exit;
        }
    }

    pCmdRsp->cmdCode = pCmdReq->cmdCode;

#ifdef __ENABLE_TAP_REMOTE__
    if (FALSE == bLocalSession)
    {
        pReqBuffer = pSessionInfo->txBuffer;
        reqBufferSize = sizeof(pSessionInfo->txBuffer);

        /* Serialize TAP command request */
        offset = 0;
        status = TAP_SERIALIZE_serialize(&SMP_INTERFACE_SHADOW_SMP_CmdReq, TAP_SD_IN,
                (ubyte *)pCmdReq, sizeof(*pCmdReq), pReqBuffer,
                reqBufferSize, &offset);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to deserialize command response, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        cmdReqHdr.cmdDest = TAP_CMD_DEST_MODULE;
        cmdReqHdr.cmdType = TAP_CMD_TYPE_SMP;
        cmdReqHdr.providerType = provider;
        cmdReqHdr.totalBytes = offset;
        byteCount = MAX_TAP_REMOTE_TX_BUFFER;
        pResBuffer = pSessionInfo->txBuffer;

        status = TAP_TransmitReceive(pSessionInfo, &cmdReqHdr, offset,
                pReqBuffer, &byteCount, pResBuffer, &pCmdRsp->returnCode);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to do TAP_TransmitReceive, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        /* Deserialize the command response, if it is present */
        if (byteCount)
        {
            offset = 0;
            status = TAP_SERIALIZE_serialize(&SMP_INTERFACE_SHADOW_SMP_CmdRsp, TAP_SD_OUT,
                    pResBuffer, byteCount, (ubyte *)pCmdRsp,
                    sizeof(*pCmdRsp), &offset);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to deserialize command response, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
        else
        {
            pCmdRsp->cmdCode = pCmdReq->cmdCode;
        }
    }
    else
#endif
    {
        switch (provider)
        {
            case TAP_PROVIDER_SW:
                status = ERR_TAP_UNSUPPORTED;
                break;
            case TAP_PROVIDER_TPM:
#ifdef  __ENABLE_DIGICERT_TPM__
                status = SMP_TPM12_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_TPM2:
#ifdef  __ENABLE_DIGICERT_TPM2__
                status = SMP_TPM2_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_SGX:
#ifdef  __ENABLE_DIGICERT_SGX__
                status = SMP_SGX_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_STSAFE:
#ifdef  __ENABLE_DIGICERT_STSAFE__
                status = SMP_STSAFE_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_NXPA71:
#ifdef  __ENABLE_DIGICERT_NXPA71__
                status = SMP_NXPA71_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
             case TAP_PROVIDER_GEMSIM:
#ifdef  __ENABLE_DIGICERT_GEMALTO__
                status = SMP_GEMALTO_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_PKCS11:
#ifdef  __ENABLE_DIGICERT_SMP_PKCS11__
                status = SMP_PKCS11_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_RENS5:
#ifdef  __ENABLE_DIGICERT_RENS5__
                status = SMP_RENS5_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_TRUSTX:
#ifdef  __ENABLE_DIGICERT_TRUSTX__
                status = SMP_TRUSTX_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_ARMM23:
#ifdef  __ENABLE_DIGICERT_ARMM23__
                status = SMP_ARMM23_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_ARMM33:
#ifdef  __ENABLE_DIGICERT_ARMM33__
                status = SMP_ARMM33_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_EPID:
#ifdef  __ENABLE_DIGICERT_EPID__
                status = SMP_EPID_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_TEE:
#ifdef  __ENABLE_DIGICERT_TEE__
                status = SMP_TEE_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            case TAP_PROVIDER_NANOROOT:
#ifdef  __ENABLE_DIGICERT_SMP_NANOROOT__
                status = SMP_NanoROOT_dispatcher((TAP_RequestContext *)pSessionInfo, pCmdReq, pCmdRsp, NULL, NULL);
#else
                status = ERR_TAP_UNSUPPORTED;
#endif
                break;
            default:
                status = ERR_TAP_INVALID_TAP_PROVIDER;
                DB_PRINT("%s.%d Invalid TAP_PROVIDER %d, status %d = %s\n", __FUNCTION__,
                        __LINE__, provider, status, MERROR_lookUpErrorCode(status));
                goto exit;
                break;
        }
        if (status != OK)
        {
            DB_PRINT("%s.%d Failed to process SMP command for provider %d (%s), status %d = %s\n", __FUNCTION__,
                    __LINE__, provider, TAP_UTILS_getProviderName(provider),
                    status, MERROR_lookUpErrorCode(status));
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* This is an internal function used by both TAP_serializeKey and TAP_serializeObject.
   It gets the underlying serialized blob from the provider, to be included with the
   serialized TAP structure.
   It calls either SMP_exportObject or SMP_serializeObject, depending on the object data.
 */
MSTATUS TAP_SMP_serializeObject(_TAP_Context *pContext, TAP_OBJECT_TYPE objType, const void *pObject,
                                TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                                TAP_Blob *pObjectBlob, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_ObjectId objectId = 0;

    /* check input */

    if ((NULL == pObject) || (NULL == pObjectBlob))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_HANDLE;
        goto exit;
    }

    /* Verify we have a valid object */
    switch (objType)
    {
        case TAP_OBJECT_TYPE_KEY:
            tokenHandle = ((TAP_Key *)pObject)->tokenHandle;
            objectHandle = (TAP_ObjectHandle)(((TAP_Key *)pObject)->keyHandle);
            objectId = ((TAP_Key *)pObject)->providerObjectData.objectInfo.objectId;
            break;
        case TAP_OBJECT_TYPE_OBJECT:
            tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
            objectHandle = (TAP_ObjectHandle)(((TAP_Object *)pObject)->objectHandle);
            objectId = ((TAP_Object *)pObject)->providerObjectData.objectInfo.objectId;
            break;
        case TAP_OBJECT_TYPE_STORAGE:
           /* For now, we are not serializing TAP_StorageObject structs */
        default:
            status = ERR_TAP_INVALID_OBJECT_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */
    MOC_UNUSED(objectId);
    smpCmdReq.cmdCode = SMP_CC_EXPORT_OBJECT;
    smpCmdReq.reqParams.exportObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.exportObject.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.exportObject.objectHandle = objectHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize/export data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (SMP_CC_SERIALIZE_OBJECT == smpCmdReq.cmdCode)
        status = TAP_UTILS_copyBlob(pObjectBlob, &(smpCmdRsp.rspParams.serializeObject.serializedObject));
    else
        status = TAP_UTILS_copyBlob(pObjectBlob, &(smpCmdRsp.rspParams.exportObject.exportedObject));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_createObject(_TAP_Context *pContext,
                             TAP_TokenHandle *pTokenHandle,
                             TAP_AttributeList *pAttributes,
                             TAP_ObjectId *pObjectIdOut,
                             TAP_ObjectHandle *pObjectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    /* check input */

    if ((NULL == pContext) || (NULL == pAttributes)
     || (NULL == pTokenHandle) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_CREATE_OBJECT;
    smpCmdReq.reqParams.createObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.createObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.createObject.pObjectAttributes = pAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pObjectIdOut = smpCmdRsp.rspParams.createObject.objectIdOut;
    *pObjectHandle = smpCmdRsp.rspParams.createObject.handle;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_deleteObject_usingAuthContext(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle,
                           TAP_AUTH_CONTEXT_PROPERTY authContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    /* check input */

    if ((NULL == pContext) || (NULL == pTokenHandle) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_DELETE_OBJECT;
    smpCmdReq.reqParams.deleteObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.deleteObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.deleteObject.objectHandle = *pObjectHandle;
    smpCmdReq.reqParams.deleteObject.authContext = authContext;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to delete object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

MSTATUS TAP_SMP_deleteObject(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    /* check input */

    if ((NULL == pContext) || (NULL == pTokenHandle) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_DELETE_OBJECT;
    smpCmdReq.reqParams.deleteObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.deleteObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.deleteObject.objectHandle = *pObjectHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_purgeObject(_TAP_Context *pContext,
                           TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectHandle *pObjectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    /* check input */

    if ((NULL == pContext) || (NULL == pTokenHandle) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_PURGE_OBJECT;
    smpCmdReq.reqParams.deleteObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.deleteObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.deleteObject.objectHandle = *pObjectHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

/* This is an internal function used by both TAP_loadKey (after TAP_deserializeKey)
   and TAP_loadObject (after TAP_deserializeObject).
   It sends the underlying blob obtained from the provider, back to the provider so that it
   can be made ready for use.
   It calls either SMP_importObject or SMP_initObject, depending on the object data.
   We may need to add TAP_BLOB_FORMAT format to the inputs if SMP APIs support it.
 */
MSTATUS TAP_SMP_importObject(TAP_OBJECT_TYPE objType, const void *pObject, TAP_TokenHandle *pTokenHandle,
                             TAP_ObjectCapabilityAttributes *pObjectAttributes,
                             TAP_EntityCredentialList *pCredentials,
                             TAP_Blob *pObjectBlob, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_ObjectCapabilityAttributes nullObjectAttributes = {0};
    volatile TAP_EntityCredentialList nullCredentials = {0};

    /* check input */
    if ((NULL == pObject) || (NULL == pObjectBlob))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pCredentials)
    {
        if ((NULL == pCredentials->pEntityCredentials) || (0 == pCredentials->numCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Credential list is empty, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        if ((TAP_ENTITY_TYPE_OBJECT != pCredentials->pEntityCredentials->entityType) &&
                (TAP_ENTITY_TYPE_MODULE != pCredentials->pEntityCredentials->entityType) &&
                (TAP_ENTITY_TYPE_TOKEN != pCredentials->pEntityCredentials->entityType))
        {
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Credential list does not match object/token/module, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        if ((0 < pCredentials->pEntityCredentials->credentialList.numCredentials) &&
            (NULL == pCredentials->pEntityCredentials->credentialList.pCredentialList))
        {
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Credential list is NULL when should have %d credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, pCredentials->pEntityCredentials->credentialList.numCredentials,
                    status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Verify we have a valid object */
    switch (objType)
    {
        case TAP_OBJECT_TYPE_KEY:
            pContext = (_TAP_Context *)((TAP_Key *)pObject)->pTapContext;
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            pContext = (_TAP_Context *)((TAP_StorageObject *)pObject)->pTapContext;
            break;
        case TAP_OBJECT_TYPE_OBJECT:
            pContext = (_TAP_Context *)((TAP_Object *)pObject)->pTapContext;
            break;
        default:
            status = ERR_TAP_INVALID_OBJECT_TYPE;
            goto exit;
            break;
    }

    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_IMPORT_OBJECT;
    smpCmdReq.reqParams.importObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.importObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.importObject.pObjectAttributes = pObjectAttributes ?
        pObjectAttributes :
        (TAP_ObjectCapabilityAttributes *)&nullObjectAttributes;
    smpCmdReq.reqParams.importObject.pCredentialList = pCredentials ?
        pCredentials :
        (TAP_EntityCredentialList *)&nullCredentials;
    smpCmdReq.reqParams.importObject.pBlob = pObjectBlob;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize/export data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_OBJECT_TYPE_KEY == objType)
        ((TAP_Key *)pObject)->keyHandle = (TAP_KeyHandle)(smpCmdRsp.rspParams.importObject.objectHandle);
    else
        ((TAP_Object *)pObject)->objectHandle = smpCmdRsp.rspParams.importObject.objectHandle;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_initObject(TAP_Context *pTapContext, TAP_TokenHandle *pTokenHandle,
                           TAP_ObjectId *pObjectId,
                           TAP_ObjectCapabilityAttributes *pObjectAttributes,
                           TAP_EntityCredentialList *pCredentials,
                           TAP_ObjectHandle *pObjectHandle, TAP_ObjectId *pObjectIdOut,
                           TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_ObjectId objectId = 0;
    volatile TAP_ObjectCapabilityAttributes nullObjectAttributes = {0};
    volatile TAP_EntityCredentialList nullCredentials = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pTokenHandle)
        || (NULL == pObjectId) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    objectId = *pObjectId;

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_INIT_OBJECT;
    smpCmdReq.reqParams.initObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.initObject.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.initObject.objectIdIn = objectId;
    smpCmdReq.reqParams.initObject.pObjectAttributes = pObjectAttributes ?
        pObjectAttributes :
        (TAP_ObjectCapabilityAttributes *)&nullObjectAttributes;
    smpCmdReq.reqParams.initObject.pCredentialList = pCredentials ?
        pCredentials :
        (TAP_EntityCredentialList *)&nullCredentials;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pObjectHandle = smpCmdRsp.rspParams.initObject.objectHandle;
    if (pObjectIdOut)
        *pObjectIdOut = smpCmdRsp.rspParams.initObject.objectIdOut;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_uninitObject(_TAP_Context *pContext,
                             TAP_TokenHandle tokenHandle,
                             TAP_ObjectHandle objectHandle)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    if (NULL == pContext)
    {
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_UNINIT_OBJECT;
    smpCmdReq.reqParams.unintObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.unintObject.tokenHandle =  tokenHandle;
    smpCmdReq.reqParams.unintObject.objectHandle = objectHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to uninit object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_getObjectList(_TAP_Context *pContext,
                              TAP_TokenHandle *pTokenHandle,
                              TAP_AttributeList *pAttributes,
                              TAP_EntityList *pObjectList)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    volatile TAP_ObjectCapabilityAttributes nullAttributes = {0};

    /* check input */
    if ((NULL == pContext) ||
        (NULL == pTokenHandle) || (NULL == pObjectList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_OBJECT_LIST;
    smpCmdReq.reqParams.getObjectList.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getObjectList.tokenHandle = *pTokenHandle;
    smpCmdReq.reqParams.getObjectList.pObjectAttributes = pAttributes ?
        (TAP_ObjectCapabilityAttributes *)pAttributes :
        (TAP_ObjectCapabilityAttributes *)&nullAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get object List, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 < smpCmdRsp.rspParams.getObjectList.objectIdList.entityIdList.numEntities)
    {
        status = DIGI_CALLOC((void **)&(pObjectList->entityIdList.pEntityIdList), 1,
                           smpCmdRsp.rspParams.getObjectList.objectIdList.entityIdList.numEntities * sizeof(TAP_EntityId));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                     __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = DIGI_MEMCPY((ubyte *)(pObjectList->entityIdList.pEntityIdList),
                            (ubyte *)(smpCmdRsp.rspParams.getObjectList.objectIdList.entityIdList.pEntityIdList),
                            smpCmdRsp.rspParams.getObjectList.objectIdList.entityIdList.numEntities * sizeof(TAP_EntityId));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy memory, status %d = %s\n", __FUNCTION__,
                     __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    pObjectList->entityIdList.numEntities = smpCmdRsp.rspParams.getObjectList.objectIdList.entityIdList.numEntities;
    pObjectList->entityType = smpCmdRsp.rspParams.getObjectList.objectIdList.entityType;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_getObjectInfo(_TAP_Context *pContext,
                              TAP_TokenHandle *pTokenHandle,
                              TAP_ObjectHandle *pObjectHandle,
                              TAP_ObjectId *pObjectId,
                              TAP_AttributeList *pAttributes,
                              TAP_AttributeList *pObjectAttributes)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    volatile TAP_ObjectCapabilityAttributes nullObjectCapAttr = {0};

    /* check input */
    if ((NULL == pContext) || (NULL == pTokenHandle) ||
            (NULL == pObjectAttributes))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((NULL == pObjectHandle) && (NULL == pObjectId))
    {
        status = ERR_TAP_INVALID_INPUT;
        DB_PRINT("%s.%d Must specify either an objectHandle or an objectId, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_OBJECT_INFO;
    smpCmdReq.reqParams.getObjectInfo.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getObjectInfo.tokenHandle = *pTokenHandle;
    if (NULL != pObjectHandle)
        smpCmdReq.reqParams.getObjectInfo.objectHandle = *pObjectHandle;
    else
        smpCmdReq.reqParams.getObjectInfo.objectHandle = 0;
    if (NULL != pObjectId)
        smpCmdReq.reqParams.getObjectInfo.objectId = *pObjectId;
    else
        smpCmdReq.reqParams.getObjectInfo.objectId = 0;
    smpCmdReq.reqParams.getObjectInfo.pCapabilitySelectAttributes = pAttributes ?
        (TAP_ObjectCapabilityAttributes *)pAttributes :
        (TAP_ObjectCapabilityAttributes *)&nullObjectCapAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get object List, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyAttributeList(pObjectAttributes,
                                         &(smpCmdRsp.rspParams.getObjectInfo.objectAttributes));
exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_getTokenList(TAP_Context *pTapContext, TAP_TOKEN_TYPE tokenType,
                         TAP_TokenCapabilityAttributes *pCapabilityAttributes,
                         TAP_EntityList *pTokenList, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;

    /* check input */
    if ((NULL == pTapContext) || (NULL == pCapabilityAttributes) || (NULL == pTokenList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_TOKEN_LIST;
    smpCmdReq.reqParams.getTokenList.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getTokenList.tokenType = tokenType;
    smpCmdReq.reqParams.getTokenList.pTokenAttributes = pCapabilityAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token List, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 < smpCmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.numEntities)
    {
        status = DIGI_CALLOC((void **)&(pTokenList->entityIdList.pEntityIdList), 1,
                           smpCmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.numEntities * sizeof(TAP_EntityId));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                     __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }


        status = DIGI_MEMCPY((ubyte *)(pTokenList->entityIdList.pEntityIdList),
                            (ubyte *)(smpCmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.pEntityIdList),
                            smpCmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.numEntities * sizeof(TAP_EntityId));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy memory, status %d = %s\n", __FUNCTION__,
                     __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    pTokenList->entityIdList.numEntities = smpCmdRsp.rspParams.getTokenList.tokenIdList.entityIdList.numEntities;
    pTokenList->entityType = smpCmdRsp.rspParams.getTokenList.tokenIdList.entityType;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_getTokenInfo(TAP_Context *pTapContext, TAP_TokenId *pTokenId,
                             TAP_TokenCapabilityAttributes *pCapabilitySelection,
                             TAP_TokenCapabilityAttributes *pTokenCapabilities,
                             TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_TokenCapabilityAttributes nullTokenCapAttr = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pTokenId)
     || (NULL == pTokenCapabilities))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_TOKEN_INFO;
    smpCmdReq.reqParams.getTokenInfo.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getTokenInfo.tokenType = TAP_TOKEN_TYPE_DEFAULT;
    smpCmdReq.reqParams.getTokenInfo.tokenId = *pTokenId;
    smpCmdReq.reqParams.getTokenInfo.pCapabilitySelectAttributes = pCapabilitySelection ?
        pCapabilitySelection :
        (TAP_TokenCapabilityAttributes *)&nullTokenCapAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token List, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    status = TAP_UTILS_copyAttributeList((TAP_AttributeList *)pTokenCapabilities,
                                          (TAP_AttributeList *)&(smpCmdRsp.rspParams.getTokenInfo.tokenAttributes));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy attribute list, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_initToken(TAP_Context *pTapContext, TAP_TokenId *pTokenId,
                          TAP_TokenCapabilityAttributes *pTokenAttributes,
                          TAP_EntityCredentialList *pCredentials,
                          TAP_TokenHandle *pTokenHandle,
                          TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_EntityCredentialList nullCredentials = {0};
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttr = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pTokenId) || (NULL == pTokenHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_INIT_TOKEN;
    smpCmdReq.reqParams.initToken.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.initToken.pTokenAttributes = pTokenAttributes ?
        pTokenAttributes :
        (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttr;
    smpCmdReq.reqParams.initToken.tokenId = *pTokenId;
    smpCmdReq.reqParams.initToken.pCredentialList = pCredentials ? pCredentials :
        (TAP_EntityCredentialList *)&nullCredentials;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to init token, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pTokenHandle = smpCmdRsp.rspParams.initToken.tokenHandle;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_SMP_uninitToken(TAP_Context *pTapContext, TAP_TokenHandle *pTokenHandle,
                            TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;

    /* check input */

    if ((NULL == pTapContext) || (NULL == pTokenHandle))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_UNINIT_TOKEN;
    smpCmdReq.reqParams.uninitToken.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.uninitToken.tokenHandle = *pTokenHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to uninit token, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getTapInfo(TAP_Context *pCtx, ubyte4 *pProviderType, ubyte4 *pModuleId)
{
    _TAP_Context *pContext = (_TAP_Context *) pCtx;

    if (NULL == pContext)
        return ERR_NULL_POINTER;
    
    if (NULL != pProviderType)
        *pProviderType = (ubyte4) pContext->providerType;
    
    if (NULL != pModuleId)
        *pModuleId = (ubyte4) pContext->module.moduleId;

    return OK;
}

/*------------------------------------------------------------------*/

/* We may want to expose this to the end user instead of having it as an internal function */
MSTATUS TAP_getPublicKey(TAP_Key *pTapKey, TAP_PublicKey *pPublicKey)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pPublicKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);


    status = DIGI_MEMSET((ubyte *)pPublicKey, 0, sizeof(TAP_PublicKey));

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_PUBLIC_KEY;
    smpCmdReq.reqParams.getPublicKey.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getPublicKey.tokenHandle =  pTapKey->tokenHandle;
    smpCmdReq.reqParams.getPublicKey.objectHandle = pTapKey->keyHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get module info, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Allocate memory for serialized structure */
    if (NULL != smpCmdRsp.rspParams.getPublicKey.pPublicKey)
    {
        status = TAP_UTILS_copyPublicKey(pPublicKey, smpCmdRsp.rspParams.getPublicKey.pPublicKey);
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/
/*                     External functions                           */
/*------------------------------------------------------------------*/

MSTATUS TAP_init(TAP_ConfigInfoList *pConfigInfoList, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

#ifdef __ENABLE_TAP_REMOTE__
    TAP_initRemoteSession();
#endif

    if (NULL == pConfigInfoList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* If Remote TAP Client is being initialized, the configuration file
       name will not be present
       */
    if (pConfigInfoList->pConfig &&
            pConfigInfoList->pConfig[0].configInfo.pBuffer)
    {
        /* On first init call in a local-only build, register the local SMPs.
           In a client-server build, this is done by the server at startup.
         */
        if (!tapInitDone)
        {
            /* For a local-only build, call register functions to get command code list.
               For a client-server build, this is done by the server at start-up. */
            status = TAP_COMMON_registerLocalProviders(pConfigInfoList, &localProviderList);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to generate the local provider list, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
            }

            tapInitDone = 1;
        }
    }
exit:

    return status;
}

#ifdef __ENABLE_TAP_REMOTE__
MSTATUS TAP_initEx(TAP_Buffer* tapClientConfig, certStorePtr pCertStore)
{
    MSTATUS status = OK;

    if (!tapRemoteInitDone)
    {
        tapClientInfo.configData.bufferLen = tapClientConfig->bufferLen;

        if ( (tapClientConfig->bufferLen > 0) )
        {
            if (NULL != tapClientInfo.configData.pBuffer)
                DIGI_FREE ((void**)&(tapClientInfo.configData.pBuffer));

            if ( OK != (status = DIGI_CALLOC ((void **)&(tapClientInfo.configData.pBuffer), 1, tapClientInfo.configData.bufferLen)))
                goto exit;

            if ( OK != (status = DIGI_MEMCPY ((void *)(tapClientInfo.configData.pBuffer), (void *)tapClientConfig->pBuffer, tapClientInfo.configData.bufferLen)))
                goto exit;
        }


        tapClientInfo.pSslCertStore             = pCertStore;

        if (pCertStore)
            tapClientInfo.isNonFsMode               = 1;
        else
            tapClientInfo.isNonFsMode               = 0;
    }

    TAP_initRemoteSession();

exit:
  return status;

}

MSTATUS TAP_uninitEx()
{
    MSTATUS status = OK;

    if(NULL != tapClientInfo.configData.pBuffer)
        DIGI_FREE ((void**)&(tapClientInfo.configData.pBuffer));

    tapClientInfo.isNonFsMode               = 0;

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_uninit(TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

#ifdef __ENABLE_TAP_REMOTE__
    TAP_unInitRemoteSession();
#endif

    /*  Free the provider list if it was initialized */
    if (tapInitDone)
    {
        /* For a local-only build, call unregister functions to free command code list(s).
           For a client-server build, this is done by the server at shutdown. */
        status = TAP_COMMON_unregisterLocalProviders(&localProviderList);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to unregister local providers and free the local provider list, status %d = %s\n",
                     __FUNCTION__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        tapInitDone = 0;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_copyConnectionInfo(TAP_ConnectionInfo *pDestConnInfo,
        TAP_ConnectionInfo *pSrcConnInfo)
{
    MSTATUS status = OK;
#ifdef __ENABLE_TAP_REMOTE__
    char *pServerName = NULL;
#endif

    if ((NULL == pDestConnInfo) || (NULL == pSrcConnInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestConnInfo->serverPort = pSrcConnInfo->serverPort;
    pDestConnInfo->serverName.bufferLen = pSrcConnInfo->serverName.bufferLen;
    pDestConnInfo->serverName.pBuffer = NULL;

    if (pSrcConnInfo->serverName.bufferLen && pSrcConnInfo->serverName.pBuffer)
    {
        status = DIGI_CALLOC((void **)&pDestConnInfo->serverName.pBuffer,
                            pDestConnInfo->serverName.bufferLen + 1,
                            sizeof(*(pDestConnInfo->serverName.pBuffer)));
        if (OK != status)
        {
            goto exit;
        }

        status = DIGI_MEMCPY(pDestConnInfo->serverName.pBuffer,
                pSrcConnInfo->serverName.pBuffer,
                pDestConnInfo->serverName.bufferLen);
        if (OK != status)
        {
            DIGI_FREE((void **)&pDestConnInfo->serverName.pBuffer);
            goto exit;
        }
    }
#ifdef __ENABLE_TAP_REMOTE__
    else
    {
        if (TAP_UNIX_DOMAIN_SOCKET == pSrcConnInfo->serverPort)
        {
            pServerName = (tapClientInfo.pServerName) ? tapClientInfo.pServerName : DEFAULT_UNIX_DOMAIN_PATH;

            pDestConnInfo->serverName.bufferLen = DIGI_STRLEN(pServerName);

            status = DIGI_CALLOC((void **)&pDestConnInfo->serverName.pBuffer,
                    pDestConnInfo->serverName.bufferLen + 1,
                    sizeof(*(pDestConnInfo->serverName.pBuffer)));
            if (OK != status)
            {
                goto exit;
            }

            status = DIGI_MEMCPY(pDestConnInfo->serverName.pBuffer,
                    pServerName, pDestConnInfo->serverName.bufferLen);
            if (OK != status)
            {
                DIGI_FREE((void **)&pDestConnInfo->serverName.pBuffer);
                goto exit;
            }
        }
    }
#endif

exit:
    return status;
}

/*------------------------------------------------------------------*/
MSTATUS TAP_freeConnectionInfo(TAP_ConnectionInfo *pDestConnInfo)
{
    MSTATUS status = OK;

    if (NULL == pDestConnInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pDestConnInfo->serverName.pBuffer)
        DIGI_FREE((void **)&pDestConnInfo->serverName.pBuffer);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* getProviderList is handled by TAP
   In a local-only build, it returns the list created during TAP_init.
   In a client-server build, it sends the request to the server, which returns the
   list populated during server startup.
 */
MSTATUS TAP_getProviderList(TAP_ConnectionInfo *pConnInfo,
                            TAP_ProviderList *pProviderList,
                            TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
#ifdef __ENABLE_TAP_REMOTE__
    TAP_CmdReq tapCmdReq = { 0, };
    TAP_CmdRsp tapCmdRsp = { 0, };
    TAP_SessionInfo sessionInfo = {0};
    TAP_CmdReqHdr cmdReqHdr = {0};
    ubyte4 byteCount = 0;
    ubyte4 reqBufferSize = 0;
    ubyte *pReqBuffer = NULL ;
    ubyte *pResBuffer = NULL ;
    ubyte4 offset = 0;
#endif

    if (NULL == pProviderList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_TAP_REMOTE__

    status = TAP_copyConnectionInfo(&sessionInfo.connInfo, pConnInfo);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy session connection info, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_OpenSession(&sessionInfo) ;
    if (OK != status)
    {
        DB_PRINT("%s.%d Error while connecting to the TAP server, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));

        goto exit;
    }

    tapCmdReq.cmdCode = TAP_CMD_GET_PROVIDER_LIST;

    pReqBuffer = sessionInfo.txBuffer;
    reqBufferSize = sizeof(sessionInfo.txBuffer);

    /* Serialize TAP command request */
    offset = 0;
    status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdReq, TAP_SD_IN,
            (ubyte *)&tapCmdReq, sizeof(tapCmdReq), pReqBuffer,
            reqBufferSize, &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to deserialize command request, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    cmdReqHdr.cmdDest = TAP_CMD_DEST_MODULE;
    cmdReqHdr.cmdType = TAP_CMD_TYPE_SMP;
    cmdReqHdr.providerType = 0; /* Not used */
    cmdReqHdr.totalBytes = offset;
    byteCount = MAX_TAP_REMOTE_TX_BUFFER;
    pResBuffer = sessionInfo.txBuffer;

    status = TAP_TransmitReceive(&sessionInfo, &cmdReqHdr, offset,
            pReqBuffer, &byteCount, pResBuffer, &tapCmdRsp.cmdStatus);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to do TAP_TransmitReceive, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Deserialize the command response, if it is present */
    if (byteCount)
    {
        offset = 0;
        status = TAP_SERIALIZE_serialize(&TAP_REMOTE_SHADOW_TAP_CmdRsp, TAP_SD_OUT,
                pResBuffer, byteCount, (ubyte *)&tapCmdRsp,
                sizeof(tapCmdRsp), &offset);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to deserialize command response, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = tapCmdRsp.cmdStatus;

        if (OK != status)
        {
            DB_PRINT("%s.%d command failed, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TAP_COMMON_copyProviderList(&tapCmdRsp.rspParams.getProviderList.providerList, pProviderList);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy provider list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            if (NULL != pProviderList->pProviderCmdList)
            {
                exitStatus = TAP_UTILS_freeProviderList(pProviderList);
                if (OK != exitStatus)
                {
                    DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                            __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
                }
            }
        }

        TAP_SERIALIZE_freeDeserializedStructure(
            &TAP_REMOTE_SHADOW_TAP_CmdRsp, (ubyte *)&tapCmdRsp, sizeof(tapCmdRsp));
    }
    else
    {
        tapCmdRsp.cmdCode = tapCmdReq.cmdCode;
    }

#else
    status = TAP_COMMON_copyProviderList(&localProviderList, pProviderList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy local provider list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        if (NULL != pProviderList->pProviderCmdList)
        {
            exitStatus = TAP_UTILS_freeProviderList(pProviderList);
            if (OK != exitStatus)
            {
                DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                        __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
            }
        }
    }
#endif

exit:
#ifdef __ENABLE_TAP_REMOTE__
    if (NULL != pConnInfo)
    {
        TAP_CloseSession(&sessionInfo) ;
        TAP_freeConnectionInfo(&sessionInfo.connInfo);
    }
#endif
    return status;
}


/*------------------------------------------------------------------*/
MSTATUS TAP_getModuleList(TAP_ConnectionInfo *pConnInfo, TAP_PROVIDER provider,
                          TAP_ModuleCapabilityAttributes *pCapabilityAttributes,
                          TAP_ModuleList *pModuleList, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 i = 0;
    TAP_ModuleProvisionAttributes newAttributes = { 0, };
    ubyte4 numAttributes = 1;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    TAP_SessionInfo sessionInfo = {0};
#ifdef __ENABLE_TAP_REMOTE__
    ubyte *pServerName = NULL;
    ubyte4 serverNameLen = 0;
#endif

    if (NULL == pModuleList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pCapabilityAttributes)
    {
        if ((0 < pCapabilityAttributes->listLen) && (NULL == pCapabilityAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pCapabilityAttributes->listLen;
    }

    /* Set the new attributes,including provider type and information from pCapabilityAttributes */
    status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    newAttributes.pAttributeList[0].type = TAP_ATTR_TAP_PROVIDER;
    newAttributes.pAttributeList[0].length = sizeof(provider);

    status = DIGI_MALLOC((void **)&newAttributes.pAttributeList[0].pStructOfType,
            sizeof(provider));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for provider attribute, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *(TAP_PROVIDER *)(newAttributes.pAttributeList[0].pStructOfType) = provider;

    i = 1;
    if (NULL != pCapabilityAttributes)
    {
        for (i=1; i<pCapabilityAttributes->listLen; i++)
        {
            newAttributes.pAttributeList[i].type = pCapabilityAttributes->pAttributeList[i].type;
            newAttributes.pAttributeList[i].length = pCapabilityAttributes->pAttributeList[i].length;
            newAttributes.pAttributeList[i].pStructOfType = pCapabilityAttributes->pAttributeList[i].pStructOfType;
        }
    }

    newAttributes.listLen = i;

    smpCmdReq.cmdCode = SMP_CC_GET_MODULE_LIST;
    smpCmdReq.reqParams.getModuleList.pModuleAttributes = &newAttributes;

    if (NULL != pConnInfo)
    {
#ifdef __ENABLE_TAP_REMOTE__
        status = TAP_copyConnectionInfo(&sessionInfo.connInfo, pConnInfo);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy session connection info, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TAP_OpenSession(&sessionInfo) ;
        if (OK != status)
        {
            DB_PRINT("%s.%d Error while connecting to the TAP server, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));

            goto exit;
        }
#else
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Connection information not valid, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;

#endif
    }

    status = TAP_dispatchSMPCommand(provider, &sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Done with input attributes, free memory */
    TAP_freeAttributeList(&newAttributes, pErrContext);

    /* in either local-only or client-server build, need to create TAP_ModuleList from TAP_EntityList returned */
    pModuleList->numModules = 0;
    pModuleList->pModuleList = NULL;

    if (TAP_ENTITY_TYPE_MODULE != smpCmdRsp.rspParams.getModuleList.moduleList.entityType)
    {
       /* This should never happen, but check just in case. */
        DB_PRINT("%s.%d Command returned invalid entity type %d, expecting %d\n", __FUNCTION__,
                __LINE__, smpCmdRsp.rspParams.getModuleList.moduleList.entityType, TAP_ENTITY_TYPE_MODULE);
        goto exit;
    }

    if (0 == smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities)
    {
        status = ERR_TAP_MODULE_NOT_FOUND;
        DB_PRINT("%s.%d Command returned empty module list\n", __FUNCTION__, __LINE__);
        goto exit;
    }

    pModuleList->numModules = 0;
    if (0 < smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities)
    {
        status = DIGI_CALLOC((void **)&(pModuleList->pModuleList), 1,
                           smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities * sizeof(TAP_Module));
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__, "failed to allocate memory for %d TAP ModuleList pointers, status %d = %s\n",
                    (int)smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities,
                    status, MERROR_lookUpErrorCode(status));
                goto exit;
        }
    }
    pModuleList->numModules = smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities;

    for (i = 0; i < smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.numEntities; i++)
    {
        status = DIGI_MEMCPY((void *)&(pModuleList->pModuleList[i].moduleId),
                            (void *)&(smpCmdRsp.rspParams.getModuleList.moduleList.entityIdList.pEntityIdList[i]),
                            sizeof(TAP_ID));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy module ID, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pModuleList->pModuleList[i].providerType = provider;
#ifdef __ENABLE_TAP_REMOTE__
        if (NULL != pConnInfo)
        {
            pModuleList->pModuleList[i].hostInfo.serverPort = pConnInfo->serverPort;

            if (pConnInfo->serverName.bufferLen)
            {
                status = DIGI_CALLOC((void **)&(pModuleList->pModuleList[i].hostInfo.serverName.pBuffer),
                        1, pConnInfo->serverName.bufferLen);
                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__, "failed to allocate memory for server name, status %d = %s\n",
                            status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                status = DIGI_MEMCPY((void *)(pModuleList->pModuleList[i].hostInfo.serverName.pBuffer),
                        (void *)(pConnInfo->serverName.pBuffer),
                        pConnInfo->serverName.bufferLen);
                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__, "failed to copy memory for server name, status %d = %s\n",
                            status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
                pModuleList->pModuleList[i].hostInfo.serverName.bufferLen = pConnInfo->serverName.bufferLen;
            }
            else
            {
                if (TAP_UNIX_DOMAIN_SOCKET == pConnInfo->serverPort)
                {
                    pServerName = tapClientInfo.pServerName ? tapClientInfo.pServerName : DEFAULT_UNIX_DOMAIN_PATH;
                    serverNameLen = DIGI_STRLEN(pServerName) + 1;

                    status = DIGI_CALLOC((void **)&(pModuleList->pModuleList[i].hostInfo.serverName.pBuffer),
                            1, serverNameLen);
                    if (OK != status)
                    {
                        DB_PRINT(__func__, __LINE__, "failed to allocate memory for server name, status %d = %s\n",
                                status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    status = DIGI_MEMCPY((void *)(pModuleList->pModuleList[i].hostInfo.serverName.pBuffer),
                            (void *)pServerName, serverNameLen);
                    if (OK != status)
                    {
                        DB_PRINT(__func__, __LINE__, "failed to copy memory for server name, status %d = %s\n",
                                status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                    pModuleList->pModuleList[i].hostInfo.serverName.bufferLen = serverNameLen;
                }
            }
        }
#endif
    }

exit:
#ifdef __ENABLE_TAP_REMOTE__
    if (NULL != pConnInfo)
    {
        TAP_CloseSession(&sessionInfo) ;
        TAP_freeConnectionInfo(&sessionInfo.connInfo);
    }
#endif

    if ((OK != status) && (NULL != pModuleList))
    {
        if ((0 < pModuleList->numModules) && (NULL != pModuleList->pModuleList))
        {
            exitStatus = TAP_freeModuleList(pModuleList);
            if (OK != exitStatus)
            {
                DB_PRINT("%s.%d Failed to free memory for module list on error, status %d = %s\n", __FUNCTION__,
                        __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
            }

            pModuleList->numModules = 0;
            DIGI_FREE((void **)&pModuleList->pModuleList);
        }
    }

    /* Release memory, only required in error path */
    TAP_freeAttributeList(&newAttributes, pErrContext);

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_freeModuleList(TAP_ModuleList *pModuleList)
{
    MSTATUS status = OK;

    if (NULL == pModuleList)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 == pModuleList->numModules) || (NULL == pModuleList->pModuleList))
    {
        goto exit;
    }

    status = TAP_UTILS_freeModuleList(pModuleList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free memory for module list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_initContext(TAP_Module *pModule, TAP_EntityCredentialList *pModuleCredentials,
                        TAP_AttributeList *pAttributes, TAP_Context **ppTapContext,
                        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    ubyte4 credentialsLen = 0;
    _TAP_Context *pContext = NULL;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_SessionInfo sessionInfo = {0, };
    volatile TAP_CredentialList nullAttributes = {0, };
    TAP_ModuleCapabilityAttributes nullModuleCredentials = {0, };
    TAP_Attribute moduleAttribute = {
                                        TAP_ATTR_CREDENTIAL_USAGE,
                                        sizeof(TAP_EntityCredentialList),
                                        NULL
                                    };
    TAP_ModuleCapabilityAttributes moduleCapabilityAttributes = {1,&moduleAttribute};

    if ((NULL == pModule)  ||  (NULL == ppTapContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    moduleCapabilityAttributes.pAttributeList->pStructOfType = pModuleCredentials;

    if (NULL != pModuleCredentials)
    {
        if ((0 < pModuleCredentials->numCredentials) && (NULL == pModuleCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Entity credential list is NULL when should have %d credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, pModuleCredentials->numCredentials, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        if (NULL != pModuleCredentials->pEntityCredentials)
        {
            if ((0 < pModuleCredentials->pEntityCredentials->credentialList.numCredentials) &&
                (NULL == pModuleCredentials->pEntityCredentials->credentialList.pCredentialList))
            {
                status = ERR_TAP_INVALID_INPUT;
                DB_PRINT("%s.%d Credential list is NULL when should have %d credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, pModuleCredentials->pEntityCredentials->credentialList.numCredentials,
                        status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
            /* Find the module credential in the list */
            for (i = 0; i < pModuleCredentials->numCredentials; i++)
            {
                if (TAP_ENTITY_TYPE_MODULE == pModuleCredentials->pEntityCredentials[i].entityType)
                {
                    smpCmdReq.reqParams.initModule.pCredentialList = &(pModuleCredentials->pEntityCredentials[i].credentialList);
                    credentialsLen = sizeof(TAP_CredentialList) +
                                     (pModuleCredentials->pEntityCredentials[i].credentialList.numCredentials * sizeof(TAP_Credential));
                    for (j = 0; j < pModuleCredentials->pEntityCredentials[i].credentialList.numCredentials; j++)
                    {
                        credentialsLen += pModuleCredentials->pEntityCredentials[i].credentialList.pCredentialList[j].credentialData.bufferLen;
                    }
                    break;
                }
            }
        }
    }

    if (NULL != pModule->hostInfo.serverName.pBuffer)
    {
        status = TAP_copyConnectionInfo(&sessionInfo.connInfo, &pModule->hostInfo);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy session connection info, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    smpCmdReq.cmdCode = SMP_CC_INIT_MODULE;
    smpCmdReq.reqParams.initModule.moduleId = pModule->moduleId;
    smpCmdReq.reqParams.initModule.pModuleAttributes = pModuleCredentials ?
                                        &(moduleCapabilityAttributes):&nullModuleCredentials;

    smpCmdReq.reqParams.initModule.pCredentialList = pAttributes ?
        (TAP_CredentialList *)pAttributes : (TAP_CredentialList *)&nullAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pModule->providerType, &sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize context, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Allocate memory for new context */
    status = DIGI_CALLOC((void **)&pContext, 1, sizeof (_TAP_Context));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set TAP context fields on success */
    pContext->signature = TAP_SIGNATURE;
    pContext->providerType = pModule->providerType;
    DIGI_MEMCPY(&pContext->sessionInfo, &sessionInfo,
                         sizeof (TAP_SessionInfo));
    status = TAP_UTILS_copyTapModule(&(pContext->module), pModule);
    pContext->moduleHandle = smpCmdRsp.rspParams.initModule.moduleHandle;

    pContext->pPolicyAuthInfo = NULL;

    *ppTapContext = (TAP_Context *)pContext;

    /* Clear local session, the ownership has transferred to one in pContext */
    sessionInfo.sessionInit = 0;
    sessionInfo.sockfd = 0;
    sessionInfo.sslSessionId = 0;

exit:
    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (OK != status)
    {
#ifdef __ENABLE_TAP_REMOTE__
        TAP_CloseSession(&sessionInfo) ;
#endif
        exitStatus = TAP_uninitContext(ppTapContext, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT(__func__, __LINE__, "Failed to uninitialize context on error.  status %d = %s\n",
                    exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS TAP_associateCredentialWithContext(TAP_Context *pTapContext,
                                                  TAP_EntityCredentialList *pModuleCredentials,
                                                  TAP_AttributeList *pAttributes,
                                                  TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = ( _TAP_Context *)pTapContext;

    if ((NULL == pTapContext) || (NULL == pModuleCredentials))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_ASSOCIATE_MODULE_CREDENTIALS;
    smpCmdReq.reqParams.associateModuleCredentials.moduleHandle =
        pContext->moduleHandle;
    smpCmdReq.reqParams.associateModuleCredentials.pEntityCredentialList =
        pModuleCredentials;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to associate credentials with module context, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_uninitContext(TAP_Context **ppTapContext, TAP_ErrorContext *pErrContext)
{

    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    if ((NULL == ppTapContext) || (NULL == *ppTapContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)*ppTapContext;

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_UNINIT_MODULE;
    smpCmdReq.reqParams.uninitModule.moduleHandle = pContext->moduleHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to uninitialize context, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    /* Clear/free TAP context fields */
    if (NULL != pContext)
    {

#ifdef __ENABLE_TAP_REMOTE__
        /* Clean up session only for Remote TAP Client */
        if (pContext->module.hostInfo.serverName.pBuffer)
        {
            TAP_CloseSession(&(pContext->sessionInfo)) ;
            TAP_freeConnectionInfo(&(pContext->sessionInfo.connInfo));
        }
#endif

        exitStatus = TAP_UTILS_freeTapModule(&(pContext->module));
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT("%s.%d Failed to free module information, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }

    }

    if (NULL != ppTapContext)
    {
        exitStatus = shredMemory((ubyte **)ppTapContext, sizeof(_TAP_Context), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_isModuleProvisioned(TAP_Module *pModule, byteBoolean *pIsProvisioned,
                                TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    ubyte4 i = 0;
    TAP_MODULE_PROVISION_STATE provisionState = 1;
    TAP_Attribute provisionAttr = {TAP_ATTR_MODULE_PROVISION_STATE, sizeof(TAP_MODULE_PROVISION_STATE), (void *)&provisionState};
    TAP_AttributeList selectionAttributes =
    {
        1,
        &provisionAttr,
    };
    TAP_AttributeList capabilities = { 0 };

    /* check input */
    if ((NULL == pModule) || (NULL == pIsProvisioned))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsProvisioned = FALSE;

    status = TAP_getModuleInfo(pModule, &selectionAttributes,
                               &capabilities, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get module capabilities, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < capabilities.listLen; i++)
    {
        if (TAP_ATTR_MODULE_PROVISION_STATE == capabilities.pAttributeList[i].type && capabilities.pAttributeList[i].pStructOfType)
        {
            *pIsProvisioned = *(TAP_MODULE_PROVISION_STATE *)(capabilities.pAttributeList[i].pStructOfType);
        }
    }

exit:

    TAP_UTILS_freeAttributeList(&capabilities);

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_provisionModule(TAP_Context *pTapContext, TAP_CredentialList *pUsageCredentials,
                            TAP_ModuleProvisionAttributes *pAttributes,
                            TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 i = 0;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_ModuleProvisionAttributes newAttributes = { 0, };
    TAP_ModuleProvisionAttributes *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;

    if (NULL == pTapContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    if (NULL != pAttributes)
    {
        if ((0 < pAttributes->listLen) && (NULL == pAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pCredentialList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pAttributes)
        {
            for (i=0; i<pAttributes->listLen; i++)
            {
                newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[i].type;
                newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[i].length;
                newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[i].pStructOfType;
            }
        }
        if (NULL != pUsageCredentials)
        {
            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        newAttributes.listLen = numAttributes;
        pNewAttributes = (TAP_ModuleProvisionAttributes *)&newAttributes;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_PROVISION_MODULE;
    smpCmdReq.reqParams.provisionModule.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.provisionModule.pModuleProvisionAttributes = pNewAttributes ?
        pNewAttributes :
        (TAP_ModuleProvisionAttributes *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to provision module, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_getModuleCapability(TAP_Module *pModule,
        TAP_ModuleCapPropertyAttributes *pCapPropertySelection,
        TAP_ModuleCapPropertyList *pModuleCapProperties,
        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    TAP_SessionInfo sessionInfo = { 0 };

    /* check input */
    if ((NULL == pModule) || (NULL == pModuleCapProperties))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_MODULE_CAPABILITY;
    smpCmdReq.reqParams.getModuleCapability.moduleId = pModule->moduleId;
    smpCmdReq.reqParams.getModuleCapability.pCapabilitySelectRange = pCapPropertySelection;

    /*Copy session info*/
    if (pModule->hostInfo.serverName.pBuffer)
    {
        status = TAP_copyConnectionInfo(&sessionInfo.connInfo, &pModule->hostInfo);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy session connection info, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pModule->providerType, &sessionInfo,
        &smpCmdReq, &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
            __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get module info, status %d = %s\n", __FUNCTION__,
            __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyModuleCapPropertyList(pModuleCapProperties,
                &smpCmdRsp.rspParams.getModuleCapability.moduleCapabilities);

    TAP_UTILS_freeModuleCapPropertyList(
                &(smpCmdRsp.rspParams.getModuleCapability.moduleCapabilities));

exit:
#ifdef __ENABLE_TAP_REMOTE__
    TAP_CloseSession(&sessionInfo);
    TAP_freeConnectionInfo(&sessionInfo.connInfo);
#endif
    TAP_SERIALIZE_freeDeserializedStructure(
        &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));
    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_getModuleInfo(TAP_Module *pModule, TAP_AttributeList *pCapabilitySelection,
                          TAP_AttributeList *pModuleCapabilities, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    TAP_SessionInfo sessionInfo = {0};

    /* check input */
    if ((NULL == pModule) || (NULL == pModuleCapabilities))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_MODULE_INFO;
    smpCmdReq.reqParams.getModuleInfo.moduleId = pModule->moduleId;
    smpCmdReq.reqParams.getModuleInfo.pCapabilitySelectCriterion = pCapabilitySelection;

    if (pModule->hostInfo.serverName.pBuffer)
    {
        status = TAP_copyConnectionInfo(&sessionInfo.connInfo, &pModule->hostInfo);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy session connection info, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pModule->providerType, &sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get module info, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyAttributeList((TAP_AttributeList *)pModuleCapabilities,
                                    (TAP_AttributeList *)&(smpCmdRsp.rspParams.getModuleInfo.moduleCapabilties));


    TAP_freeAttributeList((TAP_AttributeList *)&(smpCmdRsp.rspParams.getModuleInfo.moduleCapabilties),
                pErrContext);

exit:
#ifdef __ENABLE_TAP_REMOTE__
    TAP_CloseSession(&sessionInfo);
    TAP_freeConnectionInfo(&sessionInfo.connInfo);
#endif

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_TAP_CREDS_FILE__
#ifndef __ENABLE_TAP_REMOTE__
MSTATUS TAP_getModuleCredentials(TAP_Module *pModule, const char *pConfigFilePath,
    byteBoolean useSpecifiedConfigFilePath,
    TAP_EntityCredentialList **ppEntityCredentialList,
    TAP_ErrorContext *pErrContext)
{
    TAP_Buffer credentialBuffer = {0}, *pCredBuffer = NULL;
    TAP_Attribute credentialAttr = {TAP_ATTR_GET_MODULE_CREDENTIALS, sizeof(TAP_Buffer), (void *)&credentialBuffer};
    MSTATUS status = OK;
    ubyte4 i = 0;
    ubyte *pFullPath = NULL;
    ubyte *pRawBuffer = NULL;
    ubyte4 rawBufferLen = 0;
    TAP_AttributeList selectionAttributes =
    {
        1,
        &credentialAttr,
    };
    TAP_AttributeList capabilities = { 0 };
    sbyte4 fullPathLen = 0;
    sbyte4 pathLen = 0;
    byteBoolean isCredPathRelative = TRUE;

    /* check input */
    if ((NULL == pModule) || (NULL == ppEntityCredentialList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_getModuleInfo(pModule, &selectionAttributes,
                               &capabilities, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get module Info, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    for (i = 0; i < capabilities.listLen; i++)
    {
        if (TAP_ATTR_GET_MODULE_CREDENTIALS == capabilities.pAttributeList[i].type)
        {
            if (capabilities.pAttributeList[i].pStructOfType)
            {
                pCredBuffer = (TAP_Buffer *)(capabilities.pAttributeList[i].pStructOfType);

                /* Locate the path */
                fullPathLen = DIGI_STRLEN((const sbyte *)pConfigFilePath);

                pathLen = 0;

                TAP_UTILS_isPathRelative(pCredBuffer->pBuffer,
                            pCredBuffer->bufferLen, &isCredPathRelative);
                if (isCredPathRelative)
                {
                    while (0 < fullPathLen)
                    {
#ifndef __RTOS_WIN32__
                        if (pConfigFilePath[fullPathLen] == '/')
#else
                        if (pConfigFilePath[fullPathLen] == '/' ||
                                pConfigFilePath[fullPathLen] == '\\')
#endif
                        {
                            pathLen = (int)(&pConfigFilePath[fullPathLen] -
                                    &pConfigFilePath[0]);

                            /* Move past the path terminator */
                            pathLen++;

                            break;
                        }

                        fullPathLen--;
                    }
                }
                status = DIGI_CALLOC((void **)&pFullPath, 1,
                        pathLen + pCredBuffer->bufferLen + 1);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating memory for credential file name, status %d = %s\n", __FUNCTION__, __LINE__,
                            (int)status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                if (pathLen)
                {
                    status = DIGI_MEMCPY(&pFullPath[0],
                            pConfigFilePath, pathLen);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Error copyingcredential file path, status %d = %s\n", __FUNCTION__, __LINE__,
                                (int)status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = DIGI_MEMCPY(&pFullPath[pathLen],
                        pCredBuffer->pBuffer, pCredBuffer->bufferLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error copying credential filename, status %d = %s\n", __FUNCTION__, __LINE__,
                            (int)status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = DIGICERT_readFile((const char *)pFullPath, &pRawBuffer, &rawBufferLen);
                if (OK != status)
                {
                    if (useSpecifiedConfigFilePath)
                    {
                        DB_PRINT("%s.%d Error opening user specified configuration file %s, status %d = %s\n", __FUNCTION__, __LINE__,
                                pFullPath, status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }

                    /* Try local directory */
                    status = DIGICERT_readFile((const char *)pCredBuffer->pBuffer,
                            &pRawBuffer, &rawBufferLen);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Error opening configuration file %s, status %d = %s\n", __FUNCTION__, __LINE__,
                                pCredBuffer->pBuffer, status, MERROR_lookUpErrorCode(status));
                        goto exit;
                    }
                }

                status = TAP_parseModuleCredentials(pRawBuffer, rawBufferLen,
                        ppEntityCredentialList, NULL);
            }
            else
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Failed to get Credential Buffer, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }
    }

exit:
    if (pRawBuffer)
        DIGI_FREE((void **)&pRawBuffer);

    if (pFullPath)
        DIGI_FREE((void **)&pFullPath);

    TAP_UTILS_freeAttributeList(&capabilities);

    return status;
}
#endif /*!__ENABLE_TAP_REMOTE__*/
#endif /*!__DISABLE_DIGICERT_TAP_CREDS_FILE__ */

/*------------------------------------------------------------------*/

MSTATUS TAP_getModuleVersionInfo(TAP_Module *pModule, TAP_AttributeList *pModuleInfo,
                                 TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    TAP_ModuleCapabilityAttributes newAttributes = { 0, };
    ubyte4 numAttributes = 2;
    volatile TAP_Buffer nullBuffer = {0};
    volatile TAP_Version firmwareVersion = {0};

    /* check input */
    if ((NULL == pModule) || (NULL == pModuleInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Ask for firmware version, cannot have NULL pointers in attribute list,
     serialization fails */
    newAttributes.pAttributeList[0].type = TAP_ATTR_FIRMWARE_VERSION;
    newAttributes.pAttributeList[0].length = sizeof(firmwareVersion);
    newAttributes.pAttributeList[0].pStructOfType = (void *)&firmwareVersion;

    /* And vendor information */
    newAttributes.pAttributeList[1].type = TAP_ATTR_VENDOR_INFO;
    newAttributes.pAttributeList[1].length = sizeof(nullBuffer);
    newAttributes.pAttributeList[1].pStructOfType = (void *)&nullBuffer;

    newAttributes.listLen = numAttributes;

    status = TAP_getModuleInfo(pModule, &newAttributes,
                               pModuleInfo, pErrContext);

exit:

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}



/*------------------------------------------------------------------*/

MSTATUS TAP_freeAttributeList(TAP_AttributeList *pAttributes, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

    /* check input */
    if (NULL == pAttributes)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if ((0 == pAttributes->listLen) || (NULL == pAttributes->pAttributeList))
    {
        goto exit;
    }

    status =  TAP_UTILS_freeAttributeList(pAttributes);

exit:

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_getLastErrorInfo(TAP_Context *pTapContext, TAP_Error *pError)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;

    /* check input */
    if (NULL == pTapContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_LAST_ERROR;
    /* TODO: only have moduleHandle in the context.  How do we get the token and object handle?  Are these needed? */
    smpCmdReq.reqParams.getLastError.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getLastError.tokenHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getLastError.objectHandle = pContext->moduleHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get error info, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));


    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_freeErrorInfo(TAP_Error *pError)
{
    MSTATUS status = OK;

    /* check input */
    if (NULL == pError)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Free error string */
    if (NULL != pError->tapErrorString.pBuffer)
    {
        status = TAP_UTILS_freeBuffer(&(pError->tapErrorString));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free tapErrorString, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }
     }

    if (NULL != pError->pErrorAttributes)
    {
        status = TAP_freeAttributeList((TAP_AttributeList *)(pError->pErrorAttributes), NULL);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to free error attributes, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_selfTest(TAP_Context *pTapContext,
                     TAP_TestRequestAttributes *pRequestAttributes,
                     TAP_TestResponseAttributes *pResponseAttributes,
                     TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    volatile TAP_TestRequestAttributes nullReqAttr = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pResponseAttributes))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_SELF_TEST;
    smpCmdReq.reqParams.selfTest.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.selfTest.pTestRequest = pRequestAttributes ?
        pRequestAttributes :
        (TAP_TestRequestAttributes *)&nullReqAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to run self test, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyAttributeList((TAP_AttributeList *)pResponseAttributes,
                                         (TAP_AttributeList *)&(smpCmdRsp.rspParams.selfTest.testResponse));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getRandom(TAP_Context *pTapContext, ubyte4 bytesRequested, TAP_AttributeList *pAttributes,
                      TAP_Buffer *pData, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_RNG;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_AttributeList nullAttr = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 > bytesRequested)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Find a token that supports RNG */
    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                  &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit1;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit1;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit1;
    }
    tokenId = tokenList.entityIdList.pEntityIdList[0];

exit1:
    if (tokenList.entityIdList.pEntityIdList)
    {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    if (OK > status)
    {
        goto exit;
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               NULL, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_RANDOM;
    smpCmdReq.reqParams.getRandom.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getRandom.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.getRandom.bytesRequested = bytesRequested;
    smpCmdReq.reqParams.getRandom.pRngRequest = pAttributes ?
        pAttributes :
        (TAP_AttributeList *)&nullAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get random data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pData, &(smpCmdRsp.rspParams.getRandom.random));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy random data buffer, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }


    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_stirRandom(TAP_Context *pTapContext, ubyte4 numBytes,
                       TAP_RngAttributes *pAttributes, TAP_Buffer *pEntropy,
                       TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_RNG;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    volatile TAP_RngAttributes nullAttr = {0};

    /* check input */
    if (NULL == pTapContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (1 > numBytes)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Find a token that supports RNG */
    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                  &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit1;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit1;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit1;
    }
    tokenId = tokenList.entityIdList.pEntityIdList[0];

exit1:
    if (tokenList.entityIdList.pEntityIdList)
    {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    if (OK > status)
    {
        goto exit;
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               NULL, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Add pEntropy to attributes */
    if (NULL != pAttributes)
    {
        if ((0 < pAttributes->listLen) && (NULL == pAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pAttributes->listLen;
    }

    if (NULL != pEntropy)
    {
        numAttributes++;
    }

    if (0 < numAttributes)
    {
        /* Set the new attributes, including information from both pEntropy and pAttributes */
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pAttributes)
        {
            for (i=0; i < pAttributes->listLen; i++)
            {
                newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[i].type;
                newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[i].length;
                newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[i].pStructOfType;
            }
        }
        if (NULL != pEntropy)
        {
            newAttributes.pAttributeList[i].type = TAP_ATTR_RND_STIR;
            newAttributes.pAttributeList[i].length = sizeof(TAP_Buffer);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pEntropy;
            i++;
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_STIR_RANDOM;
    smpCmdReq.reqParams.stirRandom.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.stirRandom.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.stirRandom.pRngRequest = pNewAttributes ?
        pNewAttributes : (TAP_RngAttributes *)&nullAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to stir the RNG, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (newAttributes.pAttributeList)
    {
        DIGI_FREE((void **)&newAttributes.pAttributeList);
    }
    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymGenerateKey(TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_KeyInfo *pKeyInfo,
                            TAP_AttributeList *pKeyAttributes,
                            TAP_CredentialList *pKeyCredentials,
                            TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_AttributeList newKeyAttributes = { 0, };
    TAP_AttributeList *pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    TAP_ObjectAttributes *pNewObjAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0, j=0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttributes = {0};
    volatile TAP_EntityCredentialList nullUsageCredentials = {0};

    if ((NULL == pTapContext) || (NULL == pKeyInfo) || (NULL == ppTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* First generate module-specific key.  The  module must also set (*ppTapKey)->keyAlgorithm */

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            numAttributes = 5;
            break;
        case TAP_KEY_ALGORITHM_ECC:
            numAttributes = 4;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (TAP_KEY_USAGE_ATTESTATION == pKeyInfo->keyUsage)
    {
        tokenCapability = TAP_CAPABILITY_ATTESTATION_BASIC;
    }
    else
    {
        tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    }

    if (NULL != pKeyCredentials)
        numAttributes++;

    if (NULL != pUsageCredentials)
        numAttributes++;

    if(NULL != pKeyAttributes)
    {
        numAttributes += pKeyAttributes->listLen ;
    }

    /* Set the new key attributes, including information from both pKeyInfo and pKeyAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newKeyAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate key attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newKeyAttributes.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
        newKeyAttributes.pAttributeList[0].length = sizeof(pKeyInfo->keyAlgorithm);
        newKeyAttributes.pAttributeList[0].pStructOfType = (void *)&(pKeyInfo->keyAlgorithm);

        newKeyAttributes.pAttributeList[1].type = TAP_ATTR_KEY_USAGE;
        newKeyAttributes.pAttributeList[1].length = sizeof(pKeyInfo->keyUsage);
        newKeyAttributes.pAttributeList[1].pStructOfType = (void *)&(pKeyInfo->keyUsage);
        i = 2;

        if(NULL != pKeyAttributes)
        {
            for (j=0; j < pKeyAttributes->listLen; j++)
            {
                newKeyAttributes.pAttributeList[i].type = pKeyAttributes->pAttributeList[j].type;
                newKeyAttributes.pAttributeList[i].length = pKeyAttributes->pAttributeList[j].length;
                newKeyAttributes.pAttributeList[i].pStructOfType = pKeyAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        if (NULL != pKeyCredentials)
        {
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        if (TAP_KEY_ALGORITHM_RSA == pKeyInfo->keyAlgorithm)
        {
            /* RSA Key */
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_KEY_SIZE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.keySize);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.keySize);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_ENC_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.encScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.encScheme);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SIG_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.sigScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.sigScheme);
            i++;
        }
        else
        {
            /* ECC Key */
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CURVE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.eccInfo.curveId);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.eccInfo.curveId);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SIG_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.eccInfo.sigScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.eccInfo.sigScheme);
            i++;
        }
        newKeyAttributes.listLen = i;
        pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    }

    tokenId = pKeyInfo->tokenId;

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId,
                (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttributes,
                pUsageCredentials ? pUsageCredentials :
                (TAP_EntityCredentialList *)&nullUsageCredentials,
                &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, pKeyInfo->tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set the command values */
    smpCmdReq.cmdCode = SMP_CC_CREATE_ASYMMETRIC_KEY;
    smpCmdReq.reqParams.createAsymmetricKey.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.createAsymmetricKey.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.createAsymmetricKey.objectId = pKeyInfo->objectId;
    smpCmdReq.reqParams.createAsymmetricKey.pKeyAttributes = pNewKeyAttributes;
    smpCmdReq.reqParams.createAsymmetricKey.initFlag = TRUE;

    /* Call SMP dispatcher directly in a local-only build */

    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory */
    shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to generate asymmetric key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* We know we succeeded, so now allocate memory for new TAP key and set fields */

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppTapKey)->pTapContext = pTapContext;
    (*ppTapKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppTapKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppTapKey)->providerObjectData.objectInfo.tokenId = tokenId;
    (*ppTapKey)->providerObjectData.objectInfo.objectId = smpCmdRsp.rspParams.createAsymmetricKey.objectIdOut;

    if (NULL != pKeyCredentials)
    {
        (*ppTapKey)->hasCreds = 1;
    }

    if ((0 < smpCmdRsp.rspParams.createAsymmetricKey.objectAttributes.listLen) &&
        (NULL != smpCmdRsp.rspParams.createAsymmetricKey.objectAttributes.pAttributeList))
    {
        pNewObjAttributes = &(smpCmdRsp.rspParams.createAsymmetricKey.objectAttributes);
        status = TAP_UTILS_copyAttributeList(&((*ppTapKey)->providerObjectData.objectInfo.objectAttributes),
                                              (TAP_AttributeList *)pNewObjAttributes);
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__, "Failed to copy attribute list for new key! status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Populate the key with the attributes returned from the SMP */
    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.keySize = *(TAP_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_ENC_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.encScheme = *(TAP_ENC_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.sigScheme = *(TAP_SIG_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_CURVE:
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_ECC:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.eccInfo.sigScheme = *(TAP_SIG_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_CURVE:
                            (*ppTapKey)->keyData.algKeyInfo.eccInfo.curveId = *(TAP_ECC_CURVE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? For now, just ignoring*/
                            break;
                    }
                }
            }
            break;
        default:
            break;
    }

    if (NULL != pNewObjAttributes)
    {
        for (i = 0; i < pNewObjAttributes->listLen; i++)
        {
            if (TAP_ATTR_SERIALIZED_OBJECT_BLOB == pNewObjAttributes->pAttributeList[i].type)
            {
                /* The underlying SMP didnt have control over the ID during key generation, and
                * therefore was not able to send back a objectID < 8 bytes. Instead we got back
                * the serialized object blob to copy into the key */
                status = DIGI_MEMCPY (
                    &((*ppTapKey)->providerObjectData.objectBlob),
                    (TAP_Blob *)(pNewObjAttributes->pAttributeList[i].pStructOfType),
                    sizeof(TAP_Blob));
                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__, "Failed to copy object blob into new key %d = %s\n",
                                status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = DIGI_MALLOC (
                    (void **)&((*ppTapKey)->providerObjectData.objectBlob.blob.pBuffer),
                    ((TAP_Blob *)(pNewObjAttributes->pAttributeList[i].pStructOfType))->blob.bufferLen);
                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__, "Failed to copy object blob into new key %d = %s\n",
                                status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }

                status = DIGI_MEMCPY (
                    (*ppTapKey)->providerObjectData.objectBlob.blob.pBuffer, 
                    ((TAP_Blob *)(pNewObjAttributes->pAttributeList[i].pStructOfType))->blob.pBuffer,
                    ((TAP_Blob *)(pNewObjAttributes->pAttributeList[i].pStructOfType))->blob.bufferLen);
                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__, "Failed to copy object blob into new key %d = %s\n",
                                status, MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
        }
    }

    (*ppTapKey)->keyHandle = smpCmdRsp.rspParams.createAsymmetricKey.keyHandle;
    (*ppTapKey)->tokenHandle = tokenHandle;

    /* For now, we do not get the key blob.  Since the user has to specify a format, and we don't know it here.
       If we decide we want the key blob here in the standard/Mocana format, we do the following:
       If we have an objectIdOut, we call serializeObject.  Otherwise we call exportObject. */

    /* Now get the public key */
    status = TAP_getPublicKey(*ppTapKey, &((*ppTapKey)->keyData.publicKey));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to get public key for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if ((OK != status) && (NULL != ppTapKey) &&
        (NULL != *ppTapKey))
    {
        exitStatus = TAP_freeKey(ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newKeyAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (OK != status && 0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
        else
        {
            tokenHandle = 0;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_evictObject(TAP_Context *pTapContext,
                                   TAP_Buffer *pObjectId,
                                   TAP_AttributeList *pAttributes,
                                   TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    ubyte4 numAttributes = 0;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 i = 0;

    /* check input */
    if (NULL == pContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle in context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pAttributes)
    {
        if ( (0 < pAttributes->listLen) &&
             (NULL == pAttributes->pAttributeList) )
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pAttributes->listLen;
    }

    if (0 < numAttributes)
    {
        status = DIGI_CALLOC(
            (void **) &(newAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        for (i = 0; i < pAttributes->listLen; i++)
        {
            newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[i].type;
            newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[i].length;
            newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[i].pStructOfType;
        }

        newAttributes.listLen = numAttributes;
        pNewAttributes = (TAP_AttributeList *) &newAttributes;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_EVICT_OBJECT;
    smpCmdReq.reqParams.evictObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.evictObject.pObjectId  = pObjectId;
    smpCmdReq.reqParams.evictObject.pAttributes = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *) &newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to evict object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    /* Release attribute memory, will be needed in error path */
    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_persistObject(
    TAP_Context *pTapContext,
    TAP_Key *pTapKey,
    TAP_Buffer *pObjectId,
    TAP_ErrorContext *pErrContext)
{
    MSTATUS status;
    _TAP_Context *pContext = (_TAP_Context *) pTapContext;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };

    if ( (NULL == pContext) || (NULL == pTapKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle in context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    smpCmdReq.cmdCode = SMP_CC_PERSIST_OBJECT;
    smpCmdReq.reqParams.persistObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.persistObject.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.persistObject.pObjectId = pObjectId;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

   status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to persist object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symGenerateKey(TAP_Context *pTapContext,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_KeyInfo *pKeyInfo,
                           TAP_AttributeList *pKeyAttributes,
                           TAP_CredentialList *pKeyCredentials,
                           TAP_Key **ppTapKey,
                           TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_AttributeList newKeyAttributes = { 0, };
    TAP_AttributeList *pNewKeyAttributes = NULL;
    TAP_ObjectAttributes *pNewObjAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;

    if ((NULL == pTapContext) || (NULL == pKeyInfo) || (NULL == ppTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* First generate module-specific key. */

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
            numAttributes = 4;
            switch (pKeyInfo->algKeyInfo.aesInfo.keySize)
            {
                case TAP_KEY_SIZE_128:
                case TAP_KEY_SIZE_192:
                case TAP_KEY_SIZE_256:
                    break;
                default:
                    status = ERR_TAP_INVALID_KEY_SIZE;
                    goto exit;
                    break;
            }
            break;
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            numAttributes = 3;
            /* sizes are fixed */
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            numAttributes = 4;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (TAP_KEY_USAGE_ATTESTATION == pKeyInfo->keyUsage)
    {
        tokenCapability = TAP_CAPABILITY_ATTESTATION_BASIC;
    }
    else
    {
        tokenCapability = TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC;
    }

    if (NULL != pKeyCredentials)
        numAttributes++;

    if (NULL != pUsageCredentials)
        numAttributes++;

    if (NULL != pKeyAttributes)
    {
        numAttributes += pKeyAttributes->listLen;
    }

    /* Set the new key attributes, including information from both pKeyInfo and pKeyAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newKeyAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate key attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newKeyAttributes.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
        newKeyAttributes.pAttributeList[0].length = sizeof(pKeyInfo->keyAlgorithm);
        newKeyAttributes.pAttributeList[0].pStructOfType = (void *)&(pKeyInfo->keyAlgorithm);

        newKeyAttributes.pAttributeList[1].type = TAP_ATTR_KEY_USAGE;
        newKeyAttributes.pAttributeList[1].length = sizeof(pKeyInfo->keyUsage);
        newKeyAttributes.pAttributeList[1].pStructOfType = (void *)&(pKeyInfo->keyUsage);
        i = 2;

        if(NULL != pKeyAttributes)
        {
            for (j=0; j < pKeyAttributes->listLen; j++)
            {
                newKeyAttributes.pAttributeList[i].type = pKeyAttributes->pAttributeList[j].type;
                newKeyAttributes.pAttributeList[i].length = pKeyAttributes->pAttributeList[j].length;
                newKeyAttributes.pAttributeList[i].pStructOfType = pKeyAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        if (NULL != pKeyCredentials)
        {
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        switch (pKeyInfo->keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_HMAC:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_RAW_KEY_SIZE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
                i++;

                /* HMAC Key */
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_HASH_ALG;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_AES:
            {
                /* AES Key */
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_KEY_SIZE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.keySize);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.keySize);
                i++;

                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.symMode);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_DES:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.desInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.desInfo.symMode);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_TDES:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.tdesInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.tdesInfo.symMode);
                i++;

                break;
            }
            default:
                /* Should have already discovered this above, but for completeness... */
                status = ERR_TAP_INVALID_ALGORITHM;
                goto exit;
                break;
        }
        newKeyAttributes.listLen = numAttributes;
        pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    }


    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit1;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit1;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit1;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

exit1:
        if (tokenList.entityIdList.pEntityIdList)
        {
            DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
        }

        if (OK > status)
        {
            goto exit;
        }
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, pKeyInfo->tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    /* Set the command values */
    smpCmdReq.cmdCode = SMP_CC_CREATE_SYMMETRIC_KEY;
    smpCmdReq.reqParams.createSymmetricKey.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.createSymmetricKey.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.createSymmetricKey.objectId = pKeyInfo->objectId;
    smpCmdReq.reqParams.createSymmetricKey.pAttributeKey = pNewKeyAttributes ?
        pNewKeyAttributes : (TAP_AttributeList *)&newKeyAttributes;
    smpCmdReq.reqParams.createSymmetricKey.initFlag = TRUE;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to generate symmetric key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, don't need it anymore */
    shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    /* We know we succeeded, so now allocate memory for new TAP key and set fields */

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppTapKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppTapKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppTapKey)->providerObjectData.objectInfo.tokenId = tokenId;
    (*ppTapKey)->providerObjectData.objectInfo.objectId = smpCmdRsp.rspParams.createSymmetricKey.objectIdOut;
    if ((0 < smpCmdRsp.rspParams.createSymmetricKey.objectAttributes.listLen) &&
        (NULL != smpCmdRsp.rspParams.createSymmetricKey.objectAttributes.pAttributeList))
    {
        pNewObjAttributes = &(smpCmdRsp.rspParams.createSymmetricKey.objectAttributes);
        status = TAP_UTILS_copyAttributeList(&((*ppTapKey)->providerObjectData.objectInfo.objectAttributes),
                                              (TAP_AttributeList *)pNewObjAttributes);
    }

    (*ppTapKey)->keyData.keyAlgorithm = pKeyInfo->keyAlgorithm;
    (*ppTapKey)->keyData.keyUsage = pKeyInfo->keyUsage;

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg = pKeyInfo->algKeyInfo.hmacInfo.hashAlg;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_HASH_ALG:
                            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg = *(TAP_HASH_ALG *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_RAW_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.keyLen = *(TAP_RAW_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_AES:
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = pKeyInfo->algKeyInfo.aesInfo.keySize;
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = pKeyInfo->algKeyInfo.aesInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = *(TAP_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SYM_KEY_MODE:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_DES:
            (*ppTapKey)->keyData.algKeyInfo.desInfo.symMode = pKeyInfo->algKeyInfo.desInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_SYM_KEY_MODE:
                            (*ppTapKey)->keyData.algKeyInfo.desInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_TDES:
            (*ppTapKey)->keyData.algKeyInfo.tdesInfo.symMode = pKeyInfo->algKeyInfo.tdesInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_SYM_KEY_MODE:
                            (*ppTapKey)->keyData.algKeyInfo.tdesInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        default:
            break;
    }

    (*ppTapKey)->keyHandle = smpCmdRsp.rspParams.createSymmetricKey.keyHandle;
    (*ppTapKey)->tokenHandle = tokenHandle;

    /* TODO: We are currently not getting the key blob here, since we don't know what format to put it in yet.
             This will go in (*ppTapKey)->providerObjectData.objectBlob when we do retrieve it. */

    (*ppTapKey)->pTapContext = pTapContext;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if ((OK != status) && (NULL != ppTapKey) &&
            (NULL != *ppTapKey))
    {
        exitStatus = TAP_freeKey(ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newKeyAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (OK != status && 0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
        else
        {
            tokenHandle = 0;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TAP_createKeyInternal(TAP_Context *pTapContext,
                                TAP_EntityCredentialList *pUsageCredentials,
                                TAP_KeyInfo *pKeyInfo,
                                TAP_AttributeList *pKeyAttributes,
                                TAP_CredentialList *pKeyCredentials,
                                TAP_Key **ppTapKey,
                                TAP_ErrorContext *pErrContext,
                                SMP_CC cmdCode)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_AttributeList newKeyAttributes = { 0, };
    TAP_AttributeList *pNewKeyAttributes = NULL;
    TAP_ObjectAttributes *pNewObjAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;

    if ((NULL == pTapContext) || (NULL == pKeyInfo) || (NULL == ppTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* First generate module-specific key. */

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
            numAttributes = 4;
            break;
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            numAttributes = 3;
            /* sizes are fixed */
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            numAttributes = 4;
            break;
        case TAP_KEY_ALGORITHM_RSA:
            numAttributes = 2;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (TAP_KEY_USAGE_ATTESTATION == pKeyInfo->keyUsage)
    {
        tokenCapability = TAP_CAPABILITY_ATTESTATION_BASIC;
    }
    else
    {
        tokenCapability = TAP_CAPABILITY_CRYPTO_OP_SYMMETRIC;
    }

    if (NULL != pKeyCredentials)
        numAttributes++;

    if (NULL != pUsageCredentials)
        numAttributes++;

    if(NULL != pKeyAttributes)
    {
        numAttributes += pKeyAttributes->listLen ;
    }

    /* Set the new key attributes, including information from both pKeyInfo and pKeyAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newKeyAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate key attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newKeyAttributes.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
        newKeyAttributes.pAttributeList[0].length = sizeof(pKeyInfo->keyAlgorithm);
        newKeyAttributes.pAttributeList[0].pStructOfType = (void *)&(pKeyInfo->keyAlgorithm);

        newKeyAttributes.pAttributeList[1].type = TAP_ATTR_KEY_USAGE;
        newKeyAttributes.pAttributeList[1].length = sizeof(pKeyInfo->keyUsage);
        newKeyAttributes.pAttributeList[1].pStructOfType = (void *)&(pKeyInfo->keyUsage);
        i = 2;

        if(NULL != pKeyAttributes)
        {
            for (j=0; j < pKeyAttributes->listLen; j++)
            {
                newKeyAttributes.pAttributeList[i].type = pKeyAttributes->pAttributeList[j].type;
                newKeyAttributes.pAttributeList[i].length = pKeyAttributes->pAttributeList[j].length;
                newKeyAttributes.pAttributeList[i].pStructOfType = pKeyAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        if (NULL != pKeyCredentials)
        {
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        switch (pKeyInfo->keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_HMAC:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_RAW_KEY_SIZE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
                i++;

                /* HMAC Key */
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_HASH_ALG;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_AES:
            {
                /* AES Key */
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_KEY_SIZE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.keySize);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.keySize);
                i++;

                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.symMode);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_DES:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.desInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.desInfo.symMode);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_TDES:
            {
                newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
                newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.tdesInfo.symMode);
                newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.tdesInfo.symMode);
                i++;

                break;
            }
            case TAP_KEY_ALGORITHM_RSA:
                break;
            default:
                /* Should have already discovered this above, but for completeness... */
                status = ERR_TAP_INVALID_ALGORITHM;
                goto exit;
                break;
        }
        newKeyAttributes.listLen = numAttributes;
        pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    }


    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit1;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit1;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit1;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

exit1:
        if (tokenList.entityIdList.pEntityIdList)
        {
            DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
        }

        if (OK > status)
        {
            goto exit;
        }
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, pKeyInfo->tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set the command values */
    smpCmdReq.cmdCode = cmdCode;
    smpCmdReq.reqParams.createObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.createObject.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.createObject.pObjectAttributes = pNewKeyAttributes ?
        pNewKeyAttributes : (TAP_AttributeList *)&newKeyAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to generate asymmetric key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, don't need it anymore */
    shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    /* We know we succeeded, so now allocate memory for new TAP key and set fields */

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppTapKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppTapKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppTapKey)->providerObjectData.objectInfo.tokenId = tokenId;
    (*ppTapKey)->providerObjectData.objectInfo.objectId = smpCmdRsp.rspParams.createObject.objectIdOut;
    if ((0 < smpCmdRsp.rspParams.createObject.objectAttributesOut.listLen) &&
        (NULL != smpCmdRsp.rspParams.createObject.objectAttributesOut.pAttributeList))
    {
        pNewObjAttributes = &(smpCmdRsp.rspParams.createObject.objectAttributesOut);
        status = TAP_UTILS_copyAttributeList(&((*ppTapKey)->providerObjectData.objectInfo.objectAttributes),
                                              (TAP_AttributeList *)pNewObjAttributes);
    }

    (*ppTapKey)->keyData.keyAlgorithm = pKeyInfo->keyAlgorithm;
    (*ppTapKey)->keyData.keyUsage = pKeyInfo->keyUsage;

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg = pKeyInfo->algKeyInfo.hmacInfo.hashAlg;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_HASH_ALG:
                            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg = *(TAP_HASH_ALG *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_RAW_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.keyLen = *(TAP_RAW_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_AES:
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = pKeyInfo->algKeyInfo.aesInfo.keySize;
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = pKeyInfo->algKeyInfo.aesInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = *(TAP_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_DES:
            (*ppTapKey)->keyData.algKeyInfo.desInfo.symMode = pKeyInfo->algKeyInfo.desInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.desInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_TDES:
            (*ppTapKey)->keyData.algKeyInfo.tdesInfo.symMode = pKeyInfo->algKeyInfo.tdesInfo.symMode;
            /* Check if should override with values returned from SMP */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.tdesInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute?  Ignoring for now. */
                            break;
                    }
                }
            }
            break;
        default:
            break;
    }

    (*ppTapKey)->keyHandle = smpCmdRsp.rspParams.createObject.handle;
    (*ppTapKey)->tokenHandle = tokenHandle;

    /* TODO: We are currently not getting the key blob here, since we don't know what format to put it in yet.
             This will go in (*ppTapKey)->providerObjectData.objectBlob when we do retrieve it. */

    (*ppTapKey)->pTapContext = pTapContext;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if ((OK != status) && (NULL != ppTapKey) &&
            (NULL != *ppTapKey))
    {
        exitStatus = TAP_freeKey(ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newKeyAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symCreateKey(TAP_Context *pTapContext,
                         TAP_EntityCredentialList *pUsageCredentials,
                         TAP_KeyInfo *pKeyInfo,
                         TAP_AttributeList *pKeyAttributes,
                         TAP_CredentialList *pKeyCredentials,
                         TAP_Key **ppTapKey,
                         TAP_ErrorContext *pErrContext)
{
    return TAP_createKeyInternal(pTapContext, pUsageCredentials, pKeyInfo, pKeyAttributes, pKeyCredentials, 
                                    ppTapKey, pErrContext, SMP_CC_CREATE_OBJECT);
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symImportExternalKey(TAP_Context *pTapContext,
                                 TAP_EntityCredentialList *pUsageCredentials,
                                 TAP_KeyInfo *pKeyInfo,
                                 TAP_AttributeList *pKeyAttributes,
                                 TAP_CredentialList *pKeyCredentials,
                                 TAP_Key **ppTapKey,
                                 TAP_ErrorContext *pErrContext)
{
    return TAP_createKeyInternal(pTapContext, pUsageCredentials, pKeyInfo, pKeyAttributes, pKeyCredentials, 
                                    ppTapKey, pErrContext, SMP_CC_IMPORT_EXTERNAL_KEY);
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymCreatePubKey(TAP_Context *pTapContext,
                         TAP_EntityCredentialList *pUsageCredentials,
                         TAP_KeyInfo *pKeyInfo,
                         TAP_AttributeList *pKeyAttributes,
                         TAP_CredentialList *pKeyCredentials,
                         TAP_Key **ppTapKey,
                         TAP_ErrorContext *pErrContext)
{
    return TAP_createKeyInternal(pTapContext, pUsageCredentials, pKeyInfo, pKeyAttributes, pKeyCredentials, 
                                    ppTapKey, pErrContext, SMP_CC_CREATE_OBJECT);
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymSign(TAP_Key *pTapKey,
                     TAP_EntityCredentialList *pUsageCredentials,
                     TAP_AttributeList *pOpAttributes,
                     TAP_SIG_SCHEME sigScheme, byteBoolean isDataNotDigest,
                     TAP_Buffer *pInData, TAP_Signature *pSignature,
                     TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    SMP_signDigestCmdParams *pSignCmdParams = NULL;
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pInData) || (NULL == pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle in context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pInData->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Verify we have an asymmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
#endif
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    if (TAP_SIG_SCHEME_NONE == sigScheme)
    {
        if (TAP_KEY_ALGORITHM_RSA == pTapKey->keyData.keyAlgorithm)
            sigScheme = pTapKey->keyData.algKeyInfo.rsaInfo.sigScheme;
        else
            sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;
    }

    /* Set command parameter values */

    if (TRUE == isDataNotDigest)
    {
        pSignCmdParams = (SMP_signDigestCmdParams *)&(smpCmdReq.reqParams.signBuffer);
        smpCmdReq.cmdCode = SMP_CC_SIGN_BUFFER;
    }
    else
    {
        pSignCmdParams = (SMP_signDigestCmdParams *)&(smpCmdReq.reqParams.signDigest);
        smpCmdReq.cmdCode = SMP_CC_SIGN_DIGEST;
    }

    if (0 < numAttributes)
    {
        /* Set the new attributes, including information from both pUsageCredentials and pOpAttributes */
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    pSignCmdParams->moduleHandle = pContext->moduleHandle;
    pSignCmdParams->tokenHandle = pTapKey->tokenHandle;
    pSignCmdParams->keyHandle = pTapKey->keyHandle;
    pSignCmdParams->pDigest = pInData;
    pSignCmdParams->type = sigScheme;
    pSignCmdParams->pSignatureAttributes = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, will not need it anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to sign data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == isDataNotDigest)
    {
        status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.signBuffer.pSignature);
    }
    else
    {
        status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.signDigest.pSignature);
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* TODO: Convert TAP_signature into single DER-encoded buffer in pSignature->derEncSignature */

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    /* Release attribute memory, will be needed in error path */
    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }


    return status;
}

/*------------------------------------------------------------------*/

#ifndef __ENABLE_TAP_MIN_SIZE__
static MSTATUS TAP_constructPaddedMessage(TAP_Key *pTapKey,
                                          TAP_SignatureInfo *pSigInfo,
                                          TAP_Buffer *pData,
                                          TAP_Buffer *pPaddedMsg)
{
    MSTATUS status;
    AsymmetricKey pubKey = { 0 };
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0;
    hwAccelDescr hwAccelCtx;

    CRYPTO_initAsymmetricKey(&pubKey);

    if ((NULL == pData) || (NULL == pPaddedMsg) || (NULL == pSigInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

    status = TAP_UTILS_extractPublicKey(MOC_RSA(hwAccelCtx) &pubKey, pTapKey);
    if (OK != status)
    {
        goto exit;
    }

    /* Convert TAP signature arguments into Crypto Interface arguments */
    if (TAP_KEY_ALGORITHM_RSA == pTapKey->keyData.keyAlgorithm)
    {
        switch (pSigInfo->sigScheme)
        {
            case TAP_SIG_SCHEME_PSS:
            case TAP_SIG_SCHEME_PSS_SHA1:
            case TAP_SIG_SCHEME_PSS_SHA224:
            case TAP_SIG_SCHEME_PSS_SHA256:
            case TAP_SIG_SCHEME_PSS_SHA384:
            case TAP_SIG_SCHEME_PSS_SHA512:
                {
                    ubyte hashAlgo, mgfHashAlgo;

                    /* Only MGF1 is supported */
                    if (pSigInfo->sigInfo.rsaPss.mgf.mgfScheme != TAP_MGF1)
                    {
                        status = ERR_TAP_INVALID_INPUT;
                        goto exit;
                    }

                    /* For TAP_SIG_SCHEME's which specify the hash such as
                        *   TAP_SIG_SCHEME_PSS_SHA256
                        *   TAP_SIG_SCHEME_PSS_SHA384
                        *   etc
                        *
                        * Ensure the hash algorithm in the signature parameters
                        * is set to the same as the one specified in the
                        * signature scheme.
                        */
                    status = ERR_TAP_INVALID_INPUT;
                    if (TAP_SIG_SCHEME_PSS_SHA256 == pSigInfo->sigScheme)
                    {
                        if ( (pSigInfo->sigInfo.rsaPss.hashAlgo != TAP_HASH_ALG_SHA256) ||
                                (pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo != TAP_HASH_ALG_SHA256) )
                        {
                            goto exit;
                        }
                    }
                    else if (TAP_SIG_SCHEME_PSS_SHA224 == pSigInfo->sigScheme)
                    {
                        if ( (pSigInfo->sigInfo.rsaPss.hashAlgo != TAP_HASH_ALG_SHA224) ||
                                (pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo != TAP_HASH_ALG_SHA224) )
                        {
                            goto exit;
                        }
                    }
                    else if (TAP_SIG_SCHEME_PSS_SHA384 == pSigInfo->sigScheme)
                    {
                        if ( (pSigInfo->sigInfo.rsaPss.hashAlgo != TAP_HASH_ALG_SHA384) ||
                                (pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo != TAP_HASH_ALG_SHA384) )
                        {
                            goto exit;
                        }
                    }
                    else if (TAP_SIG_SCHEME_PSS_SHA512 == pSigInfo->sigScheme)
                    {
                        if ( (pSigInfo->sigInfo.rsaPss.hashAlgo != TAP_HASH_ALG_SHA512) ||
                                (pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo != TAP_HASH_ALG_SHA512) )
                        {
                            goto exit;
                        }
                    }
                    else if (TAP_SIG_SCHEME_PSS_SHA1 == pSigInfo->sigScheme)
                    {
                        if ( (pSigInfo->sigInfo.rsaPss.hashAlgo != TAP_HASH_ALG_SHA1) ||
                                (pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo != TAP_HASH_ALG_SHA1) )
                        {
                            goto exit;
                        }
                    }

                    status = TAP_UTILS_getHashIdFromTapHashAlg(
                        pSigInfo->sigInfo.rsaPss.hashAlgo,
                        &hashAlgo);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = TAP_UTILS_getHashIdFromTapHashAlg(
                        pSigInfo->sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo,
                        &mgfHashAlgo);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = CRYPTO_INTERFACE_PKCS1_rsaPssPad(MOC_RSA(hwAccelCtx)
                        pubKey.key.pRSA, RANDOM_rngFun, g_pRandomContext,
                        pData->pBuffer, pData->bufferLen,
                        pSigInfo->sigInfo.rsaPss.saltLen, hashAlgo,
                        pSigInfo->sigInfo.rsaPss.mgf.mgfScheme,
                        mgfHashAlgo, &(pPaddedMsg->pBuffer),
                        &(pPaddedMsg->bufferLen));
                }
                break;

            case TAP_SIG_SCHEME_PKCS1_5:
            case TAP_SIG_SCHEME_PKCS1_5_SHA1:
            case TAP_SIG_SCHEME_PKCS1_5_SHA224:
            case TAP_SIG_SCHEME_PKCS1_5_SHA256:
            case TAP_SIG_SCHEME_PKCS1_5_SHA384:
            case TAP_SIG_SCHEME_PKCS1_5_SHA512:
                {
                    ubyte hashAlg = ht_sha256;
                    if (TAP_SIG_SCHEME_PKCS1_5_SHA1 == pSigInfo->sigScheme)
                    {
                        hashAlg = ht_sha1;
                    }
                    else if (TAP_SIG_SCHEME_PKCS1_5_SHA224 == pSigInfo->sigScheme)
                    {
                        hashAlg = ht_sha224;
                    }
                    else if (TAP_SIG_SCHEME_PKCS1_5_SHA384 == pSigInfo->sigScheme)
                    {
                        hashAlg = ht_sha384;
                    }
                    else if (TAP_SIG_SCHEME_PKCS1_5_SHA512 == pSigInfo->sigScheme)
                    {
                        hashAlg = ht_sha512;
                    }

                    status = ASN1_buildDigestInfoAlloc(
                        pData->pBuffer, pData->bufferLen, hashAlg,
                        &pTemp, &tempLen);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    status = CRYPTO_INTERFACE_RSA_pkcs15Pad(MOC_RSA(hwAccelCtx)
                        pubKey.key.pRSA, MOC_ASYM_KEY_FUNCTION_SIGN,
                        RANDOM_rngFun, g_pRandomContext, pTemp, tempLen,
                        &(pPaddedMsg->pBuffer), &(pPaddedMsg->bufferLen));
                }
                break;

            case TAP_SIG_SCHEME_NONE:
                status = DIGI_MALLOC_MEMCPY(
                    ((void **) &(pPaddedMsg->pBuffer)), pData->bufferLen,
                    pData->pBuffer, pData->bufferLen);
                if (OK != status)
                {
                    goto exit;
                }
                pPaddedMsg->bufferLen = pData->bufferLen;
                break;

            default:
                status = ERR_TAP_INVALID_SCHEME;
                goto exit;
        }
    }
    else
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
    }

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    if (NULL != pTemp)
    {
        DIGI_MEMSET_FREE(&pTemp, tempLen);
    }
    CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

    return status;
}
#endif

/*------------------------------------------------------------------*/
#ifndef __ENABLE_TAP_MIN_SIZE__
MSTATUS TAP_asymSignEx(TAP_Key *pTapKey,
                       TAP_EntityCredentialList *pUsageCredentials,
                       TAP_AttributeList *pOpAttributes,
                       TAP_SignatureInfo *pSigInfo,
                       TAP_Buffer *pInData, TAP_Signature *pSignature,
                       TAP_ErrorContext *pErrContext)
{
    MSTATUS status;
    TAP_Buffer paddedMsg = { 0 };
    TAP_Buffer decryptOut = { 0 };

    if ( (NULL == pTapKey) || (NULL == pSigInfo) || (NULL == pInData) ||
         (NULL == pSignature) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Padding operation is done in software */
    status = TAP_constructPaddedMessage(
        pTapKey, pSigInfo, pInData, &paddedMsg);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create padded message, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Perform raw sign (decrypt operation) on padded message */
    status = TAP_asymDecrypt(
        pTapKey, pUsageCredentials, pOpAttributes, TAP_ENC_SCHEME_NONE,
        &paddedMsg, &decryptOut, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to perform raw sign on padded message, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Caller expects TAP_Signature structure. Copy TAP_Buffer into
     * TAP_Signature. */
    if (TAP_KEY_ALGORITHM_RSA == pTapKey->keyData.keyAlgorithm)
    {
        status = DIGI_MALLOC(
            (void **) &(pSignature->signature.rsaSignature.pSignature),
            decryptOut.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate signature buffer, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        status = DIGI_MEMCPY(
            pSignature->signature.rsaSignature.pSignature,
            decryptOut.pBuffer, decryptOut.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy signature, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        pSignature->signature.rsaSignature.signatureLen = decryptOut.bufferLen;
        pSignature->isDEREncoded = FALSE;
    }
    else
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    pSignature->keyAlgorithm = pTapKey->keyData.keyAlgorithm;

exit:

    if (NULL != decryptOut.pBuffer)
    {
        TAP_UTILS_freeBuffer(&decryptOut);
    }

    if (NULL != paddedMsg.pBuffer)
    {
        TAP_UTILS_freeBuffer(&paddedMsg);
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_symSign(TAP_Key *pTapKey,
                    TAP_EntityCredentialList *pUsageCredentials,
                    TAP_AttributeList *pOpAttributes,
                    byteBoolean isDataNotDigest,
                    TAP_Buffer *pInData, TAP_Signature *pSignature,
                    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    SMP_signDigestCmdParams *pSignCmdParams = NULL;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pInData) || (NULL == pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pInData->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:

            switch(pTapKey->keyData.algKeyInfo.hmacInfo.hashAlg)
            {
                case TAP_HASH_ALG_SHA1:
                   sigScheme = TAP_SIG_SCHEME_HMAC_SHA1;
                   break;
                case TAP_HASH_ALG_SHA224:
                   sigScheme = TAP_SIG_SCHEME_HMAC_SHA224;
                   break;
                case TAP_HASH_ALG_SHA256:
                   sigScheme = TAP_SIG_SCHEME_HMAC_SHA256;
                   break;
                case TAP_HASH_ALG_SHA384:
                   sigScheme = TAP_SIG_SCHEME_HMAC_SHA384;
                   break;
                case TAP_HASH_ALG_SHA512:
                   sigScheme = TAP_SIG_SCHEME_HMAC_SHA512;
                   break;
                default:
                    status = ERR_INVALID_INPUT;
                    goto exit;
            }
            break;
        case TAP_KEY_ALGORITHM_AES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */

    if (TRUE == isDataNotDigest)
    {
        pSignCmdParams = (SMP_signDigestCmdParams *)&(smpCmdReq.reqParams.signBuffer);
        smpCmdReq.cmdCode = SMP_CC_SIGN_BUFFER;
    }
    else
    {
        pSignCmdParams = (SMP_signDigestCmdParams *)&(smpCmdReq.reqParams.signDigest);
        smpCmdReq.cmdCode = SMP_CC_SIGN_DIGEST;
    }

    /* Set the new attributes, including information from both pUsageCredentials and pOpAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    pSignCmdParams->moduleHandle = pContext->moduleHandle;
    pSignCmdParams->tokenHandle = pTapKey->tokenHandle;
    pSignCmdParams->keyHandle = pTapKey->keyHandle;
    pSignCmdParams->pDigest = pInData;
    pSignCmdParams->type = sigScheme;
    pSignCmdParams->pSignatureAttributes = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *)&newAttributes;

    /* get Signature scheme fom keydata */
    pSignCmdParams->type = TAP_SIG_SCHEME_NONE;
    if (TAP_KEY_ALGORITHM_HMAC == pTapKey->keyData.keyAlgorithm)
    {
        switch (pTapKey->keyData.algKeyInfo.hmacInfo.hashAlg)
        {
            case TAP_HASH_ALG_NONE:
                pSignCmdParams->type = TAP_SIG_SCHEME_NONE;
                break;
            case TAP_HASH_ALG_SHA1:
                pSignCmdParams->type = TAP_SIG_SCHEME_HMAC_SHA1;
                break;
            case TAP_HASH_ALG_SHA256:
                pSignCmdParams->type = TAP_SIG_SCHEME_HMAC_SHA256;
                break;
            case TAP_HASH_ALG_SHA224:
                pSignCmdParams->type = TAP_SIG_SCHEME_HMAC_SHA224;
                break;
            case TAP_HASH_ALG_SHA384:
                pSignCmdParams->type = TAP_SIG_SCHEME_HMAC_SHA384;
                break;
            case TAP_HASH_ALG_SHA512:
                pSignCmdParams->type = TAP_SIG_SCHEME_HMAC_SHA512;
                break;
        }
    }

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, no longer needed */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to sign data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TRUE == isDataNotDigest)
    {
        status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.signBuffer.pSignature);
    }
    else
    {
        status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.signDigest.pSignature);
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != smpCmdRsp.rspParams.signFinal.pSignature)
    {
        if (TRUE == isDataNotDigest)
        {
            (void) TAP_freeSignature(smpCmdRsp.rspParams.signBuffer.pSignature);
            (void) DIGI_FREE((void **) &smpCmdRsp.rspParams.signBuffer.pSignature);
        }
        else
        {
            (void) TAP_freeSignature(smpCmdRsp.rspParams.signDigest.pSignature);
            (void) DIGI_FREE((void **) &smpCmdRsp.rspParams.signDigest.pSignature);
        }
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    /* Release attribute memory, needed in error path */
    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;

}

/*------------------------------------------------------------------*/

MSTATUS TAP_symSignInit(TAP_Key *pTapKey,
                        TAP_EntityCredentialList *pUsageCredentials,
                        TAP_AttributeList *pOpAttributes,
                        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    SMP_signInitCmdParams *pSignCmdParams = NULL;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_SignAttributes *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if (NULL == pTapKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Verify we have an hmac key */
    if (TAP_KEY_ALGORITHM_HMAC == pTapKey->keyData.keyAlgorithm)
    {
        switch(pTapKey->keyData.algKeyInfo.hmacInfo.hashAlg)
        {
            case TAP_HASH_ALG_SHA1:
                sigScheme = TAP_SIG_SCHEME_HMAC_SHA1;
                break;
            case TAP_HASH_ALG_SHA224:
                sigScheme = TAP_SIG_SCHEME_HMAC_SHA224;
                break;
            case TAP_HASH_ALG_SHA256:
                sigScheme = TAP_SIG_SCHEME_HMAC_SHA256;
                break;
            case TAP_HASH_ALG_SHA384:
                sigScheme = TAP_SIG_SCHEME_HMAC_SHA384;
                break;
            case TAP_HASH_ALG_SHA512:
                sigScheme = TAP_SIG_SCHEME_HMAC_SHA512;
                break;
            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }
    }
    else
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    /* Set command parameter values */
    pSignCmdParams = (SMP_signInitCmdParams *)&(smpCmdReq.reqParams.signInit);
    smpCmdReq.cmdCode = SMP_CC_SIGN_INIT;

    /* Set the new attributes, including information from both pUsageCredentials and pOpAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    pSignCmdParams->moduleHandle = pContext->moduleHandle;
    pSignCmdParams->tokenHandle = pTapKey->tokenHandle;
    pSignCmdParams->keyHandle = pTapKey->keyHandle;
    pSignCmdParams->type = sigScheme;
    pSignCmdParams->pSignatureAttributes = pNewAttributes ?
        pNewAttributes : (TAP_SignAttributes *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, no longer needed */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to sign data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    /* Release attribute memory, needed in error path */
    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symSignUpdate(TAP_Key *pTapKey,
                          TAP_Buffer *pInData,
                          TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    SMP_signUpdateCmdParams *pSignCmdParams = NULL;
    _TAP_Context *pContext = NULL;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pInData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pInData->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have an hmac key */
    if (TAP_KEY_ALGORITHM_HMAC != pTapKey->keyData.keyAlgorithm)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    /* Set command parameter values */

    pSignCmdParams = (SMP_signUpdateCmdParams *)&(smpCmdReq.reqParams.signUpdate);
    smpCmdReq.cmdCode = SMP_CC_SIGN_UPDATE;

    pSignCmdParams->moduleHandle = pContext->moduleHandle;
    pSignCmdParams->tokenHandle = pTapKey->tokenHandle;
    pSignCmdParams->keyHandle = pTapKey->keyHandle;
    pSignCmdParams->pBuffer = pInData;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to sign data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symSignFinal(TAP_Key *pTapKey,
                         TAP_Signature *pSignature,
                         TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    SMP_signFinalCmdParams *pSignCmdParams = NULL;
    _TAP_Context *pContext = NULL;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify we have an hmac key */
    if (TAP_KEY_ALGORITHM_HMAC != pTapKey->keyData.keyAlgorithm)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    /* Set command parameter values */
    pSignCmdParams = (SMP_signFinalCmdParams *)&(smpCmdReq.reqParams.signFinal);
    smpCmdReq.cmdCode = SMP_CC_SIGN_FINAL;

    pSignCmdParams->moduleHandle = pContext->moduleHandle;
    pSignCmdParams->tokenHandle = pTapKey->tokenHandle;
    pSignCmdParams->keyHandle = pTapKey->keyHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to sign data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.signFinal.pSignature);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (NULL != smpCmdRsp.rspParams.signFinal.pSignature)
    {
        (void) TAP_freeSignature(smpCmdRsp.rspParams.signFinal.pSignature);
        (void) DIGI_FREE((void **) &smpCmdRsp.rspParams.signFinal.pSignature);
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymVerifySignature(TAP_Key *pTapKey, TAP_EntityCredentialList *pUsageCredentials,
                                TAP_AttributeList *pOpAttributes, TAP_OP_EXEC_FLAG opExecFlag,
                                TAP_SIG_SCHEME sigScheme, TAP_Buffer *pInDigest,
                                TAP_Signature *pSignature, byteBoolean *pIsSigValid,
                                TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 2;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pInDigest) || (NULL == pSignature) || (NULL == pIsSigValid))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsSigValid = FALSE;

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pInDigest->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Verify we have an asymmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }


/*  TO DO need to decide if we should add an isDataNotDigest flag.
    if (TRUE == isDataNotDigest && TAP_SIG_SCHEME_NONE == sigScheme)
    {
        if (TAP_KEY_ALGORITHM_RSA == pTapKey->keyData.keyAlgorithm)
            sigScheme = pTapKey->keyData.algKeyInfo.rsaInfo.sigScheme;
        else
            sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;
    }
*/
    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen)
         && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pOpAttributes->listLen;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_SIG_SCHEME;
        newAttributes.pAttributeList[0].length = sizeof(TAP_SIG_SCHEME);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&sigScheme;

        newAttributes.pAttributeList[1].type = TAP_ATTR_OP_EXEC_FLAG;
        newAttributes.pAttributeList[1].length = sizeof(TAP_OP_EXEC_FLAG);
        newAttributes.pAttributeList[1].pStructOfType = (void *)&opExecFlag;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = numAttributes;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_VERIFY;

    smpCmdReq.reqParams.verify.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.verify.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.verify.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.verify.pMechanism = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.verify.pDigest = pInDigest;
    smpCmdReq.reqParams.verify.pSignature = pSignature;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to verify signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pIsSigValid = smpCmdRsp.rspParams.verify.signatureValid;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symVerifySignature(TAP_Key *pTapKey,  TAP_EntityCredentialList *pUsageCredentials,
                               TAP_AttributeList *pOpAttributes, TAP_Buffer *pInDigest,
                               TAP_Signature *pSignature, byteBoolean *pIsSigValid,
                               TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pInDigest) || (NULL == pSignature) || (NULL == pIsSigValid))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pIsSigValid = FALSE;

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pInDigest->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
             for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }
    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_VERIFY;

    smpCmdReq.reqParams.verify.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.verify.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.verify.keyHandle = pTapKey->keyHandle;
    if (0 < numAttributes)
        smpCmdReq.reqParams.verify.pMechanism = pNewAttributes;
    else
        smpCmdReq.reqParams.verify.pMechanism = (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.verify.pDigest = pInDigest;
    smpCmdReq.reqParams.verify.pSignature = pSignature;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to verify signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *pIsSigValid = smpCmdRsp.rspParams.verify.signatureValid;

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_freeSignature(TAP_Signature *pSignature)
{
    MSTATUS status = OK;

    if (NULL == pSignature)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status =  TAP_UTILS_freeTapSignatureFields(pSignature);

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymEncrypt(TAP_Key *pTapKey,
                        TAP_EntityCredentialList *pUsageCredentials,
                        TAP_AttributeList *pOpAttributes,
                        TAP_OP_EXEC_FLAG opExecFlag,  TAP_ENC_SCHEME encScheme,
                        TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 2;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pPlainText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have an asymmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_ENC_SCHEME;
        newAttributes.pAttributeList[0].length = sizeof(TAP_ENC_SCHEME);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&encScheme;

        newAttributes.pAttributeList[1].type = TAP_ATTR_OP_EXEC_FLAG;
        newAttributes.pAttributeList[1].length = sizeof(TAP_OP_EXEC_FLAG);
        newAttributes.pAttributeList[1].pStructOfType = (void *)&opExecFlag;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_ENCRYPT;

    smpCmdReq.reqParams.encrypt.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.encrypt.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.encrypt.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.encrypt.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.encrypt.pBuffer = pPlainText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, don't need it anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pCipherText, &(smpCmdRsp.rspParams.encrypt.cipherBuffer));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_symEncrypt(TAP_Key *pTapKey,
                       TAP_EntityCredentialList *pUsageCredentials,
                       TAP_AttributeList *pOpAttributes,
                       TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                       TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                       TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */

    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText) || (NULL == pIV))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pPlainText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    numAttributes += 2;
    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_SYM_KEY_MODE;
        newAttributes.pAttributeList[0].length = sizeof(TAP_SYM_KEY_MODE);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&symMode;

        newAttributes.pAttributeList[1].type = TAP_ATTR_BUFFER;
        newAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        newAttributes.pAttributeList[1].pStructOfType = (void *)pIV;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_ENCRYPT;

    smpCmdReq.reqParams.encrypt.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.encrypt.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.encrypt.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.encrypt.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.encrypt.pBuffer = pPlainText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pCipherText, &(smpCmdRsp.rspParams.encrypt.cipherBuffer));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symEncryptInit(TAP_Key *pTapKey,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_AttributeList *pOpAttributes,
                           TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                           TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */

    if ((NULL == pTapKey) || (NULL == pIV))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    numAttributes += 2;
    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_SYM_KEY_MODE;
        newAttributes.pAttributeList[0].length = sizeof(TAP_SYM_KEY_MODE);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&symMode;

        newAttributes.pAttributeList[1].type = TAP_ATTR_BUFFER;
        newAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        newAttributes.pAttributeList[1].pStructOfType = (void *)pIV;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_ENCRYPT_INIT;

    smpCmdReq.reqParams.encryptInit.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.encryptInit.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.encryptInit.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.encryptInit.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symEncryptUpdate(TAP_Key *pTapKey,
                             TAP_EntityCredentialList *pUsageCredentials,
                             TAP_AttributeList *pOpAttributes,
                             TAP_SYM_KEY_MODE symMode,
                             TAP_Buffer *pPlainText, TAP_Buffer *pCipherText,
                             TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    MOC_UNUSED(pUsageCredentials);
    MOC_UNUSED(pOpAttributes);
    MOC_UNUSED(symMode);

    /* check input */

    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pPlainText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_ENCRYPT_UPDATE;

    smpCmdReq.reqParams.encryptUpdate.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.encryptUpdate.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.encryptUpdate.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.encryptUpdate.pBuffer = pPlainText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pCipherText, &(smpCmdRsp.rspParams.encrypt.cipherBuffer));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symEncryptFinal(TAP_Key *pTapKey,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_AttributeList *pOpAttributes,
                            TAP_SYM_KEY_MODE symMode,
                            TAP_Buffer *pCipherText,
                            TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    MOC_UNUSED(pUsageCredentials);
    MOC_UNUSED(pOpAttributes);
    MOC_UNUSED(symMode);

    /* check input */

    if (NULL == pTapKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_ENCRYPT_FINAL;

    smpCmdReq.reqParams.encryptFinal.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.encryptFinal.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.encryptFinal.keyHandle = pTapKey->keyHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (smpCmdRsp.rspParams.encryptFinal.cipherBuffer.bufferLen)
    {
        status = TAP_UTILS_copyBuffer(pCipherText, &(smpCmdRsp.rspParams.encryptFinal.cipherBuffer));
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_asymDecrypt(TAP_Key *pTapKey,
                        TAP_EntityCredentialList *pUsageCredentials,
                        TAP_AttributeList *pOpAttributes,
                        TAP_ENC_SCHEME encScheme, TAP_Buffer *pCipherText,
                        TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 1;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pCipherText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have an asymmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_ENC_SCHEME;
        newAttributes.pAttributeList[0].length = sizeof(TAP_ENC_SCHEME);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&encScheme;

        i = 1;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_DECRYPT;

    smpCmdReq.reqParams.decrypt.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.decrypt.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.decrypt.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.decrypt.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.decrypt.pCipherBuffer = pCipherText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decrytp data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pPlainText, &(smpCmdRsp.rspParams.decrypt.buffer));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symDecrypt(TAP_Key *pTapKey,
                       TAP_EntityCredentialList *pUsageCredentials,
                       TAP_AttributeList *pOpAttributes,
                       TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV, TAP_Buffer *pCipherText,
                       TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */

    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText) || (NULL == pIV))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pCipherText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    numAttributes += 2;
    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_SYM_KEY_MODE;
        newAttributes.pAttributeList[0].length = sizeof(TAP_SYM_KEY_MODE);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&symMode;

        newAttributes.pAttributeList[1].type = TAP_ATTR_BUFFER;
        newAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        newAttributes.pAttributeList[1].pStructOfType = (void *)pIV;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_DECRYPT;

    smpCmdReq.reqParams.decrypt.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.decrypt.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.decrypt.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.decrypt.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.decrypt.pCipherBuffer = pCipherText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pPlainText, &(smpCmdRsp.rspParams.decrypt.buffer));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symDecryptInit(TAP_Key *pTapKey,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_AttributeList *pOpAttributes,
                           TAP_SYM_KEY_MODE symMode, TAP_Buffer *pIV,
                           TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */

    if ((NULL == pTapKey) || (NULL == pIV))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    numAttributes += 2;
    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredentials and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[0].type = TAP_ATTR_SYM_KEY_MODE;
        newAttributes.pAttributeList[0].length = sizeof(TAP_SYM_KEY_MODE);
        newAttributes.pAttributeList[0].pStructOfType = (void *)&symMode;

        newAttributes.pAttributeList[1].type = TAP_ATTR_BUFFER;
        newAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        newAttributes.pAttributeList[1].pStructOfType = (void *)pIV;

        i = 2;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_DECRYPT_INIT;

    smpCmdReq.reqParams.decryptInit.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.decryptInit.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.decryptInit.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.decryptInit.pMechanism = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symDecryptUpdate(TAP_Key *pTapKey,
                             TAP_EntityCredentialList *pUsageCredentials,
                             TAP_AttributeList *pOpAttributes,
                             TAP_SYM_KEY_MODE symMode, TAP_Buffer *pCipherText,
                             TAP_Buffer *pPlainText, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    MOC_UNUSED(pUsageCredentials);
    MOC_UNUSED(pOpAttributes);
    MOC_UNUSED(symMode);

    /* check input */

    if ((NULL == pTapKey) || (NULL == pPlainText) || (NULL == pCipherText))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (1 > pCipherText->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_DECRYPT_UPDATE;

    smpCmdReq.reqParams.decryptUpdate.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.decryptUpdate.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.decryptUpdate.keyHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.decryptUpdate.pCipherBuffer = pCipherText;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Copy data out if present */
    if (NULL != smpCmdRsp.rspParams.decryptUpdate.buffer.pBuffer)
    {
        status = TAP_UTILS_copyBuffer(pPlainText, &(smpCmdRsp.rspParams.decryptUpdate.buffer));
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_symDecryptFinal(TAP_Key *pTapKey,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_AttributeList *pOpAttributes,
                            TAP_SYM_KEY_MODE symMode,
                            TAP_Buffer *pPlainText,
                            TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    MOC_UNUSED(pUsageCredentials);
    MOC_UNUSED(pOpAttributes);
    MOC_UNUSED(symMode);

    /* check input */

    if (NULL == pTapKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Verify we have a symmetric key */
    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_DECRYPT_FINAL;

    smpCmdReq.reqParams.decryptFinal.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.decryptFinal.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.decryptFinal.keyHandle = pTapKey->keyHandle;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to decrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != smpCmdRsp.rspParams.decryptFinal.buffer.pBuffer)
    {
        status = TAP_UTILS_copyBuffer(pPlainText, &(smpCmdRsp.rspParams.decryptFinal.buffer));
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_freeKey(TAP_Key **ppKey)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;

    if ((NULL == ppKey) || (NULL == *ppKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    TAP_Key *pTapKey = *ppKey;
    status = TAP_SMP_purgeObject((_TAP_Context *)(pTapKey->pTapContext),
            &pTapKey->tokenHandle,
            (TAP_ObjectHandle *)(&pTapKey->keyHandle));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to unload key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pTapKey->keyHandle = 0;
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    /* Add explicit MLDSA key memory cleanup before generic cleanup */
    if ((*ppKey)->keyData.keyAlgorithm == TAP_KEY_ALGORITHM_MLDSA)
    {
        /* Free MLDSA-specific public key memory */
        if ((*ppKey)->keyData.publicKey.publicKey.mldsaKey.pPublicKey)
        {
            exitStatus = DIGI_FREE((void **)&((*ppKey)->keyData.publicKey.publicKey.mldsaKey.pPublicKey));
            if (OK != exitStatus)
            {
                DB_PRINT("%s.%d Failed to free MLDSA public key buffer, status %d = %s\n",
                        __FUNCTION__, __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
            }
            (*ppKey)->keyData.publicKey.publicKey.mldsaKey.pPublicKey = (void *)NULL;
            (*ppKey)->keyData.publicKey.publicKey.mldsaKey.publicKeyLen = 0;
        }
    }
#endif

    /* If we dont have global token deferred, and this key isnt marked for token deferment,
     * and we have a valid token handle, uninitialize the token */
    if ( (0 == globalDeferredTokenUnload) && (FALSE == (*ppKey)->deferredTokenUnload) &&
         (0 != (*ppKey)->tokenHandle) )
    {
        exitStatus =  TAP_SMP_uninitToken((*ppKey)->pTapContext,
                &(*ppKey)->tokenHandle, NULL);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d INFO: Context already uninitialized, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &TAP_SHADOW_TAP_Key, (ubyte *)*ppKey, sizeof(TAP_Key));

    status = TAP_UTILS_freeBlob(&((*ppKey)->providerObjectData.objectBlob));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free TAP_Key objectBlob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    /* Do not free the context, since it may still be in use elsewhere */
    (*ppKey)->pTapContext = NULL;
    (*ppKey)->tokenHandle = 0;
    (*ppKey)->keyHandle = 0;

    /* Now free the TAPKey */
    status = DIGI_FREE((void **)ppKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free TAP_Key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
MSTATUS TAP_freeKeyEx(TAP_Key **ppKey)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;

    if ((NULL == ppKey) || (NULL == *ppKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &TAP_SHADOW_TAP_Key, (ubyte *)*ppKey, sizeof(TAP_Key));

    status = TAP_UTILS_freeBlob(&((*ppKey)->providerObjectData.objectBlob));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free TAP_Key objectBlob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    /* Do not free the context, since it may still be in use elsewhere */
    (*ppKey)->pTapContext = NULL;
    (*ppKey)->tokenHandle = 0;
    (*ppKey)->keyHandle = 0;

    /* Now free the TAPKey */
    status = DIGI_FREE((void **)ppKey);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free TAP_Key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}
#endif

/*------------------------------------------------------------------*/

MSTATUS TAP_copyKey(TAP_Key **ppNewKey, TAP_Key *pSrcKey)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;

    if ((NULL == ppNewKey) || (NULL == pSrcKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Allocate memory for the new key */
    status = DIGI_CALLOC((void **)ppNewKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Now set TAPKey fields */
    (*ppNewKey)->providerObjectData.objectInfo.providerType = pSrcKey->providerObjectData.objectInfo.providerType;
    (*ppNewKey)->providerObjectData.objectInfo.moduleId = pSrcKey->providerObjectData.objectInfo.moduleId;
    (*ppNewKey)->providerObjectData.objectInfo.tokenId = pSrcKey->providerObjectData.objectInfo.tokenId;
    (*ppNewKey)->providerObjectData.objectInfo.objectId = pSrcKey->providerObjectData.objectInfo.objectId;
    status = TAP_UTILS_copyAttributeList(&((*ppNewKey)->providerObjectData.objectInfo.objectAttributes),
                                          &(pSrcKey->providerObjectData.objectInfo.objectAttributes));
    status = TAP_UTILS_copyBlob(&((*ppNewKey)->providerObjectData.objectBlob),
                                  &(pSrcKey->providerObjectData.objectBlob));

    (*ppNewKey)->keyData.keyAlgorithm = pSrcKey->keyData.keyAlgorithm;
    (*ppNewKey)->keyData.keyUsage = pSrcKey->keyData.keyUsage;
    switch (pSrcKey->keyData.keyAlgorithm)
    {
        case (TAP_KEY_ALGORITHM_RSA):
            (*ppNewKey)->keyData.algKeyInfo.rsaInfo.keySize = pSrcKey->keyData.algKeyInfo.rsaInfo.keySize;
            (*ppNewKey)->keyData.algKeyInfo.rsaInfo.exponent = pSrcKey->keyData.algKeyInfo.rsaInfo.exponent;
            (*ppNewKey)->keyData.algKeyInfo.rsaInfo.encScheme = pSrcKey->keyData.algKeyInfo.rsaInfo.encScheme;
            (*ppNewKey)->keyData.algKeyInfo.rsaInfo.sigScheme = pSrcKey->keyData.algKeyInfo.rsaInfo.sigScheme;
            break;
        case (TAP_KEY_ALGORITHM_ECC):
            (*ppNewKey)->keyData.algKeyInfo.eccInfo.curveId = pSrcKey->keyData.algKeyInfo.eccInfo.curveId;
            (*ppNewKey)->keyData.algKeyInfo.eccInfo.sigScheme = pSrcKey->keyData.algKeyInfo.eccInfo.sigScheme;
            break;
        case (TAP_KEY_ALGORITHM_AES):
            (*ppNewKey)->keyData.algKeyInfo.aesInfo.keySize = pSrcKey->keyData.algKeyInfo.aesInfo.keySize;
            (*ppNewKey)->keyData.algKeyInfo.aesInfo.symMode = pSrcKey->keyData.algKeyInfo.aesInfo.symMode;
            break;
        case (TAP_KEY_ALGORITHM_DES):
            (*ppNewKey)->keyData.algKeyInfo.desInfo.symMode = pSrcKey->keyData.algKeyInfo.desInfo.symMode;
            break;
        case (TAP_KEY_ALGORITHM_TDES):
            (*ppNewKey)->keyData.algKeyInfo.tdesInfo.symMode = pSrcKey->keyData.algKeyInfo.tdesInfo.symMode;
            break;
        case (TAP_KEY_ALGORITHM_HMAC):
            (*ppNewKey)->keyData.algKeyInfo.hmacInfo.hashAlg = pSrcKey->keyData.algKeyInfo.hmacInfo.hashAlg;
            (*ppNewKey)->keyData.algKeyInfo.hmacInfo.keyLen = pSrcKey->keyData.algKeyInfo.hmacInfo.keyLen;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }
    status = TAP_UTILS_copyPublicKey(&((*ppNewKey)->keyData.publicKey),
                                     &(pSrcKey->keyData.publicKey));


    (*ppNewKey)->pTapContext = pSrcKey->pTapContext;
    (*ppNewKey)->tokenHandle = pSrcKey->tokenHandle;
    (*ppNewKey)->keyHandle = pSrcKey->keyHandle;

exit:

    if ((OK != status) && (NULL != ppNewKey))
    {
        exitStatus = TAP_freeKey(ppNewKey);
        if (OK != exitStatus)
            status = exitStatus;
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_serializeKey(TAP_Key *pTapKey, TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                         TAP_Buffer *pSerializedKeyBuffer, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 serializedSize = 0;
    ubyte4 offset = 0;
    ubyte *pKeyBuffer = NULL;
    ubyte4 keyBufferLen = 0;

    if ((NULL == pTapKey) || (NULL == pSerializedKeyBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        goto serialize_key;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    /* Get the serialized blob from the SMP */
    if (NULL != pTapKey->providerObjectData.objectBlob.blob.pBuffer)
    {
        status = DIGI_FREE((void **)&(pTapKey->providerObjectData.objectBlob.blob.pBuffer));
        pTapKey->providerObjectData.objectBlob.blob.bufferLen = 0;
    }

    status = TAP_SMP_serializeObject((_TAP_Context *)(pTapKey->pTapContext), TAP_OBJECT_TYPE_KEY, (const void *)pTapKey,
                                   format, encoding,
                                   &(pTapKey->providerObjectData.objectBlob), pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get serialized key blob from provider. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

serialize_key:
    pSerializedKeyBuffer->bufferLen = 0;
    pSerializedKeyBuffer->pBuffer = NULL;

    /* Get the serialized size of the TAP_Key object */

    status = TAP_UTILS_getKeySize((const TAP_Key *)pTapKey, &serializedSize);
    if (OK != status)
    {
            DB_PRINT("%s.%d Failed to determine serialized size of key. status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
    }
    if (0 == serializedSize)
    {
        DB_PRINT("%s.%d TAP_UTILS_getKeySize returned invalid serialized size of key = %d. status %d = %s\n", __FUNCTION__,
                __LINE__, serializedSize, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    serializedSize += 3;

    /* Allocate memory for key buffer */
    status = DIGI_CALLOC((void **)(&pKeyBuffer), 1, serializedSize);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate %u bytes of memory for key buffer. status %d = %s\n", __FUNCTION__,
                __LINE__, serializedSize, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Serialized key is in format:
         TAP_OBJECT_TYPE_KEY:   1 byte
         TAP_BLOB_FORMAT:       1 byte
         TAP_BLOB_ENCODING:     1 byte
         serialized key blob: n bytes
     */
    offset = 3;
    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Key, TAP_SD_IN,
            (void *)(pTapKey), sizeof(TAP_Key),
            pKeyBuffer, serializedSize, &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize TAP_Key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pKeyBuffer[0] = TAP_OBJECT_TYPE_KEY;
    pKeyBuffer[1] = format;
    pKeyBuffer[2] = encoding;
    switch (format)
    {
        case TAP_BLOB_FORMAT_MOCANA:
            keyBufferLen = offset;
            break;
        case TAP_BLOB_FORMAT_DER:
            /* TODO: DER encode key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        case TAP_BLOB_FORMAT_PEM:
            /* TODO: PEM encode key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        default:
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
    }

    pSerializedKeyBuffer->pBuffer = pKeyBuffer;
    pSerializedKeyBuffer->bufferLen = keyBufferLen;
    pKeyBuffer = NULL;

exit:

    /* Free module key blob */
    if ((OK != status) && (NULL != pKeyBuffer))
    {
        exitStatus = DIGI_FREE((void **)&pKeyBuffer);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "failed to free memory for serialized key blob, status %d = %s\n",
                    exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }

        exitStatus = TAP_UTILS_freeBlob(&(pTapKey->providerObjectData.objectBlob));
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "failed to free memory for provider key blob, status %d = %s\n",
                    exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_deserializeKey(TAP_Buffer *pSerializedKeyBuffer, TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 offset = 0;
    ubyte *pDecodedKeyBlob = NULL;
    ubyte4 decodedKeyBlobLen = 0;

    if ((NULL == pSerializedKeyBuffer) || (NULL == ppTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Serialized key is in format:
         TAP_OBJECT_TYPE_KEY: 1 byte
         TAP_BLOB_FORMAT:     1 byte
         serialized key blob: n bytes
     */

    if (TAP_OBJECT_TYPE_KEY != pSerializedKeyBuffer->pBuffer[0])
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT(__func__, __LINE__, "Invalid blob - not a serialized key blob! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    switch((TAP_BLOB_FORMAT)(pSerializedKeyBuffer->pBuffer[1]))
    {
        case TAP_BLOB_FORMAT_MOCANA:
            pDecodedKeyBlob = pSerializedKeyBuffer->pBuffer;
            decodedKeyBlobLen = pSerializedKeyBuffer->bufferLen;
            break;
        case TAP_BLOB_FORMAT_DER:
            /* TODO: decode DER key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        case TAP_BLOB_FORMAT_PEM:
            /* TODO: decode PEM key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        default:
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
    }
    switch((TAP_BLOB_ENCODING)(pSerializedKeyBuffer->pBuffer[2]))
    {
        case TAP_BLOB_ENCODING_BINARY:
            break;
        case TAP_BLOB_ENCODING_BASE64:
            status = ERR_TAP_INVALID_BLOB_ENCODING;
            goto exit;
            break;
        default:
            status = ERR_TAP_INVALID_BLOB_ENCODING;
            goto exit;
            break;
    }

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* deserialize TAP_Key */
    offset = 3;
    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Key, TAP_SD_OUT,
                pDecodedKeyBlob, decodedKeyBlobLen,
                (void *)(*ppTapKey), sizeof(TAP_Key), &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to deserialize TAP_Key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* At this point we have the serialized module key blob that must be loaded. */

exit:

    /* On error, free key */
    if ((OK != status) && (NULL != ppTapKey) && (NULL != *ppTapKey))
    {
        exitStatus = DIGI_FREE((void **)ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "failed to free key, status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
            goto exit;
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_loadKey(TAP_Context *pTapContext,
                    TAP_EntityCredentialList *pUsageCredentials,
                    TAP_Key *pTapKey,
                    TAP_CredentialList *pKeyCredentials,
                    TAP_AttributeList *pAttributes,
                    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    TAP_AttributeList *pNewAttributes = NULL;
    TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    if ((NULL == pTapContext) || (NULL == pTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* For dynamic keys, check if key has been deserialized */
    if ((0 == pTapKey->providerObjectData.objectInfo.objectId) &&
            ((pTapKey->providerObjectData.objectBlob.blob.bufferLen < 1) ||
             (NULL == pTapKey->providerObjectData.objectBlob.blob.pBuffer)))
    {
        DB_PRINT(__func__, __LINE__, "Key cannot be loaded! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* Set the key context */
    pTapKey->pTapContext = pTapContext;

    if (0 == ((_TAP_Context *)(pTapKey->pTapContext))->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, ((_TAP_Context *)(pTapKey->pTapContext))->moduleHandle,
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Load token, if not already loaded */
    if (0 == pTapKey->tokenHandle)
    {
        status = TAP_SMP_initToken(pTapKey->pTapContext, &(pTapKey->providerObjectData.objectInfo.tokenId), NULL,
                                   pUsageCredentials, &(pTapKey->tokenHandle), pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if ((pTapKey->tokenHandle != 0) && (pTapKey->keyHandle != 0))
    {
        DB_PRINT("%s TokenHandle and KeyHandle are loaded\n", __FUNCTION__);
        status = OK;
        goto exit;
    }
    /* combine the pAttributes and pKeyCredentials */
    if (NULL != pAttributes)
    {
        if ((0 < pAttributes->listLen) && (NULL == pAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pAttributes->listLen;
    }

    if (NULL != pKeyCredentials)
    {
        if ((0 < pKeyCredentials->numCredentials) && (NULL == pKeyCredentials->pCredentialList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    if (0 < numAttributes)
    {
        /* Set the new attributes, including information from both pUsageCredentials and pOpAttributes */
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pKeyCredentials)
        {
            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        if (NULL != pAttributes)
        {
            for (j=0; j < pAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    status = TAP_SMP_importObject(TAP_OBJECT_TYPE_KEY, (const void *)pTapKey, &(pTapKey->tokenHandle),
            pNewAttributes, pUsageCredentials,
            &(pTapKey->providerObjectData.objectBlob), pErrContext);

    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to load key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


exit:

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_unloadKey(TAP_Key *pTapKey, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

    if (NULL == pTapKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    if (0 == ((_TAP_Context *)(pTapKey->pTapContext))->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, ((_TAP_Context *)(pTapKey->pTapContext))->moduleHandle,
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_SMP_deleteObject((_TAP_Context *)(pTapKey->pTapContext),
            &pTapKey->tokenHandle,
            (TAP_ObjectHandle *)(&pTapKey->keyHandle));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to unload key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pTapKey->keyHandle = 0;

    /* If we dont have global token deferred, and this key isnt marked for token deferment,
     * and we have a valid token handle, uninitialize the token */
    if ( (0 == globalDeferredTokenUnload) && (FALSE == (pTapKey)->deferredTokenUnload) &&
         (0 != (pTapKey)->tokenHandle) )
    {
        status =  TAP_SMP_uninitToken((pTapKey)->pTapContext,
                &(pTapKey)->tokenHandle, NULL);
        if (OK != status)
        {
            DB_PRINT("%s.%d INFO: Context already uninitialized, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }
    }

    pTapKey->tokenHandle = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_unloadSmpKey(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle, TAP_KeyHandle keyHandle)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pTapCtx)
        goto exit;

    status = ERR_INVALID_ARG;
    if (0 == keyHandle)
        goto exit;

    status = ERR_TAP_INVALID_CONTEXT;
    if (0 == ((_TAP_Context *) pTapCtx)->moduleHandle)
    {
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, ((_TAP_Context *) pTapCtx)->moduleHandle,
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_SMP_deleteObject((_TAP_Context *) pTapCtx, &tokenHandle, (TAP_ObjectHandle *) &keyHandle);
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to unload key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_uninitToken(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pTapCtx)
        goto exit;

    status = ERR_TAP_INVALID_CONTEXT;
    if (0 == ((_TAP_Context *) pTapCtx)->moduleHandle)
    {
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, ((_TAP_Context *) pTapCtx)->moduleHandle,
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (0 != tokenHandle)
    {
        status =  TAP_SMP_uninitToken(pTapCtx, &tokenHandle, NULL);
        if (OK != status)
        {
            DB_PRINT("%s.%d INFO: Context already uninitialized, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

void TAP_setGlobalDeferredTokenUnload(ubyte defer)
{
    globalDeferredTokenUnload = defer;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_generateObject(TAP_Context *pTapContext,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_AttributeList *pObjectAttributes,
                           TAP_CredentialList *pObjectCredentials,
                           TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                           TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_initObject(TAP_Context *pTapContext,
                       TAP_EntityCredentialList *pUsageCredentials,
                       TAP_ObjectInfo *pObjectInfo,
                       TAP_AttributeList *pObjectAttributes,
                       TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                       TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_serializeObject(TAP_OBJECT_TYPE objectType, void *pObject,
                            TAP_BLOB_FORMAT format, TAP_BLOB_ENCODING encoding,
                            TAP_Buffer *pSerializedObjectBuffer, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = NULL;
    ubyte4 serializedSize = 0;
    ubyte4 offset = 0;
    ubyte4 attributesLen = 0;
    TAP_AttributeList *pAttributes = NULL;
    ubyte4 blobLen = 0;
    ubyte *pObjectBuffer = NULL;
    ubyte4 objectBufferLen = 0;

    /* check input */
    if ((NULL == pObject) || (NULL == pSerializedObjectBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (objectType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            pContext = (_TAP_Context *)(((TAP_Object *)pObject)->pTapContext);
            pAttributes = (TAP_AttributeList *)&(((TAP_Object *)pObject)->providerObjectData.objectInfo.objectAttributes);
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            pContext = (_TAP_Context *)(((TAP_StorageObject *)pObject)->pTapContext);
            pAttributes = (TAP_AttributeList *)&(((TAP_StorageObject *)pObject)->providerObjectInfo.objectAttributes);
            break;
        case TAP_OBJECT_TYPE_KEY:
        default:
            break;
    }

    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    if (TAP_OBJECT_TYPE_OBJECT == objectType)
    {
        /* Get the serialized blob from the SMP */
        if (NULL != ((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.pBuffer)
        {
           status = DIGI_FREE((void **)&(((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.pBuffer));
            ((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.bufferLen = 0;
        }
        status = TAP_SMP_serializeObject(pContext, TAP_OBJECT_TYPE_OBJECT, pObject,
                                         format, encoding,
                                         &(((TAP_Object *)pObject)->providerObjectData.objectBlob), pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get serialized object blob from provider. status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
        blobLen = sizeof(TAP_Blob) - sizeof(ubyte *) +
                  ((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.bufferLen;

    }

    if (0 < pAttributes->listLen)
    {
        status = TAP_UTILS_getAttributeListLen(pAttributes, &attributesLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get size of objectAttributes. status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    serializedSize = serializedSize + 1
                     + sizeof(TAP_ObjectInfo)
                     + attributesLen
                     + blobLen;

    /* Allocate memory for object buffer */
    status = DIGI_CALLOC((void **)(&pObjectBuffer), 1, serializedSize);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for object buffer buffer. status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Serialized object is in format:
         TAP_OBJECT_TYPE_KEY:    1 byte
         TAP_BLOB_FORMAT:        1 byte
         serialized object blob: n bytes
     */
    offset = 2;
    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Object, TAP_SD_IN,
            (void *)(pObject), sizeof(TAP_Object),
            pObjectBuffer, serializedSize, &offset);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to serialize TAP_Object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pObjectBuffer[0] = TAP_OBJECT_TYPE_OBJECT;
    pObjectBuffer[1] = format;
    switch (format)
    {
        case TAP_BLOB_FORMAT_MOCANA:
            objectBufferLen = offset;
            break;
        case TAP_BLOB_FORMAT_DER:
            /* TODO: DER encode key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        case TAP_BLOB_FORMAT_PEM:
            /* TODO: PEM encode key blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        default:
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
    }

    pSerializedObjectBuffer->pBuffer = pObjectBuffer;
    pSerializedObjectBuffer->bufferLen = objectBufferLen;
    pObjectBuffer = NULL;

exit:

    /* Free module object blob */
    if ((OK != status) && (NULL != pObjectBuffer))
    {
        exitStatus = DIGI_FREE((void **)&pObjectBuffer);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "failed to free memory for serialized object blob, status %d = %s\n",
                    exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }


        if (TAP_OBJECT_TYPE_OBJECT == objectType)
        {
            exitStatus = TAP_UTILS_freeBlob(&(((TAP_Object *)pObject)->providerObjectData.objectBlob));
            if (OK != exitStatus)
            {
                status = exitStatus;
                DB_PRINT(__func__, __LINE__, "failed to free memory for provider object blob, status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
            }
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_deserializeObject(TAP_Buffer *pSerializedObjectBuffer,
                              TAP_OBJECT_TYPE *pObjectType, void **ppObject,
                              TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    ubyte4 offset = 0;
    TAP_OBJECT_TYPE objType = TAP_OBJECT_TYPE_UNDEFINED;
    void *pObject = NULL;
    ubyte4 objSize = 0;
    ubyte *pDecodedBlob = NULL;
    ubyte4 decodedBlobLen = 0;

    if ((NULL == pSerializedObjectBuffer) || (NULL == pObjectType) || (NULL == ppObject))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Serialized object is in format:
         TAP_OBJECT_TYPE:        1 byte
         TAP_BLOB_FORMAT:        1 byte
         TAP_BLOB_ENCODING:      1 byte
         serialized object blob: n bytes
     */

    objType = pSerializedObjectBuffer->pBuffer[0];
    switch (objType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            objSize = sizeof(TAP_Object);
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            objSize = sizeof(TAP_StorageObject);
            break;
        case TAP_OBJECT_TYPE_KEY:
            DB_PRINT(__func__, __LINE__, "TAP_deserializeKey should be used to deserialized key blobs!\n");
        default:
            status = ERR_TAP_INVALID_OBJECT_TYPE;
            DB_PRINT(__func__, __LINE__, "Invalid blob - not a serialized object blob! status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }

    switch(pSerializedObjectBuffer->pBuffer[1])
    {
        case TAP_BLOB_FORMAT_MOCANA:
            pDecodedBlob = pSerializedObjectBuffer->pBuffer;
            decodedBlobLen = pSerializedObjectBuffer->bufferLen;
            break;
        case TAP_BLOB_FORMAT_DER:
            /* TODO: decode DER object blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        case TAP_BLOB_FORMAT_PEM:
            /* TODO: decode PEM object blob */
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
        default:
            status = ERR_TAP_INVALID_BLOB_FORMAT;
            goto exit;
            break;
    }

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)&pObject, 1, objSize);
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new object! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* deserialize TAP_Object */
    offset = 2;
    if (TAP_OBJECT_TYPE_OBJECT == objType)
    {
        status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_Object, TAP_SD_OUT,
                    pDecodedBlob, decodedBlobLen,
                    (void *)(pObject), sizeof(TAP_Object), &offset);
    }
    else
    {
        status = TAP_SERIALIZE_serialize(&TAP_SHADOW_TAP_StorageObject, TAP_SD_OUT,
                    pDecodedBlob, decodedBlobLen,
                    (void *)(pObject), sizeof(TAP_StorageObject), &offset);
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to deserialize object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* At this point we have the serialized module object blob that must be loaded. */
    *pObjectType = objType;
    *ppObject = pObject;

exit:

    /* On error, free object */
    if ((OK != status) && (NULL != pObject))
    {
        exitStatus = DIGI_FREE((void **)&pObject);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "failed to free object, status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
            goto exit;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_associateCredentialWithObject(TAP_OBJECT_TYPE objType, void *pObject,
                                          TAP_EntityCredentialList *pObjectCredentials,
                                          TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;

    if ((NULL == pObject) || (NULL == pObjectCredentials))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 < pObjectCredentials->numCredentials) &&
        (NULL == pObjectCredentials->pEntityCredentials))
    {
        status = ERR_TAP_INVALID_INPUT;
        DB_PRINT("%s.%d Credential list is NULL when should have %d credentials, status %d = %s\n", __FUNCTION__,
                __LINE__, pObjectCredentials->numCredentials, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */

    switch(objType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            pContext = ( _TAP_Context *)(((TAP_Object *)pObject)->pTapContext);
            smpCmdReq.reqParams.associateObjectCredentials.tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
            smpCmdReq.reqParams.associateObjectCredentials.objectHandle = ((TAP_Object *)pObject)->objectHandle;
            break;
        case TAP_OBJECT_TYPE_KEY:
            pContext = ( _TAP_Context *)(((TAP_Key *)pObject)->pTapContext);
            smpCmdReq.reqParams.associateObjectCredentials.tokenHandle = ((TAP_Key *)pObject)->tokenHandle;
            smpCmdReq.reqParams.associateObjectCredentials.objectHandle = (TAP_ObjectHandle)(((TAP_Key *)pObject)->keyHandle);
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            pContext = ( _TAP_Context *)(((TAP_StorageObject *)pObject)->pTapContext);
            smpCmdReq.reqParams.associateObjectCredentials.tokenHandle = ((TAP_StorageObject *)pObject)->tokenHandle;
            smpCmdReq.reqParams.associateObjectCredentials.objectHandle = ((TAP_StorageObject *)pObject)->objectHandle;
            break;
        default:
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, objType, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    smpCmdReq.cmdCode = SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS;
    smpCmdReq.reqParams.associateObjectCredentials.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.associateObjectCredentials.pCredentialsList = pObjectCredentials;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to associate credentials with object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}


/*------------------------------------------------------------------*/

 MSTATUS TAP_loadObject(TAP_Context *pTapContext,
                        TAP_EntityCredentialList *pUsageCredentials,
                        TAP_OBJECT_TYPE objectType, void *pObject,
                        TAP_CredentialList *pObjectCredentials,
                        TAP_AttributeList *pAttributes,
                        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = NULL;
    TAP_Blob *pBlob = NULL;
    TAP_AttributeList *pObjAttributes = NULL;
    TAP_AttributeList *pNewAttributes = NULL;
    TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_ObjectId objectId = 0;
    TAP_ObjectId objectIdOut = 0;
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;

    if ((NULL == pTapContext) || (NULL == pObject))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (objectType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            pContext = ( _TAP_Context *)(((TAP_Object *)pObject)->pTapContext);
            /* Check if object has been deserialized */
            if ((((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.bufferLen < 1)
             || (NULL == ((TAP_Object *)pObject)->providerObjectData.objectBlob.blob.pBuffer))
            {
                DB_PRINT(__func__, __LINE__, "Object cannot be loaded! status %d = %s\n",
                            status, MERROR_lookUpErrorCode(status));
                status = ERR_TAP_INVALID_INPUT;
                goto exit;
            }
            tokenId = ((TAP_Object *)pObject)->providerObjectData.objectInfo.tokenId;
            objectId = ((TAP_Object *)pObject)->providerObjectData.objectInfo.objectId;
            tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
            pBlob = &(((TAP_Object *)pObject)->providerObjectData.objectBlob);
            pObjAttributes = &(((TAP_Object *)pObject)->providerObjectData.objectInfo.objectAttributes);
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            pContext = ( _TAP_Context *)(((TAP_StorageObject *)pObject)->pTapContext);
            tokenId = ((TAP_StorageObject *)pObject)->providerObjectInfo.tokenId;
            objectId = ((TAP_StorageObject *)pObject)->providerObjectInfo.objectId;
            tokenHandle = ((TAP_StorageObject *)pObject)->tokenHandle;
            pObjAttributes = &(((TAP_StorageObject *)pObject)->providerObjectInfo.objectAttributes);
            break;
        case TAP_OBJECT_TYPE_KEY:
        default:
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    if (NULL != pAttributes)
    {
        numAttributes += pAttributes->listLen;
    }
    if (NULL != pObjAttributes)
    {
        numAttributes += pObjAttributes->listLen;
    }
    if (NULL != pObjectCredentials)
    {
        if ((0 < pObjectCredentials->numCredentials) && (NULL == pObjectCredentials->pCredentialList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Load token, if not already loaded */
    if (0 == tokenHandle)
    {
        status = TAP_SMP_initToken((TAP_Context *)pContext, &tokenId, NULL,
                                   pUsageCredentials, &tokenHandle, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Combine pAttributes, pObjAttributes, and pObjectCredentials into a single list */
    if (0 < numAttributes)
    {
        /* Set the new attributes, including information from both pAttributes and pObjAttributes */
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pAttributes)
        {
            for (j=0; j < pAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        if (NULL != pObjAttributes)
        {
            for (j=0; j < pObjAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pObjAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pObjAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pObjAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        if (NULL != pObjectCredentials)
        {
            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pObjectCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        newAttributes.listLen = i;
        pNewAttributes = &newAttributes;
    }

    if (0 == objectId)
    {
        status = TAP_SMP_importObject(objectType, (const void *)pObject, &tokenHandle,
                                      pNewAttributes, pUsageCredentials,
                                      pBlob, pErrContext);
    }
    else
    {
        status = TAP_SMP_initObject(pTapContext, &tokenHandle,
                                    &objectId, pNewAttributes, pUsageCredentials,
                                    &objectHandle, &objectIdOut,
                                    pErrContext);
    }
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to load object! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    switch (objectType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            ((TAP_Object *)pObject)->tokenHandle = tokenHandle;
            ((TAP_Object *)pObject)->objectHandle = objectHandle;
            ((TAP_Object *)pObject)->providerObjectData.objectInfo.objectId = objectIdOut;
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            ((TAP_StorageObject *)pObject)->tokenHandle = tokenHandle;
            ((TAP_StorageObject *)pObject)->objectHandle = objectHandle;
            ((TAP_StorageObject *)pObject)->providerObjectInfo.objectId = objectIdOut;
            break;
        case TAP_OBJECT_TYPE_KEY:
        default:
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }

exit:

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_unloadObject(TAP_OBJECT_TYPE objectType, void *pObject, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    _TAP_Context *pContext = NULL;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;

    if (NULL == pObject)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (objectType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            pContext = ( _TAP_Context *)(((TAP_Object *)pObject)->pTapContext);
            tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
            objectHandle = ((TAP_Object *)pObject)->objectHandle;
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            pContext = ( _TAP_Context *)(((TAP_StorageObject *)pObject)->pTapContext);
            tokenHandle = ((TAP_StorageObject *)pObject)->tokenHandle;
            objectHandle = ((TAP_StorageObject *)pObject)->objectHandle;
            break;
        case TAP_OBJECT_TYPE_KEY:
            DB_PRINT("%s.%d Use TAP_unloadKey to unload key objects.\n", __FUNCTION__, __LINE__);
        default:
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (NULL == pContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    status = TAP_SMP_uninitObject(pContext, tokenHandle, objectHandle);
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to unload object! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_OBJECT_TYPE_OBJECT == objectType)
        ((TAP_Object *)pObject)->objectHandle = 0;
    else
        ((TAP_StorageObject *)pObject)->objectHandle = 0;

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_freeObject(TAP_OBJECT_TYPE objectType, void **ppObject)
{
    MSTATUS status = OK;

    if ((NULL == ppObject) || (NULL == *ppObject))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (objectType)
    {
        case TAP_OBJECT_TYPE_OBJECT:
            status = TAP_SERIALIZE_freeDeserializedStructure(
                    &TAP_SHADOW_TAP_Object, (ubyte *)*ppObject, sizeof(TAP_Object));
            break;
        case TAP_OBJECT_TYPE_STORAGE:
            status = TAP_SERIALIZE_freeDeserializedStructure(
                    &TAP_SHADOW_TAP_StorageObject, (ubyte *)*ppObject, sizeof(TAP_StorageObject));
            break;
        case TAP_OBJECT_TYPE_KEY:
            DB_PRINT("%s.%d Use TAP_freeKey to free key objects.\n", __FUNCTION__, __LINE__);
        default:
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                    __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
            goto exit;
            break;
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free object structure, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    /* Now free the object */
    status = DIGI_FREE((void **)ppObject);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getQuote(TAP_Key *pTapKey,
                     TAP_EntityCredentialList *pUsageCredentials,
                     TAP_TRUSTED_DATA_TYPE dataType,
                     TAP_TrustedDataInfo *pDataInfo,
                     TAP_Buffer *pQualifyingData,
                     TAP_AttributeList *pAttributes,
                     TAP_Blob *pAttestationData,
                     TAP_Signature *pSignature,
                     TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_CAPABILITY_FUNCTIONALITY attestationCapability = TAP_CAPABILITY_REMOTE_ATTESTATION;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(attestationCapability), &attestationCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_AttributeList nullAttributes = {0};

    /* check input */
    if ((NULL == pTapKey) || (NULL == pDataInfo) || (NULL == pAttestationData) || (NULL == pSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);


    switch (pTapKey->keyData.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_DES:
        case TAP_KEY_ALGORITHM_TDES:
            break;
        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            goto exit;
            break;
    }

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        /* TODO: Do we want TAP_CAPABILITY_REMOTE_ATTESTATION or TAP_CAPABILITY_ATTESTATION_BASIC? */
        status = TAP_SMP_getTokenList(pTapKey->pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit1;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit1;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit1;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];
exit1:
        if (tokenList.entityIdList.pEntityIdList)
        {
            DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
        }
        if (OK > status)
        {
            goto exit;
        }
    }

    status = TAP_SMP_initToken(pTapKey->pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_SMP_GET_QUOTE;

    smpCmdReq.reqParams.getQuote.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getQuote.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.getQuote.objectHandle = (TAP_ObjectHandle)(pTapKey->keyHandle);
    smpCmdReq.reqParams.getQuote.type = dataType;
    smpCmdReq.reqParams.getQuote.pInfo = pDataInfo;
    smpCmdReq.reqParams.getQuote.pNonce = pQualifyingData;
    smpCmdReq.reqParams.getQuote.pReserved = pAttributes ? pAttributes :
        (TAP_AttributeList *)&nullAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get quote data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyTapSignature(pSignature, smpCmdRsp.rspParams.getQuote.pQuoteSignature);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy quote signature, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBlob(pAttestationData, &(smpCmdRsp.rspParams.getQuote.quoteData));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy quote data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapKey->pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_sealWithTrustedData(TAP_Context *pTapContext,
                                TAP_EntityCredentialList *pUsageCredentials,
                                TAP_OBJECT_TYPE objectType, void *pObject,
                                TAP_CredentialList *pObjectCredentials,
                                TAP_SealAttributes *pSealAttributes, TAP_Buffer *pDataToSeal,
                                TAP_Buffer *pSealedData, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList *pNewAttributes = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;

    /* check input */

    if ((NULL == pTapContext) || (NULL == pDataToSeal) || (NULL == pSealedData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapContext);

    if (1 > pDataToSeal->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* If have object, use tokenHandle from object */
    if (NULL != pObject)
    {
        switch (objectType)
        {
            case TAP_OBJECT_TYPE_OBJECT:
                tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
                break;
            case TAP_OBJECT_TYPE_STORAGE:
                tokenHandle = ((TAP_StorageObject *)pObject)->tokenHandle;
                break;
            case TAP_OBJECT_TYPE_KEY:
                tokenHandle = ((TAP_Key *)pObject)->tokenHandle;
                break;
            default:
                status = ERR_TAP_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                        __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
                goto exit;
                break;
        }
    }

    /* If don't have a tokenHandle in the object, load a token */
    if (0 == tokenHandle)
    {
        /* If didn't have a tokenId in credentials, find one that works */
        if (0 == tokenId)
        {
            status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                          &tokenAttributes, &tokenList, pErrContext);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit1;
            }

            if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
            {
                DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
                status = ERR_TAP_INVALID_ENTITY_TYPE;
                goto exit1;
            }

            if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
            {
                DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
                status = ERR_TAP_NO_TOKEN_AVAILABLE;
                goto exit1;
            }

            tokenId = tokenList.entityIdList.pEntityIdList[0];
exit1:
            if (tokenList.entityIdList.pEntityIdList)
            {
                DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
            }

            if (OK > status)
            {
                goto exit;
            }
        }

        status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                                   pUsageCredentials, &tokenHandle, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pSealAttributes)
    {
        if ((0 < pSealAttributes->listLen)
         && (NULL == pSealAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pSealAttributes->listLen;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    if (NULL != pObjectCredentials)
    {
        if ((0 < pObjectCredentials->numCredentials) && (NULL == pObjectCredentials->pCredentialList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredential and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pSealAttributes)
        {
            for (i=0; i<pSealAttributes->listLen; i++)
            {
                newAttributes.pAttributeList[i].type = pSealAttributes->pAttributeList[i].type;
                newAttributes.pAttributeList[i].length = pSealAttributes->pAttributeList[i].length;
                newAttributes.pAttributeList[i].pStructOfType = pSealAttributes->pAttributeList[i].pStructOfType;
            }
        }
        if (NULL != pObjectCredentials)
        {
            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL;
            newAttributes.pAttributeList[i].length = sizeof(TAP_Credential);
            newAttributes.pAttributeList[i].pStructOfType = (void *)&(pObjectCredentials->pCredentialList[0]);
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_SEAL_WITH_TRUSTED_DATA;
    smpCmdReq.reqParams.sealWithTrustedData.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.sealWithTrustedData.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.sealWithTrustedData.pRequestTemplate = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.sealWithTrustedData.pDataToSeal = pDataToSeal;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pSealedData, &(smpCmdRsp.rspParams.sealWithTrustedData.dataOut));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_unsealWithTrustedData(TAP_Context *pTapContext,
                                  TAP_EntityCredentialList *pUsageCredentials,
                                  TAP_OBJECT_TYPE objectType, void *pObject,
                                  TAP_SealAttributes *pUnsealAttributes, TAP_Buffer *pSealedData,
                                  TAP_Buffer *pUnsealedData, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_AttributeList *pNewAttributes = NULL;
    volatile TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_STORAGE_WITH_TRUSTED_DATA;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;

    /* check input */
    if ((NULL == pTapContext) || (NULL == pSealedData) || (NULL == pUnsealedData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapContext);

    if (1 > pSealedData->bufferLen)
    {
        status = ERR_TAP_INVALID_INPUT;
        goto exit;
    }

    /* If have object, use tokenHandle from object */
    if (NULL != pObject)
    {
        switch (objectType)
        {
            case TAP_OBJECT_TYPE_OBJECT:
                tokenHandle = ((TAP_Object *)pObject)->tokenHandle;
                break;
            case TAP_OBJECT_TYPE_STORAGE:
                tokenHandle = ((TAP_StorageObject *)pObject)->tokenHandle;
                break;
            case TAP_OBJECT_TYPE_KEY:
                tokenHandle = ((TAP_Key *)pObject)->tokenHandle;
                break;
            default:
                status = ERR_TAP_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid object type %d, status %d = %s\n", __FUNCTION__,
                        __LINE__, objectType, status, MERROR_lookUpErrorCode(status));
                goto exit;
                break;
        }
    }

    /* If don't have a tokenHandle in the object, load a token */
    if (0 == tokenHandle)
    {
        /* If didn't have a tokenId in credentials, find one that works */
        if (0 == tokenId)
        {
            status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                          &tokenAttributes, &tokenList, pErrContext);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
            {
                DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
                status = ERR_TAP_INVALID_ENTITY_TYPE;
                goto exit;
            }

            if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
            {
                DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
                status = ERR_TAP_NO_TOKEN_AVAILABLE;
                goto exit;
            }

            tokenId = tokenList.entityIdList.pEntityIdList[0];
            DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
        }

        status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                                   pUsageCredentials, &tokenHandle, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pUnsealAttributes)
    {
        if ((0 < pUnsealAttributes->listLen)
         && (NULL == pUnsealAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pUnsealAttributes->listLen;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredential and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUnsealAttributes)
        {
            for (i=0; i<pUnsealAttributes->listLen; i++)
            {
                newAttributes.pAttributeList[i].type = pUnsealAttributes->pAttributeList[i].type;
                newAttributes.pAttributeList[i].length = pUnsealAttributes->pAttributeList[i].length;
                newAttributes.pAttributeList[i].pStructOfType = pUnsealAttributes->pAttributeList[i].pStructOfType;
            }
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_UNSEAL_WITH_TRUSTED_DATA;

    smpCmdReq.reqParams.unsealWithTrustedData.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.unsealWithTrustedData.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.unsealWithTrustedData.pRequestTemplate = pNewAttributes ?
        pNewAttributes :
        (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.unsealWithTrustedData.pDataToUnseal = pSealedData;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pUnsealedData, &(smpCmdRsp.rspParams.unsealWithTrustedData.dataOut));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

 MSTATUS TAP_allocatePolicyStorage(TAP_Context *pTapContext,
                                   TAP_EntityCredentialList *pUsageCredentials,
                                   TAP_StorageInfo *pStorageInfo,
                                   TAP_ObjectAttributes *pAttributes,
                                   TAP_CredentialList *pStorageCredentials,
                                   TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_AttributeList *pNewAttributes = NULL;
    TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 6;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_TokenId tokenId = 0;
    TAP_ObjectId objectId = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_CAPABILITY_FUNCTIONALITY storageCapability = TAP_CAPABILITY_STORAGE_WITH_POLICY;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(storageCapability), &storageCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };

    /* check input */

    if ((NULL == pTapContext) || (NULL == pStorageInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    if (NULL != pStorageInfo->pAttributes)
    {
        if ((0 < pStorageInfo->pAttributes->listLen)
         && (NULL == pStorageInfo->pAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pStorageInfo->pAttributes->listLen;
    }
    if (NULL != pAttributes)
    {
        if ((0 < pAttributes->listLen)  && (NULL == pAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pAttributes->listLen;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    if (NULL != pStorageCredentials)
    {
        if ((0 < pStorageCredentials->numCredentials) && (NULL == pStorageCredentials->pCredentialList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    if (0 != pStorageInfo->authContext)
    {
        if ((TAP_AUTH_CONTEXT_STORAGE != pStorageInfo->authContext) && 
                (TAP_AUTH_CONTEXT_PLATFORM != pStorageInfo->authContext))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredential and pAttributes */
    status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    i = 0;
    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_INDEX;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->index);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_SIZE;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->size);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_TYPE;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->storageType);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_PERMISSION_OWNER;
    newAttributes.pAttributeList[i].length = sizeof(TAP_PERMISSION_BITMASK);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->ownerPermission);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_PERMISSION;
    newAttributes.pAttributeList[i].length = sizeof(TAP_PERMISSION_BITMASK);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->publicPermission);
    i++;

    if (0 != pStorageInfo->authContext)
    {
        newAttributes.pAttributeList[i].type = TAP_ATTR_AUTH_CONTEXT;
        newAttributes.pAttributeList[i].length = sizeof(TAP_AUTH_CONTEXT_PROPERTY);
        newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->authContext);
        i++;
    }

    if (NULL != pStorageInfo->pAttributes)
    {
        for (j=0; (j < pStorageInfo->pAttributes->listLen) && (i < numAttributes); j++, i++)
        {
            newAttributes.pAttributeList[i].type = pStorageInfo->pAttributes->pAttributeList[j].type;
            newAttributes.pAttributeList[i].length = pStorageInfo->pAttributes->pAttributeList[j].length;
            newAttributes.pAttributeList[i].pStructOfType = pStorageInfo->pAttributes->pAttributeList[j].pStructOfType;
        }
    }
    if (NULL != pAttributes)
    {
        for (j=0; (j < pAttributes->listLen) && (i < numAttributes); j++, i++)
        {
            newAttributes.pAttributeList[i].type = pAttributes->pAttributeList[j].type;
            newAttributes.pAttributeList[i].length = pAttributes->pAttributeList[j].length;
            newAttributes.pAttributeList[i].pStructOfType = pAttributes->pAttributeList[j].pStructOfType;
        }
    }
    if (NULL != pStorageCredentials)
    {
        newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
        newAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
        newAttributes.pAttributeList[i].pStructOfType = (void *)pStorageCredentials;
        i++;
    }
    if (NULL != pUsageCredentials)
    {
        status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                    NULL, pErrContext);

        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
        newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
        newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
        i++;
    }

    newAttributes.listLen = i;
    pNewAttributes = &newAttributes;

    /* If didn't have a tokenId in credentials, find one that can be used to allocate policy storage. */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* First load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Now create the storage object */
    status = TAP_SMP_createObject(pContext, &tokenHandle, pNewAttributes, &objectId, &objectHandle);
    if ((OK != status) && (ERR_TAP_NV_INDEX_EXISTS != status))
    {
        DB_PRINT("%s.%d Failed to create object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (ERR_TAP_NV_INDEX_EXISTS == status)
        objectId = pStorageInfo->index;
    else if (OK == status)
    {
        /* Uninit the object, will no longer need it */
        status = TAP_SMP_uninitObject(pContext, tokenHandle, objectHandle);
        if (OK != exitStatus)
        {
            DB_PRINT(__func__, __LINE__, "Failed to uninitialize NV object! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

exit:

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_freePolicyStorage(TAP_Context *pTapContext,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_StorageInfo *pStorageInfo,
                              TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = NULL;
    TAP_TokenHandle tokenHandle = 0;
    TAP_AttributeList *pNewAttributes = NULL;
    TAP_AttributeList newAttributes = { 0, };
    ubyte4 numAttributes = 6;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_TokenId tokenId = 0;
    TAP_ObjectId objectId = 0;
    static TAP_CAPABILITY_FUNCTIONALITY storageCapability = TAP_CAPABILITY_STORAGE_WITH_POLICY;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(storageCapability), &storageCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_ObjectHandle objectHandle = 0;

    /* check input */
    if ((NULL == pTapContext) || (NULL == pStorageInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    if (NULL != pUsageCredentials)
    {
        status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                    NULL, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pStorageInfo->pAttributes)
    {
        if ((0 < pStorageInfo->pAttributes->listLen)
         && (NULL == pStorageInfo->pAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pStorageInfo->pAttributes->listLen;
    }
    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }
    /* Set the new attributes, including information from both pCredential and pAttributes */
    status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    i = 0;
    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_INDEX;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->index);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_SIZE;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->size);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_STORAGE_TYPE;
    newAttributes.pAttributeList[i].length = sizeof(ubyte4);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->storageType);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_PERMISSION_OWNER;
    newAttributes.pAttributeList[i].length = sizeof(TAP_PERMISSION_BITMASK);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->ownerPermission);
    i++;

    newAttributes.pAttributeList[i].type = TAP_ATTR_PERMISSION;
    newAttributes.pAttributeList[i].length = sizeof(TAP_PERMISSION_BITMASK);
    newAttributes.pAttributeList[i].pStructOfType = (void *)&(pStorageInfo->publicPermission);
    i++;

    if (NULL != pStorageInfo->pAttributes)
    {
        for (j=0; (j < pStorageInfo->pAttributes->listLen) && (i < numAttributes); j++, i++)
        {
            newAttributes.pAttributeList[i].type = pStorageInfo->pAttributes->pAttributeList[j].type;
            newAttributes.pAttributeList[i].length = pStorageInfo->pAttributes->pAttributeList[j].length;
            newAttributes.pAttributeList[i].pStructOfType = pStorageInfo->pAttributes->pAttributeList[j].pStructOfType;
          
            
            /* If we find the token type or token id then make note of it */
            if (TAP_ATTR_TOKEN_TYPE == newAttributes.pAttributeList[i].type)
            {
                if ((sizeof(ubyte4) != newAttributes.pAttributeList[i].length) || (NULL == newAttributes.pAttributeList[i].pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid storage structure length %d, "
                            "pStructOfType = %p\n",
                            __FUNCTION__, __LINE__, newAttributes.pAttributeList[i].length,
                            newAttributes.pAttributeList[i].pStructOfType);
                    goto exit;
                }
                
                tokenId = (TAP_TokenId) (*((ubyte4 *)(newAttributes.pAttributeList[i].pStructOfType)));
            }
        }
    }
    if (NULL != pUsageCredentials)
    {
        status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                    NULL, pErrContext);

        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
        newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
        newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
        i++;
    }

    newAttributes.listLen = i;
    pNewAttributes = &newAttributes;

    /* If we didn't have a tokenId in the attributes, find one that can be used to allocate policy storage. */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* First load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    objectId = pStorageInfo->index;

    /* Init object to get an handle */
    status = TAP_SMP_initObject(pTapContext, &tokenHandle,
            &objectId, pNewAttributes, pUsageCredentials,
            &objectHandle, NULL, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get handle to policy storage object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
    }

    /* Delete object */
    status = TAP_SMP_deleteObject_usingAuthContext(pContext,
                                 &tokenHandle, &objectHandle,
                                 pStorageInfo->authContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to free policy storage, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }


    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getPolicyStorageList(TAP_Context *pTapContext,
                                 TAP_EntityCredentialList *pUsageCredentials,
                                 TAP_PolicyStorageAttributes *pAttributes,
                                 TAP_ObjectInfoList *pObjectInfoList,
                                 TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    ubyte4 i = 0;
    TAP_CAPABILITY_FUNCTIONALITY storageCapability = TAP_CAPABILITY_STORAGE_WITH_POLICY;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
        sizeof(storageCapability), &storageCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_EntityList entityList = {0 };

    /* check input */
    if ((NULL == pTapContext) || (NULL == pObjectInfoList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    pObjectInfoList->count = 0;
    pObjectInfoList->pInfo = NULL;

    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
            &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit1;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit1;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit1;
    }

    tokenId = tokenList.entityIdList.pEntityIdList[0];

exit1:
    if (tokenList.entityIdList.pEntityIdList != NULL)
    {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    if (OK > status)
    {
        goto exit;
    }

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
            pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Now create the storage object */
    status = TAP_SMP_getObjectList(pContext, &tokenHandle,
            (TAP_AttributeList *)pAttributes, &entityList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get object list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == entityList.entityIdList.numEntities) || (NULL == entityList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getObjectList returned empty list\n", __FUNCTION__, __LINE__);
        goto exit;
    }

    if (TAP_ENTITY_TYPE_OBJECT != entityList.entityType)
    {
        DB_PRINT("%s.%d getObjectList returned invalid entityType of %d, status %d = %s\n", __FUNCTION__,
                __LINE__, entityList.entityType, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Now create the ObjectInfoList out of the entityList */
    status = DIGI_CALLOC((void **)&(pObjectInfoList->pInfo), 1,
            entityList.entityIdList.numEntities * sizeof(TAP_ObjectInfo));
    if (OK != status)
    {
        DB_PRINT("%s.%d failed to allocate memory for pObjectInfoList, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    for (i = 0; i < entityList.entityIdList.numEntities; i++)
    {
        pObjectInfoList->pInfo[i].providerType = pContext->providerType;
        pObjectInfoList->pInfo[i].moduleId = pContext->module.moduleId;
        pObjectInfoList->pInfo[i].tokenId = tokenId;
        pObjectInfoList->pInfo[i].objectId = entityList.entityIdList.pEntityIdList[i];
        if (pAttributes)
            status = TAP_UTILS_copyAttributeList(&(pObjectInfoList->pInfo[i].objectAttributes),
                    pAttributes);
    }

    pObjectInfoList->count = entityList.entityIdList.numEntities;

exit:

    if (tokenList.entityIdList.pEntityIdList)
    {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    if (entityList.entityIdList.pEntityIdList)
    {
        DIGI_FREE((void **)&entityList.entityIdList.pEntityIdList);
    }

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getPolicyStorageDetails(TAP_Context *pTapContext,
                                    TAP_EntityCredentialList *pUsageCredentials,
                                    TAP_PolicyStorageAttributes *pAttributes,
                                    TAP_ObjectInfoList *pObjectInfoList,
                                    TAP_StorageObjectList *pDetailsList,
                                    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte4 numObjectsRequested = 0;
    TAP_ObjectInfoList fullObjectInfoList = { 0 };
    TAP_ObjectInfoList *pNewObjectInfoList = NULL;
    TAP_AttributeList currObjectAttributes = { 0 };
    TAP_CAPABILITY_FUNCTIONALITY storageCapability = TAP_CAPABILITY_STORAGE_WITH_POLICY;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
                sizeof(storageCapability), &storageCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };

    /* check input */
    if ((NULL == pTapContext) || (NULL == pDetailsList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    pDetailsList->count = 0;
    pDetailsList->pObjects = NULL;

    if ((NULL != pObjectInfoList) && (0 < pObjectInfoList->count))
    {
        if (NULL == pObjectInfoList->pInfo)
        {
            goto exit;
        }
        pNewObjectInfoList = pObjectInfoList;
        if (0 == tokenId)
            tokenId = pObjectInfoList->pInfo[0].tokenId;
    }
    else
    {
        /* Get the list of storage objects if none specified. */
        status = TAP_getPolicyStorageList(pTapContext, pUsageCredentials, pAttributes,
                                          &fullObjectInfoList, pErrContext);
        if (OK != status)
        {
            goto exit;
        }
        pNewObjectInfoList = &fullObjectInfoList;
    }
    numObjectsRequested = pNewObjectInfoList->count;

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Allocate enough memory for the results */
    if (0 < numObjectsRequested)
    {
        status = DIGI_CALLOC((void **)&(pDetailsList->pObjects),
                             numObjectsRequested, sizeof(TAP_StorageObject));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    /* Now get the storage object details */
    for (i=0; i < numObjectsRequested; i++)
    {
        status = TAP_SMP_getObjectInfo(pContext, &tokenHandle, NULL,
                                       (TAP_ObjectId *)&(pNewObjectInfoList->pInfo[i].objectId),
                                       (TAP_AttributeList *)pAttributes, &currObjectAttributes);
        if (OK != status)
        {
            goto exit;
        }

        /* Set fields */
        for (j=0; j<currObjectAttributes.listLen; j++)
        {
            pDetailsList->pObjects[i].providerObjectInfo.providerType = pContext->providerType;
            pDetailsList->pObjects[i].providerObjectInfo.moduleId = pContext->module.moduleId;
            pDetailsList->pObjects[i].providerObjectInfo.tokenId = tokenId;
            pDetailsList->pObjects[i].providerObjectInfo.objectId = (TAP_ObjectId)(pNewObjectInfoList->pInfo[i].objectId);

            status = TAP_UTILS_copyAttributeList(&(pDetailsList->pObjects[i].providerObjectInfo.objectAttributes),
                                                 &(pNewObjectInfoList->pInfo[i].objectAttributes));
            if (OK != status)
            {
                goto exit;
            }

            pDetailsList->pObjects[i].pTapContext = pTapContext;
            pDetailsList->pObjects[i].tokenHandle = tokenHandle;

            /* TODO : how do we set pDetailsList->pObjects[i].storageInfo.pAttributes ?
             Should we set pDetailsList->pObjects[i].storageInfo.pAttributes = currObjectAttributes.pAttributeList,
             even though it will contain redundant information (index, size, etc.)? */
            switch (currObjectAttributes.pAttributeList[j].type)
            {
                case TAP_ATTR_STORAGE_INDEX:
                    pDetailsList->pObjects[i].storageInfo.index = *(ubyte4 *)(currObjectAttributes.pAttributeList[j].pStructOfType);
                    break;
                case TAP_ATTR_STORAGE_SIZE:
                    pDetailsList->pObjects[i].storageInfo.size = *(ubyte4 *)(currObjectAttributes.pAttributeList[j].pStructOfType);
                    break;
                case TAP_ATTR_STORAGE_TYPE:
                    pDetailsList->pObjects[i].storageInfo.storageType = *(ubyte4 *)(currObjectAttributes.pAttributeList[j].pStructOfType);
                    break;
                case TAP_ATTR_PERMISSION:
                    pDetailsList->pObjects[i].storageInfo.publicPermission = *(TAP_PERMISSION_BITMASK *)(currObjectAttributes.pAttributeList[j].pStructOfType);
                    break;
                case TAP_ATTR_PERMISSION_OWNER:
                    pDetailsList->pObjects[i].storageInfo.ownerPermission = *(TAP_PERMISSION_BITMASK *)(currObjectAttributes.pAttributeList[j].pStructOfType);
                    break;
                default:
                    break;
            }
        }
        status = TAP_UTILS_freeAttributeList(&currObjectAttributes);
        if (OK != status)
        {
            goto exit;
        }
    }
    pDetailsList->count =  i;

exit:

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getPolicyStorage(TAP_Context *pTapContext,
                             TAP_EntityCredentialList *pUsageCredentials,
                             TAP_ObjectInfo *pObjectInfo,
                             TAP_OperationAttributes *pOpAttributes,
                             TAP_Buffer *pOutData,
                             TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectId objectIdOut = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;

    /* check input */
    if ((NULL == pTapContext) || (NULL == pObjectInfo) || (NULL == pOutData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen)
            && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pOpAttributes->listLen;
    }

    if( NULL != pObjectInfo->objectAttributes.pAttributeList && pObjectInfo->objectAttributes.listLen)
    {
        numAttributes += pObjectInfo->objectAttributes.listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredential and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                             numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }

        if( NULL != pObjectInfo->objectAttributes.pAttributeList && pObjectInfo->objectAttributes.listLen)
        {
            for (j=0; j < pObjectInfo->objectAttributes.listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pObjectInfo->objectAttributes.pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pObjectInfo->objectAttributes.pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pObjectInfo->objectAttributes.pAttributeList[j].pStructOfType;
                i++;
            }
        }

        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        newAttributes.listLen = numAttributes;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &(pObjectInfo->tokenId), pNewAttributes ?
            pNewAttributes : (TAP_AttributeList *)&newAttributes,
                               pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /*  Initialize the object to get the handle */
    status = TAP_SMP_initObject(pTapContext, &tokenHandle,
                                &(pObjectInfo->objectId), pNewAttributes,
                                pUsageCredentials,
                                &objectHandle, &objectIdOut,
                                pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize storage object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_POLICY_STORAGE;

    smpCmdReq.reqParams.getPolicyStorage.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getPolicyStorage.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.getPolicyStorage.objectHandle = objectHandle;
    smpCmdReq.reqParams.getPolicyStorage.pOpAttributes = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Release attribute memory, not needed anymore */
    shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to encrypt data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pOutData, &(smpCmdRsp.rspParams.getPolicyStorage.data));

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_setPolicyStorage(TAP_Context *pTapContext,
                             TAP_EntityCredentialList *pUsageCredentials,
                             TAP_ObjectInfo *pObjectInfo,
                             TAP_OperationAttributes *pOpAttributes,
                             TAP_Buffer *pInData,
                             TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    volatile TAP_AttributeList newAttributes = { 0, };
    TAP_AttributeList *pNewAttributes = NULL;
    ubyte4 numAttributes = 0;
    TAP_ObjectHandle objectHandle = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_ObjectId objectIdOut = 0;
    volatile TAP_PolicyStorageAttributes policyAttributes = {0};
    ubyte4 i = 0;
    ubyte4 j = 0;
    volatile TAP_EntityCredentialList nullCredentials = {0};

    /* check input */
    if ((NULL == pTapContext) || (NULL == pObjectInfo)
     || (NULL == pInData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    if (pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen)
                && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes += pOpAttributes->listLen;
    }

    if( NULL != pObjectInfo->objectAttributes.pAttributeList && pObjectInfo->objectAttributes.listLen)
    {
        numAttributes += pObjectInfo->objectAttributes.listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    /* Set the new attributes, including information from both pCredential and pAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                             numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }

        if( NULL != pObjectInfo->objectAttributes.pAttributeList && pObjectInfo->objectAttributes.listLen)
        {
            for (j=0; j < pObjectInfo->objectAttributes.listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pObjectInfo->objectAttributes.pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pObjectInfo->objectAttributes.pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pObjectInfo->objectAttributes.pAttributeList[j].pStructOfType;
                i++;
            }
        }

        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        newAttributes.listLen = numAttributes;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &(pObjectInfo->tokenId), pNewAttributes ?
            pNewAttributes : (TAP_AttributeList *)&newAttributes,
            pUsageCredentials ? pUsageCredentials : (TAP_EntityCredentialList *)&nullCredentials,
            &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /*  Initialize the object to get the handle */
    status = TAP_SMP_initObject(pTapContext, &tokenHandle,
                                &(pObjectInfo->objectId),
                                pNewAttributes,
                                pUsageCredentials,
                                &objectHandle, &objectIdOut,
                                pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize storage object, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */

    smpCmdReq.cmdCode = SMP_CC_SET_POLICY_STORAGE;

    smpCmdReq.reqParams.setPolicyStorage.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.setPolicyStorage.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.setPolicyStorage.objectHandle = objectHandle;
    smpCmdReq.reqParams.setPolicyStorage.pPolicyAttributes = (TAP_PolicyStorageAttributes*)&policyAttributes;
    smpCmdReq.reqParams.setPolicyStorage.pOpAttributes = pNewAttributes ?
        pNewAttributes : (TAP_AttributeList *)&newAttributes;
    smpCmdReq.reqParams.setPolicyStorage.pData = pInData;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to set policy storage data, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    /* Nothing to free if the command failed */
    if (OK == status)
        TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS TAP_getTrustedData(TAP_Context *pTapContext,
                           TAP_EntityCredentialList *pUsageCredentials,
                           TAP_TRUSTED_DATA_TYPE dataType,
                           TAP_TrustedDataInfo *pDataInfo,
                           TAP_Buffer *pTrustedData, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_TokenHandle tokenHandle = 0;
    TAP_TokenId tokenId = 0;
    TAP_CAPABILITY_FUNCTIONALITY capability = TAP_CAPABILITY_TRUSTED_DATA;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
        sizeof(capability), &capability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };

    /* check input */
    if ((NULL == pTapContext) || (NULL == pDataInfo)  || (NULL == pTrustedData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((0 < pDataInfo->attributes.listLen)
            && (NULL == pDataInfo->attributes.pAttributeList))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
            &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit;
    }

    tokenId = tokenList.entityIdList.pEntityIdList[0];
    DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
            pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_GET_TRUSTED_DATA;
    smpCmdReq.reqParams.getTrustedData.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getTrustedData.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.getTrustedData.trustedDataType = dataType;
    smpCmdReq.reqParams.getTrustedData.pTrustedDataInfo = pDataInfo;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
            &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get trusted data, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pTrustedData, &(smpCmdRsp.rspParams.getTrustedData.dataValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy trusted data buffer, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

MSTATUS TAP_updateTrustedData(TAP_Context *pTapContext,
                              TAP_EntityCredentialList *pUsageCredentials,
                              TAP_TRUSTED_DATA_TYPE dataType,
                              TAP_TrustedDataInfo *pDataInfo,
                              TAP_TRUSTED_DATA_OPERATION operation,
                              TAP_Buffer *pInData,
                              TAP_Buffer *pOutData, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    TAP_TokenHandle tokenHandle = 0;
    TAP_TokenId tokenId = 0;
    TAP_CAPABILITY_FUNCTIONALITY capability = TAP_CAPABILITY_TRUSTED_DATA;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_CATEGORY,
        sizeof(capability), &capability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };

    /* check input */
    if ((NULL == pTapContext) || (NULL == pDataInfo)  || (NULL == pInData)|| (NULL == pOutData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
            &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit;
    }

    tokenId = tokenList.entityIdList.pEntityIdList[0];
    DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
            pUsageCredentials, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_UPDATE_TRUSTED_DATA;
    smpCmdReq.reqParams.updateTrustedData.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.updateTrustedData.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.updateTrustedData.trustedDataType = dataType;
    smpCmdReq.reqParams.updateTrustedData.pTrustedDataInfo = pDataInfo;
    smpCmdReq.reqParams.updateTrustedData.trustedDataOp = operation;
    smpCmdReq.reqParams.updateTrustedData.pDataValue = pInData;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
            &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to update trusted data, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBuffer(pOutData, &(smpCmdRsp.rspParams.updateTrustedData.updatedDataValue));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy trusted data buffer, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS TAP_getCertificateRequestValidationAttrs(
        TAP_Key *pTapKey,
        TAP_CSRAttributes *pCSRattributes,
        TAP_Blob *pBlob,
        TAP_ErrorContext *pErrContext
)
{
    MSTATUS status = ERR_GENERAL;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_CSRAttributes nullAttr = {0};

    /*
     * Need key for module, token and object handles. Need blob for output.
     * TAP_CSRAttributes are optional.
     */
    if (!pTapKey || !pBlob)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    /*
     * These checks are redundant, since the SMP must check them anyway. If code size is a concern,
     * these checks can possibly be removed.
     */
    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    smpCmdReq.cmdCode = SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS;
    smpCmdReq.reqParams.getCertReqValAttrs.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getCertReqValAttrs.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.getCertReqValAttrs.objectHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.getCertReqValAttrs.pCSRattributes = pCSRattributes ?
        pCSRattributes : (TAP_CSRAttributes *)&nullAttr;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get cerificate request validation attributes, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBlob(pBlob, &(smpCmdRsp.rspParams.getCertReqValAttrs.blob));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy validation attributes blob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = OK;
exit:
    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

extern MSTATUS TAP_unwrapKeyValidatedSecret(
        TAP_Context *pTapContext,
        TAP_EntityCredentialList *pUsageCredentials,
        TAP_Key *pTapKey,
        TAP_Key *pRoTKey,
        TAP_Blob *pBlob,
        TAP_Buffer *pSecret,
        TAP_ErrorContext *pErrContext
)
{
    MSTATUS status = ERR_GENERAL;
    MSTATUS exitStatus;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttributes = {0};
    volatile TAP_EntityCredentialList nullUsageCredentials = {0};

    /*
     * We dont check for pRoTKey, since it may be optional for different SMP's.
     */
    if (!pTapKey || !pBlob || !pSecret)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    /*
     * These checks are redundant, since the SMP must check them anyway. If code size is a concern,
     * these checks can possibly be removed.
     */
    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle %d in context, status %d = %s\n", __FUNCTION__,
                __LINE__, pContext->moduleHandle, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                    &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId,
                (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttributes,
                pUsageCredentials ? pUsageCredentials :
                (TAP_EntityCredentialList *)&nullUsageCredentials,
                &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    smpCmdReq.cmdCode = SMP_CC_UNWRAP_KEY_VALIDATED_SECRET;
    smpCmdReq.reqParams.unwrapKeyValidatedSecret.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.unwrapKeyValidatedSecret.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.unwrapKeyValidatedSecret.objectHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.unwrapKeyValidatedSecret.rtKeyHandle = pRoTKey?pRoTKey->keyHandle:0;
    smpCmdReq.reqParams.unwrapKeyValidatedSecret.pBlob = pBlob;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get key validated secret, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (OK != (status = TAP_UTILS_copyBuffer(pSecret, &(smpCmdRsp.rspParams.unwrapKeyValidatedSecret.secret))))
    {
        DB_PRINT("%s.%d Failed to copy data buffer, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    status = OK;
exit:
    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

extern MSTATUS TAP_getRootOfTrustCertificate(
        TAP_Context *pTapContext,
        TAP_ObjectInfo *pRotInfo,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Blob *pCertificate,
        TAP_ErrorContext *pErrContext
)
{
    MSTATUS                         status = ERR_GENERAL;
    MSTATUS                         exitStatus = ERR_GENERAL;
    SMP_CmdReq                      smpCmdReq = { 0, };
    SMP_CmdRsp                      smpCmdRsp = { 0, };
    _TAP_Context *                  pContext = NULL;
    TAP_TokenHandle                 tokenHandle = 0;
    static TAP_CAPABILITY_FUNCTIONALITY    tokenCapability =
        TAP_CAPABILITY_CRYPTO_OP_ENCRYPT;
    static TAP_Attribute                   tokenAttribute =
    {
        TAP_ATTR_CAPABILITY_FUNCTIONALITY,
        sizeof(tokenCapability),
        &tokenCapability
    };
    TAP_TokenCapabilityAttributes   tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList                  tokenList = { 0 };

    if (!pTapContext || !pRotInfo || !pCertificate)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
            &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n",
                __FUNCTION__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n",
                __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit;
    }

    if ( (0 == tokenList.entityIdList.numEntities) ||
            (NULL == tokenList.entityIdList.pEntityIdList)
       )
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n",
                __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit;
    }
    pRotInfo->tokenId = tokenList.entityIdList.pEntityIdList[0];
    DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    /* Load the token to get the handle */
    status = TAP_SMP_initToken(pTapContext, &(pRotInfo->tokenId), NULL,
            NULL, &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapContext);
    smpCmdReq.cmdCode = SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE;
    smpCmdReq.reqParams.getRootOfTrustCertificate.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getRootOfTrustCertificate.type = type;
    smpCmdReq.reqParams.getRootOfTrustCertificate.objectId = pRotInfo->objectId;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get root of trust certificate, "
                "status %d = %s\n", __FUNCTION__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_UTILS_copyBlob(pCertificate,
            &(smpCmdRsp.rspParams.getRootOfTrustCertificate.certificate));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy certificate data, status %d = %s\n",
                __FUNCTION__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    if (NULL != tokenList.entityIdList.pEntityIdList)
    {
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (0 != tokenHandle)
    {
        exitStatus =  TAP_SMP_uninitToken(pTapContext, &tokenHandle, pErrContext);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to uninitialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

extern MSTATUS TAP_getRootOfTrustKey(
        TAP_Context *pTapContext,
        TAP_KeyInfo *pRotKeyInfo,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Key **ppRotKey,
        TAP_ErrorContext *pErrContext
)
{
    MSTATUS status = ERR_GENERAL;
    MSTATUS exitStatus = ERR_GENERAL;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };

    if (!pTapContext || !pRotKeyInfo || !ppRotKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId, NULL,
                               NULL, &tokenHandle, pErrContext);
    if (OK != status)
    {
            DB_PRINT("%s.%d Failed to initialize token, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
    }

    pContext = (_TAP_Context *)(pTapContext);
    smpCmdReq.cmdCode = SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.objectId = pRotKeyInfo->objectId;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.type = type;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get root of trust certificate, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /*
     * Create TAP Key
     */
    status = DIGI_CALLOC((void **)ppRotKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppRotKey)->pTapContext = pTapContext;
    (*ppRotKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppRotKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppRotKey)->providerObjectData.objectInfo.tokenId = tokenId;
    (*ppRotKey)->providerObjectData.objectInfo.objectId = pRotKeyInfo->objectId;

    (*ppRotKey)->keyHandle = smpCmdRsp.rspParams.getRootOfTrustKeyHandle.keyHandle;
    (*ppRotKey)->tokenHandle = tokenHandle;

    status = TAP_getPublicKey(*ppRotKey, &((*ppRotKey)->keyData.publicKey));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to get public key for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppRotKey)->keyData.keyAlgorithm = (*ppRotKey)->keyData.publicKey.keyAlgorithm;

    status = OK;
exit:
    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if ((OK != status) && (NULL != ppRotKey) && (NULL != *ppRotKey))
    {
        exitStatus = TAP_freeKey(ppRotKey);
        if (OK != exitStatus)
        {
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                    exitStatus, MERROR_lookUpErrorCode(status));
        }
    }

    return status;
}

extern MSTATUS TAP_getPrivateKeyBlob(TAP_Context *pTapContext, TAP_ObjectHandle keyHandle,
       TAP_TokenHandle tokenHandle, TAP_Buffer *pPrivKey)
{
    MSTATUS status = ERR_GENERAL;
    TAP_BLOB_FORMAT     format;
    TAP_BLOB_ENCODING   encoding;
    ubyte4 serializedSize = 0;
    ubyte *pKeyBuffer = NULL;
    SMP_CmdReq smpCmdReq = { 0 };
    SMP_CmdRsp smpCmdRsp = { 0 };
    _TAP_Context *pContext = NULL;

    if (!pTapContext ||  !pPrivKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapContext);

    smpCmdReq.cmdCode = SMP_CC_GET_PRIVATE_KEY_BLOB;
    smpCmdReq.reqParams.getPrivateKeyBlob.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getPrivateKeyBlob.objectHandle = keyHandle;
    smpCmdReq.reqParams.getPrivateKeyBlob.tokenHandle = tokenHandle;


    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get private key blob, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    serializedSize = smpCmdRsp.rspParams.getPrivateKeyBlob.privkeyBlob.blob.bufferLen;
    format = smpCmdRsp.rspParams.getPrivateKeyBlob.privkeyBlob.format ;
    encoding = smpCmdRsp.rspParams.getPrivateKeyBlob.privkeyBlob.encoding ;

    /* Allocate memory for key buffer */
    status = DIGI_CALLOC((void **)(&pKeyBuffer), 1, serializedSize+3);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate %u bytes of memory for key buffer. status %d = %s\n", __FUNCTION__,
                __LINE__, serializedSize, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Serialized key is in format:
         TAP_OBJECT_TYPE_KEY:   1 byte
         TAP_BLOB_FORMAT:       1 byte
         TAP_BLOB_ENCODING:     1 byte
         serialized key blob: n bytes
     */
    pKeyBuffer[0] = TAP_OBJECT_TYPE_PRIVATE_KEY;
    pKeyBuffer[1] = format;
    pKeyBuffer[2] = encoding;
    DIGI_MEMCPY((void * )&pKeyBuffer[3],
        (const void *) smpCmdRsp.rspParams.getPrivateKeyBlob.privkeyBlob.blob.pBuffer,
        serializedSize);

    pPrivKey->pBuffer = pKeyBuffer;
    pPrivKey->bufferLen = serializedSize+3;

exit:
    if ((OK != status) && (NULL != pKeyBuffer))
    {
         DIGI_FREE((void **)&pKeyBuffer);
    }
    /* Free response only if we had a successful return, else nothing to free in the response */
    if (OK == status)
        TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS TAP_getPublicKeyBlob(TAP_Context *pTapContext, TAP_ObjectHandle keyHandle,
       TAP_TokenHandle tokenHandle, TAP_Buffer *pPubKey)
{
    MSTATUS status = ERR_GENERAL;
    TAP_BLOB_FORMAT     format;
    TAP_BLOB_ENCODING   encoding;
    ubyte4 serializedSize = 0;
    ubyte *pKeyBuffer = NULL;
    SMP_CmdReq smpCmdReq = { 0 };
    SMP_CmdRsp smpCmdRsp = { 0 };
    _TAP_Context *pContext = NULL;

    if (!pTapContext ||  !pPubKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapContext);

    smpCmdReq.cmdCode = SMP_CC_GET_PUBLIC_KEY_BLOB;
    smpCmdReq.reqParams.getPublicKeyBlob.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getPublicKeyBlob.objectHandle = keyHandle;
    smpCmdReq.reqParams.getPublicKeyBlob.tokenHandle = tokenHandle;


    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get public key blob, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    serializedSize = smpCmdRsp.rspParams.getPublicKeyBlob.pubkeyBlob.blob.bufferLen;
    format = smpCmdRsp.rspParams.getPublicKeyBlob.pubkeyBlob.format ;
    encoding = smpCmdRsp.rspParams.getPublicKeyBlob.pubkeyBlob.encoding ;

    /* Allocate memory for key buffer */
    status = DIGI_CALLOC((void **)(&pKeyBuffer), 1, serializedSize+3);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate %u bytes of memory for key buffer. status %d = %s\n", __FUNCTION__,
                __LINE__, serializedSize, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Serialized key is in format:
         TAP_OBJECT_TYPE_KEY:   1 byte
         TAP_BLOB_FORMAT:       1 byte
         TAP_BLOB_ENCODING:     1 byte
         serialized key blob: n bytes
     */
    pKeyBuffer[0] = TAP_OBJECT_TYPE_PUBLIC_KEY;
    pKeyBuffer[1] = format;
    pKeyBuffer[2] = encoding;
    DIGI_MEMCPY((void * )&pKeyBuffer[3],
        (const void *) smpCmdRsp.rspParams.getPublicKeyBlob.pubkeyBlob.blob.pBuffer,
        serializedSize);

    pPubKey->pBuffer = pKeyBuffer;
    pPubKey->bufferLen = serializedSize+3;

exit:
    if ((OK != status) && (NULL != pKeyBuffer))
    {
         DIGI_FREE((void **)&pKeyBuffer);
    }
    /* Free response only if we had a successful return, else nothing to free in the response */
    if (OK == status)
        TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;

}

extern MSTATUS TAP_extractPrivateKeyBlob(
    TAP_Key *pTapKey,
    TAP_Buffer *pPrivBlob,
    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = ERR_GENERAL;
    TAP_Buffer blob = { 0 };

    if (NULL == pTapKey || NULL == pPrivBlob)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Key not properly initialized; have invalid context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_getPrivateKeyBlob(
        pTapKey->pTapContext,
        (TAP_ObjectHandle)(((TAP_Key *)pTapKey)->keyHandle),
        pTapKey->tokenHandle, &blob);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get private key blob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* First 3 bytes are TAP specific */
    status = TAP_UTILS_copyBufferOffset(pPrivBlob, &blob, 3);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy private key blob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **)&blob.pBuffer);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS TAP_extractPublicKeyBlob(
    TAP_Key *pTapKey,
    TAP_Buffer *pPubBlob,
    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = ERR_GENERAL;
    TAP_Buffer blob = { 0 };

    if (NULL == pTapKey || NULL == pPubBlob)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Key not properly initialized; have invalid context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TAP_getPublicKeyBlob(
        pTapKey->pTapContext,
        (TAP_ObjectHandle)(((TAP_Key *)pTapKey)->keyHandle),
        pTapKey->tokenHandle, &blob);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get public key blob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* First 3 bytes are TAP specific */
    status = TAP_UTILS_copyBufferOffset(pPubBlob, &blob, 3);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy public key blob, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    DIGI_FREE((void **)&blob.pBuffer);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS TAP_getRootOfTrustPublicKeyBlob(
        TAP_Context *pTapContext,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Buffer *pPubKey,
        TAP_ErrorContext *pErrContext
)
{
    MSTATUS status = ERR_GENERAL;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    TAP_ObjectHandle keyHandle = {0};
    TAP_TokenHandle tokenHandle = {0};

    if (!pTapContext || !pPubKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapContext);
    smpCmdReq.cmdCode = SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.objectId = objectId;
    smpCmdReq.reqParams.getRootOfTrustKeyHandle.type = type;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get root of trust certificate, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }


    keyHandle = smpCmdRsp.rspParams.getRootOfTrustKeyHandle.keyHandle;

    status = TAP_getPublicKeyBlob(pTapContext, keyHandle, tokenHandle,  pPubKey);
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to get public key for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = OK;
exit:
    if(keyHandle)
    {
        tokenHandle = 1 ; /* to satisfy the API */
        TAP_SMP_deleteObject(pContext, &tokenHandle, (TAP_ObjectHandle *)(&(keyHandle)));
    }

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    return status;
}

MSTATUS TAP_exportDuplicateKey(
    TAP_Key *pTapKey,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_AttributeList *pOpAttributes,
    TAP_Buffer *pInPeerPublic,
    TAP_Buffer *pOutDuplicate,
    TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0 };
    SMP_CmdRsp smpCmdRsp = { 0 };
    TAP_Blob pubkeyBlob = {0};
    SMP_duplicateKeyCmdParams *pDupCmdParams = NULL;
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList newAttributes = { 0 };
    TAP_AttributeList *pNewAttributes = NULL; 
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte *pPubBuffer = NULL;

    /* check input */
    if (NULL == pTapKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }
    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle in context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL != pInPeerPublic)
    {
        if (3 > pInPeerPublic->bufferLen || !pInPeerPublic->pBuffer)
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        pPubBuffer = pInPeerPublic->pBuffer ;
        if(pPubBuffer[0] != TAP_OBJECT_TYPE_PUBLIC_KEY)
        {
            status = ERR_TAP_INVALID_INPUT;
            DB_PRINT("%s.%d Public key is not in expected format %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    if (NULL != pOpAttributes)
    {
        if ((0 < pOpAttributes->listLen) && (NULL == pOpAttributes->pAttributeList))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes+=pOpAttributes->listLen;
    }

    if (NULL != pUsageCredentials)
    {
        if ((0 < pUsageCredentials->numCredentials) && (NULL == pUsageCredentials->pEntityCredentials))
        {
            status = ERR_TAP_INVALID_INPUT;
            goto exit;
        }
        numAttributes++;
    }

    if (0 < numAttributes)
    {
        /* Set the new attributes, including information from both pUsageCredentials and pOpAttributes */
        status = DIGI_CALLOC((void **)&(newAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        i = 0;
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapKey->pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }
        if (NULL != pOpAttributes)
        {
            for (j=0; j < pOpAttributes->listLen; j++)
            {
                newAttributes.pAttributeList[i].type = pOpAttributes->pAttributeList[j].type;
                newAttributes.pAttributeList[i].length = pOpAttributes->pAttributeList[j].length;
                newAttributes.pAttributeList[i].pStructOfType = pOpAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }
        newAttributes.listLen = i;
        pNewAttributes = (TAP_AttributeList *)&newAttributes;
    }

    pDupCmdParams = (SMP_duplicateKeyCmdParams *)&(smpCmdReq.reqParams.duplicateKey);
    smpCmdReq.cmdCode = SMP_CC_DUPLICATEKEY;

    if (NULL != pInPeerPublic)
    {
        pubkeyBlob.format = pPubBuffer[1];
        pubkeyBlob.encoding = pPubBuffer[2];
        pubkeyBlob.blob.pBuffer = &pPubBuffer[3];
        pubkeyBlob.blob.bufferLen = pInPeerPublic->bufferLen - 3;
        pDupCmdParams->pNewPubkey = &pubkeyBlob;
    }
    
    pDupCmdParams->moduleHandle = pContext->moduleHandle;
    pDupCmdParams->tokenHandle = pTapKey->tokenHandle;
    pDupCmdParams->keyHandle = pTapKey->keyHandle;
    pDupCmdParams->pMechanism = pNewAttributes ? pNewAttributes : (TAP_AttributeList *)&newAttributes;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create duplicateKey, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    status = DIGI_CALLOC((void **)&(pOutDuplicate->pBuffer), 1,
       smpCmdRsp.rspParams.duplicateKey.duplicateBuf.bufferLen) ;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for duplicate buffer, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    DIGI_MEMCPY((void *)pOutDuplicate->pBuffer, (void *)smpCmdRsp.rspParams.duplicateKey.duplicateBuf.pBuffer,
      smpCmdRsp.rspParams.duplicateKey.duplicateBuf.bufferLen) ;
      pOutDuplicate->bufferLen = smpCmdRsp.rspParams.duplicateKey.duplicateBuf.bufferLen ;


exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));



    if (NULL != newAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }


    return status;
}


MSTATUS TAP_importKeyFromID(TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_KeyInfo *pKeyInfo,
                            TAP_Buffer *pKeyId,
                            TAP_AttributeList *pKeyAttributes,
                            TAP_CredentialList *pKeyCredentials,
                            TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK, exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    ubyte4 numAttributes = 3; /* at least KEY_ALG, KEY_USAGE, and OBJECT_ID_BYTESTRING */

    volatile TAP_EntityCredentialList nullCredentials = {0};
    volatile TAP_AttributeList newKeyAttributes = { 0, };

    TAP_AttributeList *pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;

    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttributes = {0};
    volatile TAP_EntityCredentialList nullUsageCredentials = {0};
    ubyte4 i = 0, j = 0;

    /* check input */
    if (NULL == pTapContext || NULL == pKeyId || NULL == pKeyInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pContext = (_TAP_Context *)pTapContext;

    /* Create the list of all the attributes */
    if(NULL != pKeyAttributes)
    {
        numAttributes += pKeyAttributes->listLen;
    }

    if (NULL != pKeyCredentials)
        numAttributes++;

    if (NULL != pUsageCredentials)
        numAttributes++;

    status = DIGI_CALLOC((void **)&(newKeyAttributes.pAttributeList), 1,
            numAttributes * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate key attributes block, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }
    newKeyAttributes.listLen = numAttributes;

    newKeyAttributes.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
    newKeyAttributes.pAttributeList[0].length = sizeof(pKeyInfo->keyAlgorithm);
    newKeyAttributes.pAttributeList[0].pStructOfType = (void *)&(pKeyInfo->keyAlgorithm);

    newKeyAttributes.pAttributeList[1].type = TAP_ATTR_KEY_USAGE;
    newKeyAttributes.pAttributeList[1].length = sizeof(pKeyInfo->keyUsage);
    newKeyAttributes.pAttributeList[1].pStructOfType = (void *)&(pKeyInfo->keyUsage);

    newKeyAttributes.pAttributeList[2].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
    newKeyAttributes.pAttributeList[2].length = sizeof(TAP_Buffer);
    newKeyAttributes.pAttributeList[2].pStructOfType = (void *) pKeyId;
    i = 3;

    if(NULL != pKeyAttributes)
    {
        for (j=0; j < pKeyAttributes->listLen; j++, i++)
        {
            newKeyAttributes.pAttributeList[i].type = pKeyAttributes->pAttributeList[j].type;
            newKeyAttributes.pAttributeList[i].length = pKeyAttributes->pAttributeList[j].length;
            newKeyAttributes.pAttributeList[i].pStructOfType = pKeyAttributes->pAttributeList[j].pStructOfType;
        }
    }
    
    if (NULL != pKeyCredentials)
    {
        newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
        newKeyAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
        newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
        i++;
    }

    if (NULL != pUsageCredentials)
    {
        status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                    NULL, pErrContext);

        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
        newKeyAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
        newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
        /* i++; not needed unless we add more below */
    }

    /* get the token */
    status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                    &tokenAttributes, &tokenList, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
    {
        DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_INVALID_ENTITY_TYPE;
        goto exit;
    }

    if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
    {
        DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        goto exit;
    }

    tokenId = tokenList.entityIdList.pEntityIdList[0];

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId,
                (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttributes,
                pUsageCredentials ? pUsageCredentials :
                (TAP_EntityCredentialList *)&nullUsageCredentials,
                &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, pKeyInfo->tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set command parameter values */
    smpCmdReq.cmdCode = SMP_CC_INIT_OBJECT;
    smpCmdReq.reqParams.initObject.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.initObject.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.initObject.objectIdIn = 0x00; /* Passed via attributes instead */
    smpCmdReq.reqParams.initObject.pObjectAttributes = pNewKeyAttributes;
    smpCmdReq.reqParams.initObject.pCredentialList = pUsageCredentials ? pUsageCredentials :
        (TAP_EntityCredentialList *)&nullCredentials;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize object, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* We know we succeeded, so now allocate memory for new TAP key and set fields */

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppTapKey)->pTapContext = pTapContext;
    (*ppTapKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppTapKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppTapKey)->providerObjectData.objectInfo.tokenId = tokenId;

    if ((0 < smpCmdRsp.rspParams.initObject.objectAttributes.listLen) &&
        (NULL != smpCmdRsp.rspParams.initObject.objectAttributes.pAttributeList))
    {
        pNewKeyAttributes = &(smpCmdRsp.rspParams.initObject.objectAttributes);
        status = TAP_UTILS_copyAttributeList(&((*ppTapKey)->providerObjectData.objectInfo.objectAttributes),
                                                (TAP_AttributeList *)pNewKeyAttributes);
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__, "Failed to copy attribute list status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    (*ppTapKey)->keyHandle = smpCmdRsp.rspParams.initObject.objectHandle;
    (*ppTapKey)->tokenHandle = tokenHandle;

    if (NULL != pNewKeyAttributes)
    {
        for (i = 0; i < pNewKeyAttributes->listLen; i++)
        {
            switch(pNewKeyAttributes->pAttributeList[i].type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewKeyAttributes->pAttributeList[i].pStructOfType);
                    break;

                case TAP_ATTR_KEY_USAGE:
                    (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewKeyAttributes->pAttributeList[i].pStructOfType);
                    break;
            }
        }
    }

    /* Validate that this is the key the caller intended to instantiate */
    if (pKeyInfo->keyAlgorithm != (*ppTapKey)->keyData.keyAlgorithm)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Instantiated key type does not match input key type\n", 
            __FUNCTION__, __LINE__);
        goto exit;
    }

    /* Key usage should be set in the returned key but just in case not */
    if (TAP_KEY_USAGE_UNDEFINED == (*ppTapKey)->keyData.keyUsage)
    {
        (*ppTapKey)->keyData.keyUsage = pKeyInfo->keyUsage;
    }

    /* Fill out additional info if provided in the Key Info */
    switch(pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        {
            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.sigScheme = pKeyInfo->algKeyInfo.rsaInfo.sigScheme;
            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.encScheme = pKeyInfo->algKeyInfo.rsaInfo.encScheme;   
            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.keySize = pKeyInfo->algKeyInfo.rsaInfo.keySize;
        }
        break;
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
        {
            (*ppTapKey)->keyData.algKeyInfo.mldsaInfo.sigScheme = pKeyInfo->algKeyInfo.mldsaInfo.sigScheme;
            (*ppTapKey)->keyData.algKeyInfo.mldsaInfo.qsAlg = pKeyInfo->algKeyInfo.mldsaInfo.qsAlg;
        }
        break;
#endif

        case TAP_KEY_ALGORITHM_ECC:
        {
            (*ppTapKey)->keyData.algKeyInfo.eccInfo.sigScheme = pKeyInfo->algKeyInfo.eccInfo.sigScheme;
            (*ppTapKey)->keyData.algKeyInfo.eccInfo.curveId = pKeyInfo->algKeyInfo.eccInfo.curveId;
        }
        break;

        case TAP_KEY_ALGORITHM_AES:
        {
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = pKeyInfo->algKeyInfo.aesInfo.symMode;
            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = pKeyInfo->algKeyInfo.aesInfo.keySize;
        }
        break;

        case TAP_KEY_ALGORITHM_HMAC:
        {
            (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg = pKeyInfo->algKeyInfo.hmacInfo.hashAlg;
        }
        break;
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (TAP_KEY_ALGORITHM_RSA == pKeyInfo->keyAlgorithm || TAP_KEY_ALGORITHM_ECC == pKeyInfo->keyAlgorithm ||
            TAP_KEY_ALGORITHM_MLDSA == pKeyInfo->keyAlgorithm)
#else
    if (TAP_KEY_ALGORITHM_RSA == pKeyInfo->keyAlgorithm || TAP_KEY_ALGORITHM_ECC == pKeyInfo->keyAlgorithm)
#endif
    {
        status = TAP_getPublicKey(*ppTapKey, &((*ppTapKey)->keyData.publicKey));
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__, "Failed to get public key for new key! status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if ((OK != status) && (NULL != ppTapKey) && (NULL != *ppTapKey))
    {
        exitStatus = TAP_freeKey(ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newKeyAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

MSTATUS TAP_importDuplicateKey(TAP_Context *pTapContext,
                            TAP_EntityCredentialList *pUsageCredentials,
                            TAP_KeyInfo *pKeyInfo,
                            TAP_Buffer *pDuplicateBuf,
                            TAP_AttributeList *pKeyAttributes,
                            TAP_CredentialList *pKeyCredentials,
                            TAP_Key **ppTapKey, TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    MSTATUS exitStatus = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = (_TAP_Context *)pTapContext;
    volatile TAP_AttributeList newKeyAttributes = { 0, };
    TAP_AttributeList *pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    TAP_ObjectAttributes *pNewObjAttributes = NULL;
    ubyte4 numAttributes = 0;
    ubyte4 i = 0;
    ubyte4 j = 0;
    TAP_CAPABILITY_FUNCTIONALITY tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    TAP_Attribute tokenAttribute = { TAP_ATTR_CAPABILITY_FUNCTIONALITY,
                sizeof(tokenCapability), &tokenCapability };
    TAP_TokenCapabilityAttributes tokenAttributes = { 1, &tokenAttribute };
    TAP_EntityList tokenList = { 0 };
    TAP_TokenId tokenId = 0;
    TAP_TokenHandle tokenHandle = 0;
    volatile TAP_TokenCapabilityAttributes nullTokenCapabilityAttributes = {0};
    volatile TAP_EntityCredentialList nullUsageCredentials = {0};
    byteBoolean isAsymKey = TRUE;

    if ((NULL == pTapContext) || (NULL == pKeyInfo) || (NULL == pDuplicateBuf)
        || (NULL == ppTapKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((NULL == pDuplicateBuf->pBuffer) || (0 >= pDuplicateBuf->bufferLen))
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* First generate module-specific key.  The  module must also set (*ppTapKey)->keyAlgorithm */

    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            isAsymKey = TRUE;
            numAttributes = 5;
            break;

        case TAP_KEY_ALGORITHM_ECC:
            isAsymKey = TRUE;
            numAttributes = 4;
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            isAsymKey = FALSE;
            numAttributes = 4;
            break;

        case TAP_KEY_ALGORITHM_AES:
            isAsymKey = FALSE;
            numAttributes = 4;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (TAP_KEY_USAGE_ATTESTATION == pKeyInfo->keyUsage)
    {
        tokenCapability = TAP_CAPABILITY_ATTESTATION_BASIC;
    }
    else
    {
        tokenCapability = TAP_CAPABILITY_CRYPTO_OP_ASYMMETRIC;
    }

    if (NULL != pKeyCredentials)
        numAttributes++;

    if (NULL != pUsageCredentials)
        numAttributes++;

    if(NULL != pKeyAttributes)
    {
        numAttributes += pKeyAttributes->listLen ;
    }

    /* Set the new key attributes, including information from both pKeyInfo and pKeyAttributes */
    if (0 < numAttributes)
    {
        status = DIGI_CALLOC((void **)&(newKeyAttributes.pAttributeList), 1,
                numAttributes * sizeof(TAP_Attribute));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate key attributes block, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        newKeyAttributes.pAttributeList[0].type = TAP_ATTR_KEY_ALGORITHM;
        newKeyAttributes.pAttributeList[0].length = sizeof(pKeyInfo->keyAlgorithm);
        newKeyAttributes.pAttributeList[0].pStructOfType = (void *)&(pKeyInfo->keyAlgorithm);

        newKeyAttributes.pAttributeList[1].type = TAP_ATTR_KEY_USAGE;
        newKeyAttributes.pAttributeList[1].length = sizeof(pKeyInfo->keyUsage);
        newKeyAttributes.pAttributeList[1].pStructOfType = (void *)&(pKeyInfo->keyUsage);
        i = 2;

        if(NULL != pKeyAttributes)
        {
            for (j=0; j < pKeyAttributes->listLen; j++)
            {
                newKeyAttributes.pAttributeList[i].type = pKeyAttributes->pAttributeList[j].type;
                newKeyAttributes.pAttributeList[i].length = pKeyAttributes->pAttributeList[j].length;
                newKeyAttributes.pAttributeList[i].pStructOfType = pKeyAttributes->pAttributeList[j].pStructOfType;
                i++;
            }
        }

        if (NULL != pKeyCredentials)
        {
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_SET;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_CredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pKeyCredentials;
            i++;
        }
        if (NULL != pUsageCredentials)
        {
            status = TAP_associateCredentialWithContext(pTapContext, pUsageCredentials,
                                                        NULL, pErrContext);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to associate credentials, status %d = %s\n", __FUNCTION__,
                        __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CREDENTIAL_USAGE;
            newKeyAttributes.pAttributeList[i].length = sizeof(TAP_EntityCredentialList);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)pUsageCredentials;
            i++;
        }

        if (TAP_KEY_ALGORITHM_RSA == pKeyInfo->keyAlgorithm)
        {
            /* RSA Key */
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_KEY_SIZE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.keySize);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.keySize);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_ENC_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.encScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.encScheme);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SIG_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.rsaInfo.sigScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.rsaInfo.sigScheme);
            i++;
        }
        else if (TAP_KEY_ALGORITHM_ECC == pKeyInfo->keyAlgorithm)
        {
            /* ECC Key */
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_CURVE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.eccInfo.curveId);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.eccInfo.curveId);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SIG_SCHEME;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.eccInfo.sigScheme);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.eccInfo.sigScheme);
            i++;
        }
        else if (TAP_KEY_ALGORITHM_AES == pKeyInfo->keyAlgorithm)
        {
            /* AES Key */
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_KEY_SIZE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.keySize);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.keySize);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_SYM_KEY_MODE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.aesInfo.symMode);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.aesInfo.symMode);
            i++;
        }
        else /* TAP_KEY_ALGORITHM_HMAC */
        {
            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_RAW_KEY_SIZE;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.keyLen);
            i++;

            newKeyAttributes.pAttributeList[i].type = TAP_ATTR_HASH_ALG;
            newKeyAttributes.pAttributeList[i].length = sizeof(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
            newKeyAttributes.pAttributeList[i].pStructOfType = (void *)&(pKeyInfo->algKeyInfo.hmacInfo.hashAlg);
            i++;
        }

        newKeyAttributes.listLen = i;
        pNewKeyAttributes = (TAP_AttributeList *)&newKeyAttributes;
    }

    /* If didn't have a tokenId in credentials, find one that works */
    if (0 == tokenId)
    {
        status = TAP_SMP_getTokenList(pTapContext, TAP_TOKEN_TYPE_DEFAULT,
                                      &tokenAttributes, &tokenList, pErrContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to get token list, status %d = %s\n", __FUNCTION__,
                    __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }

        if (TAP_ENTITY_TYPE_TOKEN != tokenList.entityType)
        {
            DB_PRINT("%s.%d getTokenList returned invalid entity list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_INVALID_ENTITY_TYPE;
            goto exit;
        }

        if ((0 == tokenList.entityIdList.numEntities) || (NULL == tokenList.entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d getTokenList returned empty list\n", __FUNCTION__, __LINE__);
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            goto exit;
        }

        tokenId = tokenList.entityIdList.pEntityIdList[0];

        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);
    }

    /* Init the token to get the tokenHandle */
    status = TAP_SMP_initToken(pTapContext, &tokenId,
                (TAP_TokenCapabilityAttributes *)&nullTokenCapabilityAttributes,
                pUsageCredentials ? pUsageCredentials :
                (TAP_EntityCredentialList *)&nullUsageCredentials,
                &tokenHandle, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to initialize tokenId %lu, status %d = %s\n", __FUNCTION__,
                __LINE__, pKeyInfo->tokenId, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* Set the command values */
    smpCmdReq.cmdCode = SMP_CC_IMPORTDUPLICATEKEY;
    smpCmdReq.reqParams.importDuplicateKey.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.importDuplicateKey.tokenHandle = tokenHandle;
    smpCmdReq.reqParams.importDuplicateKey.pKeyAttributes = pNewKeyAttributes;
    smpCmdReq.reqParams.importDuplicateKey.pDuplicateBuf = pDuplicateBuf ;

    /* Call SMP dispatcher directly in a local-only build */

    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to generate asymmetric key, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* We know we succeeded, so now allocate memory for new TAP key and set fields */

    /* Allocate memory for TAP_Key */
    status = DIGI_CALLOC((void **)ppTapKey, 1, sizeof(TAP_Key));
    if (OK != status)
    {
        DB_PRINT(__func__, __LINE__, "Failed to allocate memory for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    (*ppTapKey)->pTapContext = pTapContext;
    (*ppTapKey)->providerObjectData.objectInfo.providerType = pContext->providerType;
    (*ppTapKey)->providerObjectData.objectInfo.moduleId = pContext->module.moduleId;
    (*ppTapKey)->providerObjectData.objectInfo.tokenId = tokenId;

    if ((0 < smpCmdRsp.rspParams.importDuplicateKey.objectAttributes.listLen) &&
        (NULL != smpCmdRsp.rspParams.importDuplicateKey.objectAttributes.pAttributeList))
    {
        pNewObjAttributes = &(smpCmdRsp.rspParams.importDuplicateKey.objectAttributes);
        status = TAP_UTILS_copyAttributeList(&((*ppTapKey)->providerObjectData.objectInfo.objectAttributes),
                                              (TAP_AttributeList *)pNewObjAttributes);
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__, "Failed to copy attribute list status %d = %s\n",
                        status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

    (*ppTapKey)->keyData.keyAlgorithm = pKeyInfo->keyAlgorithm;
    (*ppTapKey)->keyData.keyUsage = pKeyInfo->keyUsage;

    /* Populate the key with the attributes returned from the SMP */
    switch (pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.keySize = *(TAP_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_ENC_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.encScheme = *(TAP_ENC_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.rsaInfo.sigScheme = *(TAP_SIG_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_CURVE:
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? */
                            break;
                    }
                }
            }
            break;
        case TAP_KEY_ALGORITHM_ECC:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SIG_SCHEME:
                            (*ppTapKey)->keyData.algKeyInfo.eccInfo.sigScheme = *(TAP_SIG_SCHEME *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_CURVE:
                            (*ppTapKey)->keyData.algKeyInfo.eccInfo.curveId = *(TAP_ECC_CURVE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? For now, just ignoring*/
                            break;
                    }
                }
            }
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_RAW_KEY_SIZE:
                             (*ppTapKey)->keyData.algKeyInfo.hmacInfo.keyLen =
                                 *(TAP_RAW_KEY_SIZE*)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                             break;
                        case TAP_ATTR_HASH_ALG:
                             (*ppTapKey)->keyData.algKeyInfo.hmacInfo.hashAlg =
                                 *(TAP_HASH_ALG*)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                             break;
                        case TAP_ATTR_KEY_SIZE:
                        case TAP_ATTR_ENC_SCHEME:
                        case TAP_ATTR_SIG_SCHEME:
                        case  TAP_ATTR_CURVE:
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            /* TODO: Do we want to return an error if we get back an invalid attribute? */
                            break;
                    }
                }
            }
            break;

       case TAP_KEY_ALGORITHM_AES:
            /* Set field from values returned from SMP and not from request */
            if (NULL != pNewObjAttributes)
            {
                for (i = 0; i < pNewObjAttributes->listLen; i++)
                {
                    switch(pNewObjAttributes->pAttributeList[i].type)
                    {
                        case TAP_ATTR_KEY_ALGORITHM:
                            (*ppTapKey)->keyData.keyAlgorithm = *(TAP_KEY_ALGORITHM *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_USAGE:
                            (*ppTapKey)->keyData.keyUsage = *(TAP_KEY_USAGE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_KEY_SIZE:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.keySize = *(TAP_KEY_SIZE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case TAP_ATTR_SYM_KEY_MODE:
                            (*ppTapKey)->keyData.algKeyInfo.aesInfo.symMode = *(TAP_SYM_KEY_MODE *)(pNewObjAttributes->pAttributeList[i].pStructOfType);
                            break;
                        case  TAP_ATTR_NONE:
                            break;
                        default:
                            break;
                    }
                }
            }
            break;

        default:
            break;
    }

    (*ppTapKey)->keyHandle = smpCmdRsp.rspParams.importDuplicateKey.keyHandle;
    (*ppTapKey)->tokenHandle = tokenHandle;


    /* Now get the public key for asym key*/
    if (TRUE == isAsymKey)
    {
        status = TAP_getPublicKey(*ppTapKey, &((*ppTapKey)->keyData.publicKey));
        if (OK != status)
        {
            DB_PRINT(__func__, __LINE__,
                    "Failed to get public key for new key! status %d = %s\n",
                    status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

exit:

    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));

    if (tokenList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&tokenList.entityIdList.pEntityIdList);

    if ((OK != status) && (NULL != ppTapKey) && (NULL != *ppTapKey))
    {
        exitStatus = TAP_freeKey(ppTapKey);
        if (OK != exitStatus)
        {
            status = exitStatus;
            DB_PRINT(__func__, __LINE__, "Failed to free TAP_Key on failure! status %d = %s\n",
                        exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    if (NULL != newKeyAttributes.pAttributeList)
    {
        exitStatus = shredMemory((ubyte **)&(newKeyAttributes.pAttributeList), numAttributes * sizeof(TAP_Attribute), TRUE);
        if (OK != exitStatus)
        {
            DB_PRINT("%s.%d Failed to free memory, status %d = %s\n", __FUNCTION__,
                    __LINE__, exitStatus, MERROR_lookUpErrorCode(exitStatus));
        }
    }

    return status;
}

MOC_EXTERN MSTATUS TAP_ECDH_generateSharedSecret(TAP_Key *pTapKey,
        TAP_AttributeList *pOpAttributes,
        TAP_PublicKey *pPeerPublicKey, TAP_Buffer *pSharedSecret,
        TAP_ErrorContext *pErrContext)
{
    MSTATUS status = OK;
    SMP_CmdReq smpCmdReq = { 0, };
    SMP_CmdRsp smpCmdRsp = { 0, };
    _TAP_Context *pContext = NULL;
    volatile TAP_AttributeList nullAttributes = { 0, };

    if (!pTapKey || !pPeerPublicKey || !pSharedSecret)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid inputs, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pTapKey->pTapContext)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        goto exit;
    }

    pContext = (_TAP_Context *)(pTapKey->pTapContext);

    if (0 == pContext->moduleHandle)
    {
        status = ERR_TAP_INVALID_CONTEXT;
        DB_PRINT("%s.%d Have invalid moduleHandle in context, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((0 == pTapKey->tokenHandle) || (0 == pTapKey->keyHandle))
    {
        status = ERR_TAP_KEY_NOT_INITIALIZED;
        DB_PRINT("%s.%d Key not properly initialized; have invalid handle, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    smpCmdReq.cmdCode = SMP_CC_ECDH_GENERATE_SHARED_SECRET;
    smpCmdReq.reqParams.ECDH_generateSharedSecret.moduleHandle = pContext->moduleHandle;
    smpCmdReq.reqParams.ECDH_generateSharedSecret.tokenHandle = pTapKey->tokenHandle;
    smpCmdReq.reqParams.ECDH_generateSharedSecret.objectHandle = pTapKey->keyHandle;
    smpCmdReq.reqParams.ECDH_generateSharedSecret.pOpAttributes = pOpAttributes ?
        (TAP_AttributeList *)pOpAttributes :
        (TAP_AttributeList *)&nullAttributes;
    smpCmdReq.reqParams.ECDH_generateSharedSecret.pPublicKey = pPeerPublicKey;

    /* Call SMP dispatcher directly in a local-only build */
    status = TAP_dispatchSMPCommand(pContext->providerType, &pContext->sessionInfo,
                                    &smpCmdReq,  &smpCmdRsp);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to process local SMP command, status %d = %s\n", __FUNCTION__,
                __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = smpCmdRsp.returnCode;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to generate shared secret, status %d = %s\n", __FUNCTION__,
                 __LINE__, status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (smpCmdRsp.rspParams.ECDH_generateSharedSecret.secret.bufferLen)
    {
        pSharedSecret->bufferLen = smpCmdRsp.rspParams.ECDH_generateSharedSecret.secret.bufferLen;

        status = DIGI_MALLOC((void **)&pSharedSecret->pBuffer,
                pSharedSecret->bufferLen);
        if (OK != status)
        {
            pSharedSecret->pBuffer = 0;
            goto exit;
        }

        status = DIGI_MEMCPY(pSharedSecret->pBuffer,
                smpCmdRsp.rspParams.ECDH_generateSharedSecret.secret.pBuffer,
                pSharedSecret->bufferLen);
        if (OK != status)
        {
            pSharedSecret->pBuffer = 0;
            DIGI_FREE((void **)&pSharedSecret->pBuffer);
            goto exit;
        }
    }
    else
    {
        status = ERR_GENERAL; /* should not happen, SMP will return valid length on Success */
    }

exit:
    TAP_SERIALIZE_freeDeserializedStructure(
            &SMP_INTERFACE_SHADOW_SMP_CmdRsp, (ubyte *)&smpCmdRsp, sizeof(smpCmdRsp));
    return status;
}

/*---------------------------------------------------------------------------*/

/* Function checks is a provider has already been loaded in. */
extern MSTATUS TAP_checkForProvider(TAP_PROVIDER provider, intBoolean *pFound)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (NULL == pFound)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = FALSE;

    if (NULL != localProviderList.pProviderCmdList)
    {
        for (i = 0; i < localProviderList.listLen; i++)
        {
            if (provider == localProviderList.pProviderCmdList[i].provider)
            {
                *pFound = TRUE;
                break;
            }
        }
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#ifdef __ENABLE_DIGICERT_TPM2__

#ifndef TPM2_DP_LABEL
#define TPM2_DP_LABEL "TAP Root Public Key Hash"
#endif

#include "../common/tpm2_path.h"

#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
#define TPM2_EK_OBJECT_ID                        0x81010001
#else
#define TPM2_EK_OBJECT_ID                        0x81010000
#endif

/*------------------------------------------------------------------*/

/* We compute a hash of the root public key */
static MSTATUS TAP_DP_setPubKeyElement(FingerprintElement *pElement, TAP_ConfigInfoList *pConfigInfoList)
{
    MSTATUS status = OK, fstatus = OK;
    ubyte4 offset = 0;
    ubyte pPubKeyBuffer[MAX_KEY_BUFFER] = {0};
    TAP_Context *pTapCtx = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_KeyInfo rootKeyInfo = {0};
    TAP_Key *pRootKey = NULL;
    intBoolean providerFound = FALSE;
    hwAccelDescr hwAccelCtx;

    TAP_ModuleList moduleList = {0};

    /* internal method, NULL check not needed */
    status = ERR_BAD_LENGTH;
    if (MOC_TDP_MAX_LABEL_LEN < DIGI_STRLEN((sbyte *) TPM2_DP_LABEL) + 1)
        goto exit;

    status = DIGI_MEMCPY((ubyte *) pElement->pLabel, (ubyte *) TPM2_DP_LABEL, DIGI_STRLEN((sbyte *) TPM2_DP_LABEL) + 1);
    if (OK != status)
        goto exit;

    status = TAP_checkForProvider(TAP_PROVIDER_TPM2, &providerFound);
    if (OK != status)
        goto exit;

    if (FALSE == providerFound)
    {
        status = TAP_init(pConfigInfoList, &errContext);
        if (OK != status)
            goto exit;
    }

    status = TAP_getModuleList(NULL, TAP_PROVIDER_TPM2, NULL, &moduleList, &errContext);
    if (OK != status)
        goto exit;

    if (0 == moduleList.numModules)
    {
        status = ERR_TAP_MODULE_NOT_FOUND;
        goto exit;
    }

    status = TAP_initContext(&(moduleList.pModuleList[0]), NULL, NULL, &pTapCtx, &errContext);
    if (OK != status)
        goto exit;

    /* Set ObjectId */
    rootKeyInfo.objectId = TPM2_EK_OBJECT_ID;
    status = TAP_getRootOfTrustKey(pTapCtx, &rootKeyInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN, &pRootKey, &errContext);
    if (OK != status)
        goto exit;

    /* Serialize Public key */
    status = TAP_SERIALIZE_serialize(TAP_SERALIZE_SMP_getPublicKeyShadowStruct(),
                                     TAP_SD_IN, (void *)&pRootKey->keyData.publicKey,
                                     sizeof(pRootKey->keyData.publicKey),
                                     pPubKeyBuffer, sizeof(pPubKeyBuffer), &offset);
    if (OK != status)
        goto exit;

    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPubKeyBuffer, offset, pElement->pValue);
#else
    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pPubKeyBuffer, offset, pElement->pValue);
#endif
    if (OK != status)
        goto exit;

    pElement->valueLen = SHA256_RESULT_SIZE;

exit:

    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

    /* free the root key */
    if(NULL != pRootKey)
    {
        fstatus = TAP_unloadKey(pRootKey, &errContext);
        if (OK == status)
            status = fstatus;

        fstatus = TAP_freeKey(&pRootKey);
        if (OK == status)
            status = fstatus;

        pRootKey = NULL;
    }

    /* Free tap context */
    if (NULL != pTapCtx)
    {
        fstatus = TAP_uninitContext(&pTapCtx, &errContext);
        if (OK == status)
            status = fstatus;
    }

    fstatus = TAP_freeModuleList(&moduleList);
    if (OK == status)
        status = fstatus;

    if (FALSE == providerFound)
    {
        /* free error context */
        fstatus = TAP_uninit(&errContext);
        if (OK == status)
            status = fstatus;
    }

    /* ok to leave the allocated label on error since TAP_DP_freeFingerprintCallback will handle the free */

    return status;
}
#endif /* __ENABLE_DIGICERT_TPM2__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_DP_seedCallback(ubyte *pSeedBuffer, ubyte4 *pSeedLen, void *pArg)
{
    return FP_seedCallback(pSeedBuffer, pSeedLen, pArg);
}

/*---------------------------------------------------------------------------*/

static ubyte4 g_numDefaultElements = 0;

#ifdef __ENABLE_DIGICERT_TPM2__

static MSTATUS TAP_DP_fingerprintCallbackEx(FingerprintElement **ppElements, ubyte4 *pNumElements, void *pArg)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    FingerprintElement *pOriginalElements = NULL;
    ubyte4 numOriginalElements = 0;

    FingerprintElement *pNewElements = NULL;
    ubyte4 numNewElements = 0;

    ubyte4 labelLen = 0;
    ubyte4 i = 0;

    TAP_ConfigInfoList configInfoList = {0};

    if (NULL == ppElements || NULL == pNumElements)
        goto exit;

    /* get the elements from the original callback */
    status = FP_fingerprintCallback(&pOriginalElements, &numOriginalElements, pArg);
    if (OK != status)
        goto exit;

    /* first find out if there even is a TPM configuration file */
    status = DIGI_CALLOC((void **)&(configInfoList.pConfig), 1, sizeof(TAP_ConfigInfo));
    if (OK != status)
        goto exit;

    /* We are in the process of creating the fingerprints, we can't verify a signature yet! */
    if (TRUE == FMGMT_pathExists(TPM2_CONFIGURATION_FILE, NULL) &&
        OK == TAP_readConfigFile(TPM2_CONFIGURATION_FILE, &configInfoList.pConfig[0].configInfo, TRUE))
    {
        configInfoList.count = 1;
        configInfoList.pConfig[0].provider = TAP_PROVIDER_TPM2;
        numNewElements = numOriginalElements + 1;
    }
    else
    {
        /* no tpm2.conf, so no additional new elements */
        numNewElements = numOriginalElements;
    }

    /* Allocate space for a new list of elements including one more */
    status = DIGI_CALLOC((void **)&pNewElements, numNewElements, sizeof(FingerprintElement));
    if (OK != status)
        goto exit;

    /* copy the original elements */
    for ( ; i < numOriginalElements; ++i)
    {
        labelLen = DIGI_STRLEN(pOriginalElements[i].pLabel) + 1;  /* account for the '\0' char */

        status = ERR_BAD_LENGTH;
        if (MOC_TDP_MAX_LABEL_LEN < labelLen)
            goto exit;

        status = DIGI_MEMCPY(pNewElements[i].pLabel, pOriginalElements[i].pLabel, labelLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pNewElements[i].pValue, pOriginalElements[i].pValue, pOriginalElements[i].valueLen);
        if (OK != status)
            goto exit;

        pNewElements[i].valueLen = pOriginalElements[i].valueLen;
    }

    if (numNewElements > numOriginalElements)
    {
        /* get the TAP specific element */
        status = TAP_DP_setPubKeyElement(&pNewElements[i], &configInfoList);
        if (OK != status)
            goto exit;
    }

    *ppElements = pNewElements; pNewElements = NULL;
    *pNumElements = numNewElements;

    /* We have our own copy now of all the elements, we can "free" the original ones */
    status = FP_freeFingerprintCallback(&pOriginalElements, numOriginalElements, pArg);

exit:

    if (NULL != pNewElements)
    {
        fstatus = TAP_DP_freeFingerprintCallback(&pNewElements, numNewElements, pArg);
        if (OK == status)
            status = fstatus;
    }

    /* Free config info */
    if (NULL != configInfoList.pConfig)
    {
        fstatus = TAP_UTILS_freeConfigInfoList(&configInfoList);
        if (OK == status)
            status = fstatus;
    }

    return status;
}
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_DP_freeFingerprintCallbackEx(FingerprintElement **ppElements, ubyte4 numElements, void *pArg)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    sbyte *pCurLabel = NULL;
    ubyte4 i = 0;

    MOC_UNUSED(pArg);

    if ( NULL == ppElements || (NULL == *ppElements && numElements) )
        goto exit;

    status = OK;
    if (!numElements)
        goto exit; /* nothing to do */

    for ( ; i < numElements; ++i)
    {
        pCurLabel = ((*ppElements)[i]).pLabel;
        if (NULL != pCurLabel)
        {
            fstatus = DIGI_MEMSET(pCurLabel, 0x00, DIGI_STRLEN(pCurLabel));
            if (OK == status)
                status = fstatus;
        }
        /* if error still continue to try to free as much as we can */
    }

    /* We'll memset the element values and valueLens in one fell swoop */

    fstatus = DIGI_MEMSET_FREE((ubyte **) ppElements, numElements * sizeof(FingerprintElement));
    if (OK == status)
        status = fstatus;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_DP_fingerprintCallback(FingerprintElement **ppElements, ubyte4 *pNumElements, void *pArg)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    FingerprintElement *pDefaultElements = NULL;
    ubyte4 numDefaultElements = 0;
    FingerprintElement *pNewElements = NULL;
    ubyte4 numNewElements = 0;
#ifdef __ENABLE_DIGICERT_TPM2__
    FingerprintElement *pTapElements = NULL;
    ubyte4 numTapElements = 0;
    ubyte4 i, j;
#endif

    /* We always get the SW fingerprint info */
    status = FP_fingerprintCallback(&pDefaultElements, &numDefaultElements, pArg);
    if (OK != status)
        goto exit;

    /* When we free the combined list, we need to know how many elements were given
     * by the default implementation so we can split the free call accordingly */
    g_numDefaultElements = numDefaultElements;

    /* If the TPM2 flag is enabled, check for a TPM2 and append the fingerprint elements if possible */
#ifdef __ENABLE_DIGICERT_TPM2__

    /* Attempt to get the TPM2 fingerprint elements */
    status = TAP_DP_fingerprintCallbackEx(&pTapElements, &numTapElements, pArg);

    /* Its ok for the above function to fail. We may have a TPM2 enabled build where the TPM does not
     * exist or is not yet configured. Only append the elements on success */
    if ( (OK == status) && (numTapElements > 0) )
    {
        /* Allocate the combined list */
        numNewElements = numDefaultElements + numTapElements;
        status = DIGI_CALLOC((void **)&pNewElements, numNewElements, sizeof(FingerprintElement));
        if (OK != status)
            goto exit;

        /* Copy the default elements into the new list */
        for (i = 0; i < numDefaultElements; i++)
        {
            pNewElements[i] = pDefaultElements[i];
        }

        /* Copy the TAP elements into the new list */
        j = 0;
        for (i = numDefaultElements; i < numNewElements; i++)
        {
            pNewElements[i] = pTapElements[j];
            j++;
        }

        /* Free the original default elements now that we have made a copy */
        FP_freeFingerprintCallback(&pDefaultElements, numDefaultElements, pArg);
        pDefaultElements = NULL;

        /* Free the TAP elements now that we have made a copy */
        TAP_DP_freeFingerprintCallbackEx(&pTapElements, numTapElements, pArg);
        pTapElements = NULL;
    }
#endif

    if (NULL == pDefaultElements)
    {
        /* We were able to make a combined list */
        *ppElements = pNewElements;
        *pNumElements = numNewElements;
    }
    else
    {
        /* We were not able to make a combined list, give back the default */
        *ppElements = pDefaultElements;
        *pNumElements = numDefaultElements;
        pDefaultElements = NULL;
    }

    status = OK;

exit:

    if (NULL != pDefaultElements)
    {
        FP_freeFingerprintCallback(&pDefaultElements, numDefaultElements, pArg);
    }
#ifdef __ENABLE_DIGICERT_TPM2__
    if (NULL != pTapElements)
    {
        TAP_DP_freeFingerprintCallbackEx(&pTapElements, numTapElements, pArg);
    }
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TAP_DP_freeFingerprintCallback(FingerprintElement **ppElements, ubyte4 numElements, void *pArg)
{
    MSTATUS status = ERR_NULL_POINTER;
    FingerprintElement *pDefaultElements = NULL;

    if ( NULL == ppElements || (NULL == *ppElements && numElements) )
        goto exit;

    pDefaultElements = *ppElements;

    /* Was this made as a combined list? */
    if (numElements == g_numDefaultElements)
    {
        /* Free the default elements using the previously stored global number made when the list was constructed */
        status = FP_freeFingerprintCallback(&pDefaultElements, numElements, pArg);
    }
    else
    {
        /* Free the remaining TAP elements */
        status = TAP_DP_freeFingerprintCallbackEx(&pDefaultElements, numElements, pArg);
    }

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_DATA_PROTECTION__ */

#endif /* __ENABLE_DIGICERT_TAP__ */
