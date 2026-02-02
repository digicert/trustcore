/*
 * smp_tee_interface.c
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
 *@file      smp_tee_interface.c
 *@brief     NanoSMP provider Interface function definition that an application
 *           (NanoTAP) will use to communicate/manage Tee SMP module plugin.
 *@details   This header file contains  function definitions used by NanoTAP to
 *           communicate/manage Tee NanoSMP module plugin.
 */

#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__))
#include "tee_client_api.h"

#include "smp_tee_interface.h"
#include "smp_tee.h"
#include "smp_tee_api.h"

#if !(defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
#define DB_PRINT(...)
#endif

byteBoolean SMP_TEE_cmd_Supported(SMP_CC cmd)
{
    byteBoolean supported = TRUE;

    switch (cmd)
    {
#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
        case SMP_CC_GET_MODULE_LIST:
#endif
#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
        case SMP_CC_INIT_MODULE:
#endif
#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
        case SMP_CC_UNINIT_MODULE:
#endif
#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
        case SMP_CC_INIT_TOKEN:
#endif
#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
        case SMP_CC_UNINIT_TOKEN:
#endif
#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
        case SMP_CC_INIT_OBJECT:
#endif
#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
        case SMP_CC_DELETE_OBJECT:
#endif
#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
        case SMP_CC_SET_POLICY_STORAGE:
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
        case SMP_CC_GET_POLICY_STORAGE:
#endif
            break;
        default:
            supported = FALSE;
            break;
    }

    return supported;
}

MSTATUS SMP_TEE_register(
        TAP_PROVIDER type,
        TAP_SMPVersion version,
        TAP_Version tapVersion,
        TAP_ConfigInfo *pConfigInfo,
        TAP_CmdCodeList *pRegisteredOpcodes
)
{
    MSTATUS status = OK;
    ubyte4 supportedLen = 0;
    ubyte4 count = 0;
    SMP_CC cmd = SMP_CC_INVALID;

    /* no config to deal with (at least not yet) */
    MOC_UNUSED(type);
    MOC_UNUSED(version);
    MOC_UNUSED(tapVersion);

    status = SMP_TEE_init(pConfigInfo);
    if (OK != status)
        goto exit;

    for (cmd=SMP_CC_INVALID; cmd<=SMP_CC_LAST; cmd++)
    {
        if (TRUE == SMP_TEE_cmd_Supported(cmd))
            supportedLen++;
    }

    pRegisteredOpcodes->listLen = supportedLen;
    if (supportedLen > 0)
    {
        status = DIGI_MALLOC((void **) &pRegisteredOpcodes->pCmdList, sizeof(SMP_CC) * supportedLen);
        if (OK != status)
            goto exit;

        for (cmd=SMP_CC_INVALID; cmd<=SMP_CC_LAST; cmd++)
        {
            if (TRUE == SMP_TEE_cmd_Supported(cmd))
                pRegisteredOpcodes->pCmdList[count++] = cmd;
        }
    }

exit:

    return status;
}

MSTATUS SMP_TEE_unregister()
{
    return SMP_TEE_uninit();
}

MSTATUS SMP_TEE_dispatcher(
        TAP_RequestContext *pCtx,
        SMP_CmdReq *pCmdReq,
        SMP_CmdRsp *pCmdRsp
#ifndef __DISABLE_DIGICERT_SMP_EXTENDED_ERROR__
       , TAP_ErrorAttributes *pErrorRules
       , TAP_ErrorAttributes **ppErrAttrReturned
#endif
)
{
    MSTATUS status = ERR_GENERAL;
    ubyte4 cmdCode = SMP_CC_INVALID;

    if (!pCmdReq || !pCmdRsp)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    cmdCode = pCmdReq->cmdCode;
    pCmdRsp->cmdCode = pCmdReq->cmdCode;
    switch (cmdCode)
    {
#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
    case SMP_CC_GET_MODULE_LIST                          :
        CALL_SMP_API(TEE, getModuleList,
                pCmdReq->reqParams.getModuleList.pModuleAttributes,
                &(pCmdRsp->rspParams.getModuleList.moduleList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
    case SMP_CC_INIT_MODULE                              :
        CALL_SMP_API(TEE, initModule,
                pCmdReq->reqParams.initModule.moduleId,
                pCmdReq->reqParams.initModule.pModuleAttributes,
                pCmdReq->reqParams.initModule.pCredentialList,
                &(pCmdRsp->rspParams.initModule.moduleHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
    case SMP_CC_UNINIT_MODULE                            :
        CALL_SMP_API(TEE, uninitModule,
                pCmdReq->reqParams.uninitModule.moduleHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
    case SMP_CC_INIT_TOKEN                               :
        CALL_SMP_API(TEE, initToken,
                pCmdReq->reqParams.initToken.moduleHandle,
                pCmdReq->reqParams.initToken.pTokenAttributes,
                pCmdReq->reqParams.initToken.tokenId,
                pCmdReq->reqParams.initToken.pCredentialList,
                &(pCmdRsp->rspParams.initToken.tokenHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
    case SMP_CC_UNINIT_TOKEN                             :
        CALL_SMP_API(TEE, uninitToken,
                pCmdReq->reqParams.uninitToken.moduleHandle,
                pCmdReq->reqParams.uninitToken.tokenHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
    case SMP_CC_INIT_OBJECT                              :
        CALL_SMP_API(TEE, initObject,
                pCmdReq->reqParams.initObject.moduleHandle,
                pCmdReq->reqParams.initObject.tokenHandle,
                pCmdReq->reqParams.initObject.objectIdIn,
                pCmdReq->reqParams.initObject.pObjectAttributes,
                pCmdReq->reqParams.initObject.pCredentialList,
                &(pCmdRsp->rspParams.initObject.objectHandle),
                &(pCmdRsp->rspParams.initObject.objectIdOut),
                &(pCmdRsp->rspParams.initObject.objectAttributes)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
    case SMP_CC_DELETE_OBJECT                            :
        CALL_SMP_API(TEE, deleteObject,
                pCmdReq->reqParams.deleteObject.moduleHandle,
                pCmdReq->reqParams.deleteObject.tokenHandle,
                pCmdReq->reqParams.deleteObject.objectHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
    case SMP_CC_SET_POLICY_STORAGE                       :
        CALL_SMP_API(TEE, setPolicyStorage,
                pCmdReq->reqParams.setPolicyStorage.moduleHandle,
                pCmdReq->reqParams.setPolicyStorage.tokenHandle,
                pCmdReq->reqParams.setPolicyStorage.objectHandle,
                pCmdReq->reqParams.setPolicyStorage.pPolicyAttributes,
                pCmdReq->reqParams.setPolicyStorage.pOpAttributes,
                pCmdReq->reqParams.setPolicyStorage.pData
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
    case SMP_CC_GET_POLICY_STORAGE                       :
        CALL_SMP_API(TEE, getPolicyStorage,
                pCmdReq->reqParams.getPolicyStorage.moduleHandle,
                pCmdReq->reqParams.getPolicyStorage.tokenHandle,
                pCmdReq->reqParams.getPolicyStorage.objectHandle,
                pCmdReq->reqParams.getPolicyStorage.pOpAttributes,
                &(pCmdRsp->rspParams.getPolicyStorage.data)
        );
        break;
#endif
    default:
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
        break;
    }
exit:
    return status;
}

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__)) */
