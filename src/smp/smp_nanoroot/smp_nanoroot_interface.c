/*
 * smp_nanoroot_interface.c
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
 *@file      smp_nanoroot_interface.c
 *@brief     NanoSMP provider Interface function definition that an application
 *           (NanoTAP) will use to communicate/manage NanoROOT SMP module plugin.
 *@details   This header file contains function definitions used by NanoTAP to
 *           communicate/manage NanoROOT NanoSMP module plugin.
 */

#if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__))
#include "smp_nanoroot_interface.h"
#include "smp_nanoroot.h"
#include "smp_nanoroot_api.h"

static byteBoolean SMP_NanoROOT_cmd_Supported(SMP_CC cmd)
{
    switch (cmd)
    {
        case SMP_CC_GET_MODULE_LIST:
        case SMP_CC_FREE_MODULE_LIST:
        case SMP_CC_GET_MODULE_INFO:
        case SMP_CC_GET_TOKEN_LIST:
        case SMP_CC_INIT_MODULE:
        case SMP_CC_UNINIT_MODULE:
        case SMP_CC_INIT_TOKEN:
        case SMP_CC_UNINIT_TOKEN:
        case SMP_CC_DELETE_OBJECT:
        case SMP_CC_INIT_OBJECT:

        case SMP_CC_GET_PUBLIC_KEY:
        case SMP_CC_GET_PRIVATE_KEY_BLOB:
        case SMP_CC_SIGN_DIGEST:
        case SMP_CC_SIGN_BUFFER:

        case SMP_CC_SEAL_WITH_TRUSTED_DATA:
        case SMP_CC_UNSEAL_WITH_TRUSTED_DATA:
            return TRUE;

        default:
            return FALSE;
    }

}

MSTATUS SMP_NanoROOT_register(
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

    status = NanoROOT_init(pConfigInfo);
    if (status)
    {
        goto exit;
    }

    for (cmd=SMP_CC_INVALID; cmd<=SMP_CC_LAST; cmd++)
    {
        if (TRUE == SMP_NanoROOT_cmd_Supported(cmd))
            supportedLen++;
    }

    pRegisteredOpcodes->listLen = supportedLen;
    pRegisteredOpcodes->pCmdList = MALLOC(sizeof(SMP_CC) * supportedLen);
    if (NULL == pRegisteredOpcodes->pCmdList)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for (cmd=SMP_CC_INVALID; cmd<=SMP_CC_LAST; cmd++)
    {
        if (TRUE == SMP_NanoROOT_cmd_Supported(cmd))
            pRegisteredOpcodes->pCmdList[count++] = cmd;
    }

exit:
    if(OK != status)
    {
        (void)NanoROOT_deInit();
    }
    return status;
}

MSTATUS SMP_NanoROOT_unregister()
{
    return NanoROOT_deInit();
}

MSTATUS SMP_NanoROOT_dispatcher(
        TAP_RequestContext *pCtx,
        SMP_CmdReq *pCmdReq,
        SMP_CmdRsp *pCmdRsp
#ifndef __DISABLE_MOCANA_SMP_EXTENDED_ERROR__
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
        CALL_SMP_API(NanoROOT, getModuleList,
                pCmdReq->reqParams.getModuleList.pModuleAttributes,
                &(pCmdRsp->rspParams.getModuleList.moduleList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
    case SMP_CC_FREE_MODULE_LIST                         :
        CALL_SMP_API(NanoROOT, freeModuleList,
                pCmdReq->reqParams.freeModuleList.pModuleList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__
    case SMP_CC_GET_MODULE_INFO                  :
        CALL_SMP_API(NanoROOT, getModuleInfo,
                pCmdReq->reqParams.getModuleInfo.moduleId,
                pCmdReq->reqParams.getModuleInfo.pCapabilitySelectCriterion,
                &(pCmdRsp->rspParams.getModuleInfo.moduleCapabilties)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_SLOTS__
    case SMP_CC_GET_MODULE_SLOTS                         :
        CALL_SMP_API(NanoROOT, getModuleSlots,
                pCmdReq->reqParams.getModuleSlots.moduleHandle,
                &(pCmdRsp->rspParams.getModuleSlots.moduleSlotList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
    case SMP_CC_GET_TOKEN_LIST                           :
        CALL_SMP_API(NanoROOT, getTokenList,
                pCmdReq->reqParams.getTokenList.moduleHandle,
                pCmdReq->reqParams.getTokenList.tokenType,
                pCmdReq->reqParams.getTokenList.pTokenAttributes,
                &(pCmdRsp->rspParams.getTokenList.tokenIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_INFO__
    case SMP_CC_GET_TOKEN_INFO                           :
        CALL_SMP_API(NanoROOT, getTokenInfo,
                pCmdReq->reqParams.getTokenInfo.moduleHandle,
                pCmdReq->reqParams.getTokenInfo.tokenType,
                pCmdReq->reqParams.getTokenInfo.tokenId,
                pCmdReq->reqParams.getTokenInfo.pCapabilitySelectAttributes,
                &(pCmdRsp->rspParams.getTokenInfo.tokenAttributes)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_LIST__
    case SMP_CC_GET_OBJECT_LIST                          :
        CALL_SMP_API(NanoROOT, getObjectList,
                pCmdReq->reqParams.getObjectList.moduleHandle,
                pCmdReq->reqParams.getObjectList.tokenHandle,
                pCmdReq->reqParams.getObjectList.pObjectAttributes,
                &(pCmdRsp->rspParams.getObjectList.objectIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_INFO__
    case SMP_CC_GET_OBJECT_INFO                          :
        CALL_SMP_API(NanoROOT, getObjectInfo,
                pCmdReq->reqParams.getObjectInfo.moduleHandle,
                pCmdReq->reqParams.getObjectInfo.tokenHandle,
                pCmdReq->reqParams.getObjectInfo.objectHandle,
                pCmdReq->reqParams.getObjectInfo.pCapabilitySelectAttributes,
                &(pCmdRsp->rspParams.getObjectInfo.objectAttributes)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_MODULE__
    case SMP_CC_PROVISION_MODULE                         :
        CALL_SMP_API(NanoROOT, provisionModule,
                pCmdReq->reqParams.provisionModule.moduleHandle,
                pCmdReq->reqParams.provisionModule.pModuleProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_MODULE__
    case SMP_CC_RESET_MODULE                             :
        CALL_SMP_API(NanoROOT, resetModule,
                pCmdReq->reqParams.resetModule.moduleHandle,
                pCmdReq->reqParams.resetModule.pModuleProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_TOKEN__
    case SMP_CC_PROVISION_TOKEN                          :
        CALL_SMP_API(NanoROOT, provisionTokens,
                pCmdReq->reqParams.provisionTokens.moduleHandle,
                pCmdReq->reqParams.provisionTokens.pTokenProvisionAttributes,
                &(pCmdRsp->rspParams.provisionTokens.tokenIdList)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_RESET_TOKEN__
    case SMP_CC_RESET_TOKEN                              :
        CALL_SMP_API(NanoROOT, resetToken,
                pCmdReq->reqParams.resetToken.moduleHandle,
                pCmdReq->reqParams.resetToken.tokenHandle,
                pCmdReq->reqParams.resetToken.pTokenProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_TOKEN__
    case SMP_CC_DELETE_TOKEN                             :
        CALL_SMP_API(NanoROOT, deleteToken,
                pCmdReq->reqParams.deleteToken.moduleHandle,
                pCmdReq->reqParams.deleteToken.tokenHandle,
                pCmdReq->reqParams.deleteToken.pTokenProvisionAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
    case SMP_CC_INIT_MODULE                              :
        CALL_SMP_API(NanoROOT, initModule,
                pCmdReq->reqParams.initModule.moduleId,
                pCmdReq->reqParams.initModule.pModuleAttributes,
                pCmdReq->reqParams.initModule.pCredentialList,
                &(pCmdRsp->rspParams.initModule.moduleHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
    case SMP_CC_UNINIT_MODULE                            :
        CALL_SMP_API(NanoROOT, uninitModule,
                pCmdReq->reqParams.uninitModule.moduleHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__
    case SMP_CC_ASSOCIATE_MODULE_CREDENTIALS             :
        CALL_SMP_API(NanoROOT, associateModuleCredentials,
                pCmdReq->reqParams.associateModuleCredentials.moduleHandle,
                pCmdReq->reqParams.associateModuleCredentials.pEntityCredentialList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
    case SMP_CC_INIT_TOKEN                               :
        CALL_SMP_API(NanoROOT, initToken,
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
        CALL_SMP_API(NanoROOT, uninitToken,
                pCmdReq->reqParams.uninitToken.moduleHandle,
                pCmdReq->reqParams.uninitToken.tokenHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS__
    case SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS              :
        CALL_SMP_API(NanoROOT, associateTokenCredentials,
                pCmdReq->reqParams.associateTokenCredentials.moduleHandle,
                pCmdReq->reqParams.associateTokenCredentials.tokenHandle,
                pCmdReq->reqParams.associateTokenCredentials.pCredentialList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
    case SMP_CC_INIT_OBJECT                              :
        CALL_SMP_API(NanoROOT, initObject,
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

#ifdef __SMP_ENABLE_SMP_CC_IMPORT_OBJECT__
    case SMP_CC_IMPORT_OBJECT                              :
        CALL_SMP_API(NanoROOT, importObject,
                pCmdReq->reqParams.importObject.moduleHandle,
                pCmdReq->reqParams.importObject.tokenHandle,
                pCmdReq->reqParams.importObject.pBlob,
                pCmdReq->reqParams.importObject.pObjectAttributes,
                pCmdReq->reqParams.importObject.pCredentialList,
                &(pCmdRsp->rspParams.importObject.objectHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_OBJECT__
    case SMP_CC_UNINIT_OBJECT                            :
        CALL_SMP_API(NanoROOT, uninitObject,
                pCmdReq->reqParams.unintObject.moduleHandle,
                pCmdReq->reqParams.unintObject.tokenHandle,
                pCmdReq->reqParams.unintObject.objectHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_EVICT_OBJECT__
    case SMP_CC_EVICT_OBJECT                                :
        pCmdRsp->returnCode = CALL_SMP_API(NanoROOT, evictObject,
                pCmdReq->reqParams.evictObject.moduleHandle,
                pCmdReq->reqParams.evictObject.pObjectId,
                pCmdReq->reqParams.evictObject.pAttributes
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PERSIST_OBJECT__
    case SMP_CC_PERSIST_OBJECT:
        pCmdRsp->returnCode = CALL_SMP_API(NanoROOT, persistObject,
                pCmdReq->reqParams.persistObject.moduleHandle,
                pCmdReq->reqParams.persistObject.keyHandle,
                pCmdReq->reqParams.persistObject.pObjectId
        );
        break;
#endif


#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS__
    case SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS             :
        CALL_SMP_API(NanoROOT, associateObjectCredentials,
                pCmdReq->reqParams.associateObjectCredentials.moduleHandle,
                pCmdReq->reqParams.associateObjectCredentials.tokenHandle,
                pCmdReq->reqParams.associateObjectCredentials.objectHandle,
                pCmdReq->reqParams.associateObjectCredentials.pCredentialsList
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY__
    case SMP_CC_VERIFY                                   :
        CALL_SMP_API(NanoROOT, verify,
                pCmdReq->reqParams.verify.moduleHandle,
                pCmdReq->reqParams.verify.tokenHandle,
                pCmdReq->reqParams.verify.keyHandle,
                pCmdReq->reqParams.verify.pMechanism,
                pCmdReq->reqParams.verify.pDigest,
                pCmdReq->reqParams.verify.pSignature,
                &(pCmdRsp->rspParams.verify.signatureValid)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
    case SMP_CC_VERIFY_INIT                              :
        CALL_SMP_API(NanoROOT, verifyInit,
                pCmdReq->reqParams.verifyInit.moduleHandle,
                pCmdReq->reqParams.verifyInit.tokenHandle,
                pCmdReq->reqParams.verifyInit.keyHandle,
                pCmdReq->reqParams.verifyInit.pMechanism,
                &(pCmdRsp->rspParams.verifyInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_UPDATE__
    case SMP_CC_VERIFY_UPDATE                            :
        CALL_SMP_API(NanoROOT, verifyUpdate,
                pCmdReq->reqParams.verifyUpdate.moduleHandle,
                pCmdReq->reqParams.verifyUpdate.tokenHandle,
                pCmdReq->reqParams.verifyUpdate.keyHandle,
                pCmdReq->reqParams.verifyUpdate.pBuffer,
                pCmdReq->reqParams.verifyUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_FINAL__
    case SMP_CC_VERIFY_FINAL                             :
        CALL_SMP_API(NanoROOT, verifyFinal,
                pCmdReq->reqParams.verifyFinal.moduleHandle,
                pCmdReq->reqParams.verifyFinal.tokenHandle,
                pCmdReq->reqParams.verifyFinal.keyHandle,
                pCmdReq->reqParams.verifyFinal.opContext,
                pCmdReq->reqParams.verifyFinal.pSignature,
                &(pCmdRsp->rspParams.verifyFinal.signatureValid)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
    case SMP_CC_SIGN_DIGEST                              :
        CALL_SMP_API(NanoROOT, signDigest,
                pCmdReq->reqParams.signDigest.moduleHandle,
                pCmdReq->reqParams.signDigest.tokenHandle,
                pCmdReq->reqParams.signDigest.keyHandle,
                pCmdReq->reqParams.signDigest.pDigest,
                pCmdReq->reqParams.signDigest.type,
                pCmdReq->reqParams.signDigest.pSignatureAttributes,
                &(pCmdRsp->rspParams.signDigest.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
    case SMP_CC_SIGN_BUFFER                              :
        CALL_SMP_API(NanoROOT, signBuffer,
                pCmdReq->reqParams.signBuffer.moduleHandle,
                pCmdReq->reqParams.signBuffer.tokenHandle,
                pCmdReq->reqParams.signBuffer.keyHandle,
                pCmdReq->reqParams.signBuffer.pDigest,
                pCmdReq->reqParams.signBuffer.type,
                pCmdReq->reqParams.signBuffer.pSignatureAttributes,
                &(pCmdRsp->rspParams.signBuffer.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
    case SMP_CC_SIGN_INIT                                :
        CALL_SMP_API(NanoROOT, signInit,
                pCmdReq->reqParams.signInit.moduleHandle,
                pCmdReq->reqParams.signInit.tokenHandle,
                pCmdReq->reqParams.signInit.keyHandle,
                pCmdReq->reqParams.signInit.type,
                pCmdReq->reqParams.signInit.pSignatureAttributes,
                &(pCmdRsp->rspParams.signInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_UPDATE__
    case SMP_CC_SIGN_UPDATE                              :
        CALL_SMP_API(NanoROOT, signUpdate,
                pCmdReq->reqParams.signUpdate.moduleHandle,
                pCmdReq->reqParams.signUpdate.tokenHandle,
                pCmdReq->reqParams.signUpdate.keyHandle,
                pCmdReq->reqParams.signUpdate.pBuffer,
                pCmdReq->reqParams.signUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_FINAL__
    case SMP_CC_SIGN_FINAL                               :
        CALL_SMP_API(NanoROOT, signFinal,
                pCmdReq->reqParams.signFinal.moduleHandle,
                pCmdReq->reqParams.signFinal.tokenHandle,
                pCmdReq->reqParams.signFinal.keyHandle,
                pCmdReq->reqParams.signFinal.opContext,
                &(pCmdRsp->rspParams.signFinal.pSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_SIGNATURE_BUFFER__
    case SMP_CC_FREE_SIGNATURE_BUFFER                    :
        CALL_SMP_API(NanoROOT, freeSignatureBuffer,
                pCmdReq->reqParams.freeSignature.ppSignature
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT__
    case SMP_CC_ENCRYPT                                  :
        CALL_SMP_API(NanoROOT, encrypt,
                pCmdReq->reqParams.encrypt.moduleHandle,
                pCmdReq->reqParams.encrypt.tokenHandle,
                pCmdReq->reqParams.encrypt.keyHandle,
                pCmdReq->reqParams.encrypt.pMechanism,
                pCmdReq->reqParams.encrypt.pBuffer,
                &(pCmdRsp->rspParams.encrypt.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_INIT__
    case SMP_CC_ENCRYPT_INIT                             :
        CALL_SMP_API(NanoROOT, encryptInit,
                pCmdReq->reqParams.encryptInit.moduleHandle,
                pCmdReq->reqParams.encryptInit.tokenHandle,
                pCmdReq->reqParams.encryptInit.keyHandle,
                pCmdReq->reqParams.encryptInit.pMechanism,
                &(pCmdRsp->rspParams.encryptInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_UPDATE__
    case SMP_CC_ENCRYPT_UPDATE                           :
        CALL_SMP_API(NanoROOT, encryptUpdate,
                pCmdReq->reqParams.encryptUpdate.moduleHandle,
                pCmdReq->reqParams.encryptUpdate.tokenHandle,
                pCmdReq->reqParams.encryptUpdate.keyHandle,
                pCmdReq->reqParams.encryptUpdate.pBuffer,
                pCmdReq->reqParams.encryptUpdate.opContext,
                &(pCmdRsp->rspParams.encryptUpdate.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_FINAL__
    case SMP_CC_ENCRYPT_FINAL                            :
        CALL_SMP_API(NanoROOT, encryptFinal,
                pCmdReq->reqParams.encryptFinal.moduleHandle,
                pCmdReq->reqParams.encryptFinal.tokenHandle,
                pCmdReq->reqParams.encryptFinal.keyHandle,
                pCmdReq->reqParams.encryptFinal.opContext,
                &(pCmdRsp->rspParams.encryptFinal.cipherBuffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT__
    case SMP_CC_DECRYPT                                  :
        CALL_SMP_API(NanoROOT, decrypt,
                pCmdReq->reqParams.decrypt.moduleHandle,
                pCmdReq->reqParams.decrypt.tokenHandle,
                pCmdReq->reqParams.decrypt.keyHandle,
                pCmdReq->reqParams.decrypt.pMechanism,
                pCmdReq->reqParams.decrypt.pCipherBuffer,
                &(pCmdRsp->rspParams.decryptUpdate.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_INIT__
    case SMP_CC_DECRYPT_INIT                             :
        CALL_SMP_API(NanoROOT, decryptInit,
                pCmdReq->reqParams.decryptInit.moduleHandle,
                pCmdReq->reqParams.decryptInit.tokenHandle,
                pCmdReq->reqParams.decryptInit.keyHandle,
                pCmdReq->reqParams.decryptInit.pMechanism,
                &(pCmdRsp->rspParams.decryptInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_UPDATE__
    case SMP_CC_DECRYPT_UPDATE                           :
        CALL_SMP_API(NanoROOT, decryptUpdate,
                pCmdReq->reqParams.decryptUpdate.moduleHandle,
                pCmdReq->reqParams.decryptUpdate.tokenHandle,
                pCmdReq->reqParams.decryptUpdate.keyHandle,
                pCmdReq->reqParams.decryptUpdate.pCipherBuffer,
                pCmdReq->reqParams.decryptUpdate.opContext,
                &(pCmdRsp->rspParams.decryptUpdate.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_FINAL__
    case SMP_CC_DECRYPT_FINAL                            :
        CALL_SMP_API(NanoROOT, decryptFinal,
                pCmdReq->reqParams.decryptFinal.moduleHandle,
                pCmdReq->reqParams.decryptFinal.tokenHandle,
                pCmdReq->reqParams.decryptFinal.keyHandle,
                pCmdReq->reqParams.decryptFinal.opContext,
                &(pCmdRsp->rspParams.decryptFinal.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST__
    case SMP_CC_DIGEST                                   :
        CALL_SMP_API(NanoROOT, digest,
                pCmdReq->reqParams.digest.moduleHandle,
                pCmdReq->reqParams.digest.tokenHandle,
                pCmdReq->reqParams.digest.pMechanism,
                pCmdReq->reqParams.digest.pInputBuffer,
                &(pCmdRsp->rspParams.digest.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_INIT__
    case SMP_CC_DIGEST_INIT                              :
        CALL_SMP_API(NanoROOT, digestInit,
                pCmdReq->reqParams.digestInit.moduleHandle,
                pCmdReq->reqParams.digestInit.tokenHandle,
                pCmdReq->reqParams.digestInit.pMechanism,
                &(pCmdRsp->rspParams.digestInit.opContext)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_UPDATE__
    case SMP_CC_DIGEST_UPDATE                            :
        CALL_SMP_API(NanoROOT, digestUpdate,
                pCmdReq->reqParams.digestUpdate.moduleHandle,
                pCmdReq->reqParams.digestUpdate.tokenHandle,
                pCmdReq->reqParams.digestUpdate.pBuffer,
                pCmdReq->reqParams.digestUpdate.opContext
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_FINAL__
    case SMP_CC_DIGEST_FINAL                             :
        CALL_SMP_API(NanoROOT, digestFinal,
                pCmdReq->reqParams.digestFinal.moduleHandle,
                pCmdReq->reqParams.digestFinal.tokenHandle,
                pCmdReq->reqParams.digestFinal.opContext,
                &(pCmdRsp->rspParams.digestFinal.buffer)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TRUSTED_DATA__
    case SMP_CC_GET_TRUSTED_DATA                         :
        CALL_SMP_API(NanoROOT, getTrustedData,
                pCmdReq->reqParams.getTrustedData.moduleHandle,
                pCmdReq->reqParams.getTrustedData.tokenHandle,
                pCmdReq->reqParams.getTrustedData.trustedDataType,
                pCmdReq->reqParams.getTrustedData.pTrustedDataInfo,
                &(pCmdRsp->rspParams.getTrustedData.dataValue)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UPDATE_TRUSTED_DATA__
    case SMP_CC_UPDATE_TRUSTED_DATA                      :
        CALL_SMP_API(NanoROOT, updateTrustedData,
                pCmdReq->reqParams.updateTrustedData.moduleHandle,
                pCmdReq->reqParams.updateTrustedData.tokenHandle,
                pCmdReq->reqParams.updateTrustedData.trustedDataType,
                pCmdReq->reqParams.updateTrustedData.pTrustedDataInfo,
                pCmdReq->reqParams.updateTrustedData.trustedDataOp,
                pCmdReq->reqParams.updateTrustedData.pDataValue,
                &(pCmdRsp->rspParams.updateTrustedData.updatedDataValue)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
    case SMP_CC_SEAL_WITH_TRUSTED_DATA                   :
        CALL_SMP_API(NanoROOT, sealWithTrustedData,
                pCmdReq->reqParams.sealWithTrustedData.moduleHandle,
                pCmdReq->reqParams.sealWithTrustedData.tokenHandle,
                pCmdReq->reqParams.sealWithTrustedData.pRequestTemplate,
                pCmdReq->reqParams.sealWithTrustedData.pDataToSeal,
                &(pCmdRsp->rspParams.sealWithTrustedData.dataOut)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
    case SMP_CC_UNSEAL_WITH_TRUSTED_DATA                 :
        CALL_SMP_API(NanoROOT, unsealWithTrustedData,
                pCmdReq->reqParams.unsealWithTrustedData.moduleHandle,
                pCmdReq->reqParams.unsealWithTrustedData.tokenHandle,
                pCmdReq->reqParams.unsealWithTrustedData.pRequestTemplate,
                pCmdReq->reqParams.unsealWithTrustedData.pDataToUnseal,
                &(pCmdRsp->rspParams.unsealWithTrustedData.dataOut)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
    case SMP_CC_SET_POLICY_STORAGE                       :
        CALL_SMP_API(NanoROOT, setPolicyStorage,
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
        CALL_SMP_API(NanoROOT, getPolicyStorage,
                pCmdReq->reqParams.getPolicyStorage.moduleHandle,
                pCmdReq->reqParams.getPolicyStorage.tokenHandle,
                pCmdReq->reqParams.getPolicyStorage.objectHandle,
                pCmdReq->reqParams.getPolicyStorage.pOpAttributes,
                &(pCmdRsp->rspParams.getPolicyStorage.data)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS__
    case SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS :
        CALL_SMP_API(NanoROOT, getCertificateRequestValidationAttrs,
                pCmdReq->reqParams.getCertReqValAttrs.moduleHandle,
                pCmdReq->reqParams.getCertReqValAttrs.tokenHandle,
                pCmdReq->reqParams.getCertReqValAttrs.objectHandle,
                &(pCmdRsp->rspParams.getCertReqValAttrs.blob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNWRAP_KEY_VALIDATED_SECRET__
    case SMP_CC_UNWRAP_KEY_VALIDATED_SECRET              :
        CALL_SMP_API(NanoROOT, unWrapKeyValidatedSecret,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.moduleHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.tokenHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.objectHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.rtKeyHandle,
                pCmdReq->reqParams.unwrapKeyValidatedSecret.pBlob,
                &(pCmdRsp->rspParams.unwrapKeyValidatedSecret.secret)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SMP_GET_QUOTE__
    case SMP_CC_SMP_GET_QUOTE                            :
        CALL_SMP_API(NanoROOT, getQuote,
                pCmdReq->reqParams.getQuote.moduleHandle,
                pCmdReq->reqParams.getQuote.tokenHandle,
                pCmdReq->reqParams.getQuote.objectHandle,
                pCmdReq->reqParams.getQuote.type,
                pCmdReq->reqParams.getQuote.pInfo,
                pCmdReq->reqParams.getQuote.pNonce,
                pCmdReq->reqParams.getQuote.pReserved,
                &(pCmdRsp->rspParams.getQuote.quoteData),
                &(pCmdRsp->rspParams.getQuote.pQuoteSignature)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_ASYMMETRIC_KEY__
    case SMP_CC_CREATE_ASYMMETRIC_KEY                    :
        CALL_SMP_API(NanoROOT, createAsymmetricKey,
                pCmdReq->reqParams.createAsymmetricKey.moduleHandle,
                pCmdReq->reqParams.createAsymmetricKey.tokenHandle,
                pCmdReq->reqParams.createAsymmetricKey.pKeyAttributes,
                pCmdReq->reqParams.createAsymmetricKey.initFlag,
                &(pCmdRsp->rspParams.createAsymmetricKey.objectIdOut),
                &(pCmdRsp->rspParams.createAsymmetricKey.objectAttributes),
                &(pCmdRsp->rspParams.createAsymmetricKey.keyHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PRIVATE_KEY__
    case SMP_CC_GET_PRIVATE_KEY_BLOB                           :
        CALL_SMP_API(NanoROOT, getPrivateKeyBlob,
                pCmdReq->reqParams.getPrivateKeyBlob.moduleHandle,
                pCmdReq->reqParams.getPrivateKeyBlob.tokenHandle,
                pCmdReq->reqParams.getPrivateKeyBlob.objectHandle,
                &(pCmdRsp->rspParams.getPrivateKeyBlob.privkeyBlob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__
    case SMP_CC_GET_PUBLIC_KEY                           :
        CALL_SMP_API(NanoROOT, getPublicKey,
                pCmdReq->reqParams.getPublicKey.moduleHandle,
                pCmdReq->reqParams.getPublicKey.tokenHandle,
                pCmdReq->reqParams.getPublicKey.objectHandle,
                &(pCmdRsp->rspParams.getPublicKey.pPublicKey)
        );
        break;
    case SMP_CC_GET_PUBLIC_KEY_BLOB                           :
        CALL_SMP_API(NanoROOT, getPublicKeyBlob,
                pCmdReq->reqParams.getPublicKeyBlob.moduleHandle,
                pCmdReq->reqParams.getPublicKeyBlob.tokenHandle,
                pCmdReq->reqParams.getPublicKeyBlob.objectHandle,
                &(pCmdRsp->rspParams.getPublicKeyBlob.pubkeyBlob)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DUPLICATEKEY__
    case SMP_CC_DUPLICATEKEY:
        CALL_SMP_API(NanoROOT, duplicateKey,
                pCmdReq->reqParams.duplicateKey.moduleHandle,
                pCmdReq->reqParams.duplicateKey.tokenHandle,
                pCmdReq->reqParams.duplicateKey.keyHandle,
                pCmdReq->reqParams.duplicateKey.pMechanism,
                &(pCmdRsp->rspParams.duplicateKey.duplicateBuf)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_IMPORTDUPLICATEKEY__
    case SMP_CC_IMPORTDUPLICATEKEY:
        CALL_SMP_API(NanoROOT, importDuplicateKey,
                pCmdReq->reqParams.importDuplicateKey.moduleHandle,
                pCmdReq->reqParams.importDuplicateKey.tokenHandle,
                pCmdReq->reqParams.importDuplicateKey.pKeyAttributes,
                pCmdReq->reqParams.importDuplicateKey.pDuplicateBuf,
                &(pCmdRsp->rspParams.importDuplicateKey.objectAttributes),
                &(pCmdRsp->rspParams.importDuplicateKey.keyHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_PUBLIC_KEY__
    case SMP_CC_FREE_PUBLIC_KEY                          :
        CALL_SMP_API(NanoROOT, freePublicKey,
                pCmdReq->reqParams.freePublicKey.ppPublicKey
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_SYMMETRIC_KEY__
    case SMP_CC_CREATE_SYMMETRIC_KEY                     :
        CALL_SMP_API(NanoROOT, createSymmetricKey,
                pCmdReq->reqParams.createSymmetricKey.moduleHandle,
                pCmdReq->reqParams.createSymmetricKey.tokenHandle,
                pCmdReq->reqParams.createSymmetricKey.pAttributeKey,
                pCmdReq->reqParams.createSymmetricKey.initFlag,
                &(pCmdRsp->rspParams.createSymmetricKey.objectIdOut),
                &(pCmdRsp->rspParams.createSymmetricKey.objectAttributes),
                &(pCmdRsp->rspParams.createSymmetricKey.keyHandle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_EXPORT_OBJECT__
    case SMP_CC_EXPORT_OBJECT                            :
        CALL_SMP_API(NanoROOT, exportObject,
                pCmdReq->reqParams.exportObject.moduleHandle,
                pCmdReq->reqParams.exportObject.tokenHandle,
                pCmdReq->reqParams.exportObject.objectHandle,
                &(pCmdRsp->rspParams.exportObject.exportedObject)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_SERIALIZE_OBJECT__
    case SMP_CC_SERIALIZE_OBJECT                         :
        CALL_SMP_API(NanoROOT, serializeObject,
                pCmdReq->reqParams.serializeObject.moduleHandle,
                pCmdReq->reqParams.serializeObject.tokenHandle,
                pCmdReq->reqParams.serializeObject.objectId,
                &(pCmdRsp->rspParams.serializeObject.serializedObject)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_OBJECT__
    case SMP_CC_CREATE_OBJECT                            :
        CALL_SMP_API(NanoROOT, createObject,
                pCmdReq->reqParams.createObject.moduleHandle,
                pCmdReq->reqParams.createObject.tokenHandle,
                pCmdReq->reqParams.createObject.pObjectAttributes,
                &(pCmdRsp->rspParams.createObject.objectAttributesOut),
                &(pCmdRsp->rspParams.createObject.objectIdOut),
                &(pCmdRsp->rspParams.createObject.handle)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
    case SMP_CC_DELETE_OBJECT                            :
        CALL_SMP_API(NanoROOT, deleteObject,
                pCmdReq->reqParams.deleteObject.moduleHandle,
                pCmdReq->reqParams.deleteObject.tokenHandle,
                pCmdReq->reqParams.deleteObject.objectHandle
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_PURGE_OBJECT__
    case SMP_CC_PURGE_OBJECT                             :
        CALL_SMP_API(NanoROOT, purgeObject,
                pCmdReq->reqParams.deleteObject.moduleHandle,
                pCmdReq->reqParams.deleteObject.tokenHandle,
                pCmdReq->reqParams.deleteObject.objectHandle
        );
        break;

#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE__
    case SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE            :
        CALL_SMP_API(NanoROOT, getRootOfTrustCertificate,
                pCmdReq->reqParams.getRootOfTrustCertificate.moduleHandle,
                pCmdReq->reqParams.getRootOfTrustCertificate.objectId,
                pCmdReq->reqParams.getRootOfTrustCertificate.type,
                &(pCmdRsp->rspParams.getRootOfTrustCertificate.certificate)
        );
        break;
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE__
    case SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE             :
        CALL_SMP_API(NanoROOT, getRootOfTrustKeyHandle,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.moduleHandle,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.objectId,
                pCmdReq->reqParams.getRootOfTrustKeyHandle.type,
                &(pCmdRsp->rspParams.getRootOfTrustKeyHandle.keyHandle)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_LAST_ERROR__
    case SMP_CC_GET_LAST_ERROR:
        CALL_SMP_API(NanoROOT, getLastError,
                pCmdReq->reqParams.getLastError.moduleHandle,
                pCmdReq->reqParams.getLastError.tokenHandle,
                pCmdReq->reqParams.getLastError.objectHandle,
                &(pCmdRsp->rspParams.getLastError.errorAttributes)
        );
        break;
#endif
#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST__
    case SMP_CC_SELF_TEST:
        CALL_SMP_API(NanoROOT, selfTest,
                pCmdReq->reqParams.selfTest.moduleHandle,
                pCmdReq->reqParams.selfTest.pTestRequest,
                &(pCmdRsp->rspParams.selfTest.testResponse)
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

#endif /* #if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__)) */
