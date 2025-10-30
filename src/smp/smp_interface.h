
/**
 * @file smp_interface.h
 *
 * @brief This file contains the NanoSMP component interface exposed to TAP
 * @details This file contains the NanoSMP component interface exposed to TAP
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_MOCANA_SMP__
 *
 * Copyright (c) Mocana Corp 2017. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#ifndef __SMP_INTERFACE_HEADER__
#define __SMP_INTERFACE_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/mstdlib.h"

#if defined(__ENABLE_MOCANA_SMP__)
#include "smp_cc.h"
#include "../tap/tap_smp.h"

/***************************************************************
   Constant Definitions
****************************************************************/

#define SMP_VERSION_MAJOR   0x0002
#define SMP_VERSION_MINOR   0x0000

typedef struct {
    TAP_ModuleCapabilityAttributes *pModuleAttributes;
} SMP_getModuleListCmdParams;

typedef struct {
    TAP_EntityList moduleList;
} SMP_getModuleListRspParams;

typedef struct {
    TAP_EntityList *pModuleList;
} SMP_freeModuleListCmdParams;

typedef struct {
    TAP_ModuleId moduleId;
    TAP_ModuleCapabilityAttributes *pCapabilitySelectCriterion;
} SMP_getModuleInfoCmdParams;

typedef struct {
    TAP_ModuleCapabilityAttributes moduleCapabilties;
} SMP_getModuleInfoRspParams;

typedef struct {
    TAP_ModuleId moduleId;
    TAP_ModuleCapPropertyAttributes *pCapabilitySelectRange;
} SMP_getModuleCapabilityCmdParams;

typedef struct {
    TAP_ModuleCapPropertyList moduleCapabilities;
} SMP_getModuleCapabilityRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
} SMP_getModuleSlotsCmdParams;

typedef struct {
    TAP_ModuleSlotList moduleSlotList;
} SMP_getModuleSlotsRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TOKEN_TYPE tokenType;
    TAP_TokenCapabilityAttributes *pTokenAttributes;
} SMP_getTokenListCmdParams;

typedef struct {
    TAP_EntityList tokenIdList;
} SMP_getTokenListRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TOKEN_TYPE tokenType;
    TAP_TokenId tokenId;
    TAP_TokenCapabilityAttributes *pCapabilitySelectAttributes;
} SMP_getTokenInfoCmdParams;

typedef struct {
    TAP_TokenCapabilityAttributes tokenAttributes;
} SMP_getTokenInfoRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectCapabilityAttributes *pObjectAttributes;
} SMP_getObjectListCmdParams;

typedef struct {
    TAP_EntityList objectIdList;
} SMP_getObjectListRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_ObjectId objectId;
    TAP_ObjectCapabilityAttributes *pCapabilitySelectAttributes;
} SMP_getObjectInfoCmdParams;

typedef struct {
    TAP_ObjectCapabilityAttributes objectAttributes;
} SMP_getObjectInfoRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_ModuleProvisionAttributes *pModuleProvisionAttributes;
} SMP_provisionModuleCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_ModuleProvisionAttributes *pModuleProvisionAttributes;
} SMP_resetModuleCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenProvisionAttributes *pTokenProvisionAttributes;
} SMP_provisionTokensCmdParams;

typedef struct {
    TAP_EntityList tokenIdList;
} SMP_provisionTokensRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_TokenProvisionAttributes *pTokenProvisionAttributes;
} SMP_resetTokenCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_TokenProvisionAttributes *pTokenProvisionAttributes;
} SMP_deleteTokenCmdParams;

typedef struct {
    TAP_ModuleId moduleId;
    TAP_ModuleCapabilityAttributes *pModuleAttributes;
    TAP_CredentialList *pCredentialList;
} SMP_initModuleCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
} SMP_initModuleRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
} SMP_uninitModuleCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_EntityCredentialList *pEntityCredentialList;
} SMP_associateModuleCredentialsCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenCapabilityAttributes *pTokenAttributes;
    TAP_TokenId tokenId;
    TAP_EntityCredentialList *pCredentialList;
} SMP_initTokenCmdParams;

typedef struct {
    TAP_TokenHandle tokenHandle;
} SMP_initTokenRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
} SMP_uninitTokenCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_EntityCredentialList *pCredentialList;
} SMP_associateTokenCredentialsCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectId objectIdIn;
    TAP_ObjectCapabilityAttributes *pObjectAttributes;
    TAP_EntityCredentialList *pCredentialList;
} SMP_initObjectCmdParams;

typedef struct {
    TAP_ObjectHandle objectHandle;
    TAP_ObjectId objectIdOut;
    TAP_ObjectAttributes objectAttributes;
} SMP_initObjectRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_Blob *pBlob;
    TAP_ObjectCapabilityAttributes *pObjectAttributes;
    TAP_EntityCredentialList *pCredentialList;
} SMP_importObjectCmdParams;

typedef struct {
    TAP_ObjectCapabilityAttributes objectAttributesOut;
    TAP_ObjectHandle objectHandle;
} SMP_importObjectRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_uninitObjectCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_EntityCredentialList *pCredentialsList;
} SMP_associateObjectCredentialsCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
    TAP_Buffer *pDigest;
    TAP_Signature *pSignature;
} SMP_verifyCmdParams;

typedef struct {
    byteBoolean signatureValid;
} SMP_verifyRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
} SMP_verifyInitCmdParams;

typedef struct {
    TAP_OperationHandle opContext;
} SMP_verifyInitRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pBuffer;
    TAP_OperationHandle opContext;
} SMP_verifyUpdateCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_OperationHandle opContext;
    TAP_Signature *pSignature;
} SMP_verifyFinalCmdParams;

typedef struct {
    byteBoolean signatureValid;
} SMP_verifyFinalRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pDigest;
    TAP_SIG_SCHEME type;
    TAP_SignAttributes *pSignatureAttributes;
} SMP_signDigestCmdParams;

typedef struct {
    TAP_Signature *pSignature;
} SMP_signDigestRspParams;

typedef SMP_signDigestCmdParams SMP_signBufferCmdParams;
typedef SMP_signDigestRspParams SMP_signBufferRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_SIG_SCHEME type;
    TAP_SignAttributes *pSignatureAttributes;
} SMP_signInitCmdParams;

typedef struct {
    TAP_OperationHandle opContext;
} SMP_signInitRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pBuffer;
    TAP_OperationHandle opContext;
} SMP_signUpdateCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_OperationHandle opContext;
} SMP_signFinalCmdParams;

typedef struct {
    TAP_Signature *pSignature;
} SMP_signFinalRspParams;

typedef struct {
    TAP_Signature **ppSignature;
} SMP_freeSignatureBufferCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
    TAP_Buffer *pBuffer;
} SMP_encryptCmdParams;

typedef struct {
    TAP_Buffer cipherBuffer;
} SMP_encryptRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
} SMP_encryptInitCmdParams;

typedef struct {
    TAP_OperationHandle opContext;
} SMP_encryptInitRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pBuffer;
    TAP_OperationHandle opContext;
} SMP_encryptUpdateCmdParams;

typedef struct {
    TAP_Buffer cipherBuffer;
} SMP_encryptUpdateRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_OperationHandle opContext;
} SMP_encryptFinalCmdParams;

typedef struct {
    TAP_Buffer cipherBuffer;
} SMP_encryptFinalRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
    TAP_Buffer *pCipherBuffer;
} SMP_decryptCmdParams;

typedef struct {
    TAP_Buffer buffer;
} SMP_decryptRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_MechanismAttributes *pMechanism;
} SMP_decryptInitCmdParams;

typedef struct {
    TAP_OperationHandle opContext;
} SMP_decryptInitRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pCipherBuffer;
    TAP_OperationHandle opContext;
} SMP_decryptUpdateCmdParams;

typedef struct {
    TAP_Buffer buffer;
} SMP_decryptUpdateRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_OperationHandle opContext;
} SMP_decryptFinalCmdParams;

typedef struct {
    TAP_Buffer buffer;
} SMP_decryptFinalRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_MechanismAttributes *pMechanism;
    TAP_Buffer *pInputBuffer;
} SMP_digestCmdParams;

typedef struct {
    TAP_Buffer buffer;
} SMP_digestRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_MechanismAttributes *pMechanism;
} SMP_digestInitCmdParams;

typedef struct {
    TAP_OperationHandle opContext;
} SMP_digestInitRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_OperationHandle opContext;
    TAP_Buffer *pBuffer;
} SMP_digestUpdateCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_OperationHandle opContext;
} SMP_digestFinalCmdParams;

typedef struct {
    TAP_Buffer buffer;
} SMP_digestFinalRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_RngAttributes *pRngRequest;
    ubyte4 bytesRequested;
} SMP_getRandomCmdParams;

typedef struct {
    TAP_Buffer random;
} SMP_getRandomRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_RngAttributes *pRngRequest;
} SMP_stirRandomCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_TRUSTED_DATA_TYPE trustedDataType;
    TAP_TrustedDataInfo *pTrustedDataInfo;
} SMP_getTrustedDataCmdParams;

typedef struct {
    TAP_Buffer dataValue;
} SMP_getTrustedDataRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_TRUSTED_DATA_TYPE trustedDataType;
    TAP_TrustedDataInfo *pTrustedDataInfo;
    TAP_TRUSTED_DATA_OPERATION trustedDataOp;
    TAP_Buffer *pDataValue;
} SMP_updateTrustedDataCmdParams;

typedef struct {
    TAP_Buffer updatedDataValue;
} SMP_updateTrustedDataRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_SealAttributes *pRequestTemplate;
    TAP_Buffer *pDataToSeal;
} SMP_sealWithTrustedDataCmdParams;

typedef struct {
    TAP_Buffer dataOut;
} SMP_sealWithTrustedDataRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_SealAttributes *pRequestTemplate;
    TAP_Buffer *pDataToUnseal;
} SMP_unsealWithTrustedDataCmdParams;

typedef struct {
    TAP_Buffer dataOut;
} SMP_unsealWithTrustedDataRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_PolicyStorageAttributes *pPolicyAttributes;
    TAP_OperationAttributes *pOpAttributes;
    TAP_Buffer *pData;
} SMP_setPolicyStorageCmdParams;

typedef struct {
    TAP_Buffer data;
} SMP_setPolicyStorageRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_OperationAttributes *pOpAttributes;
} SMP_getPolicyStorageCmdParams;

typedef struct {
    TAP_Buffer data;
} SMP_getPolicyStorageRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_CSRAttributes *pCSRattributes;
} SMP_getCertificateRequestValidationAttrsCmdParams;

typedef struct {
    TAP_Blob blob;
} SMP_getCertificateRequestValidationAttrsRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_ObjectHandle rtKeyHandle;
    TAP_Blob *pBlob;
} SMP_unWrapKeyValidatedSecretCmdParams;

typedef struct {
    TAP_Buffer secret;
} SMP_unWrapKeyValidatedSecretRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_TRUSTED_DATA_TYPE type;
    TAP_TrustedDataInfo *pInfo;
    TAP_Buffer *pNonce;
    TAP_AttributeList *pReserved;
} SMP_getQuoteCmdParams;

typedef struct {
    TAP_Blob quoteData;
    TAP_Signature *pQuoteSignature;
} SMP_getQuoteRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectId objectId;
    TAP_KeyAttributes *pKeyAttributes;
    byteBoolean initFlag;
} SMP_createAsymmetricKeyCmdParams;

typedef struct {
    TAP_ObjectId objectIdOut;
    TAP_ObjectAttributes objectAttributes;
    TAP_ObjectHandle keyHandle;
} SMP_createAsymmetricKeyRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_getPublicKeyCmdParams;

typedef struct {
    TAP_PublicKey *pPublicKey;
} SMP_getPublicKeyRspParams;

typedef struct {
    TAP_PublicKey **ppPublicKey;
} SMP_freePublicKeyCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_getPrivateKeyBlobCmdParams;

typedef struct {
    TAP_Blob privkeyBlob ;
} SMP_getPrivateKeyBlobRspParams ;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_getPublicKeyBlobCmdParams;

typedef struct {
    TAP_Blob pubkeyBlob ;
} SMP_getPublicKeyBlobRspParams ;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Blob *pNewPubkey;
    TAP_MechanismAttributes *pMechanism;
} SMP_duplicateKeyCmdParams;

typedef struct {
    TAP_Buffer duplicateBuf;
} SMP_duplicateKeyRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_KeyAttributes *pKeyAttributes;
    TAP_Buffer *pDuplicateBuf;
} SMP_ImportDuplicateKeyCmdParams;

typedef struct {
    TAP_ObjectAttributes objectAttributes;
    TAP_ObjectHandle keyHandle;
} SMP_ImportDuplicateKeyRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectId objectId;
    TAP_KeyAttributes *pAttributeKey;
    byteBoolean initFlag;
} SMP_createSymmetricKeyCmdParams;

typedef struct {
    TAP_ObjectId objectIdOut;
    TAP_ObjectCapabilityAttributes objectAttributes;
    TAP_ObjectHandle keyHandle;
} SMP_createSymmetricKeyRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_exportObjectCmdParams;

typedef struct {
    TAP_Blob exportedObject;
} SMP_exportObjectRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectId objectId;
} SMP_serializeObjectCmdParams;

typedef struct {
    TAP_Blob serializedObject;
} SMP_serializeObjectRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectId objectIdIn;
    TAP_KeyAttributes *pObjectAttributes;
} SMP_createObjectCmdParams;

typedef struct {
    TAP_ObjectCapabilityAttributes objectAttributesOut;
    TAP_ObjectId objectIdOut;
    TAP_ObjectHandle handle;
} SMP_createObjectRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_AUTH_CONTEXT_PROPERTY authContext;
} SMP_deleteObjectCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_Buffer *pObjectId;
    TAP_AttributeList *pAttributes;
} SMP_evictObjectCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_ObjectHandle keyHandle;
    TAP_Buffer *pObjectId;
} SMP_persistObjectCmdParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_ObjectId objectId;
    TAP_ROOT_OF_TRUST_TYPE type;
} SMP_getRootOfTrustCertificateCmdParams;

typedef struct {
    TAP_Blob certificate;
} SMP_getRootOfTrustCertificateRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_ObjectId objectId;
    TAP_ROOT_OF_TRUST_TYPE type;
} SMP_getRootOfTrustKeyHandleCmdParams;

typedef struct {
    TAP_ObjectHandle keyHandle;
} SMP_getRootOfTrustKeyHandleRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
} SMP_getLastErrorCmdParams;

typedef struct {
    TAP_ErrorAttributes errorAttributes;
} SMP_getLastErrorRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TestRequestAttributes *pTestRequest;
} SMP_selfTestCmdParams;

typedef struct {
    TAP_TestResponseAttributes testResponse;
} SMP_selfTestRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TestRequestAttributes *pTestRequest;
    TAP_TestContext testContext;
} SMP_selfTestPollCmdParams;

typedef struct {
    TAP_TestResponseAttributes testResponse;
} SMP_selfTestPollRspParams;

typedef struct {
    TAP_ModuleHandle moduleHandle;
    TAP_TokenHandle tokenHandle;
    TAP_ObjectHandle objectHandle;
    TAP_OperationAttributes *pOpAttributes;
    TAP_PublicKey *pPublicKey;
} SMP_ECDHgenerateSharedSecretCmdParams;


typedef struct {
    TAP_Buffer secret;
} SMP_ECDHgenerateSharedSecretRspParams;

typedef union
{
    SMP_getModuleListCmdParams getModuleList;
    SMP_freeModuleListCmdParams freeModuleList;
    SMP_getModuleInfoCmdParams getModuleInfo;
    SMP_getModuleSlotsCmdParams getModuleSlots;
    SMP_getTokenListCmdParams getTokenList;
    SMP_getTokenInfoCmdParams getTokenInfo;
    SMP_getObjectListCmdParams getObjectList;
    SMP_getObjectInfoCmdParams getObjectInfo;
    SMP_provisionModuleCmdParams provisionModule;
    SMP_resetModuleCmdParams resetModule;
    SMP_provisionTokensCmdParams provisionTokens;
    SMP_resetTokenCmdParams resetToken;
    SMP_deleteTokenCmdParams deleteToken;
    SMP_initModuleCmdParams initModule;
    SMP_uninitModuleCmdParams uninitModule;
    SMP_associateModuleCredentialsCmdParams associateModuleCredentials;
    SMP_initTokenCmdParams initToken;
    SMP_uninitTokenCmdParams uninitToken;
    SMP_associateTokenCredentialsCmdParams associateTokenCredentials;
    SMP_initObjectCmdParams initObject;
    SMP_importObjectCmdParams importObject;
    SMP_uninitObjectCmdParams unintObject;
    SMP_associateObjectCredentialsCmdParams associateObjectCredentials;
    SMP_verifyCmdParams verify;
    SMP_verifyInitCmdParams verifyInit;
    SMP_verifyUpdateCmdParams verifyUpdate;
    SMP_verifyFinalCmdParams verifyFinal;
    SMP_signDigestCmdParams signDigest;
    SMP_signBufferCmdParams signBuffer;
    SMP_signInitCmdParams signInit;
    SMP_signUpdateCmdParams signUpdate;
    SMP_signFinalCmdParams signFinal;
    SMP_freeSignatureBufferCmdParams freeSignature;
    SMP_encryptCmdParams encrypt;
    SMP_encryptInitCmdParams encryptInit;
    SMP_encryptUpdateCmdParams encryptUpdate;
    SMP_encryptFinalCmdParams encryptFinal;
    SMP_decryptCmdParams decrypt;
    SMP_decryptInitCmdParams decryptInit;
    SMP_decryptUpdateCmdParams decryptUpdate;
    SMP_decryptFinalCmdParams decryptFinal;
    SMP_digestCmdParams digest;
    SMP_digestInitCmdParams digestInit;
    SMP_digestUpdateCmdParams digestUpdate;
    SMP_digestFinalCmdParams digestFinal;
    SMP_getRandomCmdParams getRandom;
    SMP_stirRandomCmdParams stirRandom;
    SMP_getTrustedDataCmdParams getTrustedData;
    SMP_updateTrustedDataCmdParams updateTrustedData;
    SMP_sealWithTrustedDataCmdParams sealWithTrustedData;
    SMP_unsealWithTrustedDataCmdParams unsealWithTrustedData;
    SMP_setPolicyStorageCmdParams setPolicyStorage;
    SMP_getPolicyStorageCmdParams getPolicyStorage;
    SMP_getCertificateRequestValidationAttrsCmdParams getCertReqValAttrs;
    SMP_unWrapKeyValidatedSecretCmdParams unwrapKeyValidatedSecret;
    SMP_getQuoteCmdParams getQuote;
    SMP_createAsymmetricKeyCmdParams createAsymmetricKey;
    SMP_getPublicKeyCmdParams getPublicKey;
    SMP_freePublicKeyCmdParams freePublicKey;
    SMP_getPublicKeyBlobCmdParams getPublicKeyBlob;
    SMP_duplicateKeyCmdParams duplicateKey;
    SMP_ImportDuplicateKeyCmdParams importDuplicateKey;
    SMP_createSymmetricKeyCmdParams createSymmetricKey;
    SMP_exportObjectCmdParams exportObject;
    SMP_serializeObjectCmdParams serializeObject;
    SMP_createObjectCmdParams createObject;
    SMP_deleteObjectCmdParams deleteObject;
    SMP_getRootOfTrustCertificateCmdParams getRootOfTrustCertificate;
    SMP_getRootOfTrustKeyHandleCmdParams getRootOfTrustKeyHandle;
    SMP_getModuleCapabilityCmdParams getModuleCapability;
    SMP_getLastErrorCmdParams getLastError;
    SMP_selfTestCmdParams selfTest;
    SMP_selfTestPollCmdParams selfTestPoll;
    SMP_ECDHgenerateSharedSecretCmdParams ECDH_generateSharedSecret;
    SMP_evictObjectCmdParams evictObject;
    SMP_persistObjectCmdParams persistObject;
    SMP_getPrivateKeyBlobCmdParams getPrivateKeyBlob;

} SMP_CmdReqParams;

typedef union
{
    SMP_getModuleListRspParams getModuleList;
    SMP_getModuleInfoRspParams getModuleInfo;
    SMP_getModuleSlotsRspParams getModuleSlots;
    SMP_getTokenListRspParams getTokenList;
    SMP_getTokenInfoRspParams getTokenInfo;
    SMP_getObjectListRspParams getObjectList;
    SMP_getObjectInfoRspParams getObjectInfo;
    SMP_provisionTokensRspParams provisionTokens;
    SMP_initModuleRspParams initModule;
    SMP_initTokenRspParams initToken;
    SMP_initObjectRspParams initObject;
    SMP_importObjectRspParams importObject;
    SMP_verifyRspParams verify;
    SMP_verifyInitRspParams verifyInit;
    SMP_verifyFinalRspParams verifyFinal;
    SMP_signDigestRspParams signDigest;
    SMP_signBufferRspParams signBuffer;
    SMP_signInitRspParams signInit;
    SMP_signFinalRspParams signFinal;
    SMP_encryptRspParams encrypt;
    SMP_encryptInitRspParams encryptInit;
    SMP_encryptUpdateRspParams encryptUpdate;
    SMP_encryptFinalRspParams encryptFinal;
    SMP_decryptRspParams decrypt;
    SMP_decryptInitRspParams decryptInit;
    SMP_decryptUpdateRspParams decryptUpdate;
    SMP_decryptFinalRspParams decryptFinal;
    SMP_digestRspParams digest;
    SMP_digestInitRspParams digestInit;
    SMP_digestFinalRspParams digestFinal;
    SMP_getRandomRspParams getRandom;
    SMP_getTrustedDataRspParams getTrustedData;
    SMP_updateTrustedDataRspParams updateTrustedData;
    SMP_sealWithTrustedDataRspParams sealWithTrustedData;
    SMP_unsealWithTrustedDataRspParams unsealWithTrustedData;
    SMP_getPolicyStorageRspParams getPolicyStorage;
    SMP_setPolicyStorageRspParams setPolicyStorage;
    SMP_getCertificateRequestValidationAttrsRspParams getCertReqValAttrs;
    SMP_unWrapKeyValidatedSecretRspParams unwrapKeyValidatedSecret;
    SMP_getQuoteRspParams getQuote;
    SMP_createAsymmetricKeyRspParams createAsymmetricKey;
    SMP_getPublicKeyRspParams getPublicKey;
    SMP_getPublicKeyBlobRspParams getPublicKeyBlob;
    SMP_duplicateKeyRspParams duplicateKey;
    SMP_ImportDuplicateKeyRspParams importDuplicateKey;
    SMP_createSymmetricKeyRspParams createSymmetricKey;
    SMP_exportObjectRspParams exportObject;
    SMP_serializeObjectRspParams serializeObject;
    SMP_createObjectRspParams createObject;
    SMP_getRootOfTrustCertificateRspParams getRootOfTrustCertificate;
    SMP_getRootOfTrustKeyHandleRspParams getRootOfTrustKeyHandle;
    SMP_getModuleCapabilityRspParams getModuleCapability;
    SMP_getLastErrorRspParams getLastError;
    SMP_selfTestRspParams selfTest;
    SMP_selfTestPollRspParams selfTestPoll;
    SMP_ECDHgenerateSharedSecretRspParams ECDH_generateSharedSecret;
    SMP_getPrivateKeyBlobRspParams getPrivateKeyBlob;

} SMP_CmdRspParams;

typedef struct
{
    SMP_CC           cmdCode;
    SMP_CmdReqParams reqParams;
} SMP_CmdReq;


typedef struct
{
    SMP_CC           cmdCode;
    MSTATUS          returnCode;
    SMP_CmdRspParams rspParams;
} SMP_CmdRsp;

/*
 * Include SMP specific interface header files here.
 */
#if defined (__ENABLE_MOCANA_NAME__)
#include "smp_name/smp_name_interface.h"
#endif

#if defined (__ENABLE_MOCANA_TPM2__)
#include "smp_tpm2/smp_tpm2_interface.h"
#endif

#if defined (__ENABLE_MOCANA_TPM__)
#include "smp_tpm12/smp_tpm12_interface.h"
#endif

#if defined (__ENABLE_MOCANA_GEMALTO__)
#include "smp_gemalto/smp_gemalto_interface.h"
#endif

#if defined (__ENABLE_MOCANA_SMP_PKCS11__)
#include "smp_pkcs11/smp_pkcs11_interface.h"
#endif

#if defined(__ENABLE_MOCANA_TEE__)
#include "smp_tee/smp_tee_interface.h"
#endif

#if defined(__ENABLE_MOCANA_SMP_NANOROOT__)
#ifndef __SMP_NANOROOT_INTERFACE_HEADER__
#include "smp_nanoroot/smp_nanoroot_interface.h"
#endif
#endif

#endif /* __ENABLE_MOCANA_SMP__ */
#endif /* __SMP_INTERFACE_HEADER__ */
