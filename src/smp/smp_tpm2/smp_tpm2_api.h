/*
 * smp_tpm2_api.h
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
@file       smp_tpm2_api.h
@brief      NanoSMP module feature API header for TPM2.
@details    This header file contains enumerations, and function
            declarations for feature APIs implemented by the TPM2 NanoSMP.
*/

#ifndef __SMP_TPM2_API_HEADER__
#define __SMP_TPM2_API_HEADER__

/*------------------------------------------------------------------*/
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__))

#include "../smp.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************
   General Structure Definitions
****************************************************************/


/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @ingroup smp_functions
 * @brief This function returns list of modules controlled by this SMP.
 * @details Function to retrieve list of modules controlled by this SMP. @p pModuleAttributes can be optionally provided to filter this list to
 * just those modules that have the specified attributes 
 * @param [in]  pModuleAttributes Optional pointer to a list of capabilities that will be used to select module ids of specific attributes  
 * @param [out]  pModuleIdList Pointer to list of module Ids. SMP_TPM2_freeModuleList should be called to free resources allocated to the the TAP_EntityList
 * @return OK on success
 * @return ERR_NULL_POINTER if @p pModuleIdList is NULL
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getModuleList,
        TAP_ModuleCapabilityAttributes *pModuleAttributes,
        TAP_EntityList *pModuleIdList
);

/**
 * @ingroup smp_functions
 * @brief This function frees resources allocated to TAP_EntityList returned in SMP_TPM2_getModuleList. 
 * @details Function to release resouces allocated to TAP_EntityList in an earlier SMP_TPM2_getModuleList call. 
 * @param [in]  pModuleIdList Pointer to a TAP_EntityList.  
 * @return OK on success
 * @return ERR_NULL_POINTER if @p pModuleList is NULL 
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, freeModuleList,
        TAP_EntityList *pModuleList
);

/**
 * @ingroup smp_functions
 * @brief Function to retrieve SMP capabilities 
 * @details Function to get SMP capabilities such as Vendor information, Firmware version, Token types supported. @p pCapabilitySelectAttributes
 * can be used to limit the attributes returned to the caller. For example setting TAP_ATTR_FIRMWARE_VERSION in @p pCapabilitySelectAttributes will
 * result in only the Firmware version being returned in the @p pModuleCapabilities.
 * @param [in]  moduleId 
 * @param [in]  pCapabilitySelectAttributes 
 * @param [out]  pModuleCapabilities 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
);

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_CAPABILITY__
MSTATUS SMP_API(TPM2, getCapability,
    TAP_ModuleId moduleId,
    TAP_ModuleCapPropertyAttributes *pCapPropertySelectCriterion,
    TAP_ModuleCapPropertyList *pModuleCapProperties
);
#endif /*#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_CAPABILITY__*/

/**
 * @ingroup smp_functions
 * @brief Function to return the number of slots referenced by @p moduleHandle 
 * @details Function to return the number of slots supported by this module. The slot list is returned it @p pModuleSlotList.
 *      The returned slot list can be used to provision module slots with tokens.
 * @param [in]  moduleHandle Specifies the module handle to be queried 
 * @param [in]  pModuleSlotList Pointer to module slot list structure 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getModuleSlots,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleSlotList *pModuleSlotList
);

/**
 * @ingroup smp_functions
 * @brief Function to return list of token IDs.
 * @details Function to return list of tokens of the specified @p tokenType or having attributes specified through @p pTokenAttributes.
 * @param [in] moduleHandle Specifies the module handle to be queried. 
 * @param [in] tokenType Optional token type 
 * @param [in] pTokenAttributes 
 * @param [out] pTokenIdList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes *pTokenAttributes,
        TAP_EntityList *pTokenIdList
);

/**
 * @ingroup smp_functions
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenType 
 * @param [in]  tokenId
 * @param [in]  pCapabilitySelectAttributes
 * @param [in]  pTokenCapabilities
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getTokenInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenId tokenId,
        TAP_TokenCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_TokenCapabilityAttributes  *pTokenCapabilities
);

/**
 * @ingroup smp_functions
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pObjectAttributes 
 * @param [in]  pObjectIdList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectId 
 * @param [in]  pCapabilitySelectAttributes
 * @param [in]  pObjectCapabilities 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getObjectInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_ObjectCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectCapabilities
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pModuleProvisionAttributes 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, provisionModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pModuleProvisionAttributes 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, resetModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pTokenProvisionAttributes 
 * @param [in]  pTokenIdList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, provisionTokens,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes,
        TAP_EntityList *pTokenIdList
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pModuleAttribute 
 * @param [in]  pCredentials 
 * @param [in]  pModuleHandle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes* pModuleAttribute,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, uninitModule,
        TAP_ModuleHandle moduleHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pEntityCredentials 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, associateModuleCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_EntityCredentialList *pEntityCredentials
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  pTokenAttributes 
 * @param [in]  tokenId 
 * @param [in]  pCredentials
 * @param [in]  pTokenHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle * pTokenHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pCredentials 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, associateTokenCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_EntityCredentialList *pCredentials
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectIdIn 
 * @param [in]  pObjectAttribute
 * @param [in]  pCredentials 
 * @param [in]  pObjectHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, initObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle,
        TAP_ObjectId *pObjectIdOut
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pObjectAttributes 
 * @param [in]  pCredentials 
 * @param [in]  pObjectHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, importObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Blob *pObjectBuffer,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectCapabilityAttributes *pObjectAttributesOut,
        TAP_ObjectHandle *pObjectHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, uninitObject,
        TAP_ModuleHandle ModuleHandle,
        TAP_TokenHandle TokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  ObjectHandle 
 * @param [in]  pCredentials
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, associateObjectCredentials,
        TAP_ModuleHandle ModuleHandle,
        TAP_TokenHandle TokenHandle,
        TAP_ObjectHandle ObjectHandle,
        TAP_EntityCredentialList *pCredentials
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  keyHandle 
 * @param [in]  pMechanism
 * @param [in]  pDigest 
 * @param [in]  pSignature
 * @param [in]  pSignatureValid 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, verify,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pDigest,
        TAP_Signature *pSignature,
        byteBoolean *pSignatureValid
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  keyHandle 
 * @param [in]  pDigest
 * @param [in]  type 
 * @param [in]  pSignatureAttributes
 * @param [in]  ppSignature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, signDigest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pDigest,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  keyHandle 
 * @param [in]  pDigest
 * @param [in]  type 
 * @param [in]  pSignatureAttributes
 * @param [in]  ppSignature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, signBuffer,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  ppSignature 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, freeSignatureBuffer,
        TAP_Signature **ppSignature
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  keyHandle 
 * @param [in]  pMechanism
 * @param [in]  pBuffer 
 * @param [in]  pCipherBuffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, encrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pBuffer,
        TAP_Buffer *pCipherBuffer
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  keyHandle 
 * @param [in]  pMechanism
 * @param [in]  pCipherBuffer 
 * @param [in]  pBuffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, decrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pCipherBuffer,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pMechanism 
 * @param [in]  pInputBuffer 
 * @param [in]  pBuffer 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, digest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pInputBuffer,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pRngRequest 
 * @param [in]  bytesRequested
 * @param [in]  pRandom 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest,
        ubyte4 bytesRequested,
        TAP_Buffer *pRandom
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pRngRequest 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, stirRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest
);

MOC_EXTERN MSTATUS SMP_API(TPM2, getTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_Buffer *pDataValue
);

MOC_EXTERN MSTATUS SMP_API(TPM2, updateTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrusteDataInfo,
        TAP_TRUSTED_DATA_OPERATION trustedDataOp,
        TAP_Buffer *pDataValue,
        TAP_Buffer *pUpdatedDataValue
);

MOC_EXTERN MSTATUS SMP_API(TPM2, sealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToSeal,
        TAP_Buffer *pDataOut
);

MOC_EXTERN MSTATUS SMP_API(TPM2, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
);

MOC_EXTERN MSTATUS SMP_API(TPM2, setPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PolicyStorageAttributes *pPolicyAttributes,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
);

MOC_EXTERN MSTATUS SMP_API(TPM2, getPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
);

MOC_EXTERN MSTATUS SMP_API(TPM2, getCertificateRequestValidationAttrs,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_CSRAttributes *pCSRattributes,
        TAP_Blob *pBlob
);

MOC_EXTERN MSTATUS SMP_API(TPM2, unWrapKeyValidatedSecret,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectHandle rtKeyHandle,
        TAP_Blob *pBlob, 
        TAP_Buffer *pSecret
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectHandle 
 * @param [in]  type 
 * @param [in]  pInfo
 * @param [in]  pNonce
 * @param [in]  pReserved
 * @param [in]  pQuoteData
 * @param [in]  ppQuoteSignature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getQuote,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_TRUSTED_DATA_TYPE type,
        TAP_TrustedDataInfo *pInfo,
        TAP_Buffer *pNonce,
        TAP_AttributeList *pReserved,
        TAP_Blob *pQuoteData,
        TAP_Signature **ppQuoteSignature
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  pObjectAttributes 
 * @param [in]  pObjectIdList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, createAsymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pKeyAttributes,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectHandle 
 * @param [in]  ppPublicKey
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppPublicKey
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  ppPublicKey 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, freePublicKey,
        TAP_PublicKey **ppPublicKey
);

/**
 * @ingroup smp_functions
 * @brief This API returns the private key blob of the asymmetric key identified by @p objectHandle.
 * @details This API exports the private key blob of the asymmetric key identified by @p objectHandle in SMP native format.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [out]  pPrivateBlob Pointer to the blob structure
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getPrivateKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPrivateBlob
);

/**
 * @ingroup smp_functions
 * @brief This API returns the public key blob of the asymmetric key identified by @p objectHandle.
 * @details This API exports the public key blob of the asymmetric key identified by @p objectHandle in SMP native format, used in the SMP_DuplicateKey API.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context 
 * @param [in]  objectHandle Handle to the Object Context 
 * @param [out]  pPublicBlob Pointer to the blob structure
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getPublicKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPublicBlob
);


/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectId 
 * @param [in]  pAttributeKey
 * @param [in]  initFlag 
 * @param [out]  pObjectAttributes
 * @param [out]  pKeyHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, createSymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pAttributeKey,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectId 
 * @param [in]  pAttributeKey
 * @param [out]  pObjectAttributes
 * @param [out]  pKeyHandle 
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, importExternalKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pAttributeKey,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

MOC_EXTERN MSTATUS SMP_API(TPM2, exportObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pExportedObject
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  tokenHandle 
 * @param [in]  objectId 
 * @param [in]  pSerializedObject
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, serializeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_Blob *pSerializedObject
);

MOC_EXTERN MSTATUS SMP_API(TPM2, createObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectAttributesOut,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectHandle *pHandle
);

MSTATUS SMP_API(TPM2, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_AUTH_CONTEXT_PROPERTY authContext
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  objectId 
 * @param [in]  type
 * @param [in]  pCertificate
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getRootOfTrustCertificate,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Blob *pCertificate
);

/**
 * @ingroup smp_functions
 * @brief 
 * @details 
 * @param [in]  moduleHandle 
 * @param [in]  objectId 
 * @param [in]  type
 * @param [in]  pKeyHandle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, getRootOfTrustKeyHandle,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE rootOfTrustType,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief This API duplicates the object identified by @p keyHandle under new parent 
 * @details This API creates serialized duplicate keyblob of an existing asymmetric key under a new parent. This blob can be imported to another SMP/TPM2.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Object Context
 * @param [in]  pNewPubKey public key blob of the new parent
 * @param [out] pDuplicateBuf duplicated buffer of the object identified by keyHandle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, DuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Blob *pNewPubkey,
        TAP_Buffer *pDuplicateBuf
);

/**
 * @ingroup smp_functions
 * @brief This API imports and creates an asymmetric key in SMP for the duplicate blob at @p pDuplicateBuf 
 * @details This API imports and creates an asymmetric key in SMP for the duplicate blob
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pKeyAttributes Optional, attributes containing properties of key
 *              to create. 
 * @param [in]  pDuplicateBuf duplicated buffer of the object to be imported
 * @param [out] pObjectAttributes Optional pointer to attributes that contains
 *              attributes of the newly created key
 * @param [out]  pKeyHandle Context handle to the key
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, ImportDuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributes,
        TAP_Buffer *pDuplicateBuf,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief This API evicts key object in the SMP from the object ID index specified using @p pObjectId
 * @details This API evicts key object in the SMP from the object ID index
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   pObjectId Object ID index where object is to be evicted from
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, evictObject,
        TAP_ModuleHandle moduleHandle,
        TAP_Buffer *pObjectId,
        TAP_AttributeList *pAttributes
);

/**
 * @ingroup smp_functions
 * @brief This API persists a key object in the SMP at the object ID index specified using @p pObjectId
 * @details This API persists a key object in the SMP at the object ID index
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   keyHandle Handle to the key object
 * @param [in]   pObjectId Object ID index where object is to be persisted
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, persistObject,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pObjectId
);

/**
 * @ingroup smp_functions
 * @brief
 * @details
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   pTestRequest
 * @param [out]  pTestResponse
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, selfTest,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestResponseAttributes *pTestResponse
);

/**
 * @ingroup smp_functions
 * @brief
 * @details
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   pTestRequest
 * @param [in]   testContext
 * @param [out]  pTestResponse
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(TPM2, selfTestPoll,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestContext testContext,
        TAP_TestResponseAttributes *pTestResponse
);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_TPM2__ */
#endif /* __SMP_TPM2_API_HEADER__ */

