/*
 * smp_nanoroot_api.h
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
@file       smp_nanoroot_api.h
@ingroup    nanosmp_nanoroot
@brief      NanoSMP module feature API header for NanoROOT.
@details    This header file contains enumerations, and function
            declarations for feature APIs implemented by the NanoROOT NanoSMP.
@flags      This file requires that the following flags be defined:
    + \c \__ENABLE_MOCANA_SMP__
*/

#ifndef __SMP_NanoROOT_API_HEADER__
#define __SMP_NanoROOT_API_HEADER__

#if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__))

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mocana.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"

#include "smp/smp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup smp_functions
 * @brief This function returns list of modules controlled by this SMP.
 * @details Function to retrieve list of modules controlled by this SMP. @p pModuleAttributes can be optionally provided to filter this list to
 * just those modules that have the specified attributes.
 *
 * @param [in]  pModuleAttributes Optional pointer to a list of capabilities that will be used to select module identifiers with specific attributes
 *              <br>#TAP_ATTR_FIRMWARE_VERSION
 *              <br>#TAP_ATTR_VENDOR_INFO
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 * @param [out]  pModuleIdList Pointer to list of module Ids. SMP_NanoROOT_freeModuleList should be called to free resources allocated to the the TAP_EntityList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getModuleList,
        TAP_ModuleCapabilityAttributes *pModuleAttributes,
        TAP_EntityList *pModuleIdList
);

/**
 * @ingroup smp_functions
 * @brief This function frees resources allocated to TAP_EntityList returned in SMP_NanoROOT_getModuleList. 
 * @details Function to release resouces allocated to TAP_EntityList in an earlier SMP_NanoROOT_getModuleList call. 
 * @param [in]  pModuleIdList Pointer to a TAP_EntityList.  
 * @return OK on success
 * @return ERR_NULL_POINTER if @p pModuleList is NULL 
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, freeModuleList,
        TAP_EntityList *pModuleList
);

/**
 * @ingroup smp_functions
 * @brief Function to return a list of Token Identifiers
 * @details FUnction to return a list of tokens of the specified @p tokenType and/or having attributes specified through @p pTokenAttributes
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in] tokenType Optional Token type to use for selecting token identifiers
 * @param [in] pTokenAttributes Optional list of Token attributes to use for
 *             selecting Token identifiers. <br>Can be set from the following
 *             <br>#TAP_ATTR_CAPABILITY_CATEGORY
 *             <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [out] pTokenIdList Pointer to list of token identifiers returned.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_EntityList *pTokenIdList
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
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
);

/**
 * @ingroup smp_functions
 * @brief Function initializes the module context and returns a handle for future operations on the module.
 * @details Function initializes the module context and returns a handle for future operations on the module.
 *          The module for which the context is initialized is identified by the @p moduleId and verified
 *          against an optional @p pModuleAttribute.
 * @param [in]  moduleId Module identifier
 * @param [in]  pModuleAttribute Optional, attributes that can be used to verify module id
 *              <br>#TAP_ATTR_TOKEN_TYPE
 *              <br>#TAP_ATTR_FIRMWARE_VERSION
 *              <br>#TAP_ATTR_VENDOR_INFO
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 * @param [in]  pCredentials Pointer to credentials
 * @param [out]  pModuleHandle Pointer to the Module context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes* pModuleAttributes,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to free resources allocated to module context.
 * @details Function to free resources allocated to a previously initialized module context.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, uninitModule,
        TAP_ModuleHandle moduleHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to create a new token context.
 * @details Function to create a new token context. The token for which the
 *          context is uniquely indentified by @p tokenId and/or verfied against
 *          @p pTokenAttributes.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  pTokenAttributes Optional, attributes to specify the type of token to create
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [in]  tokenId Token identifier
 * @param [in]  pCredentials pointer to the credentials
 * @param [out]  pTokenHandle Pointer to the Token context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle *pTokenHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to free resources allocated to the token context.
 * @details Function to free resources allocated to the token context.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
);

/**
 * @ingroup smp_functions
 * @brief This API performs the seal operation on @p pDataToSeal with trusted data or extended seal attributes identified by @p pRequestTemplate
 * @details This API performs the seal operation on @p pDataToSeal with trusted data or extended seal attributes identified by @p pRequestTemplate
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pRequestTemplate Optional, attributes used for seal operation
 *              <br>#TAP_ATTR_CREDENTIAL
 *              <br>#TAP_ATTR_OBJECT_HANDLE
 *              <br>#TAP_ATTR_TRUSTED_DATA_TYPE
 *              <br>#TAP_ATTR_TRUSTED_DATA_INFO
 * @param [in]  pDataToSeal Pointer to data to seal
 * @param [out] pDataOut Pointer to buffer containing sealed data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, sealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToSeal,
        TAP_Buffer *pDataOut
);

/**
 * @ingroup smp_functions
 * @brief This API performs the unseal operation on @p pDataToUnseal with trusted data or extended seal attributes identified by @p pRequestTemplate
 * @details This API performs the unseal operation on @p pDataToUnseal with trusted data or extended seal attributes identified by @p pRequestTemplate
 *
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pRequestTemplate Optional, attributes used for unseal operation.
 *              <br>Can be set to the following
 *              <br>#TAP_ATTR_CREDENTIAL
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 *              <br>#TAP_ATTR_PERMISSION
 * @param [in]  pDataToUnseal Pointer to data to unseal
 * @param [out] pDataOut Pointer to buffer containing unsealed data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
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
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getPrivateKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPrivateBlob
);

/**
 * @ingroup smp_functions
 * @brief This API returns the public key of the asymmetric key identified by @p objectHandle.
 * @details This API returns the public key of the asymmetric key identified by @p objectHandle.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [out]  ppPublicKey Pointer to the public key structure
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppPublicKey
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
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getPublicKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPublicBlob
);

/**
 * @ingroup smp_functions
 * @brief Function to sign the input digest
 * @details Function to generate signature of the input @p pDigest using @p keyHandle.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pDigest Pointer digest buffer being signed
 * @param [in]  signScheme Signature scheme
 * @param [in]  pSignatureAttributes Optional
 * @param [out]  ppSignature Pointer to pointer to buffer containing signature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, signDigest,
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
 * @brief Function to sign the input buffer
 * @details Function to generate signature of the input @p pBuffer using @p keyHandle
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pBuffer Pointer to buffer to be signed
 * @param [in]  signScheme Signature scheme
 * @param [in]  pSignatureAttributes Optional, attribute to select hash algorithm to digest the input buffer.
 * @param [out]  ppSignature Pointer to pointer to buffer containing signature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, signBuffer,
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
 * @brief This API creates a Asymmetric key as described by @p pKeyAttributes and/or @p objectId.
 * @details This API creates a Asymmetric key. The keys object context will also be created and returned in @p pKeyHandle.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pKeyAttributes Optional, attributes containing properties of key
 *              to create. <br>Can be a set from following
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_KEY_USAGE
 *              <br>#TAP_ATTR_KEY_SIZE
 *              <br>#TAP_ATTR_CURVE
 *              <br>#TAP_ATTR_ENC_SCHEME
 *              <br>#TAP_ATTR_SIG_SCHEME
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 * @param [in]  initFlag Hint to SMP provider to keep the newly key loaded
 * @param [out] pObjectIdOut ObjectId for the object created if 8 bytes or less.
 * @param [out] pObjectAttributes Optional pointer to attributes that contains
 *              attributes of the newly created key
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_KEY_USAGE
 *              <br>#TAP_ATTR_KEY_SIZE
 *              <br>#TAP_ATTR_CURVE
 *              <br>#TAP_ATTR_ENC_SCHEME
 *              <br>#TAP_ATTR_SIG_SCHEME
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 * @param [out]  pKeyHandle Context handle to the key
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, createAsymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributes,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief This API creates an object and corresponding context, as described by @p pObjectAttributes and returns the context handle in @p pHandle.
 * @details This API creates an object and corresponding context, as described by @p pObjectAttributes and returns the context handle in @p pHandle.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 ^ @param [in]  pKeyAttributeList Key attributes.
 * @param [in]  pKeyObjectAttributes Attributes used to create the object context.
 *              <br>Can be set to following
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @param [out]  pObjectIdOut ObjectId for the object created if 8 bytes or less.
 * @param [out]  pHandle Context handle to the object
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, createObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectHandle *pHandle
);

/**
 * @ingroup smp_functions
 * @brief This API deletes the object and corresponding context, identified by @p objectHandle
 * @details This API deletes the object and corresponding context, identified by @p objectHandle
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to create a new object context.
 * @details Function to create a new object. The object for which the context is
 *          created is uniquely identified by @p objectIdIn and/or verified against
 *          attributes specified in @p pObjectAttributes.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectIdIn Optional objectId. An ID  passed in via attributes will take precedence.
 * @param [in]  pObjectAttributes Optional
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [in]  pCredentials Optional
 * @param [out]  pObjectHandle Handle to the Object Contex
 * @param [out]  pObjectIdOut Pointer to initialized object identifier if 8 bytes or less.
 * @param [out] pObjectAttributesOut Optional pointer to attributes that contains
 *              attributes of the newly created key
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_KEY_SIZE
 *              <br>#TAP_ATTR_CURVE
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, initObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributesOut
);

/**
 * @ingroup smp_functions
 * @brief Function to free resources allocated to the object context.
 * @details Function to free resources allocated to the object context.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, uninitObject,
        TAP_ModuleHandle ModuleHandle,
        TAP_TokenHandle TokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief Function returns the list of object identifiers for the specified @p tokenHandle
 * @details Function returns the list of object identifiers for the specified @p tokenHandle
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pObjectAttributes Optional, attributes used to select
 *              specific object identifiers to be returned in @p pObjectIdList.
 *              <br>Can be set to
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [out]  pObjectIdList Pointer to Object identifiers list returned.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(NanoROOT, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_MOCANA_SMP__ && __ENABLE_MOCANA_SMP_NANOROOT__ */
#endif /* __SMP_NanoROOT_API_HEADER__ */

