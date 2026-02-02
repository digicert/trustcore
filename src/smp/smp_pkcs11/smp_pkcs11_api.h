/*
 * smp_pkcs11_api.h
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
@file       smp_pkcs11_api.h
@ingroup    nanosmp_tree
@brief      NanoSMP module feature API header for PKCS11.
@details    This header file contains enumerations, and function
            declarations for feature APIs implemented by the PKCS11 NanoSMP.
@flags      This file requires that the following flags be defined:
    + \c \__ENABLE_DIGICERT_SMP__
*/

#ifndef __SMP_PKCS11_API_HEADER__
#define __SMP_PKCS11_API_HEADER__

/*------------------------------------------------------------------*/
#include "../../asn1/mocasn1.h"
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"

/*! @cond */
#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_PKCS11__))
/*! @endcond */

#include "../smp.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS PKCS11_init(
        TAP_ConfigInfo *pConfigInfo
);

MOC_EXTERN MSTATUS PKCS11_deInit(
        void
);

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
 * @param [out]  pModuleIdList Pointer to list of module Ids. SMP_PKCS11_freeModuleList should be called to free resources allocated to the the TAP_EntityList
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getModuleList,
        TAP_ModuleCapabilityAttributes *pModuleAttributes,
        TAP_EntityList *pModuleIdList
);

/**
 * @ingroup smp_functions
 * @brief This function frees resources allocated to @p pModuleList
 * @details Function to release resouces allocated to @p pModuleList
 * @param [in]  pModuleIdList Pointer to a TAP_EntityList.
 * @return OK on success
 * @return ERR_NULL_POINTER if @p pModuleList is NULL
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, freeModuleList,
        TAP_EntityList *pModuleList
);

/**
 * @ingroup smp_functions
 * @brief Function to retrieve SMP capabilities
 * @details Function to get SMP capabilities such as Vendor information, Firmware version, Token types supported. @p pCapabilitySelectAttributes
 * can be used to limit the attributes returned to the caller. For example setting TAP_ATTR_FIRMWARE_VERSION in @p pCapabilitySelectAttributes will
 * result in only the Firmware version being returned in the @p pModuleCapabilities.
 * @param [in]  moduleId Module identifier to be queried
 * @param [in]  pCapabilitySelectAttributes Optional filter attributes to select module capabilities to be returned.
 *              It can take attributes from the following list
 *              <br>#TAP_ATTR_TOKEN_TYPE
 *              <br>#TAP_ATTR_FIRMWARE_VERSION
 *              <br>#TAP_ATTR_VENDOR_INFO
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 * @param [out]  pModuleCapabilities Module capabilities to be returned.
 *               <br>Attributes from the following list will be returned
 *               <br>#TAP_ATTR_TOKEN_TYPE
 *               <br>#TAP_ATTR_FIRMWARE_VERSION
 *               <br>#TAP_ATTR_VENDOR_INFO
 *               <br>#TAP_ATTR_CAPABILITY_CATEGORY
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
);

/**
 * @ingroup smp_functions
 * @brief Function to return the number of slots referenced by @p moduleHandle.
 * @details Function to return the number of slots referenced by @p moduleHandle. The slot list is returned it @p pModuleSlotList.
 *          The returned slot list can be used to provision module slots with tokens.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [out]  pModuleSlotList Pointer to slot list
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getModuleSlots,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleSlotList *pModuleSlotList
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_EntityList *pTokenIdList
);

/**
 * @ingroup smp_functions
 * @brief Function to get list of token attributes for the specified token identifier.
 * @details Function to get list of token attributes specified by @p tokenId.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenType Optional Token type
 * @param [in]  tokenId Token Identifier to query
 * @param [in]  pCapabilitySelectAttributes Optional list of Token attributes
 *              to use for selecting token identifiers.
 *              <br>Can be set from the following
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [out] pTokenCapabilities Pointer to list of token capabilities returned.
 *              <br>#TAP_ATTR_CAPABILITY_CATEGORY
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getTokenInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenId tokenId,
        TAP_TokenCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_TokenCapabilityAttributes  *pTokenCapabilities
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
);

/**
 * @ingroup smp_functions
 * @brief Function to get object attributes for the specified @p tokenHandle
 * @details Function to get object attributes for the specified @p tokenHandle
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pCapabilitySelectAttributes Optional, attributes used to select
 *              specific object capabilities to be returned in @p pObjectCapabilities
 *              <br>Can be set to
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @param [out]  pObjectCapabilities Pointer to Object capabilities returned.
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getObjectInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectCapabilities
);

/**
 * @ingroup smp_functions
 * @brief Function to provision this module for use.
 * @details Function to provision this module for use.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  pModuleProvisionAttributes
 *              <br>#TAP_ATTR_MODULE_PROVISION_TYPE
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, provisionModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
);

/**
 * @ingroup smp_functions
 * @brief Function to reset module for reprovisioning.
 * @details
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  pModuleProvisionAttributes
 *              <br>#TAP_ATTR_MODULE_PROVISION_TYPE
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, resetModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
);

/**
 * @ingroup smp_functions
 * @brief Function to provision a single token or all tokens on this module.
 * @details Function to provision a single token or all tokens on this module. If a token of
 *          a specific token type and/or on a particular slot id is desired provide
 *          TAP_ATTR_TOKEN_TYPE and/or TAP_ATTR_SLOT_ID in the @p pTokenProvisionAttributes.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  pTokenProvisionAttributes
 *              <br>#TAP_ATTR_TOKEN_TYPE
 *              <br>#TAP_ATTR_SLOT_ID
 *              <br>#TAP_ATTR_MODULE_PROVISION_TYPE
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @param [out]  pTokenIdList Pointer to list of Token identifiers
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, provisionTokens,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes,
        TAP_EntityList *pTokenIdList
);

/**
 * @ingroup smp_functions
 * @brief Function to reset specified @p tokenHandle
 * @details Function to reset specified @p tokenHandle. It clears the associated objects and
 *          resets the credentials. If a new token type is desired, TAP_ATTR_TOKEN_TYPE should be
 *          specified in @p pTokenProvisionAttributes.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pTokenProvisionAttributes Optional, attributes to specify token capabilities and
 *              credentials
 *              <br>#TAP_ATTR_TOKEN_TYPE
 *              <br>#TAP_ATTR_MODULE_PROVISION_TYPE
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, resetToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes
);

/**
 * @ingroup smp_functions
 * @brief Function to delete specified @p tokenHandle
 * @details Function to delete specified @p tokenHandle.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pTokenAttributes Optional, attributes to specify credentials needed, slot id
 *              and token type can be used for verification.
 *              <br>#TAP_ATTR_SLOT_ID
 *              <br>#TAP_ATTR_TOKEN_TYPE
 *              <br>#TAP_ATTR_MODULE_PROVISION_TYPE
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, deleteToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, initModule,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, uninitModule,
        TAP_ModuleHandle moduleHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to associate access @p pCredentials with the specified module context
 * @details Function to associate access credentials with @p moduleHandle.
 *          This function can be used to associate credentials with a moduleHandle created without credentials.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  pEntityCredentials Pointer to credentials to associate with this Module context.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, associateModuleCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_EntityCredentialList *pEntityCredentials
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, initToken,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
);

/**
 * @ingroup smp_functions
 * @brief Function to associate access @p pCredentials with the specified token context
 * @details Function to associate access credentials with @p tokenHandle.
 *          This function can be used to associate credentials with tokenHandle created without credentials.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pCredentials Pointer to credentials to be associated with this Token context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, associateTokenCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_EntityCredentialList *pCredentials
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, initObject,
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
 * @brief Function to create a new object context from the input object buffer.
 * @details Function to create a new object context from the input object buffer
 *          @p pObjectBuffer. Optional @p pObjectAttributes may contain additional
 *          information to create this object.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pObjectBuffer Pointer to blob from which the object will be created.
 * @param [in]  pObjectAttributes Optional, attributes that specify additional information needed to import this object
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 * @param [in]  pCredentials Optional, credentials needed to create the object in the secure element.
 * @param [out]  pObjectHandle Pointer to the Object context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, importObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Blob *pObjectBuffer,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, uninitObject,
        TAP_ModuleHandle ModuleHandle,
        TAP_TokenHandle TokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief This API evicts key object in the SMP from the object ID index specified using @p pObjectId
 * @details This API evicts key object in the SMP from the object ID index
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   pObjectId Object ID index where object is to be evicted from
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, evictObject,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, persistObject,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pObjectId
);

/**
 * @ingroup smp_functions
 * @brief This function can be used to associate credentials with objectHandle created without credentials.
 * @details This function can be used to associate credentials with objectHandle created without credentials.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  ObjectHandle Handle to the Object Context
 * @param [in]  pCredentials Pointer to the credential list to associate with the Object.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11,associateObjectCredentials,
        TAP_ModuleHandle ModuleHandle,
        TAP_TokenHandle TokenHandle,
        TAP_ObjectHandle ObjectHandle,
        TAP_EntityCredentialList *pCredentials
);

/**
 * @ingroup smp_functions
 * @brief Function to verify the signature on the input buffer.
 * @details Function to verify the signature on the input buffer. If the key
 *          associated with the keyHandle was created without a signature scheme
 *          it will be specified using the @p pMechanism attribute.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional, attributes to select the signature scheme
 *              and/or select hardware/software verification operation.
 *              <br>#TAP_ATTR_SIG_SCHEME
 *              <br>#TAP_ATTR_OP_EXEC_FLAG
 * @param [in]  pDigest Pointer to digest data whose signature is being verified
 * @param [in]  pSignature Pointer to signature buffer of the digest
 * @param [out]  pSignatureValid Pointer to buffer that will contain result of the
 *               verification operation.
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, verify,
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
 * @brief Function to initialize the multipart operational context for signature
 *        verification.
 * @details Function to initialize the multipart operational context for signature
 *          verification.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional, attributes to select the signature scheme and/or select hardware/software verification operation.
 *              <br>#TAP_ATTR_SIG_SCHEME
 *              <br>#TAP_ATTR_OP_EXEC_FLAG
 * @param [out]  pOpContext Handle to the Operational Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, verifyInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
);

/**
 * @ingroup smp_functions
 * @brief Function to update the operational context with content buffer
 *        for multipart signature verification operation.
 * @details Function to update the operational context with content buffer
 *        for multipart signature verification operation.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pBuffer Pointer to buffer to be added to the verification operation.
 * @param [in]  opContext Handle to the Operational Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, verifyUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
);

/**
 * @ingroup smp_functions
 * @brief Function to get the result of the multipart signature verification.
 * @details Function to get the result of the multipart signature verification
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  opContext Handle to the Operational Context
 * @param [in]  pSignature Pointer to signature structure
 * @param [out]  pSignatureValid Pointer to buffer containing result of the
 *               verification operation
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, verifyFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Signature *pSignature,
        byteBoolean *pSignatureValid
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, signDigest,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, signBuffer,
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
 * @brief Function to initialize the operational context for a multipart signature
 *        generation operation.
 * @details Function to initialize the operational context for signature
 *          generation.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  signScheme Signature scheme
 * @param [in]  pSignatureAttributes Optional, attribute to select hash algorithm to digest the input buffer.
 * @param [out]  pOpContext Pointer to operational context handle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, signInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_OperationHandle *pOpContext
);

/**
 * @ingroup smp_functions
 * @brief Function to update the multipart operational context with content buffer
 * @details Function to update the multipart operational context with content buffer
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pBuffer Pointer to buffer to be added to the sign operation
 * @param [in]  opContext Handle to the Operational Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, signUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
);

/**
 * @ingroup smp_functions
 * @brief Function to complete the multipart signature generation
 * @details Function to complete the multipart signature generation
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  ppSignature Pointer to pointer to buffer containing signature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, signFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Signature **ppSignature
);

/**
 * @ingroup smp_functions
 * @brief Function to release resources associated with signature buffer
 * @details Function to release resources associated with signature buffer
 * @param [in]  ppSignature Pointer to pointer to signature buffer to be freed
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, freeSignatureBuffer,
        TAP_Signature **ppSignature
);

/**
 * @ingroup smp_functions
 * @brief Function to encrypt input buffer
 * @details Function to encrypt input buffer @p pBuffer using @p keyHandle. The encrypted buffer is returned in @p pCipherBuffer.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional, attributes to select encryption scheme
 *              and hardware/software mode of operation. <br>Can be set to
 *              <br>#TAP_ATTR_ENC_SCHEME
 *              <br>#TAP_ATTR_OP_EXEC_FLAG
 *              <br>#TAP_ATTR_SYM_MODE
 * @param [in]  pBuffer Pointer to buffer being encrypted
 * @param [out]  pCipherBuffer Pointer to encrypted buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, encrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pBuffer,
        TAP_Buffer *pCipherBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to initialize operational context for multipart encrypt operation
 * @details Function to initialize operational context for multipart encrypt operation
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional, attributes to select encryption scheme
 *              and hardware/software mode of operation. <br>Can be set to
 *              <br>#TAP_ATTR_ENC_SCHEME
 *              <br>#TAP_ATTR_OP_EXEC_FLAG
 *              <br>#TAP_ATTR_SYM_MODE
 * @param [out]  pOpContext Pointer to Handle to the Operational Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, encryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
);

/**
 * @ingroup smp_functions
 * @brief Function to update the multipart operational context with data to encrypt.
 * @details Function to update the multipart operational context with data to encrypt.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pBuffer Pointer to data to encrypt
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  pCipherBuffer Pointer to encrypted buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11,encryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext,
        TAP_Buffer *pCipherBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to complete the multipart encrypt operation
 * @details Function to complete the multipart encrypt operation
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  pCipherBuffer Pointer to encrypted buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, encryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pCipherBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to decrypt cipher buffer
 * @details Function to decrypt cipher buffer and returns the decrypted buffer
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional, attributes to specify operation mode
 *              <br>#TAP_ATTR_SYM_MODE
 *              <br>#TAP_ATTR_ENC_SCHEME
 *              <br>#TAP_ATTR_OP_EXEC_FLAG
 * @param [in]  pCipherBuffer Pointer to the encrypted buffer
 * @param [out]  pBuffer Pointer to the decrypted data buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, decrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pCipherBuffer,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to initialize the operational context for a multipart
 *        decrypt operation.
 * @details Function to initialize the operational context for a multipart
 *          decrypt operation.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pMechanism Optional
 * @param [out]  pOpContext Pointer to operational context handle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, decryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
);

/**
 * @ingroup smp_functions
 * @brief Function to update content buffer on the operational context for a
 *        multipart decrypt operation
 * @details Function to update content buffer on the operational context for a
 *        multipart decrypt operation
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle Handle to the Key Context
 * @param [in]  pCipherBuffer Pointer to the encrypted buffer
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  pBuffer Pointer to decrypted data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, decryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pCipherBuffer,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to complete the multipart decrypt operation and get the final
 *        decrypted buffer
 * @details Function to complete the multipart decrypt operation and get the final
 *        decrypted buffer
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  keyHandle  Handle to the Key Context
 * @param [in]  pCipherBuffer Pointer to the encrypted buffer
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  pBuffer Pointer to decrypted data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, decryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to generate the digest value on the input buffer
 * @details Function to generate the digest value on the input buffer @p pInputBuffer
 *          and returns the digest in @p pBuffer. @p pMechanism can be used to
 *          specify the Hash algorithm to use.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pMechanism, attributes used to select specific hash function
 *              <br>#TAP_ATTR_HASH_ALG
 * @param [in]  pInputBuffer Pointer to buffer to digest
 * @param [out] pBuffer Pointer to buffer containing digest
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, digest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pInputBuffer,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief Function to initialize the operational context for a multipart
 *        digest generation.
 * @details Function to initialize the operational context for a multipart
 *          digest generation.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pMechanism Optional, attributes used to select specific hash function. <br>Can be set to
 *              <br>#TAP_ATTR_HASH_ALG
 * @param [out]  pOpContext Pointer to operational context handle
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, digestInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationHandle *pOpContext
);

/**
 * @ingroup smp_functions
 * @brief Function to update content buffer on the operational context for a
 *        multipart decrypt operation
 * @details Function to update content buffer on the operational context for a
 *        multipart decrypt operation
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pBuffer Pointer to data to be digested
 * @param [in]  opContext Handle to the Operational Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, digestUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationHandle opContext
);

/**
 * @ingroup smp_functions
 * @brief Function to complete the multipart digest operation and get the
 *        digest buffer
 * @details Function to complete the multipart digest operation and get the
 *        digest buffer
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  opContext Handle to the Operational Context
 * @param [out]  pBuffer Pointer to digest data buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, digestFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_OperationHandle opContext,
        TAP_Buffer *pBuffer
);

/**
 * @ingroup smp_functions
 * @brief This API returns the request number of random bytes from the secure element random number generator.
 * @details This API returns the request number of random bytes from the secure element random number generator.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pRngRequest Optional, attributes to influence random number operation.
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY - Possible values are TAP_CAPABILITY_RNG_TRNG, TAP_CAPABILITY_RNG_PRNG
 *              <br>#TAP_ATTR_RNG_PROPERTY - Possible values are TAP_RNG_PROPERTY_NO_ZERO
 *              <br>#TAP_ATTR_RNG_SEED
 * @param [in]  bytesRequested
 * @param [out]  pRandom
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest,
        ubyte4 bytesRequested,
        TAP_Buffer *pRandom
);

/**
 * @ingroup smp_functions
 * @brief This API is used to seed or add additional data to the random number generator.
 * @details This API is used to seed or add additional data to the random number generator.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pRngRequest Optional, attributes to influence the seed operation
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY - Possible values are TAP_CAPABILITY_RNG_TRNG, TAP_CAPABILITY_RNG_PRNG
 *              <br>#TAP_ATTR_RNG_SEED
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, stirRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest
);

/**
 * @ingroup smp_functions
 * @brief This API returns trusted data as identified by the @p trustedDataType and @p pTrustedDataInfo
 * @details This API returns trusted data as identified by the @p trustedDataType and @p pTrustedDataInfo
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  trustedDataType Trusted data type. <br>Can be set to
 *              <br>#TAP_TRUSTED_DATA_TYPE_MEASUREMENT
 *              <br>#TAP_TRUSTED_DATA_TYPE_IDENTIFIER
 *              <br>#TAP_TRUSTED_DATA_TYPE_REPORT
 *              <br>#TAP_TRUSTED_DATA_TYPE_TIME
 * @param [in]  pTrustedDataInfo Pointer to Trusted data specific structure
 * @param [out] pDataValue Pointer to output data value
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_Buffer *pDataValue
);

/**
 * @ingroup smp_functions
 * @brief This API returns trusted data as identified by the @p trustedDataType and @p pTrustedDataInfo
 * @details This API returns trusted data as identified by the @p trustedDataType and @p pTrustedDataInfo
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  trustedDataType Trusted data type. <br>Can be set to
 *              <br>#TAP_TRUSTED_DATA_TYPE_MEASUREMENT
 *              <br>#TAP_TRUSTED_DATA_TYPE_IDENTIFIER
 *              <br>#TAP_TRUSTED_DATA_TYPE_REPORT
 *              <br>#TAP_TRUSTED_DATA_TYPE_TIME
 * @param [in]  pTrustedDataInfo Pointer to Trusted data specific structure
 * @param [in]  trustedDataOp Trusted data operation. <br>Can be set to
 *              <br>#TAP_TRUSTED_DATA_OPERATION_WRITE
 *              <br>#TAP_TRUSTED_DATA_OPERATION_READ
 *              <br>#TAP_TRUSTED_DATA_OPERATION_UPDATE
 *              <br>#TAP_TRUSTED_DATA_OPERATION_RESET
 * @param [in]  pDataValue Pointer to data value to update
 * #param [out]  pUpdatedDataValue Pointer to buffer containing updated data value
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, updateTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_TRUSTED_DATA_OPERATION trustedDataOp,
        TAP_Buffer *pDataValue,
        TAP_Buffer *pUpdatedDataValue
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, sealWithTrustedData,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
);

/**
 * @ingroup smp_functions
 * @brief This API sets the data in a storage object which is saved on the secure element, with an associated policy.
 * @details This API sets the data in a storage object which is saved on the secure element, with an associated policy.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pPolicyAttributes Optional, attributes used for the set operation.
 *              <br>Can be set to the following
 *              <br>#TAP_ATTR_CREDENTIAL
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 *              <br>#TAP_ATTR_PERMISSION
 * @param [in]  pOpAttributes Attributes used to pass information for set operation.
 *              <br>Can be set to the following
 *              <br>#TAP_ATTR_WRITE_OP
 *              <br>#TAP_ATTR_OFFSET
 *              <br>#TAP_ATTR_SIZE
 * @param [in] pData Pointer to buffer containing data to save
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, setPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PolicyStorageAttributes *pPolicyAttributes,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
);

/**
 * @ingroup smp_functions
 * @brief This API gets the data in a storage object which is saved on the secure element, with an associated policy.
 * @details This API gets the data in a storage object which is saved on the secure element, with an associated policy.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pOpAttributes Attributes containing information on operational
 *              parameters. <br>Can be set to following
 *              <br>#TAP_ATTR_OFFSET
 *              <br>#TAP_ATTR_READ_OP
 *              <br>#TAP_ATTR_SIZE
 * @param [out] pData Pointer to buffer containing retrieved data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
);

/**
 * @ingroup smp_functions
 * @brief This API returns an encoded blob of data, that is required for extended validation during certificate generation for an object which can be used for attestation.
 * @details This API returns an encoded blob of data, that is required for extended validation during certificate generation for an object which can be used for attestation.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [out] pBlob Pointer to blob containing extended validation data
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getCertificateRequestValidationAttrs,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pBlob
);

/**
 * @ingroup smp_functions
 * @brief This API unwraps the secret encrypted using the root of trust key.
 * @details This API is used by an authorized user to invoke the secure element to unwrap the secret encrypted using the root of trust key.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  rtKeyHandle Context handle to the Root of Trust key
 * @param [in]  pBlob Pointer to blob containing the encrypted secret
 * @param [out]  pSecret Pointer to buffer containing unwrapped secret
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, unWrapKeyValidatedSecret,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectHandle rtKeyHandle,
        TAP_Blob *pBlob,
        TAP_Buffer *pSecret
);

/**
 * @ingroup smp_functions
 * @brief This API returns a signed quote of the secure elements trusted data.
 * @details This API returns a signed quote of the secure elements trusted data.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pQuotePayload Pointer to the Quote buffer
 * @param [in]  type Trusted data type
 *              <br>Can take values from the following
 *              <br>#TAP_TRUSTED_DATA_TYPE_MEASUREMENT
 *              <br>#TAP_TRUSTED_DATA_TYPE_IDENTIFIER
 *              <br>#TAP_TRUSTED_DATA_TYPE_REPORT
 *              <br>#TAP_TRUSTED_DATA_TYPE_TIME
 * @param [in]  pInfo Pointer to Trusted Data specific structure
 * @param [in]  pNonce Pointer to Nonce buffer
 * @param [in]  pReserved Optional, pointer to attributes
 * @param [out]  pQuoteData Pointer to resultant Quote blob
 * @param [out]  ppQuoteSignature Pointer to Quote signature
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getQuote,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, createAsymmetricKey,
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
 * @brief This API returns the public key of the asymmetric key identified by @p objectHandle.
 * @details This API returns the public key of the asymmetric key identified by @p objectHandle.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [out]  ppPublicKey Pointer to the public key structure
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppPublicKey
);

/**
 * @ingroup smp_functions
 * @brief This API free's the TAP_PublicKey structure returned by SMP_getPublicKey API.
 * @details This API free's the TAP_PublicKey structure returned by SMP_getPublicKey API.
 * @param [in]  ppPublicKey
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, freePublicKey,
        TAP_PublicKey **ppPublicKey
);

/**
 * @ingroup smp_functions
 * @brief This API creates a symmetric key as described by @p pAttributeKey and/or @p objectId.
 * @details This API creates a symmetric key. The keys object context will also be created and returned in @p pKeyHandle.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pAttributeKey Optional, attributes containing properties of key
 *              to create. <br>Can be a set from following
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_KEY_USAGE
 *              <br>#TAP_ATTR_KEY_SIZE
 *              <br>#TAP_ATTR_SYM_MODE
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 * @param [in]  initFlag Hint to SMP provider to keep the newly key loaded
 * @param [out]  pObjectIdOut ObjectId for the object created if 8 bytes or less.
 * @param [out] pObjectAttributes Optional pointer to attributes that contains
 *              attributes of the newly created key
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_KEY_USAGE
 *              <br>#TAP_ATTR_KEY_SIZE
 *              <br>#TAP_ATTR_SYM_MODE
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_OBJECT_PROPERTY
 * @param [out]  pKeyHandle Context handle to the key
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, createSymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pAttributeKey,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief This API creates an object blob for the object identified by @p objectHandle
 * @details This API creates an object blob for the object identified by @p objectHandle such that it can later be imported into the same or different secure element.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [out]  pExportedObject Pointer to serialized blob
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, exportObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pExportedObject
);

/**
 * @ingroup smp_functions
 * @brief This API serializes the persistent object identified by @p objectId.
 * @details This API serializes the verifiable data corresponding to the persistent object identified by @p objectID.
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectId Object identifier to serialize into a blob
 * @param [out]  pSerializedObject Pointer to the serialized blob
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, serializeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_Blob *pSerializedObject
);

/**
 * @ingroup smp_functions
 * @brief This API creates an object and corresponding context, as described by @p pObjectAttributes and returns the context handle in @p pHandle.
 * @details This API creates an object and corresponding context, as described by @p pObjectAttributes and returns the context handle in @p pHandle.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pKeyAttributeList Key attributes.
 * @param [in]  pKeyObjectAttributes Attributes used to create the object context.
 *              <br>Can be set to following
 *              <br>#TAP_ATTR_CAPABILITY_FUNCTIONALITY
 *              <br>#TAP_ATTR_ENTITY_CREDENTIAL
 *              <br>#TAP_ATTR_CREDENTIAL
 * @param [out]  pObjectIdOut ObjectId for the object created if 8 bytes or less.
 * @param [out]  pHandle Context handle to the object
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, createObject,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief This API purges and destroys the object and corresponding context, identified by @p objectHandle, including the internal object.
 * @details This API deletes the object and corresponding context, identified by @p objectHandle, including the internal object.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, purgeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
);

/**
 * @ingroup smp_functions
 * @brief This API wraps a key using the key identified by @p objectHandle as the wrapping key.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  objectHandle Handle to the Object Context
 * @param [in]  pMechanism Required, attributes to specify operation
 *              <br>#TAP_ATTR_BUFFER
 *              <br>#TAP_ATTR_KEY_WRAP_TYPE
 *              <br>#TAP_ATTR_KEY_TO_BE_WRAPPED_ID
 * @param [out]  pDuplicateBuf Pointer to the wrapped key buffer
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11,duplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pDuplicateBuf
);

/**
 * @ingroup smp_functions
 * @brief This API unwraps a key.
 * @param [in]  moduleHandle Handle to the Module Context
 * @param [in]  tokenHandle Handle to the Token Context
 * @param [in]  pMechanism Required, attributes to specify operation
 *              <br>#TAP_ATTR_KEY_ALGORITHM
 *              <br>#TAP_ATTR_BUFFER
 *              <br>#TAP_ATTR_KEY_WRAP_TYPE
 *              <br>#TAP_ATTR_WRAPPING_KEY_ID
 * @param [in]  pDuplicateBuf Pointer to the wrapped key buffer
 * @param [out] pObjectAttributes Optional pointer to attributes
 * @param [out] pKeyHandle Context handle to the key
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11,importDuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pMechanism,
        TAP_Buffer *pDuplicateBuf,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief This API returns a DER encoded certificate for the Root of Trust key, identified by @p rootOfTrustType and/or @p objectID
 * @details This API returns a DER encoded certificate for the Root of Trust key, identified by @p rootOfTrustType and/or @p objectID
 * @param [in]  moduleHandle  Handle to the Module Context
 * @param [in]  objectId Optional Object identifier
 * @param [in]  rootOfTrustType Optional Root of Trust type, can be set to
                <br>#TAP_ROOT_OF_TRUST_TYPE_UNKNOWN
 * @param [out]  pCertificate Pointer to blob containing DER encoded certificate
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getRootOfTrustCertificate,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE rootOfTrustType,
        TAP_Blob *pCertificate
);

/**
 * @ingroup smp_functions
 * @brief This API returns the object handle to the Root of Trust key, identified by @p rootOfTrustType and/or @p objectID
 * @details This API returns the object handle to the Root of Trust key, identified by @p rootOfTrustType and/or @p objectID
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   objectId Optional Object identifier
 * @param [in]   rootOfTrustType Optional Root of Trust type, can be set to
                 <br>#TAP_ROOT_OF_TRUST_TYPE_UNKNOWN
 * @param [out]  pKeyHandle Context handle to the key
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getRootOfTrustKeyHandle,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE rootOfTrustType,
        TAP_ObjectHandle *pKeyHandle
);

/**
 * @ingroup smp_functions
 * @brief
 * @details
 * @param [in]   moduleHandle Handle to the Module Context
 * @param [in]   tokenHandle Handle to the Token Context
 * @param [in]   objectHandle Handle to the Object Context
 * @param [out]  pErrorAttributes
 * @return OK on success
 */
MOC_EXTERN MSTATUS SMP_API(PKCS11, getLastError,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ErrorAttributes *pErrorAttributes
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, selfTest,
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
MOC_EXTERN MSTATUS SMP_API(PKCS11, selfTestPoll,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestContext testContext,
        TAP_TestResponseAttributes *pTestResponse
);
#ifdef __cplusplus
}
#endif
/*! @cond */
#endif /* __ENABLE_DIGICERT_SMP__ && __ENABLE_DIGICERT_SMP_PKCS11__ */
/*! @endcond */
#endif /* __SMP_PKCS11_API_HEADER__ */

