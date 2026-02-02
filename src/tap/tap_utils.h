/**
 * @file tap_utils.h
 *
 * @ingroup nanotap_tree
 *
 * @brief Trust Anchor Platform (TAP) Utility functions
 * @details This file contains functions to copy and free TAP structures
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_TAP__
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


/*------------------------------------------------------------------*/

#ifndef __TAP_UTILS_HEADER__
#define __TAP_UTILS_HEADER__

/*! @cond */

#ifdef __ENABLE_DIGICERT_TAP__

/*! @endcond */

#include "tap_common.h"


/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_Buffer structure.
 *
 * @param [out] pBuffer       Pointer to the TAP_Buffer structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffer within the TAP_Buffer structure, and not the TAP_Buffer structure itself.
 *         If memory for pBuffer was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeBuffer(TAP_Buffer *pBuffer);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Buffer structure.
 *
 * @param [out] pDestBuffer       Pointer to the new TAP_Buffer structure.
 * @param [out] pSrcBuffer        Pointer to the TAP_Buffer structure to be copied.
 * @param [in] offset             Offset in the source buffer from which to start copying.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function allocates memory for pDestBuffer->pBuffer, which must be freed via TAP_UTILS_freeBuffer.
 *         It does not allocate memory for pDestBuffer itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyBufferOffset(TAP_Buffer *pDestBuffer, TAP_Buffer *pSrcBuffer, ubyte4 offset);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Buffer structure.
 *
 * @param [out] pDestBuffer       Pointer to the new TAP_Buffer structure.
 * @param [out] pSrcBuffer        Pointer to the TAP_Buffer structure to be copied.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function allocates memory for pDestBuffer->pBuffer, which must be freed via TAP_UTILS_freeBuffer.
 *         It does not allocate memory for pDestBuffer itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyBuffer(TAP_Buffer *pDestBuffer, TAP_Buffer *pSrcBuffer);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_Blob structure.
 *
 * @param [out] pBlob       Pointer to the TAP_Blob structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffer within the TAP_Blob structure, and not the TAP_Blob structure itself.
 *         If memory for pBlob was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeBlob(TAP_Blob *pBlob);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Blob structure.
 *
 * @param [out] pDestBlob       Pointer to the new TAP_Blob structure.
 * @param [out] pSrcBlob        Pointer to the TAP_Blob structure to be copied.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function allocates memory for pDestBlob->blob.pBuffer, which must be freed via TAP_UTILS_freeBlob(pDestBlob)
 *         of TAP_UTILS_freeBuffer(&(pDestBlob->blob)).
 *         It does not allocate memory for pDestBlob itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyBlob(TAP_Blob *pDestBlob, TAP_Blob *pSrcBlob);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_ConfigInfoList structure.
 *
 * @param [in,out] pConfigInfoList    Pointer to the TAP_ConfigInfoList structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffers within the TAP_ConfigInfoList structure, and not the TAP_ConfigInfoList structure itself.
 *         If memory for pConfigInfoList was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeConfigInfoList(TAP_ConfigInfoList *pConfigInfoList);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_ProviderList structure.
 *
 * @param [in,out] pProviderList    Pointer to the TAP_ProviderList structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffers within the TAP_ProviderList structure, and not the TAP_ProviderList structure itself.
 *         If memory for pProviderList was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeProviderList(TAP_ProviderList *pProviderList);

/**
 * @ingroup tap_functions
 *
 * @details Function to get the serialized length of a TAP_ProviderList structure.
 *
 * @param [in] pList        Pointer to the TAP_ProviderList structure whose size is to be returned.
 * @param [out] pListLen    Pointer to the serialized size of the TAP_ProviderList structure.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_UTILS_getProviderListLen(TAP_ProviderList *pList, ubyte4 *pListLen);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Module structure
 *
 * @param [in,out] pDestModule       New TAP_Module structure
 * @param [in]     pSrcModule        TAP_Module to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapModule
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapModule(TAP_Module *pDestModule, TAP_Module *pSrcModule);


/**
 * @ingroup tap_functions
 *
 * @details Function used by all TAP client modules to tear down connection to TAP server 
 *
 * @param [in,out] pModule       TAP_Module to be freed 
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapModule(TAP_Module *pModule);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_ModuleList structure.
 *
 * @param [out] pList    Pointer to the TAP_ModuleList structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffers within the TAP_ModuleList structure, and not the TAP_ModuleList structure itself.
 *         If memory for pList was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeModuleList(TAP_ModuleList *pList);


/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_AttributeList structure
 *
 * @param [in,out] pDestList       New TAP_AttributeList structure
 * @param [in]     pSrcList        TAP_AttributeList to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  The new structure must be freed by TAP_UTILS_freeAttributeList.
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyAttributeList(TAP_AttributeList *pDestList,
                                          TAP_AttributeList *pSrcList);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_AttributeList structure.
 *
 * @param [out] pList    Pointer to the TAP_AttributeList structure to be freed.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 *
 * @memory This function only frees the buffers within the TAP_AttributeList structure, and not the TAP_AttributeList structure itself.
 *         If memory for pList was allocated by the caller, it must be freed after this call.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeAttributeList(TAP_AttributeList *pList);

/**
* @ingroup tap_functions
*
* @details Function to copy a TAP_ModuleCapPropertyList structure
*
* @param [in,out] pDestList       New TAP_ModuleCapPropertyList structure
* @param [in]     pSrcList        TAP_ModuleCapPropertyList to be copied
*
* @return OK on success
* @return
*
* @memory This memory allocates memory for the underlying buffers.  The new structure must be freed by TAP_ModuleCapPropertyList.
*/
MOC_EXTERN MSTATUS TAP_UTILS_copyModuleCapPropertyList(
                TAP_ModuleCapPropertyList *pDestPropList,
                TAP_ModuleCapPropertyList *pSrcPropList);

/**
* @ingroup tap_functions
*
* @details Function to free a TAP_ModuleCapPropertyList structure.
*
* @param [out] pList    Pointer to the TAP_ModuleCapPropertyList structure to be freed.
*
* @return OK on success.
* @return ERR_NULL_POINTER if a NULL pointer is passed
* @return ERR_INVALID_ARG if an invalid argument is specified
*
* @memory This function only frees the TAP_ModuleCapProperty values within the TAP_ModuleCapPropertyList structure, and not the TAP_ModuleCapPropertyList structure itself.
*         If memory for pList was allocated by the caller, it must be freed after this call.
*/
MOC_EXTERN MSTATUS TAP_UTILS_freeModuleCapPropertyList(TAP_ModuleCapPropertyList *pList);

/**
 * @ingroup tap_functions
 *
 * @details Function to get the serialized length of a TAP_AttributeList structure.
 *
 * @param [out] pList       Pointer to the TAP_AttributeList structure whose size is to be returned.
 * @param [out] pListLen    Pointer to the serialized size of the TAP_AttributeList structure.
 *
 * @return OK on success.
 * @return ERR_NULL_POINTER if a NULL pointer is passed
 * @return ERR_INVALID_ARG if an invalid argument is specified
 */
MOC_EXTERN MSTATUS TAP_UTILS_getAttributeListLen(TAP_AttributeList *pList, ubyte4 *pListLen);

/**
 * @ingroup tap_functions
 *
 * @details Function joins two TAP_CredentialLists. If either list contains 1 or more elements,
 *          then ppOutCreds points to a new list containing all elements.
 *
 * @param [in] pCred1,       TAP_CredentialList to be joined.
 * @param [in] pCred2,       TAP_CredentialList to be joined.
 * @param [out] pOutCreds,       TAP_CredentialList new list containing all items in first two lists.
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_joinCredentialList(TAP_CredentialList *pCred1, TAP_CredentialList *pCred2, TAP_CredentialList **pOutCreds);

/**
 * @ingroup tap_functions
 *
 * @details Function used to clear a credential
 *
 * @param [in,out] pCredential       TAP_Credential to be cleared
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_clearCredential(TAP_Credential *pCredential);

/**
 * @ingroup tap_functions
 *
 * @details Function used to clear a credential list
 *
 * @param [in,out] pCredentials       TAP_CredentialList to be cleared
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_clearCredentialList(TAP_CredentialList *pCredentials);

/**
 * @ingroup tap_functions
 *
 * @details Function used to clear a TAP_EntityCredentialList
 *
 * @param [in,out] pCredentials       TAP_EntityCredentialList to be cleared
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_clearEntityCredentialList(TAP_EntityCredentialList *pCredentials);

/**
 * @ingroup tap_functions
 *
 * @details Function to convert hash ID into a TAP_HASH_ALG
 *
 * @param [in]      hashId              Hash ID (ht_sha1, ht_sha224, etc)
 * @param [out]     pTapHashAlg         TAP_HASH_ALG equivalent of the hash provided
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapModule
 */
MOC_EXTERN MSTATUS TAP_UTILS_getTapHashAlgFromHashId(ubyte hashId, TAP_HASH_ALG *pTapHashAlg);

/**
 * @ingroup tap_functions
 *
 * @details Function to convert TAP_HASH_ALG into a hash ID
 *
 * @param [in]      tapHashAlg          TAP_HASH_ALG (TAP_HASH_ALG_SHA1, TAP_HASH_ALG_SHA256, etc)
 * @param [out]     pHashId             Hash ID equivalent of the TAP_HASH_ALG provided
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapModule
 */
MOC_EXTERN MSTATUS TAP_UTILS_getHashIdFromTapHashAlg(TAP_HASH_ALG tapHashAlg, ubyte *pHashId);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_RSASignature structure
 *
 * @param [in,out] pDestSignature       New TAP_RSASignature structure
 * @param [in]     pSrcSignature        TAP_RSASignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapModule
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapRSASignature(TAP_RSASignature *pDestSignature, TAP_RSASignature *pSrcSignature);


/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_ECCSignature structure
 *
 * @param [in,out] pDestSignature       New TAP_ECCSignature structure
 * @param [in]     pSrcSignature        TAP_ECCSignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapModule
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapECCSignature(TAP_ECCSignature *pDestSignature, TAP_ECCSignature *pSrcSignature);


/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_DSASignature structure
 *
 * @param [in,out] pDestSignature       New TAP_DSASignature structure
 * @param [in]     pSrcSignature        TAP_DSASignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTAPSignature
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapDSASignature(TAP_DSASignature *pDestSignature, TAP_DSASignature *pSrcSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_SymSignature structure
 *
 * @param [in,out] pDestSignature       New TAP_SymSignature structure
 * @param [in]     pSrcSignature        TAP_SymSignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTAPSignature
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapSymSignature(TAP_SymSignature *pDestSignature, TAP_SymSignature *pSrcSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Signature structure
 *
 * @param [in,out] pDestSignature       New TAP_Signature structure
 * @param [in]     pSrcSignature        TAP_Signature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_UTILS_freeTapSignature
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyTapSignature(TAP_Signature *pDestSignature, TAP_Signature *pSrcSignature);


/**
 * @ingroup tap_functions
 *
 * @details Function to free only the fields of a TAP_RSASignature.
 *
 * @param [in,out] pSignature TAP_RSASignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapRSASignatureFields(TAP_RSASignature *pSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to free only the fields of a TAP_ECCSignature.
 *
 * @param [in,out] pSignature TAP_ECCSignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapECCSignatureFields(TAP_ECCSignature *pSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to free only the fields of a TAP_DSASignature.
 *
 * @param [in,out] pSignature TAP_DSASignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapDSASignatureFields(TAP_DSASignature *pSignature);


/**
 * @ingroup tap_functions
 *
 * @details Function to free only the fields of a TAP_SymSignature.
 *
 * @param [in,out] pSignature TAP_SymSignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapSymSignatureFields(TAP_SymSignature *pSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to free only the fields of a TAP_Signature, based on key algorithm.
 *
 * @param [in,out] pSignature TAP_Signature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapSignatureFields(TAP_Signature *pSignature);

/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_Signature, based on key algorithm.  This function frees all fields as well as the TAP_Signature structure.
 *
 * @param [in,out] ppSignature TAP_Signature to be freed
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeTapSignature(TAP_Signature **ppSignature);


/**
 * @ingroup tap_functions
 *
 * @details Function to free a TAP_PublicKey structure, based on key algorithm.
 *
 * @param [in,out] ppPublicKey TAP_PublicKey to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, as well as the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freePublicKey(TAP_PublicKey **ppPublicKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to free the fields of a TAP_PublicKey structure, based on key algorithm.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_PublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freePublicKeyFields(TAP_PublicKey *pPublicKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to free the fields of a TAP_RSAPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_RSAPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeRSAPublicKeyFields(TAP_RSAPublicKey *pPublicKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to free the fields of a TAP_MLDSAPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_MLDSAPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeMLDSAPublicKeyFields(TAP_MLDSAPublicKey *pPublicKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to free the fields of a TAP_ECCPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_ECCPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeECCPublicKeyFields(TAP_ECCPublicKey *pPublicKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to free the fields of a TAP_DSAPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_DSAPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
MOC_EXTERN MSTATUS TAP_UTILS_freeDSAPublicKeyFields(TAP_DSAPublicKey *pPublicKey);


/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_PublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_PublicKey structure
 * @param [in]     pSrcKey        TAP_PublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by TAP_UTILS_freePublicKey
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyPublicKey(TAP_PublicKey *pDestKey, TAP_PublicKey *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_RSAPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_RSAPublicKey structure
 * @param [in]     pSrcKey        TAP_RSAPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by TAP_UTILS_freeRSAPublicKeyFields
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyRSAPublicKey(TAP_RSAPublicKey *pDestKey, TAP_RSAPublicKey *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_ECCPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_ECCPublicKey structure
 * @param [in]     pSrcKey        TAP_ECCPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by TAP_UTILS_freeECCPublicKeyFields
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyECCPublicKey(TAP_ECCPublicKey *pDestKey, TAP_ECCPublicKey *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_DSAPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_DSAPublicKey structure
 * @param [in]     pSrcKey        TAP_DSAPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by TAP_UTILS_freeDSAPublicKeyFields.
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyDSAPublicKey(TAP_DSAPublicKey *pDestKey, TAP_DSAPublicKey *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_MLDSAPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_MLDSAPublicKey structure
 * @param [in]     pSrcKey        TAP_MLDSAPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by TAP_UTILS_freeMLDSAPublicKeyFields
 */
MOC_EXTERN MSTATUS TAP_UTILS_copyMLDSAPublicKey(TAP_MLDSAPublicKey *pDestKey, TAP_MLDSAPublicKey *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to copy a TAP_Key structure
 *
 * @param [in,out] pAsymKey       New AsymmetricKey structure
 * @param [in]     pSrcKey        TAP_Key to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by CRYPTO_uninitAsymmetricKey.
 */
MOC_EXTERN MSTATUS TAP_UTILS_extractPublicKey(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pDestKey, TAP_Key *pSrcKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to get the size of a TAP_PublicKey structure for serialization
 *
 * @param [in]      pPublicKey      TAP_PublicKey structure to determine size of
 * @param [in,out]  pKeySize        serialized size of pPublicKey
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_getPublicKeySize(const TAP_PublicKey *pPublicKey, ubyte4 *pKeySize);


/**
 * @ingroup tap_functions
 *
 * @details Function to get the size of a TAP_Key structure for serialization
 *
 * @param [in]      pKey          TAP_Key structure to determine size of
 * @param [in,out]  pKeySize      serialized size of pKey
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_getKeySize(const TAP_Key *pKey, ubyte4 *pKeySize);


/**
 * @ingroup tap_functions
 *
 * @details Function to serialize the public key into PEM bytes
 * @param [in]      pPublicKey      TAP_PublicKey structure to serialize
 * @param [in,out]  pPemBuffer      TAP_Buffer structure to contain the serialized PEM buffer
 *
 * @return OK on success
 * @return
 */
MOC_EXTERN MSTATUS TAP_UTILS_serializePubKeyToPEM(const TAP_KeyData *pKeyData,
                                TAP_Buffer *pPemBuffer);


/**
 * @ingroup tap_functions
 *
 * @details Function to read a TAP_Key from a file.
 *
 * @param [in]  pFileName        TAP_Buffer containing the full path of the file from which to read a serialized TAP_Key
 * @param [out] pKey             TAP_Key read from file
 *
 * @return OK on success
 * @return
 *
 */
MOC_EXTERN MSTATUS
TAP_UTILS_readKeyFromFile(TAP_Buffer *pFileName, TAP_Key *pKey);


/**
 * @ingroup tap_functions
 *
 * @details Function to write a TAP_Key to a file.
 *
 * @param [in]  pFileName        TAP_Buffer containing the full path of the file to which to write a serialized TAP_Key
 * @param [out] pKey             TAP_Key to write to file
 *
 * @return OK on success
 *
 */
MOC_EXTERN MSTATUS
TAP_UTILS_writeKeyToFile(TAP_Buffer *pFileName, TAP_Key *pKey);

/**
 * @ingroup tap_functions
 *
 * @details Function to return a human readable string for a TAP_PROVIDER.
 *
 * @param [in]  provider    TAP_PROVIDER for which to return a name
 *
 * @return Provider name string on success
 * @return NULL if invalid provider given
 *
 */
MOC_EXTERN char *TAP_UTILS_getProviderName(TAP_PROVIDER provider);

/**
 * @ingroup tap_functions
 *
 * @details Utility function to parse Credentials and return 
 *          TAP_EntityCredentialList for use with subsequent 
 *          TAP APIs that require credentials.
 *
 * @param [in]  pEncodedCredentials       Pointer to buffer containing encoded credentials 
 * @param [in]  encodedCredentialsLength  Length of encoded credentials buffer
 * @param [out] ppEntityCredentialList    Pointer to pointer to output credentials list
 * @param [in]  pErrContext               Optional pointer to buffer that contains debug information
 *
 * @return OK on Success
 * @return error code on failure
 *
 * @memory This memory allocates memory for the Credentials list. It must be freed by TAP_UTILS_clearEntityCredentialList 
 */
MOC_EXTERN MSTATUS TAP_parseModuleCredentials(ubyte *pEncodedCredentials, 
        ubyte4 encodedCredentialsLength, 
        TAP_EntityCredentialList **ppEntityCredentialList,
        TAP_ErrorContext *pErrContext);

MOC_EXTERN MSTATUS TAP_UTILS_getServerInfo(char *pServerName, ubyte4 serverNameLen, ubyte4 *pServerNameLen, byteBoolean *pServerNameSpecified, ubyte4 *pServerPort);

MOC_EXTERN MSTATUS TAP_readConfigFile(const char *pConfigFileName, TAP_Buffer *pConfigBuffer,
        byteBoolean useSpecifiedConfigFile);

#if defined(__RTOS_WIN32__) 
MOC_EXTERN MSTATUS TAP_UTILS_getWinConfigDir(ubyte **ppConfigDirPath,
                                         const ubyte *pConfigDirName);

MOC_EXTERN MSTATUS TAP_UTILS_getWinConfigFilePath(ubyte **ppConfigFilePath,
    const ubyte *pConfigFileRelativePath);
#endif  /* __RTOS_WIN32__ */

MOC_EXTERN MSTATUS TAP_UTILS_isPathRelative(const ubyte* pPathStr, const ubyte4 pathLen,
                                byteBoolean *pResult);
/*! @cond */
#endif /* __ENABLE_DIGICERT_TAP__ */
/*! @endcond */

#endif

