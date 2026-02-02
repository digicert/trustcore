/**
 * @file smp_utils.h
 *
 * @ingroup smp_functions
 *
 * @brief Common Security Module Provider Utility functions
 * @details This file contains utility functions needed by SMP
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_SMP__
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

#ifndef __SMP_UTILS_HEADER__
#define __SMP_UTILS_HEADER__

#include "../../tap/tap_smp.h"

/***************************************************************
   Function Definitions
****************************************************************/

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_RSASignature structure
 *
 * @param [in,out] pDestSignature       New TAP_RSASignature structure
 * @param [in]     pSrcSignature        TAP_RSASignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_freeTapModule
 */
extern MSTATUS SMP_UTILS_copyTapRSASignature(TAP_RSASignature *pDestSignature, TAP_RSASignature *pSrcSignature);


/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_ECCSignature structure
 *
 * @param [in,out] pDestSignature       New TAP_ECCSignature structure
 * @param [in]     pSrcSignature        TAP_ECCSignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by TAP_freeTapModule
 */
extern MSTATUS SMP_UTILS_copyTapECCSignature(TAP_ECCSignature *pDestSignature, TAP_ECCSignature *pSrcSignature);


/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_DSASignature structure
 *
 * @param [in,out] pDestSignature       New TAP_DSASignature structure
 * @param [in]     pSrcSignature        TAP_DSASignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by SMP_UTILS_freeTAPSignature
 */
extern MSTATUS SMP_UTILS_copyTapDSASignature(TAP_DSASignature *pDestSignature, TAP_DSASignature *pSrcSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_SymSignature structure
 *
 * @param [in,out] pDestSignature       New TAP_SymSignature structure
 * @param [in]     pSrcSignature        TAP_SymSignature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by SMP_UTILS_freeTAPSignature
 */
extern MSTATUS SMP_UTILS_copyTapSymSignature(TAP_SymSignature *pDestSignature, TAP_SymSignature *pSrcSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_Signature structure
 *
 * @param [in,out] pDestSignature       New TAP_Signature structure
 * @param [in]     pSrcSignature        TAP_Signature to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  This must be freed by SMP_UTILS_freeTapSignature
 *
 */
extern MSTATUS SMP_UTILS_copyTapSignature(TAP_Signature *pDestSignature, TAP_Signature *pSrcSignature);


/**
 * @ingroup smp_functions
 *
 * @details Function to free only the fields of a TAP_RSASignature.
 *
 * @param [in,out] pSignature TAP_RSASignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
extern MSTATUS SMP_UTILS_freeTapRSASignatureFields(TAP_RSASignature *pSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to free only the fields of a TAP_ECCSignature.
 *
 * @param [in,out] pSignature TAP_ECCSignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
extern MSTATUS SMP_UTILS_freeTapECCSignatureFields(TAP_ECCSignature *pSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to free only the fields of a TAP_DSASignature.
 *
 * @param [in,out] pSignature TAP_DSASignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
extern MSTATUS SMP_UTILS_freeTapDSASignatureFields(TAP_DSASignature *pSignature);


/**
 * @ingroup smp_functions
 *
 * @details Function to free only the fields of a TAP_SymSignature.
 *
 * @param [in,out] pSignature TAP_SymSignature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
extern MSTATUS SMP_UTILS_freeTapSymSignatureFields(TAP_SymSignature *pSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to free only the fields of a TAP_Signature, based on key algorithm.
 *
 * @param [in,out] pSignature TAP_Signature whose fields are to be freed
 *
 * @return OK on success
 * @return
 */
extern MSTATUS SMP_UTILS_freeTapSignatureFields(TAP_Signature *pSignature);

/**
 * @ingroup smp_functions
 *
 * @details Function to free a TAP_Signature, based on key algorithm.  This function frees all fields as well as the TAP_Signature structure.
 *
 * @param [in,out] ppSignature TAP_Signature to be freed
 *
 * @return OK on success
 * @return
 *
 */
extern MSTATUS SMP_UTILS_freeTapSignature(TAP_Signature **ppSignature);


/**
 * @ingroup smp_functions
 *
 * @details Function to free a TAP_PublicKey structure, based on key algorithm.
 *
 * @param [in,out] ppPublicKey TAP_PublicKey to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, as well as the public key itself.
 */
extern MSTATUS SMP_UTILS_freePublicKey(TAP_PublicKey **ppPublicKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to free the fields of a TAP_PublicKey structure, based on key algorithm.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_PublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
extern MSTATUS SMP_UTILS_freePublicKeyFields(TAP_PublicKey *pPublicKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to free the fields of a TAP_RSAPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_RSAPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
extern MSTATUS SMP_UTILS_freeRSAPublicKeyFields(TAP_RSAPublicKey *pPublicKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to free the fields of a TAP_ECCPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_ECCPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
extern MSTATUS SMP_UTILS_freeECCPublicKeyFields(TAP_ECCPublicKey *pPublicKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to free the fields of a TAP_DSAPublicKey structure.
 *
 * @param [in,out] pPublicKey   Pointer to the TAP_DSAPublicKey whose fields are to be freed 
 *
 * @return OK on success
 *
 * @memory This function frees the underlying key fields, but does NOT free the public key itself.
 */
extern MSTATUS SMP_UTILS_freeDSAPublicKeyFields(TAP_DSAPublicKey *pPublicKey);


/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_PublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_PublicKey structure
 * @param [in]     pSrcKey        TAP_PublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by SMP_UTILS_freePublicKey
 */
extern MSTATUS SMP_UTILS_copyPublicKey(TAP_PublicKey *pDestKey, TAP_PublicKey *pSrcKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_RSAPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_RSAPublicKey structure
 * @param [in]     pSrcKey        TAP_RSAPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by SMP_UTILS_freeRSAPublicKeyFields
 */
extern MSTATUS SMP_UTILS_copyRSAPublicKey(TAP_RSAPublicKey *pDestKey, TAP_RSAPublicKey *pSrcKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_ECCPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_ECCPublicKey structure
 * @param [in]     pSrcKey        TAP_ECCPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by SMP_UTILS_freeECCPublicKeyFields
 */
extern MSTATUS SMP_UTILS_copyECCPublicKey(TAP_ECCPublicKey *pDestKey, TAP_ECCPublicKey *pSrcKey);

/**
 * @ingroup smp_functions
 *
 * @details Function to copy a TAP_DSAPublicKey structure
 *
 * @param [in,out] pDestKey       New TAP_DSAPublicKey structure
 * @param [in]     pSrcKey        TAP_DSAPublicKey to be copied
 *
 * @return OK on success
 * @return
 *
 * @memory This memory allocates memory for the underlying buffers.  These must be freed by SMP_UTILS_freeDSAPublicKeyFields.
 */
extern MSTATUS SMP_UTILS_copyDSAPublicKey(TAP_DSAPublicKey *pDestKey, TAP_DSAPublicKey *pSrcKey);

extern MSTATUS TAP_UTILS_getMocanaError(ubyte4 smpErrorCode);

extern MSTATUS SMP_UTILS_freeBuffer(TAP_Buffer *pBuffer);

#endif
