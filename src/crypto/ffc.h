/*
 * ffc.h
 *
 * Finite Field Cryptography Domain Parameter Generation/Validation.
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
@file       ffc.h

@brief      Header file for the Nanocrypto FFC Domain Generation/Validation..
@details    Header file for the Nanocrypto FFC Domain Generation/Validation..

*/


/*------------------------------------------------------------------*/


#ifndef __FFC_HEADER__
#define __FFC_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

struct vlong;

typedef enum
{
    FFC_sha1,
    FFC_sha224,
    FFC_sha256,
    FFC_sha384,
    FFC_sha512

} FFCHashType;

/**
 * @brief      Verifies that G is a valid generator of the cyclic group of order Q in the field of order P.
 *
 * @details    Verifies that G is a valid generator of the cyclic group of order Q in the field of order P.
 *
 * @param pP            The prime P defining the domain field.
 * @param pQ            The cyclic group order Q.
 * @param pG            The generator to be validated.
 * @param pIsValid      Contents will be set to \c TRUE for a valid G and \c FALSE if otherwise.
 * @param ppVlongQueue  Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of OK and a pIsValid value of TRUE
 *             before accepting that G is valid with respect to P and Q.
 */
MOC_EXTERN MSTATUS FFC_verifyG(MOC_FFC(hwAccelDescr hwAccelCtx) vlong *pP, vlong *pQ, vlong *pG, intBoolean *pIsValid, vlong **ppVlongQueue);

/**
 * @brief      Computes the hash of a buffer for FFC purposes.
 *
 * @details    Computes the hash of a buffer for FFC purposes.
 *
 * @param hashType      The hash algorithm to use. This is one of the \c FFCHashType values...
 *                      FFC_sha1
 *                      FFC_sha224
 *                      FFC_sha256
 *                      FFC_sha384
 *                      FFC_sha512
 *
 * @param pSrc          The input buffer of data to be hashed.
 * @param length        The length of the pSrc buffer in bytes.
 * @param pHashVal      The resulting hash. This buffer must be large enough for the hash algorithm chosen.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS FFC_getHashValue(MOC_FFC(hwAccelDescr hwAccelCtx) FFCHashType hashType, ubyte *pSrc, ubyte4 length, ubyte *pHashVal);

/**
 * @brief      Gets the hash length of a hashType for FFC purposes.
 *
 * @details    Gets the hash length of a hashType for FFC purposes.
 *
 * @param hashType      The hash algorithm to use. This is one of the \c FFCHashType values...
 *                      FFC_sha1
 *                      FFC_sha224
 *                      FFC_sha256
 *                      FFC_sha384
 *                      FFC_sha512
 *
 * @param pHashLen      Contents will be set to the length of the hash output in bytes.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS FFC_getHashLen(FFCHashType hashType, ubyte4 *pHashLen);

/**
 * @brief      Computes the domain parameters P and Q via the FIPS 186-4 algorithm.
 *
 * @details    Computes the domain parameters P and Q via the FIPS 186-4 algorithm.
 *
 * @param pFipsRngCtx   Pointer to a FIPS 186 RNG context.
 * @param ppNewP        The location that will receive the newly allocated P value in \vlong form.
 * @param ppNewQ        The location that will receive the newly allocated Q value in \vlong form.
 * @param L             The bitlength required of P.
 * @param Nin           The bitlength required of Q.
 * @param hashType      The hash algorithm to be used for generating P and Q. This is one
 *                      of the \c FFCHashType values...
 *                      FFC_sha1
 *                      FFC_sha224
 *                      FFC_sha256
 *                      FFC_sha384
 *                      FFC_sha512
 *
 * @param pRetC         The final counter value that was used when P and Q are generated.
 * @param pSeed         The seed to be used for generating P and Q.
 * @param seedSize      The length of the seed in bytes.
 * @param pIsPrimePQ    Contents will be set to \c TRUE for both a prime P and prime Q, and \c FALSE if otherwise.
 * @param ppVlongQueue  Optional pointer to a \c vlong queue.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @funcdoc    dh.c
 */
MOC_EXTERN MSTATUS FFC_computePQ_FIPS_1864(MOC_FFC(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                           vlong **ppNewP, vlong **ppNewQ, ubyte4 L, ubyte4 Nin, FFCHashType hashType, ubyte4 *pRetC,
                                           ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue);
    
#ifdef __cplusplus
}
#endif

#endif /* __FFC_HEADER__ */
