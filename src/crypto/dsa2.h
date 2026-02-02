/*
 * dsa2.h
 *
 * DSA with hashes other than SHA-1 (FIPS 186-3)
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


#ifndef __DSA2_HEADER__
#define __DSA2_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief      Computes the DSA signature after message truncation.
 *
 * @details    Computes the DSA signature after message truncation. This method allocates
 *             \c vlong elements to hold the signature values R and S. Be sure to free these buffers when done.
 *
 * @param rngfun         User defined callback method for returning random data.
 * @param rngArg         Argument for the rngFun, typically a random context.
 * @param p_dsaDescr     Pointer to DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param msg            The message to be signed.
 * @param msgLen         The length of the message in bytes.
 * @param ppR            Contents will be set to the vlong holding the R value.
 * @param ppS            Contents will be set to the vlong holding the S value.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   dsa2.h
 * @funcdoc    dsa2.h
 */
MOC_EXTERN MSTATUS DSA_computeSignature2(MOC_DSA(hwAccelDescr hwAccelCtx)
                                          RNGFun rngfun, void* rngArg,
                                          const DSAKey *p_dsaDescr,
                                          const ubyte* msg, ubyte4 msgLen,
                                          vlong **ppR, vlong **ppS, vlong **ppVlongQueue);

/**
 * @brief      Verifies a DSA signature after message truncation.
 *
 * @details    Verifies a DSA signature after message truncation.
 *
 * @param p_dsaDescr     Pointer to DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param msg            The message to be verified.
 * @param msgLen         The length of the message in bytes.
 * @param pR             The R signature value.
 * @param pS             The S signature value.
 * @param isGoodSignature   Contents will be set to \c TRUE if the signature is valid
 *                          and \c FALSE otherwise.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check BOTH a status of \c OK and a \c isGoodSignature
 *             of \c TRUE before accepting that a signature is valid.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   dsa2.h
 * @funcdoc    dsa2.h
 */
MOC_EXTERN MSTATUS DSA_verifySignature2(MOC_DSA(hwAccelDescr hwAccelCtx)
                                        const DSAKey *p_dsaDescr,
                                        const ubyte *msg, ubyte4 msgLen,
                                        vlong *pR, vlong *pS,
                                        intBoolean *isGoodSignature,
                                        vlong **ppVlongQueue);

/**
 * @brief      Computes the DSA signature after message truncation.
 *
 * @details    Computes the DSA signature after message truncation. This method allocates buffers to hold
 *             the signature values R and S. Be sure to free these buffers when done.
 *
 * @param rngfun         User defined callback method for returning random data.
 * @param pRngArg        Argument for the rngFun, typically a random context.
 * @param pKey           Pointer to DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param pM             The message to be signed.
 * @param mLen           The length of the message in bytes.
 * @param ppR            Contents will be set to the buffer holding the R value.
 * @param pRLen          Contents will be set to the length of R in bytes.
 * @param ppS            Contents will be set to the buffer holding the S value.
 * @param pSLen          Contents will be set to the length of S in bytes.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   dsa2.h
 * @funcdoc    dsa2.h
 */
MOC_EXTERN MSTATUS DSA_computeSignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) RNGFun rngfun, void *pRngArg, DSAKey *pKey, ubyte *pM, ubyte4 mLen,
                                            ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue);


/**
 * @brief      Verifies a DSA signature after message truncation.
 *
 * @details    Verifies a DSA signature after message truncation.
 *
 * @param pKey           Pointer to DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param pM             The message to be verified.
 * @param mLen           The length of the message in bytes.
 * @param pR             Buffer holding the R value.
 * @param rLen           The length of R in bytes.
 * @param pS             Buffer holding the S value.
 * @param sLen           The length of S in bytes.
 * @param pIsGoodSignature  Contents will be set to \c TRUE if the signature is valid
 *                          and \c FALSE otherwise.
 * @param ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                       that contains this function's intermediate value,
 *                       which can subsequently be used and eventually
 *                       discarded. (Before ending, your application should
 *                       be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check BOTH a status of \c OK and a \c pIsGoodSignature
 *             of \c TRUE before accepting that a signature is valid.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   dsa2.h
 * @funcdoc    dsa2.h
 */
MOC_EXTERN MSTATUS DSA_verifySignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen,
                                           intBoolean *pIsGoodSignature, vlong **ppVlongQueue);
    
    
#ifdef __cplusplus
}
#endif

#endif /* __DSA2_HEADER__ */
