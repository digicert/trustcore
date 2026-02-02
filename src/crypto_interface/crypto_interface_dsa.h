/*
 * crypto_interface_dsa.h
 *
 * Cryptographic Interface header file for declaring DSA methods
 * for the Crypto Interface.
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
@file       crypto_interface_dsa.h
@brief      Cryptographic Interface header file for declaring DSA methods.

@filedoc    crypto_interface_dsa.h
*/
#ifndef __CRYPTO_INTERFACE_DSA_HEADER__
#define __CRYPTO_INTERFACE_DSA_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 @brief      Create memory storage for a DSA key.

 @details    This function creates storage (allocates memory) for a DSA key.
             After the memory is allocated, applications can use the
             CRYPTO_INTERFACE_DSA_generateKey() function to generate the DSA key.

 @note       This function does not generate an actual DSA key value; to
             generate the DSA key pair, call the DSA_generateKey() function.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  pp_dsaDescr  On return, pointer to address of allocated memory
         (for a DSA key).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_createKey (
    DSAKey **pp_dsaDescr
    );

/**
 @brief      Clone (copy) a DSA key.

 @details    This function clones (copies) a DSA key. To avoid memory leaks,
             your application should call CRYPTO_INTERFACE_DSA_freeKey() when
             it is done using the cloned key.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  ppNew        On return, double pointer to cloned (copied) DSA key.
 @param  pSrc         Pointer to DSA key to clone (copy).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_cloneKey (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey** ppNew,
    const DSAKey* pSrc
    );

/**
 @brief      Free (delete) a DSA key.

 @details    This function frees (deletes) a DSA key. To avoid memory leaks,
             applications should call this function when an allocated DSA key
             is no longer needed.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  pp_dsaDescr     Pointer to address of DSA key to free (delete).
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_freeKey (
    DSAKey **pp_dsaDescr,
    vlong **ppVlongQueue
    );

/**
 @brief      Generate DSA key pair (but not their associated parameters).

 @details    This function generates a DSA key pair, but not their associated
             parameters (which should already be within the DSA key). This
             method will obtain the key length and q length from the key.

 @note       To generate a DSA key pair \e and their associated parameters, call
             the DSA_generateKey() function instead of this function.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  pFipsRngCtx Pointer to RNG context to use for DSA key generation.
 @param  p_dsaDescr  Pointer to DSA key memory, previously allocated by calling
                     DSA_createKey(), and already filled with associated
                     parameters.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                     that contains this function's intermediate value,
                     which can subsequently be used and eventually
                     discarded. (Before ending, your application should
                     be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeKeyPair(
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    vlong **ppVlongQueue
    );

/**
 @brief      Get DSA key blob converted from  DSA key data structure.

 @details    This function generates a DSA key blob from information in a DSA
             key data structure, and returns the resultant key blob through
             the \p pKeyBlob parameter.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @warning    Before calling this function, be sure that the buffer pointed to
             by the \p pKeyBlob parameter is large enough; otherwise, buffer
             overflow will occur.

 @inc_file crypto_interface_dsa.h

 @param  p_dsaDescr          Pointer to DSA key variable's data structure.
 @param  pKeyBlob            On return, pointer to resultant key blob. <b>(The
                             calling function must allocate sufficient
                             memory for the result; otherwise buffer
                             overflow will occur.)</b>
 @param  pRetKeyBlobLength   On return, pointer to number of bytes in resultant
                             key blob buffer (\p pKeyBlob).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_makeKeyBlob (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *p_dsaDescr,
    ubyte *pKeyBlob,
    ubyte4 *pRetKeyBlobLength
    );

/**
 @brief      Get DSA key data structure converted from DSA key blob.

 @details    This function generates a DSA key data structure from information
             in a DSA key blob, and returns the resultant key data structure
             through the \p pp_RetNewDsaDescr parameter.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  pp_RetNewDsaDescr   On return, pointer to address of resultant DSA key
                             variable.
 @param  pKeyBlob            Pointer to input key blob.
 @param  keyBlobLength       Number of bytes in input key blob (\p pKeyBlob).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_extractKeyBlob (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey **pp_RetNewDsaDescr,
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength
    );

/**
 @brief      Determine whether two DSA keys are equal.

 @details    This function determines whether two DSA keys are equal, and
             returns the result through the \p res parameter.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file crypto_interface_dsa.h

 @param  pKey1   Pointer to first DSA key.
 @param  pKey2   Pointer to second DSA key.
 @param  pResult On return, pointer to \c TRUE if the two keys are equal;
                 otherwise pointer to \c FALSE.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_equalKey (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *pKey1,
    const DSAKey *pKey2,
    byteBoolean* pResult
    );

/**
 * @brief   Gets the length in bytes of the DSA prime p.
 *
 * @details Gets the length in bytes of the DSA prime p.
 *
 * @param pKey           Pointer to a DSA key that has its domain parameters set.
 * @param cipherTextLen  Contents will be set to the length in bytes of the DSA prime p.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getCipherTextLength (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *pKey,
    sbyte4* cipherTextLen
    );


/**
 * @brief   Gets the length in bytes of the DSA prime q and therefore the signature
 *          components r and s.
 *
 * @details Gets the length in bytes of the DSA prime q and therefore the signature
 *          components r and s.
 *
 * @param pKey           Pointer to a DSA key that has its domain parameters set.
 * @param pSigLen        Contents will be set to the length in bytes of the DSA prime q.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getSignatureLength (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    ubyte4 *pSigLen
    );

/**
 * @brief   Generates the DSA domain parameters p and q.
 *
 * @details Generates the DSA prime number p of the appropriate size, such that
 *          the associated mutliplicative group contains a cyclic subgroup
 *          of a prime order q of the appropriate size. The C value and seed
 *          used to generate these parameters are also given as output values.
 *
 * @param pFipsRngCtx    Pointer to RNG context to be used during DSA domain parameter generation.
 * @param p_dsaDescr     Pointer to a previously allocated DSA key. The domain parameters
 *                       p and q will be set within this key.
 * @param L              The desired size of p in bits.
 * @param Nin            The desired cyclic group order q's size in bits.
 * @param hashType       The hash algorithm you wish to use in domain parameter generation.
 *                       This should be one of...
 *
 *                       + DSA_sha1
 *                       + DSA_sha224
 *                       + DSA_sha256
 *                       + DSA_sha384
 *                       + DSA_sha512
 *
 * @param pRetC          Contents will be set to the number of iterations used
 *                       to compute the prime p.
 * @param pRetSeed       Buffer that will be filled with the seed to the prime
 *                       generation algorithm. The length of this seed in bytes is
 *                       \c Nin/8 and this buffer should have enough space.
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
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generatePQ (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 L,
    ubyte4 Nin,
    DSAHashType hashType,
    ubyte4 *pRetC,
    ubyte *pRetSeed,
    vlong **ppVlongQueue
    );

/**
 * @brief      Generate DSA key pair (private and public keys) and associated
 *             parameters.
 *
 * @details    Generate DSA key pair (private and public keys) and associated
 *             parameters.
 *
 * @param pFipsRngCtx    Pointer to RNG context to use for DSA key and parameter
 *                       generation.
 * @param p_dsaDescr     Pointer to DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param keySize        Bit length of the generated DSA key. (For
 *                       details, refer to the appropriate FIPS Publication,
 *                       accessible from the following Web page:
 *                       http://www.nist.gov/itl/fips.cfm.) Currently supported
 *                       are lengths of 1024, 2048, and 3072.
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
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateKeyAux (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 keySize,
    vlong **ppVlongQueue
    );

/**
 * @brief      Generate DSA key pair (private and public keys) and associated
 *             parameters with flexibility to set the q size and hash algo.
 *
 * @details    Generate DSA key pair (private and public keys) and associated
 *             parameters with flexibility to set the q size and hash algo.
 *
 * @param pFipsRngCtx    Pointer to RNG context to use for DSA key and parameter
 *                       generation.
 * @param p_dsaDescr     Pointer to DSA key memory, previously allocated by
 *                       \c CRYPTO_INTERFACE_DSA_createKey().
 * @param keySize        Bit length of the generated DSA domain parameter p. (For
 *                       details, refer to the appropriate FIPS Publication,
 *                       accessible from the following Web page:
 *                       http://www.nist.gov/itl/fips.cfm.) Currently supported
 *                       are lengths of 1024, 2048, and 3072.
 * @param qSize          Bit length of the generated DSA domain parameter q.
 *                       Currently supported lengths are 160, 224, and 256.
 * @param hashType       The hash algorithm to use in domain parameter generation.
 *                       Valid values are...
 *                       \c DSA_sha1
 *                       \c DSA_sha224
 *                       \c DSA_sha256
 *                       \c DSA_sha384
 *                       \c DSA_sha512
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
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateKeyAux2 (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 keySize,
    ubyte4 qSize,
    DSAHashType hashType,
    vlong **ppVlongQueue
    );

/**
 * @brief      Computes the DSA signature.
 *
 * @details    Computes the DSA signature. This method allocates buffers to hold
 *             the signature values R and S. Be sure to free these buffers when done.
 *
 * @param pRngCtx        Pointer to RNG context to use for DSA key and parameter
 *                       generation.
 * @param pKey           Pointer to DSA key memory, previously allocated by
 *                       \c CRYPTO_INTERFACE_DSA_createKey().
 * @param pM             The message to be signed.
 * @param mLen           The length of the message in bytes.
 * @param pVerify        If non-null the signature will be verified (as a sanity check)
 *                       In that case contents will be set \c TRUE if valid and \c FALSE
 *                       otherwise.
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
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeSignatureAux (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext *pRngCtx,
    DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    intBoolean *pVerify,
    ubyte **ppR,
    ubyte4 *pRLen,
    ubyte **ppS,
    ubyte4 *pSLen,
    vlong **ppVlongQueue
    );

/**
 * @brief      Verifies a DSA signature.
 *
 * @details    Verifies a DSA signature.
 *
 * @param pKey           Pointer to DSA key memory, previously allocated by
 *                       \c CRYPTO_INTERFACE_DSA_createKey().
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
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifySignatureAux (
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    intBoolean *pIsGoodSignature,
    vlong **ppVlongQueue
    );

/**
 * @brief      Sets DSA key and domain parameters.
 *
 * @details    Sets DSA key and domain parameters.
 *
 * @param pKey           Pointer to the target DSA key memory, previously allocated by
 *                       \c CRYPTO_INTERFACE_DSA_createKey().
 * @param pTemplate      Template holding the paramters to be set.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_setKeyParametersAux (
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate
    );

/**
 * @brief      Gets DSA key and domain parameters.
 *
 * @details    Gets DSA key and domain parameters. This method will allocated the
 *             fields within the passed in template. Be sure to call \c DSA_freeKeyTemplate
 *             to free these fields when done with them.
 *
 * @param pKey           Pointer to the DSA key memory containing key and domain parameters.
 * @param pTemplate      Target template that will hold all parameters that were contained in \c pKey.
 * @param keyType        Type of key data to receive, must be one of
 *                       \c MOC_GET_PUBLIC_KEY_DATA or \c MOC_GET_PRIVATE_KEY_DATA.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getKeyParametersAlloc (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate,
    ubyte keyType
    );

/**
 * @brief      Frees the fields within a key template.
 *
 * @details    Frees the fields within a key template.
 *
 * @param pKey          Pointer to the DSA key associated with the template.
 * @param pTemplate     Template whose fields will be freed.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @ingroup    dsa_functions
 * @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__
 * @inc_file   crypto_interface_dsa.h
 * @funcdoc    crypto_interface_dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_freeKeyTemplate (
    DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate
    );

/**
 * @brief   Randomly computes a generator g of the cyclic group of order q.
 *
 * @details Randomly computes a generator g of the cyclic group of order q.
 *
 * @param pKey           Pointer to a previously allocated DSA key that already
 *                       has the domain parameters p and q set. The new value g
 *                       will be set within this DSA key too.
 * @param pRandomContext Pointer to RNG context to be used.
 * @param ppH            Optional. If provided, pointer to the location that will receive
 *                       receive a newly allocated buffer with the base h used to compute g,
 *                       ie g = h^((p-1)/q). h will be in Big Endian.
 * @param pHLen          Required if ppH is not NULL. Contents will be set to the length
 *                       of h in bytes.
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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateRandomGAux (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
                                                            randomContext *pRandomContext, ubyte **ppH, ubyte4 *pHLen, vlong **ppVlongQueue);

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
 * @param pVerify        If non-null the signature will be verified (as a sanity check)
 *                       In that case contents will be set \c TRUE if valid and \c FALSE
 *                       otherwise.
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeSignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) RNGFun rngfun, void *pRngArg, DSAKey *pKey, ubyte *pM, ubyte4 mLen,
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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifySignature2Aux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte *pM, ubyte4 mLen,
                                                            ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen,
                                                            intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief      Validates a DSA public key.
 * @details    Validates a DSA public key.
 *
 * @param pKey           A key context containing a public key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
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
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyPublicKey(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);

/**
 * @brief      Validates a DSA private/public key pair.
 * @details    Validates a DSA private/public key pair.
 *
 * @param pKey           A key context containing a private and public key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
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
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyKeyPair(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);


/**
 * @brief      Validates a DSA private key.
 * @details    Validates a DSA private key.
 *
 * @param pKey           A key context containing a private key.
 * @param pIsValid       Contents will be set to \c TRUE if the key is valid
 *                       and \c FALSE otherwise.
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
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyPrivateKey(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DSA_HEADER__ */
