/*
 * dsa.h
 *
 * DSA Factory Header
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
 @file       dsa.h

 @brief      Header file for the Nanocrypto DSA API.
 @details    This file documents the APIs of NanoCrypto DSA.

 @flags      To use these APIs one must define
             + \c \__ENABLE_DIGICERT_DSA__

 @filedoc    dsa.h
*/

/*------------------------------------------------------------------*/


#ifndef __DSA_HEADER__
#define __DSA_HEADER__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_dsa_priv.h"
#endif

#include "../crypto/ffc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/

#define DSA_CONTEXT(X)          (X)->p_dsaDescr
#define PRIVATE_KEY_BYTE_SIZE   (20)  /* To be deleted in the future. Should no longer be used. */


/*------------------------------------------------------------------*/

struct vlong;

#define NUM_DSA_VLONG   (5)
#define NUM_DSA_MODEXP  (2)

typedef struct DSAKey
{
    vlong*          dsaVlong[NUM_DSA_VLONG];

    MocAsymKey pPrivateKey;
    MocAsymKey pPublicKey;
    ubyte4     enabled;
} DSAKey;

typedef enum
{
    DSA_sha1 = FFC_sha1,
    DSA_sha224 = FFC_sha224,
    DSA_sha256 = FFC_sha256,
    DSA_sha384 = FFC_sha384,
    DSA_sha512 = FFC_sha512

} DSAHashType;

typedef enum
{
    DSA_186_2,
    DSA_186_4
} DSAKeyType;

#define DSA_P(k)            ((k)->dsaVlong[0])
#define DSA_Q(k)            ((k)->dsaVlong[1])
#define DSA_G(k)            ((k)->dsaVlong[2])
#define DSA_Y(k)            ((k)->dsaVlong[3])
#define DSA_X(k)            ((k)->dsaVlong[4])

typedef struct MDsaKeyTemplate *MDsaKeyTemplatePtr;

/*------------------------------------------------------------------*/

/**
 @brief      Create memory storage for a DSA key.

 @details    This function creates storage (allocates memory) for a DSA key.
             After the memory is allocated, applications can use the
             DSA_generateKey() function to generate the DSA key.

 @note       This function does not generate an actual DSA key value; to
             generate the DSA key pair, call the DSA_generateKey() function.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  pp_dsaDescr  On return, pointer to address of allocated memory
         (for a DSA key).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_createKey(DSAKey **pp_dsaDescr);


/**
 @brief      Clone (copy) a DSA key.

 @details    This function clones (copies) a DSA key. To avoid memory leaks,
             your application should call DSA_freeKey() when it is done using
             the cloned key.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  ppNew        On return, double pointer to cloned (copied) DSA key.
 @param  pSrc         Pointer to DSA key to clone (copy).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_cloneKey(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey** ppNew, const DSAKey* pSrc);


/**
 @brief      Free (delete) a DSA key.

 @details    This function frees (deletes) a DSA key. To avoid memory leaks,
             applications should call this function when an allocated DSA key
             is no longer needed.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

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

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_freeKey(DSAKey **pp_dsaDescr, vlong **ppVlongQueue);


/**
 @brief      Generate DSA key pair (private and public keys) and associated
             parameters.

 @details    This function generates a DSA key pair (private and public keys)
             and associated parameters. Typically, your application calls this
             function after calling the DSA_createKey() function.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                         expands to an additional parameter, "hwAccelDescr
                         hwAccelCtx". Otherwise, this macro resolves to nothing.
                         @todo_eng_review  But... what does the user specify? In
                         the 5.3.1 docs, we just said that this was "Reserved
                         for future use." Ditto this for all dsa.{c,h}
                         functions.

 @param  pFipsRngCtx     Pointer to RNG context to use for DSA key and parameter
                         generation.
 @param  p_dsaDescr      Pointer to DSA key memory, previously allocated by
                         DSA_createKey().
 @param  keySize         Bit length of the generated DSA key. (For
                         details, refer to the appropriate FIPS Publication,
                         accessible from the following Web page:
                         http://www.nist.gov/itl/fips.cfm.) Currently supported
                         are lengths of 1024, 2048, and 3072.
 @param  pRetC           On return, pointer to C value to use for DSK key
                         verification.
 @param  pRetSeed        If NULL, the function does not return the seed, otherwise,
                         it is a user-supplied buffer into which the function
                         will place the seed value. This is a value related to
                         FIPS certification. It must be the same size as the
                         subprime (160 bits for 1024-bit DSA keys, 256 bits for
                         2048-bit or 3072-bit DSA keys)
 @param  ppRetH          On return, pointer to address of H value to use for
                         DSA key verification (see DSA_verifyKeys). Call
                         VLONG_freeVlong when you are done with this value.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used (see DSA_verifyKeys).
                         (Before ending, your application should be sure to free
                         the entire queue by calling VLONG_freeVlongQueue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_generateKey(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue);


/**
 @brief      Generate DSA key pair (private and public keys).

 @details    Generate DSA key pair (private and public keys) and associated
             parameters. This method allows for a hash type and qSize to be
             passed in only the configurations allowed via FIPS 186-4 are allowed.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                         expands to an additional parameter, "hwAccelDescr
                         hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  pFipsRngCtx     Pointer to RNG context to use for DSA key and parameter
                         generation.
 @param  p_dsaDescr      Pointer to DSA key memory, previously allocated by
                         DSA_createKey().
 @param  keySize         Bit length of the generated DSA key.
 @param  qSize           Bit length of the cyclic group order q.
 @param  hashType        The hash algorithm to use in key generation.
 @param  pRetC           On return, pointer to C value to use for DSK key
                         verification.
 @param  pRetSeed        If NULL, the function does not return the seed, otherwise,
                         it is a user-supplied buffer into which the function
                         will place the seed value. This is a value related to
                         FIPS certification. It must be the same size as the
                         subprime (160 bits for 1024-bit DSA keys, 256 bits for
                         2048-bit or 3072-bit DSA keys)
 @param  ppRetH          On return, pointer to address of H value to use for
                         DSA key verification (see DSA_verifyKeys). Call
                         VLONG_freeVlong when you are done with this value.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used (see DSA_verifyKeys).
                         (Before ending, your application should be sure to free
                         the entire queue by calling VLONG_freeVlongQueue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_generateKeyEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 qSize, DSAHashType hashType, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue);


/**
 @brief      Generate DSA key pair (but not their associated parameters).

 @details    This function generates a DSA key pair, but not their associated
             parameters (which should already be within the DSA key). This
             method will obtain the key length and q length from the key, else
             use \c DSA_computeKeyPairEx.

 @note       To generate a DSA key pair \e and their associated parameters, call
             the DSA_generateKey() function instead of this function.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

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

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_computeKeyPair(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, vlong **ppVlongQueue);


/**
 @brief      Generate DSA key pair (but not their associated parameters).

 @details    This function generates a DSA key pair, but not their associated
             parameters (which should already be within the DSA key).

 @note       To generate a DSA key pair \e and their associated parameters, call
             the DSA_generateKey() function instead of this function.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx  If a hardware acceleration flag is defined, this macro
                     expands to an additional parameter, "hwAccelDescr
                     hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  pFipsRngCtx Pointer to RNG context to use for DSA key generation.
 @param  p_dsaDescr  Pointer to DSA key memory, previously allocated by calling
                     DSA_createKey(), and already filled with associated
                     parameters.
 @param  Lin         The length in bytes of the DSA prime p. (not used by this method)
 @param  Nin         The length in bytes of the DSA cyclic group order q.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                     that contains this function's intermediate value,
                     which can subsequently be used and eventually
                     discarded. (Before ending, your application should
                     be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_computeKeyPairEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr,  ubyte4 Lin, ubyte4 Nin, vlong **ppVlongQueue);


/**
 @brief      Generate DSA signature.

 @details    This function generates a DSA signature.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  pRandomContext  Pointer to RNG context to use for signature generation.
 @param  p_dsaDescr      Pointer to DSA key pair.
 @param  m               Pointer to digested input message.
 @param  pVerifySignature    On return, pointer to \c TRUE if generated
                         signature is valid; otherwise pointer to \c FALSE.
 @param  ppR             On return, pointer to address of \c R portion of the
                         resultant signature.
 @param  ppS             On return, pointer to address of \c S portion of the
                         resultant signature.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_computeSignature(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext, const DSAKey *p_dsaDescr,
                                        vlong* m, intBoolean *pVerifySignature, vlong **ppR, vlong **ppS, vlong **ppVlongQueue);


/**
 @brief       This is the same as \c DSAComputeSignature, except that it uses an RNGFun and
              rngArg to generate the random values, rather than a randomContext.

 @details    This function generates a DSA signature.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  rngfun          The random number generating function used
 @param  rngArg          Any info the rngfun needs to perform its operations
 @param  p_dsaDescr      Pointer to DSA key pair.
 @param  m               Pointer to digested input message.
 @param  pVerifySignature    On return, pointer to \c TRUE if generated
                         signature is valid; otherwise pointer to \c FALSE.
 @param  ppR             On return, pointer to address of \c R portion of the
                         resultant signature.
 @param  ppS             On return, pointer to address of \c S portion of the
                         resultant signature.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_computeSignatureEx(MOC_DSA(hwAccelDescr hwAccelCtx)
                                          RNGFun rngfun, void* rngArg,
                                          const DSAKey *p_dsaDescr, vlong* m,
                                          intBoolean *pVerifySignature,
                                          vlong **ppR, vlong **ppS, vlong **ppVlongQueue);


/**
 @brief      Verify message's DSA signature.

 @details    This function verifies a message's DSA signature.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                         expands to an additional parameter, "hwAccelDescr
                         hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  p_dsaDescr      Pointer to DSA key.
 @param  m               Pointer to digested input message.
 @param  pR              Pointer to \c R portion of the signature to verify.
 @param  pS              Pointer to \c S portion of the signature to verify.
 @param  isGoodSignature On return, pointer to \c TRUE if the signature is
                         valid; otherwise pointer to \c FALSE.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_verifySignature(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *p_dsaDescr,
                                       vlong *m, vlong *pR, vlong *pS, intBoolean *isGoodSignature, vlong **ppVlongQueue);


/**
 @brief      Verify DSA key.

 @details    This function verifies a DSA key that was generated by the
             DSA_generateKey() function with a default seed length of
             20 bytes, a default hashType of SHA-1, and a default keyType
             of DSA_186_4.

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                         expands to an additional parameter, "hwAccelDescr
                         hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  pFipsRngCtx     Pointer to RNG context used for DSA key generation.
 @param  pSeed           Pointer to seed value returned from DSA_generateKey().
 @param  p_dsaDescr      Pointer to DSA key to verify.
 @param  C               The iteration count C value returned from DSA_generateKey().
 @param  pH              Pointer to H value returned from DSA_generateKey().
 @param  isGoodKeys      On return, pointer to \c TRUE if the key is valid;
                         otherwise pointer to \c FALSE.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_verifyKeys(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, ubyte *pSeed, const DSAKey *p_dsaDescr, ubyte4 C, vlong *pH, intBoolean *isGoodKeys, vlong **ppVlongQueue);


/**
 @brief      Verify DSA key.

 @details    This function verifies a DSA key that was generated by the
             DSA_generateKey() function.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  hwAccelCtx      If a hardware acceleration flag is defined, this macro
                         expands to an additional parameter, "hwAccelDescr
                         hwAccelCtx". Otherwise, this macro resolves to nothing.
 @param  pFipsRngCtx     Pointer to RNG context used for DSA key generation.
 @param  pSeed           Pointer to seed value returned from DSA_generateKey().
 @param  seedSize        The size of the seed in bytes.
 @param  p_dsaDescr      Pointer to DSA key to verify.
 @param  hashType        The hash algorithm used within DSA_generateKey().
 @param  keyType         Either \c DSA_186_2 or \c DSA_186_4.
 @param  C               The iteration count C value returned from DSA_generateKey().
 @param  pH              Pointer to H value returned from DSA_generateKey().
 @param  isGoodKeys      On return, pointer to \c TRUE if the key is valid;
                         otherwise pointer to \c FALSE.
 @param  ppVlongQueue    On return, pointer to location in the \c vlong queue
                         that contains this function's intermediate value,
                         which can subsequently be used and eventually
                         discarded. (Before ending, your application should
                         be sure to free the entire queue.)

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_verifyKeysEx(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, ubyte *pSeed, ubyte4 seedSize, const DSAKey *p_dsaDescr, DSAHashType hashType, DSAKeyType keyType, ubyte4 C, vlong *pH, intBoolean *isGoodKeys, vlong **ppVlongQueue);


/**
 * @brief Verifies that the parameters p and q come from seed and initial
 *        domain parameters passed in.
 *
 * @details  Verifies that the parameters p and q come from seed and initial
 *           domain parameters passed in.
 *
 * @param pFipsRngCtx    Pointer to RNG context used during DSA key generation.
 * @param p_dsaDescr     Pointer to DSA key to with the p and q to verify.
 * @param L              The key size in bits.
 * @param Nin            The cyclic group order q's size in bits.
 * @param hashType       The original hash type used when key generation was done.
 * @param keyType        The original key type \c DSA_186_2 or \c DSA_186_4 used
 *                       when key generation was done.
 * @param C              The iteration count C value returned when original key
 *                       generation was done.
 * @param pSeed          Buffer holding the original seed used to generate p and q.
 * @param seedSize       The length of the seed in bytes.
 * @param pIsPrimePQ     Contents will be set to TRUE if p and q are successfully
 *                       verified and FALSE otherwise.
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
 */
MOC_EXTERN MSTATUS DSA_verifyPQ(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, DSAKeyType keyType, ubyte4 C,
                                ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue);

/**
 * @brief Verifies that g generates a cyclic group of prime order q.
 *
 * @details  Verifies that g generates a cyclic group of prime order q. This method
 *           does not verify q is prime. If q is not prime then g will also not
 *           be properly verified as a generator of the cyclic group.
 *
 * @param pP             The DSA large prime number p.
 * @param pQ             The cyclic group order q.
 * @param pG             The integer g to be verified.
 * @param isValid        Contents will be set to TRUE if p and q are successfully
 *                       verified and FALSE otherwise.
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
 */
MOC_EXTERN MSTATUS DSA_verifyG(MOC_DSA(hwAccelDescr hwAccelCtx) vlong *pP, vlong *pQ, vlong *pG, intBoolean *isValid, vlong **ppVlongQueue);


/**
 @brief      Get DSA key blob converted from  DSA key data structure.

 @details    This function generates a DSA key blob from information in a DSA
             key data structure, and returns the resultant key blob through
             the \p pKeyBlob parameter.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @warning    Before calling this function, be sure that the buffer pointed to
             by the \p pKeyBlob parameter is large enough; otherwise, buffer
             overflow will occur.

 @inc_file dsa.h

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

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_makeKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *p_dsaDescr, ubyte *pKeyBlob, ubyte4 *pRetKeyBlobLength);


/**
 @brief      Get DSA key data structure converted from DSA key blob.

 @details    This function generates a DSA key data structure from information
             in a DSA key blob, and returns the resultant key data structure
             through the \p pp_RetNewDsaDescr parameter.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  pp_RetNewDsaDescr   On return, pointer to address of resultant DSA key
                             variable.
 @param  pKeyBlob            Pointer to input key blob.
 @param  keyBlobLength       Number of bytes in input key blob (\p pKeyBlob).

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_extractKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey **pp_RetNewDsaDescr, const ubyte *pKeyBlob, ubyte4 keyBlobLength);


/**
 @brief      Determine whether two DSA keys are equal.

 @details    This function determines whether two DSA keys are equal, and
             returns the result through the \p res parameter.

 <table class="moc_crypto_info">
 <tr><td>FIPS Approved</td>
 <td>@image html check-green.gif ""
 @image latex check-green.png "" width=0.25in </td></tr>
 <tr><td>Suite B Algorithm</td>
 <td>@image html x-red.gif ""
 @image latex x-red.png "" width=0.25in </td></tr>
 <tr><td>Flowchart</td>
 <td>@htmlonly <a href="images/flowchart_dsa.jpg">DSA</a>@endhtmlonly
 @latexonly
 {See \nameref{Flowcharts}.}
 @endlatexonly</td></tr>
 </table>

 @ingroup    dsa_functions

 @flags      To use this API one must define + \c \__ENABLE_DIGICERT_DSA__

 @inc_file dsa.h

 @param  pKey1   Pointer to first DSA key.
 @param  pKey2   Pointer to second DSA key.
 @param  pResult On return, pointer to \c TRUE if the two keys are equal;
                 otherwise pointer to \c FALSE.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.

 @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_equalKey(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *pKey1, const DSAKey *pKey2, byteBoolean* pResult);


/**
 * @brief    Sets all the DSA domain and key parameters in a DSA key.
 *
 * @details  Sets all the DSA domain and key parameters in a DSA key from Big Endian
 *           byte arrays. The public key will be computed from the private key.
 *
 * @param pKey           Pointer to a previously allocated DSA key.
 * @param p              The DSA large prime number p as a Big Endian byte array.
 * @param pLen           The length of p in bytes.
 * @param q              The cyclic group order q as a Big Endian byte array.
 * @param qLen           The length of q in bytes.
 * @param g              The cyclic group generator g as a Big Endian byte array.
 * @param gLen           The length of g in bytes.
 * @param x              The private key x as a Big Endian byte array.
 * @param xLen           The length of x in bytes.
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
MOC_EXTERN MSTATUS DSA_setAllKeyParameters(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey* pKey,  const ubyte* p, ubyte4 pLen,
                                            const ubyte* q, ubyte4 qLen,
                                            const ubyte* g, ubyte4 gLen,
                                            const ubyte* x, ubyte4 xLen,
                                            vlong **ppVlongQueue);

/**
 * @brief    Sets all the DSA domain and public key parameters in a DSA key.
 *
 * @details  Sets all the DSA domain and public key parameters in a DSA key from Big Endian
 *           byte arrays.
 *
 * @param pKey           Pointer to a previously allocated DSA key.
 * @param p              The DSA large prime number p as a Big Endian byte array.
 * @param pLen           The length of p in bytes.
 * @param q              The cyclic group order q as a Big Endian byte array.
 * @param qLen           The length of q in bytes.
 * @param g              The cyclic group generator g as a Big Endian byte array.
 * @param gLen           The length of g in bytes.
 * @param y              The public key y as a Big Endian byte array.
 * @param yLen           The length of y in bytes.
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
MOC_EXTERN MSTATUS DSA_setPublicKeyParameters(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey* pKey,  const ubyte* p, ubyte4 pLen,
                                            const ubyte* q, ubyte4 qLen,
                                            const ubyte* g, ubyte4 gLen,
                                            const ubyte* y, ubyte4 yLen,
                                            vlong **ppVlongQueue);

/**
 * @brief    Sets the DSA domain parameters in a DSA key.
 *
 * @details  Sets the DSA domain parameters in a DSA key from Big Endian
 *           byte arrays. Setting the generator g is optional.
 *
 * @param pKey           Pointer to a previously allocated DSA key.
 * @param p              The DSA large prime number p as a Big Endian byte array.
 * @param pLen           The length of p in bytes.
 * @param q              The cyclic group order q as a Big Endian byte array.
 * @param qLen           The length of q in bytes.
 * @param g              Optional. The cyclic group generator g as a Big Endian byte array.
 * @param gLen           The length of g in bytes.
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
MOC_EXTERN MSTATUS DSA_setKeyParameters (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, const ubyte* p, ubyte4 pLen,
                                         const ubyte* q, ubyte4 qLen,
                                         const ubyte* g, ubyte4 gLen,
                                         vlong **ppVlongQueue);

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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_getCipherTextLength(MOC_DSA(hwAccelDescr hwAccelCtx) const DSAKey *pKey, sbyte4* cipherTextLen);


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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_getSignatureLength (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte4 *pSigLen);

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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS generatePQ(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                            DSAKey *p_dsaDescr, ubyte4 L,
                                            ubyte4 Nin, DSAHashType hashType,
                                            ubyte4 *pRetC, ubyte *pRetSeed,
                                            vlong **ppVlongQueue);

/**
 * @brief   Deterministically computes a generator g of the cyclic group of order q.
 *
 * @details Deterministically computes a generator g of the cyclic group of order q.
 *          Optionally, the intermediate value h can be be output by this method
 *          in \c vlong form. If exercising that option be sure to call
 *          \c VLONG_freeVlong when done with it.
 *
 * @param p_dsaDescr     Pointer to a previously allocated DSA key that already
 *                       has the domain parameters p and q set. The new value g
 *                       will be set within this DSA key too.
 * @param ppRetH         Optional. If provided, pointer to the location that will receive
 *                       receive a newly allocated vlong with the base h used to compute g,
 *                       ie g = h^((p-1)/q).
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
MOC_EXTERN MSTATUS generateG(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *p_dsaDescr,
                                            vlong **ppRetH, vlong **ppVlongQueue);

/**
 * @brief   Randomly computes a generator g of the cyclic group of order q.
 *
 * @details Randomly computes a generator g of the cyclic group of order q.
 *          Optionally, the intermediate value h can be be output by this method
 *          in \c vlong form. If exercising that option be sure to call
 *          \c VLONG_freeVlong when done with it.
 *
 * @param p_dsaDescr     Pointer to a previously allocated DSA key that already
 *                       has the domain parameters p and q set. The new value g
 *                       will be set within this DSA key too.
 * @param pRandomContext Pointer to RNG context to be used.
 * @param ppRetH         Optional. If provided, pointer to the location that will receive
 *                       receive a newly allocated vlong with the base h used to compute g,
 *                       ie g = h^((p-1)/q).
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
MOC_EXTERN MSTATUS DSA_generateRandomG (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *p_dsaDescr,
                                        randomContext *pRandomContext, vlong **ppRetH, vlong **ppVlongQueue);

/**
 * @brief   Randomly computes a generator g of the cyclic group of order q.
 *
 * @details Randomly computes a generator g of the cyclic group of order q.
 *
 * @param p_dsaDescr     Pointer to a previously allocated DSA key that already
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
MOC_EXTERN MSTATUS DSA_generateRandomGAux (MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *p_dsaDescr,
                                           randomContext *pRandomContext, ubyte **ppH, ubyte4 *pHLen, vlong **ppVlongQueue);

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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_generateKeyAux(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, vlong **ppVlongQueue);

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
 *                       \c DSA_createKey().
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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_generateKeyAux2(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize,
                                       ubyte4 qSize, DSAHashType hashType, vlong **ppVlongQueue);

/**
 * @brief      Computes the DSA signature.
 *
 * @details    Computes the DSA signature. This method allocates buffers to hold
 *             the signature values R and S. Be sure to free these buffers when done.
 *
 * @param pRngCtx        Pointer to RNG context to use for DSA key and parameter
 *                       generation.
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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_computeSignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) randomContext *pRngCtx, DSAKey *pKey, ubyte *pM, ubyte4 mLen, intBoolean *pVerify, ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue);


/**
 * @brief      Verifies a DSA signature.
 *
 * @details    Verifies a DSA signature.
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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_verifySignatureAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

/**
 * @brief      Sets DSA key and domain parameters.
 *
 * @details    Sets DSA key and domain parameters.
 *
 * @param pKey           Pointer to the target DSA key memory, previously allocated by
 *                       \c DSA_createKey().
 * @param pTemplate      Template holding the paramters to be set.
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
MOC_EXTERN MSTATUS DSA_setKeyParametersAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, MDsaKeyTemplatePtr pTemplate);

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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_getKeyParametersAlloc(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey, MDsaKeyTemplatePtr pTemplate, ubyte keyType);

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
 * @inc_file   dsa.h
 * @funcdoc    dsa.h
 */
MOC_EXTERN MSTATUS DSA_freeKeyTemplate(DSAKey *pKey, MDsaKeyTemplatePtr pTemplate);

#ifdef __cplusplus
}
#endif

#endif /* __DSA_HEADER__ */
