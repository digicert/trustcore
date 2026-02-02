/**
 * @file rsa.h
 *
 * @brief     Header file for the Nanocrypto RSA API.
 * @details   RSA public key encryption
 *
 * @ingroup crypto_tree
 * @ingroup crypto_nanotap_tree
 *
 * @flags
 * Whether the following flags are defined determines which additional header files
 * are included:
 *   + \c \__ENABLE_DIGICERT_FIPS_MODULE__
 *   + \c \__ENABLE_DIGICERT_PKCS11_CRYPTO__
 *   + \c \__ENABLE_DIGICERT_HW_SECURITY_MODULE__
 *   + \c \__RSA_HARDWARE_ACCELERATOR__
 *
 * @flags
 * Whether the following flags are defined determines which function declarations
 * are enabled:
 *   + \c \__CUSTOM_RSA_BLINDING__
 *   + \c \__DISABLE_DIGICERT_KEY_GENERATION__
 *   + \c \__DISABLE_DIGICERT_RSA_CLIENT_CODE__
 *   + \c \__DISABLE_DIGICERT_RSA_DECRYPTION__
 *   + \c \__DISABLE_DIGICERT_RSA_SIGN__
 *   + \c \__DISABLE_DIGICERT_RSA_VERIFY__
 *   + \c \__DISABLE_DIGICERT_RSA_VERIFY_CERTIFICATE__
 *   + \c \__DISABLE_PKCS1_KEY_READ__
 *   + \c \__ENABLE_ALL_TESTS__
 *   + \c \__ENABLE_DIGICERT_FIPS_MODULE__
 *   + \c \__ENABLE_DIGICERT_PKCS11_CRYPTO__
 *   + \c \__ENABLE_DIGICERT_VERIFY_RSA_SIGNATURE__
 *   + \c \__DIGICERT_BLIND_FACTOR_SIZE__
 *   + \c \__RSAINT_HARDWARE__
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

#ifndef __RSA_H__
#define __RSA_H__

#include "../cap/capdecl.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration */
typedef struct MRsaKeyTemplate *MRsaKeyTemplatePtr;

/*! @cond */

#define NUM_RSA_VLONG   (7)
#define NUM_RSA_MODEXP  (2)

#if !defined( __DISABLE_DIGICERT_RSA_DECRYPTION__) && !defined(__PSOS_RTOS__)
typedef struct BlindingHelper
{
    RTOS_MUTEX      blindingMutex;
    vlong*          pRE;
    vlong*          pR1;
    ubyte4          counter;
} BlindingHelper;
#endif

/*! @endcond */

struct RSAKey;

#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
struct HSMRSAInfo;
#endif

typedef struct RSAKey
{
    intBoolean      privateKey;
    vlong*          v[NUM_RSA_VLONG];
    ModExpHelper    modExp[NUM_RSA_MODEXP];
#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) && !defined( __PSOS_RTOS__)
    BlindingHelper  blinding;
#endif
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
    struct HSMRSAInfo*     hsmInfo;
#endif
    MocAsymKey pPrivateKey;
    MocAsymKey pPublicKey;
    ubyte4     enabled;
} RSAKey;

/*! Macro to return e */
#define RSA_E(k)            ((k)->v[0])
/*! Macro to return n (modulus = size of encrypted data) */
#define RSA_N(k)            ((k)->v[1])
/*! Macro to return p */
#define RSA_P(k)            ((k)->v[2])
/*! Macro to return q */
#define RSA_Q(k)            ((k)->v[3])
/*! Macro to return Dp */
#define RSA_DP(k)           ((k)->v[4])
/*! Macro to return Dq */
#define RSA_DQ(k)           ((k)->v[5])
/*! Macro to return Qinv */
#define RSA_QINV(k)         ((k)->v[6])
/*! Macro to return mod p */
#define RSA_MODEXP_P(k)     ((k)->modExp[0])
/*! Macro to return mod q */
#define RSA_MODEXP_Q(k)     ((k)->modExp[1])

/*! Macro to return RSA key size */
#define RSA_KEYSIZE(k)	    (VLONG_bitLength(RSA_N(k)))

/*------------------------------------------------------------------*/

/** @cond   Omit the following from Doxygen output. **/

/* RSA primitives defined in PKCS#1 version 2.1 */
#if !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__)
MOC_EXTERN MSTATUS RSA_RSADP(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, const vlong *pCipherText, vlong **ppMessage, vlong **ppVlongQueue);
#endif
MOC_EXTERN MSTATUS RSA_RSAEP(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pPublicRSAKey, const vlong *pMessage, vlong **ppRetCipherText, vlong **ppVlongQueue);

#if (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__) && defined(__RSAINT_HARDWARE__) && defined(__ENABLE_DIGICERT_PKCS11_CRYPTO__))
#define RSA_RSASP1 RSAINT_decrypt
#elif (!defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))
MOC_EXTERN MSTATUS RSA_RSASP1(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pRSAKey, const vlong *pMessage, RNGFun rngFun, void* rngFunArg, vlong **ppRetSignature, vlong **ppVlongQueue);
#endif
MOC_EXTERN MSTATUS RSA_RSAVP1(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pPublicRSAKey, const vlong *pSignature, vlong **ppRetMessage, vlong **ppVlongQueue);

/** @endcond **/

/*------------------------------------------------------------------*/

/** @cond   Omit the following from Doxygen output. **/

/* used for custom RSA blinding implementation */
typedef MSTATUS (*RSADecryptFunc)(MOC_RSA(hwAccelDescr hwAccelCtx)
                                         const RSAKey *pRSAKey,
                                         const vlong *c,
                                         vlong **ppRetDecrypt,
                                         vlong **ppVlongQueue);

typedef MSTATUS (*CustomBlindingFunc)( MOC_RSA(hwAccelDescr hwAccelCtx)
                                        const RSAKey* pRSAKeyInt,
                                        const vlong* pCipher,
                                        RNGFun rngFun, void* rngFunArg,
                                        RSADecryptFunc rsaDecryptPrimitive,
                                        vlong** ppRetDecrypt,
                                        vlong** ppVlongQueue);

/** @endcond **/

/*------------------------------------------------------------------*/

/**
 * @private
 * @internal
 *
 * @brief  exported for FIPS RSA Key Generation Testing
 *
 * @ingroup    rsa_functions
 */
MOC_EXTERN MSTATUS
RSA_generateKeyFipsSteps(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                         ubyte4 nLen, vlong *e, const vlong *pDebugX, ubyte4 length1, ubyte4 length2,
                         vlong **ppRetP1, vlong **ppRetP2, vlong **ppRetXp, vlong **ppRetPrime,
                         ubyte *pInputSeed, ubyte4 inputSeedLength,
                         ubyte *pRetPrimeSeed1, ubyte *pRetPrimeSeed2,
                         intBoolean *pRetFail,
                         MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
                         ubyte4 hashResultSize,
                         vlong **ppVlongQueue);


/**
 * @brief      Create memory storage for an RSA key pair.
 *
 * @details    This function creates storage (allocates memory) for an RSA key
 *             pair. After the memory is allocated, applications can use the
 *             RSA_generateKey() function to generate the RSA key pair.
 *
 * @note       This function does not generate actual RSA key values; to
 *             generate an RSA key pair, call the RSA_generateKey() function.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param  [out] pp_RetRSAKey   On return, pointer to address of allocated memory
 *                              (for an RSA key).
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_createKey(RSAKey **pp_RetRSAKey);

/**
 * @brief      Free (delete) an RSA key.
 *
 * @details    This function frees (deletes) an RSA key. To avoid memory leaks,
 *             applications should call this function when an allocated RSA key
 *             is no longer needed.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 * There are no flag dependencies to enable this function.
 *
 * @param  [in,out] ppFreeRSAKey  Pointer to address of RSA key to free (delete).
 * @param  [in,out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                                that contains this function's intermediate value,
 *                                which can subsequently be used and eventually
 *                                discarded. (Before ending, your application should
 *                                be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_freeKey(RSAKey **ppFreeRSAKey, vlong **ppVlongQueue);

/**
 * @brief      Clone (copy) an RSA key.
 *
 * @details    This function clones (copies) an RSA key. To avoid memory leaks,
 *             your application should call RSA_freeKey() when it is done using
 *             the cloned key.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param  [out]    ppNew        On return, pointer to address of cloned RSA key.
 * @param  [in]     pSrc         Pointer to RSA key to clone.
 * @param  [in,out] ppVlongQueue On return, pointer to location in the \c vlong queue
 *                               that contains this function's intermediate value,
 *                               which can subsequently be used
 *                               and eventually discarded. (Before ending, your
 *                               application should be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS      RSA_cloneKey(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey **ppNew, const RSAKey *pSrc, vlong **ppVlongQueue);


/**
 * @brief      Determine whether two RSA keys are equal.
 *
 * @details    This function determines whether two RSA keys are equal, and
 *             returns the result through the \p pResult parameter.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param [in]  pKey1   Pointer to first RSA key.
 * @param [in]  pKey2   Pointer to second RSA key.
 * @param [out] pResult On return, pointer to \c TRUE if the two keys are equal;
 *                      otherwise pointer to \c FALSE.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS      RSA_equalKey(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey1, const RSAKey *pKey2, byteBoolean *pResult);


/**
 * @brief      Set RSA public key parameters: %exponent and %modulus.
 *
 * @details    This function sets an RSA public key's \c exponent and \c modulus
 *             parameters. The \c modulus is a string of bytes in big endian
 *             format.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param  [in,out] pKey          Pointer to RSA public key.
 * @param  [in] exponent          RSA public key %exponent. (For details, refer to the
 *                                appropriate FIPS Publication, accessible from the
 *                                following Web page:
 *                                http://www.nist.gov/itl/fips.cfm.)
 * @param  [in] modulus           Pointer to buffer containing the desired %modulus, represented
 *                                as a buffer of bytes in big endian format.
 * @param  [in] modulusLen        Number of bytes in \p modulus.
 * @param  [in,out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                                that contains this function's intermediate value,
 *                                which can subsequently be used and eventually
 *                                discarded. (Before ending, your application should
 *                                be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_setPublicKeyParameters(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pKey,
                                              ubyte4 exponent,
                                              const ubyte* modulus,
                                              ubyte4 modulusLen,
                                              vlong **ppVlongQueue);

/** This is the same as RSA_setPublicKeyParameters, except the public exponent is
 * passed in as a canonical int.
 *
 * @param  [in,out] pKey          Pointer to RSA public key.
 * @param  [in] pPubExpo          RSA public key %exponent. (For details, refer to the
 *                                appropriate FIPS Publication, accessible from the
 *                                following Web page:
 *                                http://www.nist.gov/itl/fips.cfm.)
 * @param  [in] pubExpoLen        Number of bytes in \p pPubExpo.
 * @param  [in] pModulus          Pointer to buffer containing the desired %modulus, represented
 *                                as a buffer of bytes in big endian format.
 * @param  [in] modulusLen        Number of bytes in \p pModulus.
 * @param  [in,out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                                that contains this function's intermediate value,
 *                                which can subsequently be used and eventually
 *                                discarded. (Before ending, your application should
 *                                be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_setPublicKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  vlong **ppVlongQueue
  );

/**
 * @brief      Set RSA public key parameters.
 *
 * @details    This function sets an RSA public key's parameters. The \c modulus
 *             is a string of bytes in big endian format.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable the functions in this header file.
 *
 * @param  [in]     hwAccelCtx    (Reserved for future use.)
 * @param  [in,out] pKey          Pointer to RSA public key.
 * @param  [in]     exponent      RSA public key %exponent.
 * @param  [in]     modulus       Pointer to buffer containing %modulus, represented as a
 *                                buffer of bytes in big endian format.
 * @param  [in]     modulusLen    Number of bytes in \p modulus.
 * @param  [in]     prime1        Pointer to buffer containing first prime number for RSA key
 *                                calculation.
 * @param  [in]     prime1Len     Number of bytes in the first prime number buffer (\p
 *                                prime1).
 * @param  [in]     prime2        Pointer to buffer containing second prime number for RSA key
 *                                calculation.
 * @param  [in]     prime2Len     Number of bytes in the second prime number buffer (\p
 *                                prime2).
 * @param  [out]    ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                                that contains this function's intermediate value,
 *                                which can subsequently be used and eventually
 *                                discarded. (Before ending, your application should
 *                                be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_setAllKeyParameters(
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte4 exponent,
  const ubyte *modulus,
  ubyte4 modulusLen,
  const ubyte *prime1,
  ubyte4 prime1Len,
  const ubyte *prime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue);

/** This is the same as RSA_setAllKeyParameters, except the public exponent is
 * passed in as a canonical int.
 *
 * @param  [in,out] pKey          Pointer to RSA public key.
 * @param  [in]     pPubExpo      RSA public key %exponent. (For details, refer to the
 *                                appropriate FIPS Publication, accessible from the
 *                                following Web page:
 *                                http://www.nist.gov/itl/fips.cfm.)
 * @param  [in]     pubExpoLen    Number of bytes in \p pPubExpo.
 * @param  [in]     pModulus      Pointer to buffer containing the desired %modulus, represented
 *                                as a buffer of bytes in big endian format.
 * @param  [in]     modulusLen    Number of bytes in \p pModulus.
 * @param  [in]     pPrime1       Pointer to buffer containing first prime number for RSA key
 *                                calculation.
 * @param  [in]     prime1Len     Number of bytes in the first prime number buffer (\p
 *                                prime1).
 * @param  [in]     pPrime2       Pointer to buffer containing second prime number for RSA key
 *                                calculation.
 * @param  [in]     prime2Len     Number of bytes in the second prime number buffer (\p
 *                                prime2).
 * @param  [in,out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                                that contains this function's intermediate value,
 *                                which can subsequently be used and eventually
 *                                discarded. (Before ending, your application should
 *                                be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_setAllKeyData (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  ubyte *pPubExpo,
  ubyte4 pubExpoLen,
  const ubyte *pModulus,
  ubyte4 modulusLen,
  const ubyte *pPrime1,
  ubyte4 prime1Len,
  const ubyte *pPrime2,
  ubyte4 prime2Len,
  vlong **ppVlongQueue
  );

/**
 *
 * Retrieve the following components from an RSA key as byte string buffers:
 *   - Public Exponent (E)
 *   - Modulus (N)
 *   - Components of N (For private keys):
 *     - Prime P
 *     - Prime Q
 *
 * This function allocates the buffers onto the heap, therefore a call to
 * the free function RSA_freeKeyTemplate is required in order to properly free
 * these buffers.
 *
 *
 * @param  [in]      pKey         Pointer to an RSA key.
 * @param  [in,out]  pTemplate    Pointer to the RSA standard key template
 *                                structure.
 * @param  [in]      keyType      Instructs the function whether to return
 *                                public or private key data. Value may either
 *                                be MOC_GET_PUBLIC_KEY_DATA or
 *                                MOC_GET_PRIVATE_KEY_DATA
 *
 * @return    \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_getKeyParametersAlloc (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pKey,
  MRsaKeyTemplatePtr pTemplate,
  ubyte keyType
  );

/**
 *
 * Free the RSA standard key template structure previouslly allocated by
 * RSA_getKeyParametersAlloc.
 *
 * @param   [in]      pKey         Pointer to the original key the data was
 *                                 retrieved from.
 * @param   [in,out]  pTemplate    Pointer to the RSA standard key template
 *                                 structure.
 *
 * @return    \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_freeKeyTemplate (
  RSAKey *pKey,
  MRsaKeyTemplatePtr pTemplate
  );

/**
 * @brief      Get an RSA public key's ciphertext length.
 *
 * @details    This function gets an RSA public key's ciphertext length, and
 *             returns it through the \p cipherTextLen parameter.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param  pKey            Pointer to RSA public key.
 * @param  pCipherTextLen  On return, pointer to number of bytes in key's
 *                           ciphertext.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */

MOC_EXTERN MSTATUS   RSA_getCipherTextLength(MOC_RSA(hwAccelDescr hwAccelCtx) const RSAKey *pKey, sbyte4 *pCipherTextLen);


/**
 * @brief      Encrypt plaintext using PKCS&nbsp;\#1.
 *
 * @details    This function encrypts a plaintext buffer, using PKCS&nbsp;\#1
 *             and the provided RSA public key.
 *
 * @note       This function uses a public key. To use a private key, call the
 *             RSA_signMessage() function.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @warning    Before calling this function, be sure that the buffer pointed to
 *             by the \p cipherText parameter is large enough; otherwise, buffer
 *             overflow will occur. (To determine the ciphertext length, call
 *             the RSA_getCipherTextLength() function).
 *
 * @param [in] hwAccelCtx     (Reserved for future use.)
 * @param [in] pKey           Pointer to RSA public key.
 * @param [in] plainText      Pointer to plaintext buffer to encrypt.
 * @param [in] plainTextLen   Number of bytes in the plaintext buffer (\p plainText).
 * @param [out] cipherText    On return, pointer to encrypted ciphertext. <b>(The
 *                            calling function must allocate sufficient memory
 *                            for the resulting \p cipherText; otherwise, buffer overflow will occur.)</b>
 * @param [in] rngFun         Pointer to a function that generates random numbers
 *                            suitable for cryptographic use. To be FIPS-compliant,
 *                            reference RANDOM_rngFun() (defined in random.c), and make
 *                            sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
 *                            moptions.h
 * @param [in] rngFunArg      Pointer to arguments that are required by the function
 *                            referenced in \p rngFun. If you use RANDOM_rngFun(), you
 *                            must supply a \c randomContext structure, which you can
 *                            create by calling RANDOM_acquireContext().
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS   RSA_encrypt(MOC_RSA(hwAccelDescr hwAccelCtx)
                             const RSAKey *pKey,
                             const ubyte* plainText,
                             ubyte4 plainTextLen,
                             ubyte* cipherText,
                             RNGFun rngFun,
                             void* rngFunArg,
                             vlong **ppVlongQueue);

#ifndef __DISABLE_DIGICERT_RSA_DECRYPTION__
/**
 * @brief      Decrypt ciphertext using PKCS&nbsp;\#1.
 *
 * @details    This function decrypts a ciphertext buffer, using PKCS&nbsp;\#1
 *             and the provided RSA private key.
 *
 * @note       This function uses a private key. To use a public key, call the
 *             RSA_verifySignature() function.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 *   To enable this function, the following flag must #not# be defined:
 *     - $__DISABLE_DIGICERT_RSA_DECRYPTION__$
 *
 * @param [in] hwAccelCtx     (Reserved for future use.)
 * @param [in] pKey           Pointer to RSA private key.
 * @param [in] cipherText     Pointer to ciphertext to decrypt.
 * @param [out] plainText     On return, pointer to decrypted plaintext. <b>(The calling
 *                            function must allocate sufficient memory for the
 *                            resulting \p plainText; otherwise, buffer overflow will
 *                            occur.)</b>
 * @param [out] plainTextLen  On return, pointer to number of bytes in the
 *                            plaintext buffer (\p plainText).
 * @param [in] rngFun         Pointer to a function that generates random numbers
 *                            suitable for cryptographic use. To be FIPS-compliant,
 *                            reference RANDOM_rngFun() (defined in random.c), and make
 *                            sure that \c \__ENABLE_DIGICERT_FIPS_MODULE__ is defined in
 *                            moptions.h
 * @param [in] rngFunArg      Pointer to arguments that are required by the function
 *                            referenced in \p rngFun. If you use RANDOM_rngFun(), you
 *                            must supply a \c randomContext structure, which you can
 *                            create by calling RANDOM_acquireContext().
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS   RSA_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx)
                             const RSAKey *pKey,
                             const ubyte* cipherText,
                             ubyte* plainText,
                             ubyte4* plainTextLen,
                             RNGFun rngFun,
                             void* rngFunArg,
                             vlong **ppVlongQueue);
#endif


/**
 * @brief      Verify decrypted buffer's signature.
 *
 * @details    This function verifies the signature of a PKCS&nbsp;\#1-encrypted
 *             data buffer, using the provided RSA public key (essentially
 *             decrypting the ciphertext).
 *
 * @note       This function uses a public key. To use a private key, call the
 *             RSA_decrypt() function.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 * There are no flag dependencies to enable this function.
 *
 * @param [in]  hwAccelCtx    (Reserved for future use.)
 * @param [in]  pKey          Pointer to RSA public key.
 * @param [in]  cipherText    Pointer to ciphertext to decrypt.
 * @param [out] plainText     On return, pointer to decrypted plaintext. <b>(The calling
 *                            function must allocate sufficient memory for the
 *                            resulting \p plainText; otherwise, buffer overflow will
 *                            occur.)</b>
 * @param [out] plainTextLen  On return, pointer to number of bytes in the
 *                            plaintext buffer (\p plainText).
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_verifySignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                                        const RSAKey *pKey,
                                        const ubyte* cipherText,
                                        ubyte* plainText,
                                        ubyte4* plainTextLen,
                                        vlong **ppVlongQueue);

/**
 * @brief      Verify the digest of a message.
 *
 * @details    This function verifies the digest of a message, 
 *             using the provided RSA public key.
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 * There are no flag dependencies to enable this function.
 *
 * @param [in]  hwAccelCtx    (Reserved for future use.)
 * @param [in]  pKey          Pointer to RSA public key.
 * @param [in]  pMsgDigest    Pointer to Msg Digest to be verified.
 * @param [in]  digestLen     The length of the message digest in bytes.
 * @param [in]  pSignature    Pointer to the signature to be verified.
 * @param [in]  sigLen        The length of the signature in bytes.
 * @param [out] pIsValid      Contents will be set with \c TRUE if the signature
 *                            is valid and \c FALSE if otherwise.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pIsValid
 *             of \c TRUE before accepting that a signature is valid.
 */
MOC_EXTERN MSTATUS RSA_verifyDigest(MOC_RSA(hwAccelDescr hwAccelCtx)
                                    RSAKey *pKey,
                                    ubyte *pMsgDigest,
                                    ubyte4 digestLen,
                                    ubyte* pSignature,
                                    ubyte4 sigLen,
                                    intBoolean *pIsValid,
                                    vlong **ppVlongQueue);

/**
 * @brief      Generate signature for plaintext buffer, using provided RSA
 *             private key and PKCS&nbsp;\#1.
 *
 * @details    This function generates a signature for a plaintext buffer, using
 *             the provided RSA private key and PKCS&nbsp;\#1 (essentially
 *             encrypting the plaintext).
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @note       This function uses a private key. To use a public key, call the
 *             RSA_encrypt() function.
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param [in]  hwAccelCtx    (Reserved for future use.)
 * @param [in]  pKey          Pointer to RSA private key.
 * @param [in]  plainText     Pointer to plaintext buffer to encrypt.
 * @param [in]  plainTextLen  Number of bytes in the plaintext buffer (\p plainText).
 * @param [out] cipherText    On return, pointer to encrypted ciphertext containing the
 *                            signature. <b>(The calling function must allocate
 *                            sufficient memory for the resulting \p cipherText;
 *                            otherwise, buffer overflow will occur.)</b>
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx)
                                    const RSAKey *pKey,
                                    const ubyte* plainText,
                                    ubyte4 plainTextLen,
                                    ubyte* cipherText,
                                    vlong **ppVlongQueue);

/**
 * @brief      Performs all signature scheme steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @details    Performs all signature scheme steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @ingroup    rsa_functions
 *
 * @note       This function uses a private key.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_RSA_SIGN_DATA__
 *
 * @param [in]  pKey          Pointer to RSA private key.
 * @param [in]  pData         Buffer holding the data to be signed.
 * @param [in]  dataLen       The length of the data in bytes.
 * @param [in]  hashId        One of the enum values in crypto.h indicating
 *                            which hash algorithm should be used to digest
 *                            the data.
 * @param [out] pSignature    Buffer to hold the resulting signature. This buffer
 *                            must have enough space based on the key size.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS RSA_signData(MOC_RSA(hwAccelDescr hwAccelCtx)
                                RSAKey *pKey,
                                ubyte *pData,
                                ubyte4 dataLen,
                                ubyte hashId,
                                ubyte *pSignature,
                                vlong **ppVlongQueue);

/**
 * @brief      Performs all signature verification steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @details    Performs all signature verification steps on raw data, 
 *             ie data digestation, digest info creation, and signing.
 *
 * @ingroup    rsa_functions
 *
 * @note       This function uses a public key.
 *
 * @flags
 *   To enable this function, the following flag must be defined:
 *     __ENABLE_DIGICERT_RSA_SIGN_DATA__
 *
 * @param [in]  pKey          Pointer to RSA public key.
 * @param [in]  pData         Buffer holding the data to be verified.
 * @param [in]  dataLen       The length of the data in bytes.
 * @param [in]  hashId        One of the enum values in crypto.h indicating
 *                            which hash algorithm should be used to digest
 *                            the data.
 * @param [in]  pSignature    Buffer holding the signature to be verified.
 * @param [in]  signatureLen  The length of the signature in bytes.
 * @param [out] pIsValid      Contents will be set with \c TRUE if the signature
 *                            is valid and \c FALSE if otherwise.
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @warning    Be sure to check for both a return status of \c OK and a \c pIsValid
 *             of \c TRUE before accepting that a signature is valid.
 */
MOC_EXTERN MSTATUS RSA_verifyData(MOC_RSA(hwAccelDescr hwAccelCtx)
                                  RSAKey *pKey,
                                  ubyte *pData,
                                  ubyte4 dataLen,
                                  ubyte hashId,
                                  ubyte *pSignature,
                                  ubyte4 signatureLen,
                                  intBoolean *pIsValid,
                                  vlong **ppVlongQueue);

/**
 * @private
 * @internal
 * @ingroup    rsa_functions
*/
MOC_EXTERN MSTATUS  RSA_generateKeyFIPS(MOC_RSA(hwAccelDescr hwAccelCtx) randomContext *pRandomContext,
                RSAKey *p_rsaKey, ubyte4 keySize, vlong **Xp, vlong **Xp1, vlong **Xp2,
                vlong **Xq, vlong **Xq1, vlong **Xq2, vlong **ppVlongQueue);



/**
 * @brief      Generate RSA key pair (private and public keys).
 *
 * @details    This function generates an RSA key pair (private and public
 *             keys). Typically, your application calls this function after
 *             calling the RSA_createKey() function.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 * @ingroup    crypto_nanotap_functions
 *
 * @flags
 * There are no flag dependencies to enable this function.
 *
 * @param [in] hwAccelCtx      (Reserved for future use.)
 * @param [in] pRandomContext  Pointer to RNG context.
 * @param [in,out] p_rsaKey    Pointer to RSA key memory, previously allocated by
 *                             calling RSA_createKey().
 * @param [in] keySize         Number of bits for generated RSA key; for example,
 *                             1024). (For details, refer to the appropriate FIPS
 *                             Publication, accessible from the following Web page:
 *                             http://www.nist.gov/itl/fips.cfm.)
 * @param [out] ppVlongQueue   On return, pointer to location in the \c vlong queue
 *                             that contains this function's intermediate value,
 *                             which can subsequently be used and eventually
 *                             discarded. (Before ending, your application should
 *                             be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_generateKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                                    randomContext *pRandomContext,
                                    RSAKey *p_rsaKey,
                                    ubyte4 keySize,
                                    vlong **ppVlongQueue);


/**
 * @brief      Compute RSA private key.
 *
 * @details    This function computes an RSA private key.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @param  [in]  hwAccelCtx    (Reserved for future use.)
 * @param  [out] pRSAKey       On return, pointer to RSA private key.
 *                             that contains this function's intermediate value,
 *                             which can subsequently be used and eventually
 *                             discarded. (Before ending, your application should
 *                             be sure to free the entire queue.)
 * @param  [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_prepareKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                                   RSAKey *pRSAKey, vlong** ppVlongQueue);

/**
 * @brief      Convert byte string to RSA key, using PKCS&nbsp;\#1.
 *
 * @details    This function converts a byte string to an RSA key, using
 *             PKCS&nbsp;\#1, and returns the resultant RSA key through the
 *             \p ppKey parameter.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 * There are no flag dependencies to enable this function.
 *
 * @note       To avoid memory leaks, be sure to free the resultant RSA key by
 *             calling RSA_freeKey().
 *
 * @param [out] ppKey         On return, pointer to address of new RSA key.
 * @param [in]  byteString    Pointer to buffer containing RSA key as a string of
 *                            PKCS&nbsp;\#1 bytes.
 * @param [in]  len           Number of bytes in RSA key buffer (\p byteString).
 * @param [out] ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                            that contains this function's intermediate value,
 *                            which can subsequently be used and eventually
 *                            discarded. (Before ending, your application should
 *                            be sure to free the entire queue.)
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_keyFromByteString(MOC_RSA(hwAccelDescr hwAccelCtx)
                                            RSAKey **ppKey,
                                            const ubyte* byteString,
                                            ubyte4 len,
                                            vlong **ppVlongQueue);
/**
 * @brief      Convert RSA key to a string of (PKCS&nbsp;\#1) bytes.
 *
 * @details    This function converts an RSA key to a string of (PKCS&nbsp;\#1)
 *             bytes.
 *
 * <table class="moc_crypto_info">
 *   <tr><td>FIPS Approved</td>
 *       <td>@image html check-green.gif ""
 *           @image latex check-green.png "" width=0.25in </td></tr>
 *   <tr><td>Suite B Algorithm</td>
 *       <td>@image html x-red.gif ""
 *       @image latex x-red.png "" width=0.25in </td></tr>
 *   <tr><td>Flowchart</td>
 *       <td>@htmlonly <a href="images/flowchart_rsa.jpg">RSA</a>@endhtmlonly
 *           @latexonly
 *           {See \nameref{Flowcharts}.}
 *           @endlatexonly</td></tr>
 * </table>
 *
 * @ingroup    rsa_functions
 *
 * @flags
 *   There are no flag dependencies to enable this function.
 *
 * @warning    Before calling this function, be sure that the buffer pointed to
 *             by the \p pBuffer parameter is large enough; otherwise, buffer
 *             overflow will occur.
 *
 * @param [in]  hwAccelCtx  (Reserved for future use.)
 * @param [in]  pKey        Pointer to RSA key to convert.
 * @param [out] pBuffer     Pointer to the address of a previously allocated
 *                          buffer. On return, the buffer contains a byte-string
 *                          representation of the RSA key. <b>(The calling function
 *                          must allocate sufficient memory for the resulting
 *                          \c key. Otherwise, buffer overflow will occur.)</b>
 * @param [out] pRetLen     On input, pointer to the size of the \p pBuffer parameter.
 *                          On return, pointer to number of bytes written to the \p
 *                          buffer buffer.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS  RSA_byteStringFromKey(MOC_RSA(hwAccelDescr hwAccelCtx)
                                          const RSAKey *pKey, ubyte *pBuffer,
                                          ubyte4 *pRetLen);

/* The RSAKey struct does not contain the priExpo. So if you need it, compute it
 * using this function.
 */
MOC_EXTERN MSTATUS RSA_getPrivateExponent (
    MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey,
    vlong **ppRetD,
    vlong **ppVlongQueue
    );

/**
 * This function performs an RSA public key operation with no padding. The
 * output of this operation will always be exactly modulus length bytes.
 *
 * @param pPublicKey    Pointer to the public key to be applied.
 * @param pInput        Buffer containing the input data.
 * @param inputLen      Length in bytes of the input material, must be less
 *                      than the modulus length.
 * @param ppOutput      Pointer to the location that will recieve the
 *                      allocated buffer with exactly modulus length bytes
 *                      of processed data.
 * @param ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                      that contains this function's intermediate value,
 *                      which can subsequently be used and eventually
 *                      discarded. (Before ending, your application should
 *                      be sure to free the entire queue.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS RSA_applyPublicKey (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pPublicKey,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue
    );

/**
 * This function performs an RSA private key operation with no padding. If a
 * RNGFun is provided, RSA blinding will be used. The output of this operation
 * will always be exactly modulus length bytes.
 *
 * @param pPrivateKey   Pointer to the private key to be applied.
 * @param rngFun        Function pointer for generating random bytes, RSA
 *                      blinding will be used if this is provided.
 * @param rngFunArg     Argument to the rngFun.
 * @param pInput        Buffer containing the input data.
 * @param inputLen      Length in bytes of the input material, must be less
 *                      than the modulus length.
 * @param ppOutput      Pointer to the location that will recieve the
 *                      allocated buffer with exactly modulus length bytes
 *                      of processed data.
 * @param ppVlongQueue  On return, pointer to location in the \c vlong queue
 *                      that contains this function's intermediate value,
 *                      which can subsequently be used and eventually
 *                      discarded. (Before ending, your application should
 *                      be sure to free the entire queue.
 *
 * @return              \c OK (0) if successful, otherwise a negative number
 *                      error code from merrors.h
 */
MOC_EXTERN MSTATUS RSA_applyPrivateKey (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey *pPrivateKey,
    RNGFun rngFun,
    void *rngFunArg,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue
    );

#ifdef __cplusplus
}
#endif

#endif
