/*
 * cryptointerface.h
 *
 * Implementation of Crypto Wrapper.
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
@file       cryptointerface.h
@ingroup    nanocryptowrapper_tree
@brief      Crypto wrapper developer API header.
@details    This header file contains definitions and function
            declarations used by clients which requires Asymmetric
            Key Operations like Sign and verify to be done irrespective
            of the below layer which is implementing the operation.
@flags      This file requires that the following flags be defined:
    + \c \__ENABLE_DIGICERT_CRYPTO_INTERFACE__

@filedoc    cryptointerface.h
*/

/*------------------------------------------------------------------*/

#ifndef __CRYPTOINTERFACE_HEADER__
#define __CRYPTOINTERFACE_HEADER__

#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/primefld_priv.h"
#include "../crypto/primeec_priv.h"
#include "../crypto/sha256.h"
#include "../crypto/pkcs1.h"
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"

#if defined(__ENABLE_DIGICERT_TAP__)
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_aes_gcm.h"
#include "../crypto_interface/crypto_interface_tdes.h"

#if defined(__ENABLE_DIGICERT_ECC__)
#include "../crypto_interface/crypto_interface_ecc.h"
#endif

#if defined(__ENABLE_DIGICERT_TAP__)
#include "../data_protection/tap_data_protect.h"
#endif

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#if defined(__ENABLE_DIGICERT_TAP__)

#if defined(__ENABLE_DIGICERT_TAP_EXTERN__)
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAPExternInit();
#endif
/**
@ingroup    cryptowrapper_functions
@brief      Function pointer to get the TAPContext.

@details    This function pointer gets the TAPContext.
            Client has to register to this callback.

@param ppTapCtx         On return, Double pointer to TAPContext.
@param ppTapEnityCred   On return, Double pointer to TAPEntityCredentials.
@param ppTapKeyCred     On return, Double pointer to TAPKeyCredentials.
@param pKey             Pointer to the key object, either a MocAsymKey or a MocSymCtx
                        depending on the operation.
@param op               TapOperation to be used.
@param getContext       If 1, get the context from application;
                        If 0, release the context.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
typedef MSTATUS (*pFuncPtrGetTapContext)(TAP_Context **ppTapCtx,
                                         TAP_EntityCredentialList **ppTapEntityCred,
                                         TAP_CredentialList **ppTapKeyCred,
                                         void *pKey, TapOperation op, ubyte getContext);

MOC_EXTERN pFuncPtrGetTapContext g_pFuncPtrGetTapContext;

/**
@ingroup    cryptowrapper_functions
@brief      Function to get the finger print from a tap device.
@details    This function is used to get the finger print of the tap device.
            The finger print is derived from the ek public key. The finger
            print is used in the data protect APIs to protect confidential data.

@param ppElements      On return, Pointer to the finger print data. The buffer
                       for this structure, and its element pLabel are allocated
                       by this API and needs to be freed by the caller using DIGI_FREE
@param pNumElements    On return, number of elements in FingerprintElement
@param ppInitialSeed   On return, pointer to initial seed. The buffer is allocated
                       by this API and needs to be freed by the caller using DIGI_FREE
@param pInitialSeedLen On return, length of ppInitialSeed buffer.
@param ek_obj_id       object id of endorsement key

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_retrieveFingerPrintInfo_TAPSeed(
    FingerprintElement **ppElements,
    ubyte4 *pNumElements,
    ubyte **ppInitialSeed,
    ubyte4 *pInitialSeedLen,
    ubyte8  ek_obj_id
    );

#endif

/**
@ingroup    cryptowrapper_functions
@brief      Function pointer to set the callback which can
            return tapcontext.
@details    This function is to register the callback which
            can return tapContext.

@param pCallback Pointer to the callback function.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_registerTapCtxCallback(void *pCallback);

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getKeyType(void *pKey, ubyte4 *keyType);

/**
@ingroup    cryptowrapper_functions
@brief      This function returns the keyusage value based on the
            keytype.
@details    This function returns the key usage value based on the
            tap key type.

@param pKey      Pointer to the key.
@param keyType   Type of the key.
@param pKeyUsage On return, Pointer to the keyusage.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getKeyUsage(void *pKey, ubyte4 keyType, ubyte *pKeyUsage);

MOC_EXTERN MSTATUS
CRYPTO_WRAPPER_getRSATAPKeySize(void *pKey, ubyte4 *keySize);

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelDescr hwAccelCtx) void *pKey, sbyte4 *pModulusLen, ubyte4 keyType);

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_copyAsymmetricKey(AsymmetricKey *pNew, const AsymmetricKey *pSrc);

/**
@ingroup    cryptowrapper_functions
@brief      Get the Asymmetric Public key from the Asymmetric key.

@details    This function creates an Asymmetric Public key from the Asymmetric
            key.
            It supports both TAP keys and SW keys.

@param pKey    Pointer to the AsymmetricKey.
@param ppPub   On return, Pointer to the Asymmetric Public key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getPublicKey(AsymmetricKey *pKey, AsymmetricKey *pPubKey);

#ifdef __ENABLE_DIGICERT_ECC__
/* This function is deprecated. Use CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux
 * instead.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getECurve(void *pKey, PEllipticCurvePtr *ppECurve, ubyte4 keyType);
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
/**
@ingroup    cryptowrapper_functions
@brief      Get the ECC Public key from the Asymmetric key.

@details    This function creates a ECC Public key from the Asymmetric Key.
            It supports both TAP Key and SW Key.

@param pKey    Pointer to the AsymmetricKey.
@param ppPub   On return, Pointer to the ECC public key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getECCPublicKey(AsymmetricKey *pKey, ECCKey **ppPub);
#endif

/**
@ingroup    cryptowrapper_functions
@brief      Get the RSA Public key from the Asymmetric key.

@details    This function creates a RSA Public key from the Asymmetric Key.
            It supports both TAP Key and SW Key.

@param pKey    Pointer to the AsymmetricKey.
@param ppPub   On return, Pointer to the RSA public key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getRSAPublicKey(AsymmetricKey *pKey, RSAKey **ppPub);

/**
@ingroup    cryptowrapper_functions
@brief      Get the RSA Public key from a RSA TAP key.

@details    This function creates a RSA Public key from the RSA TAP key.
            It supports only TAP keys and retrieves the public key as a
            software key.

@param pKey    Pointer to the RSA TAP key.
@param ppPub   On return, Pointer to the RSA SW public key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getRsaSwPubFromTapKey(RSAKey *pKey, RSAKey **ppPub);

#if defined(__ENABLE_DIGICERT_TAP__)
/**
 * @brief   Add credentials to a TAP key
 * @details Stores credentials in a TAP AsymmetricKey structure. The credentials
 *          must be freed by calling CRYPTO_INTERFACE_asymmetricKeyRemoveCreds.
 *
 * @param pKey                Pointer to Asymmetric TAP key
 * @param pPassword           Credential buffer
 * @param passwordLen         Credential buffer length
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_asymmetricKeyAddCreds(
    AsymmetricKey *pKey,
    sbyte *pPassword,
    sbyte4 passwordLen);

/**
 * @brief   Remove credentials from a TAP key
 * @details Frees the credentials stored in the TAP AsymmetricKey structure.
 *
 * @param pKey                Pointer to Asymmetric TAP key
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(
    AsymmetricKey *pKey);

/**
 * @brief   Marks an Asymmetric Key containing a TAP key to not be unloaded when done with its cipher operations.
 * @details Marks an Asymmetric Key containing a TAP key to not be unloaded when done with its cipher operations.
 *
 * @param pCtx                Pointer to an Asymmetric Key containing a TAP key.
 * @param deferredTokenUnload If TRUE, this key will not unload the token when freed or unloaded.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_AsymDeferUnload(AsymmetricKey *pKey, byteBoolean deferredTokenUnload);

/**
 * @internal This API is for internal use, \c CRYPTO_INTERFACE_TAP_rsaDeferUnload should be used.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(MocAsymKey pKey, byteBoolean deferredTokenUnload);

#if defined(__ENABLE_DIGICERT_ECC__)
/**
 * @internal This API is for internal use. \c CRYPTO_INTERFACE_TAP_eccDeferUnload should be used.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(MocAsymKey pKey, byteBoolean deferredTokenUnload);
#endif /* __ENABLE_DIGICERT_ECC__ */

/**
 * @brief   Gets the key handle and token handle for an internal TAP key.
 * @details Gets the key handle and token handle for an internal TAP key. This is
 *          typically used for obtaining the key handle and token handle for a deferred
 *          unload TAP key. This method should be called after the cipher operation and
 *          before the cipher context cleanup.
 *
 * @param pCtx         Pointer to a TAP enabled Asymmetric key containing a TAP Key.
 * @param keyType      One of \c MOC_ASYM_KEY_TYPE_PRIVATE or \c MOC_ASYM_KEY_TYPE_PUBLIC.
 * @param pTokenHandle Contents will be set to the token handle of the TAP key.
 * @param pKeyHandle   Contents will be set to the key handle of the TAP key.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(AsymmetricKey *pKey, ubyte4 keyType, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle);

/**
 * @internal This API is for internal use. \c CRYPTO_INTERFACE_TAP_rsaGetKeyInfo should be used.
 */
MOC_EXTERN MSTATUS 
CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(MocAsymKey pKey, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle);

#if defined(__ENABLE_DIGICERT_ECC__)

/**
 * @internal This API is for internal use. \c CRYPTO_INTERFACE_TAP_eccGetKeyInfo should be used.
 */
MOC_EXTERN MSTATUS 
CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(MocAsymKey pKey, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle);

#endif /* __ENABLE_DIGICERT_ECC__ */


/**
@ingroup    cryptowrapper_functions
@brief      Get the TAP ID from an Asymmetric key.

@param pKey    Pointer to the AsymmetricKey.
@param pId     Pointer to the location that will receive the allocated pointer 
               that points to the buffer containing the ID.
@param         Pointer to the location that will receive the ID buffer length.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_asymGetTapObjectId(AsymmetricKey *pKey, ubyte **ppId, ubyte4 *pIdLen);

/**
@ingroup    cryptowrapper_functions
@brief      Get the TAP key within the Asymmetric key.

@details    This function yields a reference to the TAP key within the
            AsymmetricKey. This function only supports TAP keys. Note
            that this function does not allocate any data, upon return
            the dereference of ppTapKey will point to the TAP key
            previously allocated that lives within the AsymmetricKey.

@param pKey    Pointer to the AsymmetricKey.
@param ppPub   On return, Pointer to the TAP key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getTapKey(AsymmetricKey *pKey, TAP_Key **ppTapKey);

/**
@ingroup    cryptowrapper_functions
@brief      Unload the key for a no longer needed TAP key.

@details    Unload the key for a no longer needed TAP key. This
            is typically used to unload keys for a cipher context whose
            deferred unload flag has been set to \c TRUE.

@param pTapCtx      Pointer to the TAP context associated with the key and token
                    to be unloaded.
@param pTokenHandle The handle of the token associated with the key to be unloaded.
@param pKeyHandle   The handle of the key to be unloaded.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_unloadTapKey(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle, TAP_KeyHandle keyHandle);

/**
@ingroup    cryptowrapper_functions
@brief      Uninitialize the token.

@details    Uninitialize the token. This is typically used to uninitialize a token that has remained
            loaded after marking it for deferred unload.

@param pTapCtx      Pointer to the TAP context associated with token
                    to be unloaded.
@param pTokenHandle The handle of the token to be unloaded.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_unloadTapToken(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle);

/**
@ingroup    cryptowrapper_functions
@brief      Get the TAP key from an RSA key.

@details    This function yields a reference to the TAP key within the
            RSA Key. This function only supports TAP keys. Note
            that this function does not allocate any data, upon return
            the dereference of ppTapKey will point to the TAP key
            previously allocated that lives within the AsymmetricKey.

@param pKey    Pointer to the RSA Key.
@param ppPub   On return, Pointer to the TAP key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_getTapKey(RSAKey *pRsaKey, TAP_Key **ppTapKey);

#if (defined(__ENABLE_DIGICERT_ECC__))

MOC_EXTERN MSTATUS 
CRYPTO_INTERFACE_TAP_eccGetKeyInfo(ECCKey *pECCKey, ubyte4 keyType,
                                   TAP_TokenHandle *pTokenHandle,
                                   TAP_KeyHandle *pKeyHandle);
/**
@ingroup    cryptowrapper_functions
@brief      Get the TAP key from an ECC key.

@details    This function yields a reference to the TAP key within the
            ECC Key. This function only supports TAP keys. Note
            that this function does not allocate any data, upon return
            the dereference of ppTapKey will point to the TAP key
            previously allocated that lives within the AsymmetricKey.

@param pKey    Pointer to the ECC Key.
@param ppPub   On return, Pointer to the TAP key.

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECC_getTapKey(ECCKey *pEccKey, TAP_Key **ppTapKey);

#endif /* if (defined(__ENABLE_DIGICERT_ECC__)) */
#endif /* if defined(__ENABLE_DIGICERT_TAP__) */

/**
@ingroup    cryptowrapper_functions
@brief      Creates RSA Signature of the given input buffer.

@details    This function creates RSA Signature of the given input buffer.
            It supports TAP Key and SW key for calculating RSA Signature.

@param pRSAKey      Pointer to RSAKey. It could be MocAsymkey or RSAKey.
@param plainText    Pointer to the plain text to be signed.
@param plainTextLen Length of the plain text.
@param cipherText   On return, Pointer to the cipher text.
@param ppVlongQueue Double Pointer to the vlong.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_rsa
                    \ref akt_rsa

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* plainText, ubyte4 plainTextLen,
        ubyte* cipherText, vlong **ppVlongQueue, ubyte4 keyType);

/**
@ingroup    cryptowrapper_functions
@brief      Creates RSA Signature of the given input buffer. This API
            signs the plain buffer and not the digested buffer.

@details    This function creates RSA Signature of the given input buffer.
            This function only applies for TAP attestation keys. Use
            CRYPTO_INTERFACE_RSA_signMessageAux to handle both software and
            TAP non-attestation keys. This function performs the digest of the
            plaintext by using the underneath provider. For providers like TPM2,
            the digest of the plaintext MUST be done by the TPM2 for attestation
            keys.

@param pRSAKey      Pointer to RSAKey. It could be MocAsymkey or RSAKey.
@param plainText    Pointer to the plain text to be signed.
@param plainTextLen Length of the plain text.
@param cipherText   On return, Pointer to the cipher text.
@param ppVlongQueue Double Pointer to the vlong.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_rsa
                    \ref akt_rsa

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_signMessageEx(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* plainText, ubyte4 plainTextLen,
        ubyte* cipherText, vlong **ppVlongQueue, ubyte4 keyType);


/**
@ingroup    cryptowrapper_functions
@brief      Verify the RSA signature against the given input ciphertext and the plain buffer.

@details    This function verifies RSA signature against the given input cipher text and the plain buffer.
            It supports TAP Key and SW key for RSA verification.

@param pRSAKey      Pointer to RSAKey. It could be MocAsymkey or RSAKey.
@param cipherText   Pointer to the cipher text.
@param plainText    Pointer to the plain text to be signed.
@param plainTextLen Pointer to the length of the plain text.
@param ppVlongQueue Double Pointer to the vlong.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_rsa
                    \ref akt_rsa

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
    const ubyte* cipherText, ubyte* plainText, ubyte4* plainTextLen, vlong **ppVlongQueue, ubyte4 keyType);

#if (defined(__ENABLE_DIGICERT_ECC__))
/**
@ingroup    cryptowrapper_functions
@brief      Creates ECDSA signature.

@details    This function creates ECDSA signature of the given input.
            It supports TAP Key and SW key for calculating ECDSA sign.

@param pECCKey      Pointer to ECCKey. It could be MocAsymkey or ECCKey.
@param rngFun       Random function pointer.
@param rngArg       Argument to the random function.
@param hash         Pointer to the digest input.
@param hashLen      Length of the digested input.
@param r            On return, Pointer to the PrimeField r.
@param s            On return, Pointer to the PrimeFiled s.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_ecc
                    \ref akt_ecc

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h

@deprecated This function is deprecated. Use
            CRYPTO_INTERFACE_ECDSA_signDigestAux instead.
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_sign(void *pECCKey, RNGFun rngFun, void *rngArg,
                                     const ubyte* hash, ubyte4 hashLen,
                                     PFEPtr r, PFEPtr s, ubyte4 keyType);
/**
@ingroup    cryptowrapper_functions
@brief      Creates ECDSA signature.

@details    This function creates ECDSA signature of the given input.
            It supports TAP Key and SW key for calculating ECDSA sign.
            This API signs the plain buffer and not the digest buffer.

@param pECCKey          Pointer to ECCKey. It could be MocAsymkey or ECCKey.
@param rngFun           Random function pointer.
@param rngArg           Argument to the random function.
@param pPlainText       Pointer to the digest input.
@param plainTextLen     Length of the digested input.
@param r                On return, Pointer to the PrimeField r.
@param s                On return, Pointer to the PrimeFiled s.
@param keyType          Type of the key. Possible values:
                        \ref akt_tap_ecc
                        \ref akt_ecc

@inc_file               cryptointerface.h

@return                 \c OK (0) if sucessful; otherwise a negative number error code
                        defintion from merrors.h. To retrieve a string containing an
                        English text error identifier corresponding to the function's
                        returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc                cryptointerface.h

@deprecated This function is deprecated. Use
            CRYPTO_INTERFACE_ECDSA_signDigestAux for software and TAP keys.
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_signEx(void *pECCKey, RNGFun rngFun, void *rngArg,
                                     const ubyte* pPlainText, ubyte4 plainTextLen,
                                     PFEPtr r, PFEPtr s, ubyte4 keyType);


/**
@ingroup    cryptowrapper_functions
@brief      Verifies ECDSA signature.

@details    This function verifies given input cipher buffer with ECDSA verification.
            It supports TAP Key and SW key for ECDSA verification.

@param pECCKey      Pointer to ECCKey. It could be MocAsymkey or ECCKey.
@param hash         Pointer to the digest input.
@param hashLen      Length of the digested input.
@param r            On return, Pointer to the PrimeField r.
@param s            On return, Pointer to the PrimeFiled s.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_ecc
                    \ref akt_ecc

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h

@deprecated This function is deprecated. Use
            CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux instead.
*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_verifySignature( void *pECCKey, const ubyte* hash, ubyte4 hashLen,
                                           ConstPFEPtr r, ConstPFEPtr s, ubyte4 keyType);
#endif

/**
 * Free an RSA key.
 *
 * @param ppKey          Double pointer to the key to be deleted.
 * @param ppVlongQueue   Optional vlong queue.
 * @param keyType        The key type, must be akt_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKey(
    void **ppKey,
    vlong **ppVlongQueue,
    ubyte4 keyType
    );

/**
 * Set the public parameters of an RSA key. The caller must provide the RSA
 * exponent as a ubyte4 and the RSA modulus as a byte string.
 *
 * @param pKey         The key object to be set.
 * @param exponent     The RSA exponent.
 * @param pModulus     The RSA modulus as a byte string.
 * @param modulusLen   The length of the RSA modulus.
 * @param ppVlongQueue Optional vlong queue.
 * @param keyType      The key type, must be akt_rsa.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setPublicKeyParameters(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte4 exponent,
    const ubyte *pModulus,
    ubyte4 modulusLen,
    vlong **ppVlongQueue,
    ubyte4 keyType
    );

/**
 * Set all the parameters in a RSA key. The caller must provide the RSA
 * exponent, RSA modulus, RSA prime, and RSA subprime values.
 *
 * @param pKey         The key object to set.
 * @param pPubExpo     The RSA exponent as a byte string.
 * @param pubExpoLen   The RSA exponent length.
 * @param pModulus     The RSA modulus as a byte string.
 * @param modulusLen   The RSA modulus length.
 * @param pPrime       The RSA prime as a byte string.
 * @param primeLen     The RSA prime length.
 * @param pSubprime    The RSA subprime as a byte string.
 * @param subprimeLen  The RSA subprime length.
 * @param ppVlongQueue Optional vlong queue.
 * @param keyType      The key type, must be akt_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyData(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pPubExpo,
    ubyte4 pubExpoLen,
    const ubyte *pModulus,
    ubyte4 modulusLen,
    const ubyte *pPrime,
    ubyte4 primeLen,
    const ubyte *pSubprime,
    ubyte4 subprimeLen,
    vlong **ppVlongQueue,
    ubyte4 keyType
    );

/**
 * Allocates and sets the appropriate key parameters of pTemplate with the data
 * in the key. The caller must provide an allocated MRsaKeyTemplate structure,
 * which will then have its internal pointers allocated by this function. Note
 * it is the callers responsibility to free this memory using
 * RSA_freeKeyTemplate. The reqType should be either MOC_GET_PUBLIC_KEY_DATA or
 * MOC_GET_PRIVATE_KEY_DATA. Tha latter option will get both the private and
 * public key parameters. and as such can only be used with a private key.
 * Retrieving the public data from a private key is allowed, retrieving the
 * private data from a public key is impossible and will result in an error. See
 * the documentation for MRsaKeyTemplate in capasym.h for more info on the
 * format of template data.
 *
 * @param pKey      The key to retrieve data from.
 * @param pTemplate Pointer to an exisiting MRsaKeyTemplate structure. The
 *                  internal pointers within structure will be allocated by this
 *                  function.
 * @param reqType   Type of data to retrieve. This must be
 *                  MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA.
 * @param keyType   The key type, must be akt_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte reqType,
    ubyte4 keyType
    );

/**
 * Free the RSA key template.
 *
 * @param pKey      The key used to delete the key template. This key is not
 *                  always required.
 * @param pTemplate Template to free.
 * @param keyType   The key type, must be akt_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_freeKeyTemplate(
    void *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte4 keyType
    );

/**
 * Apply the public key to the input data. The input data must be the same
 * length as the RSA modulus. The output buffer will be allocated by this
 * function and must be freed by the caller.
 *
 * @param pKey         The key used to perform the operation. This must contain
 *                     RSA public key data.
 * @param pInput       The input data to process. Must be the same length as the
 *                     RSA modulus.
 * @param inputLen     The input data length.
 * @param ppOutput     The output buffer. This buffer will be allocated by this
 *                     function and must be freed by the caller using DIGI_FREE.
 * @param ppVlongQueue Optional vlong queue.
 * @param keyType      The key type, must be akt_rsa or akt_tap_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPublicKey(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue,
    ubyte4 keyType
    );

/**
 * Apply the private key to the input data. The input data must be the same
 * length as the RSA modulus. The output buffer will be allocated by this
 * function and must be freed by the caller.
 *
 * @param pKey         The key used to perform the operation. This must contain
 *                     RSA private key data.
 * @param rngFun       Function pointer to a random number generation function.
 * @param pRngFunArg   Input data into the random number generation function
 *                     pointer.
 * @param pInput       The input data to process. Must be the same length as the
 *                     RSA modulus.
 * @param inputLen     The input data length.
 * @param ppOutput     The output buffer. This buffer will be allocated by this
 *                     function and must be freed by the caller using DIGI_FREE.
 * @param ppVlongQueue Optional vlong queue.
 * @param keyType      The key type, must be akt_rsa or akt_tap_rsa.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_applyPrivateKey(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    RNGFun rngFun,
    void *pRngFunArg,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue,
    ubyte4 keyType
    );

/**
@ingroup    cryptowrapper_functions
@brief      Creates RSA encryption.

@details    This function creates RSA encryption of the given input buffer.
            It supports TAP Key and SW key for calculating RSA encryption.

@param pRSAKey      Pointer to RSAKey. It could be MocAsymkey or RSAKey.
@param plainText    Pointer to the plain text to be signed.
@param plainTextLen Pointer to the length of the plain text.
@param cipherText   Pointer to the cipher text.
@param rngFun       Random function pointer.
@param rngFunArg    Argument to the random function.
@param ppVlongQueue Double Pointer to the vlong.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_rsa
                    \ref akt_rsa

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* plainText, ubyte4 plainTextLen, ubyte* cipherText,
        RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue, ubyte4 keyType);

/**
@ingroup    cryptowrapper_functions
@brief      Decrypts the given cipher text using RSA decryption.

@details    This function decrypts given cipher text using RSA decryption.
            It supports TAP Key and SW key for doing RSA decryption.

@param pRSAKey      Pointer to RSAKey. It could be MocAsymkey or RSAKey.
@param cipherText   Pointer to the cipher text.
@param plainText    Pointer to the plain text to be signed.
@param plainTextLen Pointer to the length of the plain text.
@param rngFun       Random function pointer.
@param rngFunArg    Argument to the random function.
@param ppVlongQueue Double Pointer to the vlong.
@param keyType      Type of the key. Possible values:
                    \ref akt_tap_rsa
                    \ref akt_rsa

@inc_file   cryptointerface.h

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    cryptointerface.h
*/
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* cipherText, ubyte* plainText, ubyte4* plainTextLen,
        RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue, ubyte4 keyType);

#if (defined(__ENABLE_DIGICERT_ECC__))

/**
 * Free an ECC Key.
 *
 * @param ppKey   Double pointer to the key to be deleted.
 * @param keyType The key type, must be akt_tap_ecc if this is a TAP key,
 *                and akt_ecc otherwise.
 *
 * @return        \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_deleteKey (
    void **ppKey,
    ubyte4 keyType
    );

/**
 * Clone an ECC Key.
 *
 * @param ppNew   Double pointer that will be allocated and filled with the
 *                cloned key.
 * @param pSrc    The key to be cloned.
 * @param keyType The src key type, must be akt_tap_ecc if this is a TAP key,
 *                and akt_ecc otherwise.
 *
 * @return        \c OK (0) if successful, otherwise a negative number error
 *                code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_cloneKey (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void **ppNew,
    void *pSrc,
    ubyte4 keyType
    );

/**
 * Retrieve the curve identifier from a key previously created with EC_newKeyEx
 * or generated with EC_generateKeyPairAlloc.
 *
 * @param pKey      The key to retrieve the curve identifier from.
 * @param pCurveId  The curve identifier, see ca_mgmt.h for possible values.
 * @param keyType   The key type, must be akt_tap_ecc if this is a TAP key,
 *                  and akt_ecc otherwise.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getCurveIdFromKey (
    void *pKey,
    ubyte4 *pCurveId,
    ubyte4 keyType
    );

/**
 * Get the length of an individual prime field element when represented as a
 * bytestring. When signing with ECDSA_signDigest, the output length will be
 * exactly (2 * elementLen).
 *
 * @param pKey    The key to retrieve the element bytestring length from.
 * @param pLen    Pointer to the location that will recieve the element length.
 * @param keyType The key type, must be akt_tap_ecc if this is a TAP key,
 *                and akt_ecc otherwise.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getElementByteStringLen (
    void *pKey,
    ubyte4 *pLen,
    ubyte4 keyType
    );

/**
 * Get the length of the bytestring representation of the public key, typically
 * used to determine the buffer size for EC_writePublicKeyToBuffer.
 *
 * @param pKey    The key to retrieve the element bytestring length from.
 * @param pLen    Pointer to the location that will recieve the point length.
 * @param keyType The key type, must be akt_tap_ecc if this is a TAP key,
 *                and akt_ecc otherwise.
 *
 * @return      \c OK (0) if successful, otherwise a negative number error
 *              code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenEx (
    void *pKey,
    ubyte4 *pLen,
    ubyte4 keyType
  );

/**
 * Set the individual components of an ECC key. Note the public point must
 * be in the uncompressed form.
 *
 * @param pKey      The key object to be set.
 * @param pPoint    Buffer containing the public point.
 * @param pointLen  Length in bytes of the public point.
 * @param pScalar   Buffer containing the private scalar value.
 * @param scalarLen Length in bytes of the private scalar value.
 * @param keyType   The key type, must be akt_tap_ecc if this is a TAP key,
 *                  and akt_ecc otherwise.
 *
 * @return          \c OK (0) if successful, otherwise a negative number error
 *                  code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_setKeyParameters (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    const ubyte *pPoint,
    ubyte4 pointLen,
    const ubyte *pScalar,
    ubyte4 scalarLen,
    ubyte4 keyType
    );

/**
 * Write the public point (X,Y) to a buffer. The function EC_getPointByteStringLenEx
 * can be used to determine how large the public key buffer needs to be. The public
 * key is encoded as a single byte to indicate compression status, which is always
 * 0x04 (uncompressed) for this function, followed by public values X and Y as big
 * endian bytestrings, zero padded to element length if necessary. This format is
 * described in the Standards for Efficient Cryptography 1: Elliptic Curve
 * Cryptography Ver 1.9 section 2.3.3.
 *
 * @param pKey        The key from which the public values are to be extracted
 *                    and written to the provided buffer.
 * @param pBuffer     Pointer to allocated memory that will recieve the encoded
 *                    public key.
 * @param bufferSize  The size in bytes of the memory block pointed to by pBuffer,
 *                    must be large enough for the encoded public key. You can use
 *                    EC_getPointByteStringLenEx to determine this length.
 * @param keyType     The key type, must be akt_tap_ecc if this is a TAP key,
 *                    and akt_ecc otherwise.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBuffer (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pBuffer,
    ubyte4 bufferSize,
    ubyte4 keyType
    );

/**
 * Allocate a new buffer and write the public point (X,Y) to it. The public
 * key is encoded as a single byte to indicate compression status, which is always
 * 0x04 (uncompressed) for this function, followed by public values X and Y as big
 * endian bytestrings, zero padded to element length if necessary. This format is
 * described in the Standards for Efficient Cryptography 1: Elliptic Curve
 * Cryptography Ver 1.9 section 2.3.3.
 *
 * @param pKey        The key from which the public values are to be extracted
 *                    and written to the provided buffer.
 * @param ppBuffer    Double pointer that will be allocated and filled with the
 *                    bytestring representation of the public key.
 * @param pBufferSize The size in bytes of bytestring representation of the
 *                    public key.
 * @param keyType     The key type, must be akt_tap_ecc if this is a TAP key,
 *                    and akt_ecc otherwise.
 *
 * @return            \c OK (0) if successful, otherwise a negative number error
 *                    code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte **ppBuffer,
    ubyte4 *pBufferSize,
    ubyte4 keyType
    );

/**
 * Create a new ECC public key from the bytestring representation of public
 * point (X,Y). The public key must be encoded in the uncompressed form, this
 * function does not handle compressed public keys. The public key encoding must
 * be a single byte to indicate compression status, always 0x04 for this
 * function, followed by public values X and Y as big endian bytestrings,
 * zero padded to element length if necessary. This format is described in
 * the Standards for Efficient Cryptography 1: Elliptic Curve Cryptography
 * Ver 1.9 section 2.3.3.
 *
 * @param curveId        One of the cid_EC_* values from ca_mgmt.h
 *                       indicating the curve this key should be created on.
 * @param ppNewKey       Pointer to the location that will recieve the new
 *                       public key.
 * @param pByteString    Pointer to a bytestring representation of an ECC
 *                       public key.
 * @param byteStringLen  The length in bytes of the bytestring.
 * @param keyType        The key type, must be akt_tap_ecc if this is a TAP key,
 *                       and akt_ecc otherwise.
 *
 * @return               \c OK (0) if successful, otherwise a negative number
 *                       error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_newPublicKeyFromByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 curveId,
    void **ppNewKey,
    ubyte *pByteString,
    ubyte4 byteStringLen,
    ubyte4 keyType
    );

/**
 * Allocates and sets the appropriate keys parameters of pTemplate with
 * that from the passed in pKey. The caller must provide an allocated
 * MEccKeyTemplate structure, which will then have its internal pointers
 * allocated by this function. Note it is the callers responsibility to
 * free this memory using EC_freeKeyTemplate. reqType should be one of
 * MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA. The latter option
 * will get both the private and public key parameters and as such can only be
 * used with a private key. Retrieving the public data from a private key is
 * allowed, retrieving private data from a public key is impossible and
 * will result in an error. See the documentation for MEccKeyTemplate in
 * capasym.h for more info on the format of the recieved key data.
 *
 * @param pKey      The key to retrieve data from.
 * @param pTemplate Pointer to an existing MEccKeyTemplate structure, the
 *                  internal pointers within the structure will be allocated
 *                  by this function.
 * @param reqType   Type of key data to recieve, must be one of
 *                  MOC_GET_PUBLIC_KEY_DATA or MOC_GET_PRIVATE_KEY_DATA.
 * @param keyType   The key type, must be akt_tap_ecc if this is a TAP key,
 *                  and akt_ecc otherwise.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getKeyParametersAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    MEccKeyTemplate *pTemplate,
    ubyte reqType,
    ubyte4 keyType
    );

/**
 * Frees the key data stored within the provided template structure.
 *
 * @param pKey      Pointer to the original key the data was retrieved from.
 * @param pTemplate Pointer to a key template structure previously filled using
 *                  EC_getKeyParametersAlloc.
 * @param keyType   The key type, must be akt_tap_ecc if this is a TAP key,
 *                  and akt_ecc otherwise.
 *
 * @return          \c OK (0) if successful, otherwise a negative number
 *                  error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_freeKeyTemplate (
    void *pKey,
    MEccKeyTemplate *pTemplate,
    ubyte4 keyType
    );

/**
 * Verify the public portion of an EC key. This function will validate the
 * public point by checking whether it is on the curve or not. The caller must
 * check the byte boolean value. This value will be TRUE if the point is on the
 * curve otherwise it will be FALSE.
 *
 * @param pKey     Pointer to the key to verify. It must contain the public
 *                 point.
 * @param pIsValid Pointer to the return value the caller must check. Will be
 *                 TRUE if the point is valid otherwise it will be FALSE.
 * @param keyType  The key type, must be akt_tap_ecc if this is a TAP key,
 *                 and akt_ecc otherwise.
 *
 *
 * @return         \c OK (0) if successful, otherwise a negative number
 *                 error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_verifyPublicKey(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    byteBoolean *pIsValid,
    ubyte4 keyType
    );

/**
 * Perform an ECDSA signing operation on the provided digest, producing the raw
 * signature value. The signature is represented as the concatenation of r and
 * s as big endian bytestrings, zero padded if necessary to ensure each
 * bytestring is exactly elementLen. If you dont know how long the signature will be,
 * you can call this function with a NULL pSignature and a bufferSize of zero.
 * This will result in a return code of ERR_BUFFER_TOO_SMALL and the length of
 * the raw signature will be placed into pSignatureLen. For callers
 * who wish to precompute the buffer size, it will always be exactly
 * (2 * elementLen), where elementLen is the bytestring length of each
 * element on the curve as determined by EC_getElementByteStringLen.
 *
 * @param pKey             The private key to be used to sign the hash.
 * @param rngFun           Function pointer for generating the random values. If
 *                         you have a randomContext you would like to use, simply
 *                         pass RANDOM_rngFun for this param and the randomContext
 *                         as the rngArg.
 * @param rngArg           Argument to the rngFun. If you have a randomContext you
 *                         would like to use, pass in RANDOM_rngFun for the rngFun
 *                         and pass the randomContext here as the argument.
 * @param pHash            Buffer that contains the hash to be signed.
 * @param hashLen          Length in bytes of the hashed data.
 * @param pSignature       Caller allocated buffer that will recieve the raw
 *                         signature.
 * @param bufferSize       Size in bytes of the pSignature buffer.
 * @param pSignatureLen    Pointer to the location that will recieve the length
 *                         in bytes of the signature.
 * @param keyType          The key type, must be akt_tap_ecc if this is a TAP key,
 *                         and akt_ecc otherwise.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    ubyte4 keyType
    );

/**
 * Perform an ECDSA signing operation on the provided message, producing the raw
 * signature value. The signature is represented as the concatenation of r and
 * s as big endian bytestrings, zero padded if necessary to ensure each
 * bytestring is exactly elementLen. If you dont know how long the signature will be,
 * you can call this function with a NULL pSignature and a bufferSize of zero.
 * This will result in a return code of ERR_BUFFER_TOO_SMALL and the length of
 * the raw signature will be placed into pSignatureLen. For callers
 * who wish to precompute the buffer size, it will always be exactly
 * (2 * elementLen), where elementLen is the bytestring length of each
 * element on the curve as determined by EC_getElementByteStringLen.
 *
 * This function only applies for TAP keys and digests the message based on the
 * TAP parameters used to generate the key. For control over which digest is
 * used, compute the digest and use CRYPTO_INTERFACE_ECDSA_signDigestAux
 * instead, which works for both software and TAP keys. Refer to the existing
 * usage in crypto_interface_ecc_example.c.
 *
 * @param pKey             The private key to be used to sign the hash.
 * @param rngFun           Function pointer for generating the random values. If
 *                         you have a randomContext you would like to use, simply
 *                         pass RANDOM_rngFun for this param and the randomContext
 *                         as the rngArg.
 * @param rngArg           Argument to the rngFun. If you have a randomContext you
 *                         would like to use, pass in RANDOM_rngFun for the rngFun
 *                         and pass the randomContext here as the argument.
 * @param pMessage         Buffer that contains the plaintext message to be hashed
 *                         and signed.
 * @param messageLen       Length in bytes of the plaintext message.
 * @param pSignature       Caller allocated buffer that will recieve the raw
 *                         signature.
 * @param bufferSize       Size in bytes of the pSignature buffer.
 * @param pSignatureLen    Pointer to the location that will recieve the length
 *                         in bytes of the signature.
 * @param keyType          The key type, must be akt_tap_ecc if this is a TAP key,
 *                         and akt_ecc otherwise.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_signMessage (
    void *pKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    ubyte4 keyType
    );

/**
 * Verify individual signature values with the provided public key. Note that this
 * function returns OK even if the verification failed. For this function, a
 * non zero return code means we were not able to properly inspect the signature
 * for verification. This could be due to invalid input such as a NULL pointer
 * or invalid length. If the return status if OK that does not mean the signature
 * verified, rather that we were able to properly check the provided signature.
 * If we were able to check the signature and it didnt verify, then the value
 * pointed to by pVerifyFailures will be non zero. If the return code is OK and
 * the value pointed to by pVerifyFailures is zero, the signature verified.
 *
 * @param pPublicKey      Pointer to the public key used to verify this signature.
 * @param pHash           Buffer containing the original hash that was signed.
 * @param hashLen         Length in bytes of the hashed data.
 * @param pR              Buffer containing the R portion of the signature,
 *                        encoded as a big endian bytestring.
 * @param rLen            Length in bytes of the data in pR buffer.
 * @param pS              Buffer containing the S portion of the signature,
 *                        encoded as a big endian bytestring.
 * @param sLen            Length in bytes of the data in pS buffer.
 * @param pVerifyFailures Pointer to the location that will recieve the result
 *                        of the verification check. If that value is zero upon
 *                        return, the signature verified.
 * @param keyType         The key type, must be akt_tap_ecc if this is a TAP key,
 *                        and akt_ecc otherwise.
 *
 * @return                \c OK (0) if successful, otherwise a negative number
 *                        error code from merrors.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDSA_verifySignatureDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPublicKey,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    ubyte4 *pVerifyFailures,
    ubyte4 keyType
    );

/**
 * Generate an ECDH shared secret from a public and private key. Note that this
 * function will allocate the shared secret and it is the callers responsibility
 * to free that memory using DIGI_FREE.
 *
 * @param pPrivateKey      Pointer to the private key for this operation.
 * @param pPublicKey       Pointer to the public key for this operation.
 * @param ppSharedSecret   Double pointer that will be allocated by this function
 *                         and filled with the shared secret material.
 * @param pSharedSecretLen Pointer to the location that will recieve the length of
 *                         the shared secret value in bytes.
 * @param flag             Flag indicating whether to use both the x and y
 *                         coordinates or just the x coordinate. Always use
 *                         only the x coordinate unless you know what you are doing.
 * @param pKdfInfo         Pointer to possible information on a KDF to apply during
 *                         the secret generation process, unused at this time so
 *                         simply pass NULL.
 * @param keyType          The key type, must be akt_tap_ecc if this is a TAP key,
 *                         and akt_ecc otherwise.
 *
 * @return                 \c OK (0) if successful, otherwise a negative number
 *                         error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeys (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPrivateKey,
    void *pPublicKey,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo,
    ubyte4 keyType
    );

/**
 * Generate an ECDH shared secret from private key and bytestring representation
 * of the public point. The public point must be encoded as an uncompressed point
 * per Standards for Efficient Cryptography 1: Elliptic Curve Cryptography
 * Ver 1.9 section 2.3.3.
 *
 * @param pPrivateKey               Pointer to the private key for this operation.
 * @param pPublicPointByteString    Pointer to the bytestring representation of the
 *                                  public key to use for this operation.
 * @param pointByteStringLen        Length in bytes of the public point bytestring.
 * @param ppSharedSecret            Double pointer that will be allocated by this function
 *                                  and filled with the shared secret material.
 * @param pSharedSecretLen          Pointer to the location that will recieve the length of
 *                                  the shared secret value in bytes.
 * @param flag                      Flag indicating whether to use both the x and y
 *                                  coordinates or just the x coordinate. Always use
 *                                  only the x coordinate unless you know what you are doing.
 * @param pKdfInfo                  Pointer to possible information on a KDF to apply during
 *                                  the secret generation process, unused at this time so
 *                                  simply pass NULL.
 * @param keyType                   The key type, must be akt_tap_ecc if this is a TAP key,
 *                                  and akt_ecc otherwise.
 *
 * @return                          \c OK (0) if successful, otherwise a negative number
 *                                  error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPrivateKey,
    ubyte *pPublicPointByteString,
    ubyte4 pointByteStringLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo,
    ubyte4 keyType
    );

#endif /* ifdef __ENABLE_DIGICERT_ECC__ */

/**
 * Clone a hash object. A context must have been at least initialized
 * so that this method knows the proper underlying clone method to call.
 *
 * @param pSrc   The hash context to be cloned.
 * @param pDest  The allocated shell to be filled with the cloned object.
 * @param size   Optional (not needed). The size of the context to be cloned. 
 *
 * @return                \c OK (0) if successful, otherwise a negative number
 *                        error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_cloneHashCtx (
    MOC_HASH(hwAccelDescr hwAccelCtx)
    BulkCtx pSrc,
    BulkCtx pDest,
    ubyte4 size
    );

/**
 * Free a previously cloned hash object. If this object was cloned from
 * a hash object using an alternate implementation, then the underlying
 * object will be freed, otherwise this function does nothing.
 *
 * @param pCtx Pointer to a hash object previously created using
 *             CRYPTO_INTERFACE_cloneHashCtx.
 *
 * @return     \c OK (0) if successful, otherwise a negative number
 *             error code from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_freeCloneHashCtx (
    BulkCtx pCtx
    );


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AES_createKeyMaterial (
    RNGFun rngFun,
    void *rngArg,
    void **ppKeyMaterial,
    ubyte4 *pKeyMaterialLen,
    ubyte4 keyType,
    void *pKeyAttributes
    );


#endif /* #ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__  */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTOINTERFACE_HEADER__ */
