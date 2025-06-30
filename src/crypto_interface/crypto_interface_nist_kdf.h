/*
 * crypto_interface_nist_kdf.h
 *
 * Mocana Cryptographic Interface specification for NIST-KDF.
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
 @file       crypto_interface_hmac_kdf.h
 @brief      Cryptographic Interface header file for declaring NIST-KDF functions.
 
 @filedoc    crypto_interface_hmac_kdf.h
 */
#ifndef __CRYPTO_INTERFACE_NIST_KDF_HEADER__
#define __CRYPTO_INTERFACE_NIST_KDF_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Performs the NIST key derivation function in Counter Mode.
 *
 * @details Performs the NIST key derivation function in Counter Mode.
 *
 * @param counterSize      The number of bytes used to encode the counter. This must be 1 to 4.
 * @param prfContext       Pointer to the pseudo random function (PRF) context used by your \c prfAlgo.
 * @param prfAlgo          The PRF algorithm suite you wish to use. Please see
 *                         the structure definition and function pointer types in nist_prf.h.
 * @param label            Optional. Buffer holding the label as a byte array.
 * @param labelSize        The length of the label in bytes.
 * @param context          Optional. Buffer holding the context as a byte array.
 * @param contextSize      The length of the context in bytes.
 * @param keyMaterialEncodingSize  The number of bytes used to encode the requested key material size.
 * @param littleEndian     TRUE (1) if the counter and key material size parameters are to
 *                         be encoded Little Endian. FALSE (0) if otherwise.
 * @param keyMaterial      Buffer that will hold the resulting key material.
 * @param keyMaterialSize  The length of the key material requested in bytes.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto_interface_nist_kdf.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_CounterMode( 
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize);

/**
 * @brief   Performs the NIST key derivation function in Feedback Mode.
 *
 * @details Performs the NIST key derivation function in Feedback Mode.
 *
 * @param counterSize      The number of bytes used to encode the optional counter.
 *                         Enter 0 for no counter and 1 to 4 otherwise.
 * @param prfContext       Pointer to the pseudo random function (PRF) context used by your \c prfAlgo.
 * @param prfAlgo          The PRF algorithm suite you wish to use. Please see
 *                         the structure definition and function pointer types in nist_prf.h.
 * @param iv               Optional. Buffer holding the initialization vector as a byte array.
 * @param ivSize           The length of the iv in bytes.
 * @param label            BOptional. uffer holding the label as a byte array.
 * @param labelSize        The length of the label in bytes.
 * @param context          Optional. Buffer holding the context as a byte array.
 * @param contextSize      The length of the context in bytes.
 * @param keyMaterialEncodingSize  The number of bytes used to encode the requested key material size.
 * @param littleEndian     TRUE (1) if the counter and key material size parameters are to
 *                         be encoded Little Endian. FALSE (0) if otherwise.
 * @param keyMaterial      Buffer that will hold the resulting key material.
 * @param keyMaterialSize  The length of the key material requested in bytes.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto_interface_nist_kdf.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_FeedbackMode(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* iv, ubyte4 ivSize,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize);

/**
 * @brief   Performs the NIST key derivation function in Double Pipeline Mode.
 *
 * @details Performs the NIST key derivation function in Double Pipeline Mode.
 *
 * @param counterSize      The number of bytes used to encode the optional counter.
 *                         Enter 0 for no counter and 1 to 4 otherwise.
 * @param prfContext       Pointer to the pseudo random function (PRF) context used by your \c prfAlgo.
 * @param prfAlgo          The PRF algorithm suite you wish to use. Please see
 *                         the structure definition and function pointer types in nist_prf.h.
 * @param label            Optional. Buffer holding the label as a byte array.
 * @param labelSize        The length of the label in bytes.
 * @param context          Optional. Buffer holding the context as a byte array.
 * @param contextSize      The length of the context in bytes.
 * @param keyMaterialEncodingSize  The number of bytes used to encode the requested key material size.
 * @param littleEndian     TRUE (1) if the counter and key material size parameters are to
 *                         be encoded Little Endian. FALSE (0) if otherwise.
 * @param keyMaterial      Buffer that will hold the resulting key material.
 * @param keyMaterialSize  The length of the key material requested in bytes.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto_interface_nist_kdf.h
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_KDF_NIST_DoublePipelineMode(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte4 counterSize, void* prfContext,
    const PRF_NIST_108* prfAlgo,
    const ubyte* label, ubyte4 labelSize,
    const ubyte* context, ubyte4 contextSize,
    ubyte4 keyMaterialEncodingSize, ubyte4 littleEndian,
    ubyte* keyMaterial, ubyte4 keyMaterialSize);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_NIST_KDF_HEADER__ */
