/*
 * hmac_kdf.h
 * 
 * Implementes Hmac KDF (HKDF) as per RFC 5869
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
@file     hmac_kdf.h
@brief    Hmac KDF (HKDF) implementation as per RFC  5869
@details  Add details here.

@filedoc  hmac_kdf.h
 */

#ifndef __HMAC_KDF_H__
#define __HMAC_KDF_H__

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_hmac_kdf_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Perform the extract operation for Hmac KDF. This function will take in the
 * input key material as well as an optional salt value and generate a pseudo
 * random key bits. Note that the output of the psuedo random key will be the
 * size of the digest output of the digest functions provided as input.
 *
 * IMPORTANT: Do not use the output of the extract function as actual key
 * material. The output material should be passed into the Hmac KDF expand
 * method.
 *
 * @param pDigest               The digest suite used for the Hmac operations.
 * @param pSalt                 Optional salt value. Providing a salt value is
 *                              recommended. The salt value should ideally be a
 *                              random or pseudorandom value of digest length.
 * @param saltLen               The length of the salt buffer.
 * @param pInputKeyMaterial     The input keying material. This is keying
 *                              material which may be non-uniformly distributed,
 *                              and the caller wants to create a "stronger" or
 *                              more evenly dispersed key. The key material can
 *                              be any length.
 * @param inputKeyMaterialLen   The length of the key material which can be any
 *                              length.
 * @param pOutput               The output buffer. This is where the pseudo
 *                              random key will be placed. Note that the key
 *                              should not be used as actual key material. The
 *                              key will be digest length in size (Based on the
 *                              digest suite passed in by the caller).
 * @param outputLen             The size of the output buffer.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS HmacKdfExtract(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen
    );

/**
 * Perform the extract operation for Hmac KDF. This function will take in the
 * input key material as well as an optional salt value and generate a pseudo
 * random key bits. Note that the output of the psuedo random key will be the
 * size of the digest output of the digest functions provided as input.
 *
 * IMPORTANT: Do not use the output of the extract function as actual key
 * material. The output material should be passed into the Hmac KDF expand
 * method.
 *
 * @param pDigest               The digest suite used for the Hmac operations.
 * @param pSalt                 Optional salt value. Providing a salt value is
 *                              recommended. The salt value should ideally be a
 *                              random or pseudorandom value of digest length.
 * @param saltLen               The length of the salt buffer.
 * @param pInputKeyMaterial     The input keying material. This is keying
 *                              material which may be non-uniformly distributed,
 *                              and the caller wants to create a "stronger" or
 *                              more evenly dispersed key. The key material can
 *                              be any length.
 * @param inputKeyMaterialLen   The length of the key material which can be any
 *                              length.
 * @param pOutput               The output buffer. This is where the pseudo
 *                              random key will be placed. Note that the key
 *                              should not be used as actual key material. The
 *                              key will be digest length in size (Based on the
 *                              digest suite passed in by the caller).
 * @param outputLen             The size of the output buffer.
 * @param pExtCtx               An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS HmacKdfExtractExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pSalt,
    ubyte4 saltLen,
    ubyte *pInputKeyMaterial,
    ubyte4 inputKeyMaterialLen,
    ubyte *pOutput,
    ubyte4 outputLen,
    void *pExtCtx
    );

/**
 * Perform the expand operation for Hmac KDF. This function will take in the
 * psuedo random key generated from the extract step and generate key material
 * bits. There is an optional context which can be passed in.
 *
 * @param pDigest               The digest suite used for the Hmac operations.
 * @param pPseudoRandomKey      This is the psuedo random key of at least digest
 *                              length bytes. This is usually the pseudo random
 *                              key from the extract step.
 * @param pseudoRandomKeyLen    The length of the psuedo random key. Must be at
 *                              least digest length in bytes.
 * @param pContext              Optional context information specific to the
 *                              application.
 * @param contextLen            The length of the context in bytes.
 * @param pIV                   The 'initial value' byte array. Can be NULL when
 *                              'ivLen' is zero (0).
 * @param ivLen                 The length of the 'initial vector' in bytes. Is
 *                              allowed to be zero.
 * @param pOutput               The output buffer where the keying material
 *                              will be deposited.
 * @param keyLength             This parameter it the amount of key material
 *                              bytes that the caller is requesting. It cannot
 *                              exceed 255 multiplied by the digest size.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS HmacKdfExpand(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength
    );

/**
 * Perform the expand operation for Hmac KDF. This function will take in the
 * psuedo random key generated from the extract step and generate key material
 * bits. There is an optional context which can be passed in.
 *
 * @param pDigest               The digest suite used for the Hmac operations.
 * @param pPseudoRandomKey      This is the psuedo random key of at least digest
 *                              length bytes. This is usually the pseudo random
 *                              key from the extract step.
 * @param pseudoRandomKeyLen    The length of the psuedo random key. Must be at
 *                              least digest length in bytes.
 * @param pContext              Optional context information specific to the
 *                              application.
 * @param contextLen            The length of the context in bytes.
 * @param pIV                   The 'initial value' byte array. Can be NULL when
 *                              'ivLen' is zero (0).
 * @param ivLen                 The length of the 'initial vector' in bytes. Is
 *                              allowed to be zero.
 * @param pOutput               The output buffer where the keying material
 *                              will be deposited.
 * @param keyLength             The size of the output buffer. Must have at
 *                              least keyLength bytes.
 * @param pExtCtx               An extended context reserved for future use.
 *
 * @return             \c OK (0) if successful, otherwise a negative number
 *                     error code from merrors.h.
 */
MOC_EXTERN MSTATUS HmacKdfExpandExt(
    MOC_HASH(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo *pDigest,
    ubyte *pPseudoRandomKey,
    ubyte4 pseudoRandomKeyLen,
    ubyte *pContext,
    ubyte4 contextLen,
    ubyte *pIv,
    ubyte4 ivLen,
    ubyte *pOutput,
    ubyte4 keyLength,
    void *pExtCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __HMAC_KDF_H__ */
