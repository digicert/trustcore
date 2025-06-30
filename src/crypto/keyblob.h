/*
 * keyblob.h
 *
 * Functions for serializing key blobs
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
@file       keyblob.h
@brief      Mocana SoT Platform key blob management code.
@details    This header file contains structures, enumerations, and function
            declarations for SoT Platform key blob management functions.

@since 1.41
@version 5.3 and later

@todo_version (new structures, new functions, etc.)

@flags
Whether the following flags are defined determines which structures and
enumerations are defined:
+ \c \__ENABLE_MOCANA_ECC__

Whether the following flags are defined determines which function declarations are enabled:
+ \c \__PUBCRYPTO_HEADER__

@filedoc    keyblob.h
*/


/*------------------------------------------------------------------*/

#ifndef __KEYBLOB_HEADER__
#define __KEYBLOB_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

/* these values are serialized -- add but don't modify */
/* these values correspond to the AsymmetricKey types */
typedef enum
{
    keyblob_type_undefined = 0, /* keep it 0 -> static var are correctly initialized */
                                /* as undefined */
    keyblob_type_rsa = 0x01,    /* must be same as akt_rsa in ca_mgmt.h */
    keyblob_type_ecc = 0x02,    /* must be same as akt_ecc in ca_mgmt.h */
    keyblob_type_dsa = 0x03,    /* must be same as akt_dsa in ca_mgmt.h */
    keyblob_type_rsa_pss = 0x05, /* must be same as akt_rsa_pss in ca_mgmt.h */

    keyblob_type_custom  = 0x65,    /* must be same as akt_custom in ca_mgmt.h */
    keyblob_type_moc     = 0x66,    /* must be same as akt_moc in ca_mgmt.h */

    keyblob_type_ecc_ed = 112,      /* must be same as akt_ecc_ed in ca_mgmt.h */
    keyblob_type_hybrid = 113,      /* must be same as akt_hybrid in ca_mgmt.h */
    keyblob_type_qs     = 114,      /* must be same as akt_qs in ca_mgmt.h */

    /* HSM types */
    keyblob_type_hsm_rsa = 0x010001,
    keyblob_type_hsm_ecc = 0x010002,

    keyblob_tap_rsa = 0x00020001,
    keyblob_tap_ecc = 0x00020002

} KEYBLOB_TYPE;


/*------------------------------------------------------------------*/

struct AsymmetricKey;

#ifdef __PUBCRYPTO_HEADER__
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS KEYBLOB_makeKeyBlobEx(const AsymmetricKey *pKey, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS KEYBLOB_extractKeyBlobEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength, AsymmetricKey* pKey);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS KEYBLOB_extractKeyBlobTypeEx(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte4 *pRetKeyType);
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS KEYBLOB_extractPublicKey(const ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength, ubyte4 *pRetKeyType);
#endif /* __PUBCRYPTO_HEADER__ */

/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_makeRSAKeyBlob(MOC_RSA(hwAccelDescr hwAccelCtx)
                       RSAKey *pRSAContext, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength);

#ifdef __ENABLE_MOCANA_DSA__
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_makeDSAKeyBlob(MOC_DSA(hwAccelDescr hwAccelCtx)
                       DSAKey *pDSAContext, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength);
#endif

/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_makeECCKeyBlob(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey *pECCKey, ubyte4 curveId,
                       ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength);
    
MOC_EXTERN MSTATUS
KEYBLOB_makeHybridBlob(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                       ubyte **ppRetKeyBlob, ubyte4 *pRetKeyLength);

MOC_EXTERN MSTATUS 
KEYBLOB_makeQsBlob(MOC_ASYM(hwAccelDescr hwAccelCtx) QS_CTX *pCtx, ubyte **ppRetKeyBlob,
                   ubyte4 *pRetKeyLength);

#if defined(__ENABLE_MOCANA_HW_SECURITY_MODULE__)
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_makeHSMRSAKeyBlob(RSAKey *pRSAKey, ubyte **ppRetKeyBlob,
                       ubyte4 *pRetKeyLength);
#endif


#if (defined(__ENABLE_MOCANA_DSA__))
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_readDSAKeyPart(MOC_DSA(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                       AsymmetricKey* pKey);
#endif

#if (defined(__ENABLE_MOCANA_ECC__))
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_readECCKeyPart(MOC_ECC(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey);
#endif

/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_readOldRSAKeyBlob(MOC_RSA(hwAccelDescr hwAccelCtx)
                         const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         AsymmetricKey* pKey);

/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_readRSAKeyPart(MOC_RSA(hwAccelDescr hwAccelCtx)
                       const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                       AsymmetricKey* pKey);

#if defined(__ENABLE_MOCANA_HW_SECURITY_MODULE__)
/** This is an old function.
 * <p>You should use CRYPTO_serialize to to get key blobs, along with DER and PEM
 * encodings from keys, and CRYPTO_deserialize to build keys from key blobs, DER,
 * and PEM.
 */
MOC_EXTERN MSTATUS
KEYBLOB_readHSMRSAKeyPart(const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                       AsymmetricKey* pKey);
#endif

MOC_EXTERN MSTATUS KEYBLOB_parseHeader(
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLen,
    ubyte4 *pKeyType,
    ubyte4 *pVersion
    );

#ifdef __cplusplus
}
#endif

#endif /* __KEYBLOB_HEADER__ */
