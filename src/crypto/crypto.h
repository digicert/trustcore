/*
 * crypto.h
 *
 * General Crypto Definitions & Types Header
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
 * @file       crypto.h
 *
 * @brief      Header file for the NanoCrypto general crypto APIs.
 *
 * @details    Header file for the NanoCrypto general crypto APIs.
 *
 * @filedoc    crypto.h
 */

/*------------------------------------------------------------------*/

#ifndef __CRYPTO_HEADER__
#define __CRYPTO_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define CERT_MAXDIGESTSIZE         (64)      /*(SHA512_RESULT_SIZE)*/
#define MAX_IV_LENGTH              (16)      /* AES */
#define MAX_ENC_KEY_LENGTH         (32)      /* AES-256 */

/*------------------------------------------------------------------*/


/* bulk encryption algorithms descriptions */
typedef BulkCtx (*CreateBulkCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
typedef MSTATUS (*DeleteBulkCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);
typedef MSTATUS (*CipherFunc)       (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte* data, sbyte4 dataLength, sbyte4 encrypt, ubyte* iv);
typedef MSTATUS (*CloneFunc)        (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

/**
 * @brief   Structure to hold function pointers to symmetric key cipher methods.
 *
 * @details Structure to hold function pointers to symmetric key cipher methods.
 */
typedef struct BulkEncryptionAlgo
{
    ubyte4                  blockSize;
    CreateBulkCtxFunc       createFunc;
    DeleteBulkCtxFunc       deleteFunc;
    CipherFunc              cipherFunc;
    CloneFunc               cloneFunc;
} BulkEncryptionAlgo;

/* predefined BulkEncryptionAlgos */
#ifndef __DISABLE_3DES_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_TripleDESSuite;
#endif

#ifndef __DISABLE_3DES_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_TwoKeyTripleDESSuite;
#endif

#ifdef __ENABLE_DES_CIPHER__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_DESSuite;
#endif

#ifndef __DISABLE_ARC4_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_RC4Suite;
#endif

#ifdef __ENABLE_ARC2_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_RC2Suite;
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_RC2EffectiveBitsSuite;
#endif

#ifdef __ENABLE_BLOWFISH_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_BlowfishSuite;
#endif

#ifndef __DISABLE_AES_CIPHERS__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_AESSuite;
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_AESCtrSuite;
#endif

#ifdef __ENABLE_NIL_CIPHER__
MOC_EXTERN const BulkEncryptionAlgo CRYPTO_NilSuite;
#endif

/**
 * @brief   Performs a symmetric key cipher algorithm on a buffer of data.
 *
 * @details Performs a symmetric key cipher algorithm on a buffer of data.
 *
 * @param pAlgo        Pointer to a suite holding the function pointer cipher methods to be used.
 * @param keyMaterial  Buffer holding the key material as a byte array.
 * @param keyLength    The length of the key in bytes. This may vary depending on the cipher chosen.
 * @param iv           Initialization vector (if required by the cipher chosen)
 * @param data         Buffer holding the input data to be processed by the cipher chosen.
 *                     This will be processed in place.
 * @param dataLength   The length of the data in bytes. Whether this needs to be a multiple
 *                     of the cipher blocklength depends on the cipher chosen.
 * @param encrypt      Enter TRUE (1) for encryption and FALSE (0) for decryption. For stream
 *                     ciphers or ciphers where the encryption operation is the same as the
 *                     decryption operation, this parameter will be ignored.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto.h
 */
MOC_EXTERN MSTATUS CRYPTO_Process( MOC_SYM(hwAccelDescr hwAccelCtx) const BulkEncryptionAlgo* pAlgo,
                                            ubyte* keyMaterial, sbyte4 keyLength,
                                            ubyte* iv, ubyte* data, sbyte4 dataLength, sbyte4 encrypt);

/* bulk hash algorithms descriptions */
typedef MSTATUS (*BulkCtxAllocFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx);
typedef MSTATUS (*BulkCtxFreeFunc)  (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pCtx);
typedef MSTATUS (*BulkCtxInitFunc)  (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx);
typedef MSTATUS (*BulkCtxUpdateFunc)(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, const ubyte *pData, ubyte4 datalength);
typedef MSTATUS (*BulkCtxFinalFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult);
typedef MSTATUS (*BulkCtxFinalXOFFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx ctx, ubyte *pResult, ubyte4 resultLen);
typedef MSTATUS (*BulkCtxDigestFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult);
typedef MSTATUS (*BulkCtxDigestXOFFunc) (MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pData, ubyte4 dataLen, ubyte *pResult, ubyte4 resultLen);

/**
 * @brief   Structure to hold function pointers to hashing or extenable output methods.
 *
 * @details Structure to hold function pointers to hashing or extenable output methods.
 */
typedef struct BulkHashAlgo
{
    ubyte4                  digestSize;
    ubyte4                  blockSize; /* used for HMAC */
    BulkCtxAllocFunc        allocFunc;
    BulkCtxFreeFunc         freeFunc;
    BulkCtxInitFunc         initFunc;
    BulkCtxUpdateFunc       updateFunc;
    BulkCtxFinalFunc        finalFunc;
    BulkCtxFinalXOFFunc     finalXOFFunc;
    BulkCtxDigestFunc       digestFunc;
    BulkCtxDigestXOFFunc    digestXOFFunc;
    ubyte hashId;
} BulkHashAlgo;

/**
 * @brief   Enum of identifiers for the available hashing methods.
 *
 * @details Enum of identifiers for the available hashing methods. When
 *          possible this is the suffix of the pkcs1_OID.
 */
enum {
    rsaEncryption = 1,
    pkcs1Mgf = 8,
    rsaSsaPss = 10,
    md2withRSAEncryption = 2,
    md4withRSAEncryption = 3,
    md5withRSAEncryption = 4,
    sha1withRSAEncryption = 5,
    sha256withRSAEncryption = 11,
    sha384withRSAEncryption = 12,
    sha512withRSAEncryption = 13,
    sha224withRSAEncryption = 14,
    /* duplicate definition = hash_type */
    ht_none = 0,
    ht_md2 = 2,
    ht_md4 = 3,
    ht_md5 = 4,
    ht_sha1 = 5,
    ht_sha3_224 = 7,
    ht_sha3_256 = 8,
    ht_sha3_384 = 9,
    ht_sha3_512 = 10,
    ht_shake128 = 111, /* last byte of oid is 11 but that is a duplicate, use 111 */
    ht_shake256 = 112, /* last byte of oid is 12 but that is a duplicate, use 112 */
    ht_sha256 = 11,
    ht_sha384 = 12,
    ht_sha512 = 13,
    ht_sha224 = 14,
    ht_blake2b = 15,
    ht_blake2s = 16,

    /* For use with cert requests, don't sign the request with an asymmetric
     * algorithm, just place the digest in the signature location.
     */
    sha1_with_no_sig = 31
};

/**
 * @brief   Gets a hash suite of function pointers, appropriate for RSA, given a hash identifier.
 *
 * @details Gets a hash suite of function pointers, appropriate for RSA, given a hash identifier.
 *
 * @param rsaAlgoId       The identifier for the hash algorithm.
 * @param ppBulkHashAlgo  Pointer whose contents will be set to the location of the hash
 *                        suite for the algorithm requested.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto.h
 */
MOC_EXTERN MSTATUS CRYPTO_getRSAHashAlgo( ubyte rsaAlgoId, const BulkHashAlgo **ppBulkHashAlgo);

/**
 * @brief   Gets a hash suite of function pointers, appropriate for ECC, given a hash identifier.
 *
 * @details Gets a hash suite of function pointers, appropriate for ECC, given a hash identifier.
 *
 * @param eccAlgoId       The identifier for the hash algorithm.
 * @param ppBulkHashAlgo  Pointer whose contents will be set to the location of the hash
 *                        suite for the algorithm requested.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto.h
 */
MOC_EXTERN MSTATUS CRYPTO_getECCHashAlgo( ubyte eccAlgoId, BulkHashAlgo **ppBulkHashAlgo);

/**
 * @brief   Computes a hash of a buffer of data given a hash identifier.
 *
 * @details Computes a hash of a buffer of data given a hash identifier.
 *
 * @param buffer       The buffer of data to be hashed.
 * @param bytesToHash  The length of the data to hash in bytes.
 * @param hash         Buffer to hold the resulting output data.
 * @param hashSize     Contents will be set to the length of the output data in bytes.
 * @param rsaAlgoId    The identifier for the hash algorithm to be used.
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc crypto.h
 */
MOC_EXTERN MSTATUS CRYPTO_computeBufferHash(MOC_HASH(hwAccelDescr hwAccelCtx)
                                            const ubyte* buffer,
                                            ubyte4 bytesToHash,
                                            ubyte hash[CERT_MAXDIGESTSIZE],
                                            sbyte4 *hashSize,
                                            ubyte4 rsaAlgoId);

/* bulk encryption algorithms descriptions */
typedef BulkCtx (*CreateAeadCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* keyMaterial, sbyte4 keyLength, sbyte4 encrypt);
typedef MSTATUS (*DeleteAeadCtxFunc)(MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ctx);
typedef MSTATUS (*AeadCipherFunc)  (MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,  ubyte* nonce, ubyte4 nlen, ubyte* adata, ubyte4 alen, ubyte* data, ubyte4 dataLength, ubyte4 verifyLen, sbyte4 encrypt);
typedef MSTATUS (*AeadCloneFunc) ( MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx, BulkCtx *ppNewCtx);

typedef struct AeadAlgo
{
    ubyte4                  implicitNonceSize;
    ubyte4                  explicitNonceSize;
    ubyte4                  tagSize;
    CreateAeadCtxFunc       createFunc;
    DeleteAeadCtxFunc       deleteFunc;
    AeadCipherFunc          cipherFunc;
    AeadCloneFunc           cloneFunc;

} AeadAlgo;


#ifdef __cplusplus
}
#endif


#endif /* __CRYPTO_HEADER__ */
