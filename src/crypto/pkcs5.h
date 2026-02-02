/*
 * pkcs5.h
 *
 * PKCS #5 Factory Header
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
@file       pkcs5.h

@brief      Header file for SoT Platform PKCS&nbsp;\#5 convenience API.
@details    Header file for SoT Platform PKCS&nbsp;\#5, version 2.0, convenience
            API, as defined by RFC&nbsp;2898.
*/

#ifndef __PPKCS5_HEADER__
#define __PPKCS5_HEADER__

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_pkcs5_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum hashFunc
{
    md2Encryption = 2,
    md4Encryption = 3,
    md5Encryption = 4,
    sha1Encryption = 5,
    sha256Encryption = 11,
    sha384Encryption = 12,
    sha512Encryption = 13,
    sha224Encryption = 14
};

enum encFunc
{
    nilEncryption = 0,
    tdesEncryption = 1,
    twoKeyTdesEncryption = 2,
    desEncryption = 3,
    rc4Encryption = 4,
    rc2Encryption = 5,
    rc2EkbEncryption = 6,
    bfEncryption = 7,
    aesEncryption = 8,
    aesCtrEncryption = 9
};

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PKCS5__

#define MOC_MIN_800_132_SALT_LEN          16
#define MOC_MIN_800_132_KEY_LEN           14
#define MOC_MIN_800_132_ITERATION_COUNT   1000

/**
 * @cond
 */
MOC_EXTERN const ubyte pkcs5_root_OID[];    /* 1.2.840.113549.1.5 */
MOC_EXTERN const ubyte pkcs5_PBKDF2_OID[];  /* 1.2.840.113549.1.5.12 */
MOC_EXTERN const ubyte pkcs5_PBES2_OID[];   /* 1.2.840.113549.1.5.13 */
/**
 * @endcond
 */

/**
@brief      Generate a key based on the RFC&nbsp;2898 PBKDF1 key generation
            method.

@details    This function implements the PBKDF1 key derivation method defined in
            RFC 2898. It applies the hash function the specified number of
            times, \p iterationCount, to the given password and salt
            (\p pPassword and \p pSalt) to derive the key. In addition to
            supporting SHA-1, MD2, and MD5 as specified by RFC&nbsp;2898,
            this function extends support to SHA[224|256|384|512] and MD4
            hash functions. The length of the resulting key is bounded by
            the length of the hash function output, which is:
            + 16 octets for MD2, MD4, and MD5.
            + 20 octets for SHA-1.
            + 28 octets for SHA-224.
            + 32 octets for SHA-256.
            + 48 octets for SHA-384.
            + 64 octets for SHA-512.

@note       Use PBKDF1 only for existing applications that require it for
            backward compatibility. Use PBKDF2 for newer applications; see
            PKCS5_CreateKey_PBKDF2().

@ingroup    pkcs_functions

@todo_eng_review (is MD4 still, in SoTP 6.4 that is, supported? Global question...)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param pSalt            Pointer to salt to hash.
@param saltLen          Length in bytes of the salt (\p pSalt).
@param iterationCount   Number of hash function (\p hashingFunction) iterations.
@param hashingFunction  Hash function to apply to the password and salt; any of
                          the \c hashFunc enum values from pkcs5.h:
                          + \c md2Encryption
                          + \c md4Encryption
                          + \c md5Encryption
                          + \c sha1Encryption
                          + \c sha256Encryption
                          + \c sha384Encryption
                          + \c sha512Encryption
                          + \c sha224Encryption
@param pPassword        Pointer to password to hash.
@param passwordLen      Length in bytes of password (\p pPassword).
@param dkLen            Length of key to deive. Must be less than or equal to
                          the length of the hash function ouptut.
@param pRetDerivedKey   On return, pointer to derived key&mdash;an octet string
                          of length \p dkLen.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs5.h
*/
MOC_EXTERN MSTATUS PKCS5_CreateKey_PBKDF1(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
                                          ubyte4 iterationCount, enum hashFunc hashingFunction,
                                          const ubyte *pPassword, ubyte4 passwordLen,
                                          ubyte4 dkLen, ubyte *pRetDerivedKey);

/**
@brief      Generate a key based on the RFC&nbsp;2898 PBKDF2 key generation
            method.

@details    This function implements the PBKDF2 key derivation method defined in
            RFC&nbsp;2898. It applies a pseudorandom function the specified number
            of times, \p iterationCount, to the given password and salt to derive
            the key. PBKDF2 is recommended for new applications. The pseudorandom
            function is HMAC with a digest algorithm. The caller specifies which
            digest algorithm to use.
            <p>In FIPS mode, the only digest algorithms allowed are SHA-1,
            SHA-224, SHA-256, SHA-384, and SHA-512. In any new allplication, you
            should not use MD2, MD4, or MD5, they are only provided to support
            older applications.
            <p>In FIPS mode, the salt length must be at least 16 bytes (128 bits).
            <p>In FIPS mode, the derived key length (dkLen) must be at least 14
            bytes (112 bits).

@note       Use PBKDF2 for new applications. If you have an existing appliation
            that requires PBKDF1 for backward compatibility, use the
            PKCS5_CreateKey_PBKDF1() function.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param pSalt            Pointer to salt to hash.
@param saltLen          Length in bytes of the salt (\p pSalt).
@param iterationCount   Number of pseudorandom function iterations.
@param digestAlg        Digest algorithm to apply to the password
                          and salt; any of the following enum values from
                          src/crypto/crypto.h:
                          + \c ht_md2 (not valid in FIPS mode)
                          + \c md2withRSAEncryption (same as ht_md2)
                          + \c ht_md4 (not valid in FIPS mode)
                          + \c md4withRSAEncryption (same as ht_md4)
                          + \c ht_md5 (not valid in FIPS mode)
                          + \c md5withRSAEncryption (same as ht_md5)
                          + \c ht_sha1
                          + \c sha1withRSAEncryption (same as ht_sha1)
                          + \c ht_sha224
                          + \c sha224withRSAEncryption (same as ht_sha224)
                          + \c ht_sha256
                          + \c sha256withRSAEncryption (same as ht_sha256)
                          + \c ht_sha384
                          + \c sha384withRSAEncryption (same as ht_sha384)
                          + \c ht_sha512
                          + \c sha512withRSAEncryption (same as ht_sha512)
@param pPassword        Pointer to password to hash.
@param passwordLen      Length in bytes of password (\p pPassword).
@param dkLen            Length of key to derive; the maximum value is
                          (2^32 - 1) bytes.
@param pRetDerivedKey   On return, pointer to derived key&mdash;an octet string
                          of length \p dkLen.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs5.h
*/
MOC_EXTERN MSTATUS PKCS5_CreateKey_PBKDF2(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
                                          ubyte4 iterationCount, ubyte rsaAlgoId,
                                          const ubyte *pPassword, ubyte4 passwordLen,
                                          ubyte4 dkLen, ubyte *pRetDerivedKey);

/**
@brief Decrypt data that is PKCS5 encrypted.

@ingroup pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param subType           The type of algorithm used for encryption, either V1 or V2.
                         Use the enum PKCS5_PBES2 to indicate PBE2, anything else
                         will be treated as PBE1.
@param cs                The CStream associated with the ASN1 item pointers.
@param pPBEParam         ASN1 item pointing to the PBE params to use for the decryption.
@param pEncrypted        ASN1 item pointing to the encrypted data to be decrypted.
@param password          Buffer containing the password that the data was originally
                         encrypted with.
@param passwordLen       Length in bytes of the password data.
@param privateKeyInfo    Pointer to the location that will recieve the newly allocated
                         decrypted data buffer.
@param privateKeyInfoLen Length in bytes of the decrypted data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN MSTATUS PKCS5_decrypt( MOC_SYM(hwAccelDescr hwAccelCtx)
                                    ubyte subType, CStream cs,
                                    ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
                                    const ubyte* password, sbyte4 passwordLen,
                                    ubyte** privateKeyInfo,
                                    sbyte4* privateKeyInfoLen);

/**
@brief Decrypt data that is PKCS5 V2 encrypted and in a raw buffer form.

@ingroup pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param pAsn1PBE          The PBE params to use for the decryption in a raw buffer ASN1 form.
@param pbeLen            The length of the \c pAsn1PBE buffer in bytes.
@param pData             The data to be encrypted in a raw buffer form.
@param dataLen           The length of the \c pData buffer in bytes.
@param password          Buffer containing the password that the data was originally
                         encrypted with.
@param passwordLen          Length in bytes of the password data.
@param pPrivateKeyInfo      Buffer to hold the decrypted data.
@param privKeyInfoBufferLen Length of the \c pPrivateKeyInfo buffer in bytes.
@param pPrivKeyInfoLen      Contents will be set to the actual length of the private key info.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN MSTATUS PKCS5_decryptV2( MOC_SYM(hwAccelDescr hwAccelCtx)
                                    const ubyte *pAsn1PBE, ubyte4 pbeLen,
                                    ubyte *pData, ubyte4 dataLen,
                                    const ubyte *pPassword, sbyte4 passwordLen,
                                    ubyte *pPrivateKeyInfo, ubyte4 privKeyInfoBufferLen,
                                    ubyte4 *pPrivKeyInfoLen);

/**
@brief      Encrypt a plaintext buffer with PBES1 encryption as defined in
            RFC&nbsp;2898.

@details    This function encrypts a plaintext buffer with PBES1 encryption as
            defined in RFC&nbsp;2898. It combines PBKDF1 key derivation with
            either DES or RC2 block cipher encryption, depending on the given \p
            pkdcs5SubType parameter.

@note       Use PBES1 only for compatibility with existing applications because
            it uses small key sizes and supports only two encryption schemes.
            Use PBES2 (see PKCS5_encryptV2()) for new applications because it
            supports large key sizes and many encryption schemes.

@ingroup    pkcs_functions

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param pkcs5SubType     PKCS8 encryption type; any of the \c PKCS8EncryptionType
                          enum values from pkcs_key.h:
                          + \c PCKS8_EncryptionType_pkcs5_v1_md2_des
                          + \c PCKS8_EncryptionType_pkcs5_v1_md5_des
                          + \c PCKS8_EncryptionType_pkcs5_v1_md2_rc2
                          + \c PCKS8_EncryptionType_pkcs5_v1_md5_rc2
                          + \c PCKS8_EncryptionType_pkcs5_v1_sha1_des
                          + \c PCKS8_EncryptionType_pkcs5_v1_sha1_rc2
@param password         Pointer to password to use for key derivation.
@param passwordLen      Length in bytes of password (\p pPassword).
@param salt             Pointer to salt to use for key derivation.
@param saltLen          Length in bytes of the salt (\p salt).
@param iterCount        Iteration count to use for key derivation.
@param plainText        On input, pointer to plaintext message to encrypt.\n
                          On return, pointer to encrypted ciphertext.
@param ptLen            Length in bytes of plaintext message, \p plainText. On
                          return, the ciphertext will have the same length.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs5.h
*/
MOC_EXTERN MSTATUS PKCS5_encryptV1( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  ubyte pkcs5SubType,
                                  const ubyte* password, ubyte4 passwordLen,
                                  const ubyte* salt, ubyte4 saltLen,
                                  ubyte4 iterCount,
                                  ubyte* plainText, ubyte4 ptLen);

/**
@brief      Encrypt a plaintext buffer with PBES2 encryption as defined in
            RFC&nbsp;2898.

@details    This function encrypts a plaintext buffer with PBES2 encryption as
            defined in RFC&nbsp;2898. It combines the PBKDF2 password-based key
            derivation function with the given bulk encryption algorithm.

@note       Use PBES2 for new applications because it supports large key sizes
            and many encryption schemes. Use PBES1 (see PKCS5_encryptV1()) only
            for compatibility with existing applications because it uses small
            key sizes and supports only two encryption schemes.

@ingroup    pkcs_functions

@todo_eng_review (clarify how \c effectiveKeyBits works)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS5__

@inc_file pkcs5.h

@param pAlgo            Pointer to bulk encryption algorithm to apply; any of
                          the following BulkEncryptionAlgo constant arrays
                          defined in src/crypto/crypto.c:
                          + \c CRYPTO_TripleDESSuite
                          + \c CRYPTO_TwoKeyTripleDESSuite
                          + \c CRYPTO_DESSuite
                          + \c CRYPTO_RC4Suite
                          + \c CRYPTO_RC2Suite
                          + \c CRYPTO_RC2EffectiveBitsSuite
                          + \c CRYPTO_BlowfishSuite
                          + \c CRYPTO_AESSuite
                          + \c CRYPTO_AESCtrSuite
                          + \c CRYPTO_NilSuite
@param rsaAlgoId        Pseudorandom function algorithm to apply to the password
                          and salt; any of the following enum values from
                          src/crypto/crypto.h:
                          + \c md2withRSAEncryption
                          + \c md4withRSAEncryption
                          + \c md5withRSAEncryption
                          + \c sha1withRSAEncryption
                          + \c sha224withRSAEncryption
                          + \c sha256withRSAEncryption
                          + \c sha384withRSAEncryption
                          + \c sha512withRSAEncryption
@param keyLength        Length of key to derive; the maximum value is
                          (2^32 - 1) bytes.
@param effectiveKeyBits Specify "1" to ensure encryption.
@param password         Pointer to password to use for key derivation.
@param passwordLen      Length in bytes of password (\p password).
@param salt             Pointer to salt to use for key derivation.
@param saltLen          Length in bytes of the salt (\p salt).
@param iterCount        Iteration count to use for key derivation.
@param iv               Initialization vector whose first pAlgo->blockSize bytes
                          are appended to the derived key.
@param plainText        On input, pointer to plaintext message to encrypt.\n
                          On return, pointer to encrypted ciphertext.
@param ptLen            Length in bytes of plaintext message, \p plainText. On
                          return, the ciphertext will have the same length.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc pkcs5.h
*/
MOC_EXTERN MSTATUS PKCS5_encryptV2( MOC_SYM(hwAccelDescr hwAccelCtx)
                                  const BulkEncryptionAlgo* pAlgo, ubyte rsaAlgoId,
                                  ubyte4 keyLength, sbyte4 effectiveKeyBits,
                                  const ubyte* password, ubyte4 passwordLen,
                                  const ubyte* salt, ubyte4 saltLen,
                                  ubyte4 iterCount, const ubyte* iv,
                                  ubyte* plainText, ubyte4 ptLen);


/**
 @brief      Encrypt a plaintext buffer with PBES2 encryption as defined in
             RFC&nbsp;2898.

 @details    This function encrypts a plaintext buffer with PBES2 encryption as
             defined in RFC&nbsp;2898. It combines the PBKDF2 password-based key
             derivation function with the given bulk encryption algorithm.

 @note       Use PBES2 for new applications because it supports large key sizes
             and many encryption schemes. Use PBES1 (see PKCS5_encryptV1()) only
             for compatibility with existing applications because it uses small
             key sizes and supports only two encryption schemes.

 @param encryptionAlgo   The encryption algorithm. One of the following enum values
                         + \c nilEncryption
                         + \c tdesEncryption
                         + \c twoKeyTdesEncryption
                         + \c desEncryption
                         + \c rc4Encryption
                         + \c rc2Encryption
                         + \c rc2EkbEncryption
                         + \c bfEncryption
                         + \c aesEncryption
                         + \c aesCtrEncryption
 @param digestAlg        Pseudorandom function algorithm to apply to the password
                         and salt; any of the following enum values from
                         src/crypto/crypto.h:
                         + \c md2withRSAEncryption
                         + \c md4withRSAEncryption
                         + \c md5withRSAEncryption
                         + \c sha1withRSAEncryption
                         + \c sha224withRSAEncryption
                         + \c sha256withRSAEncryption
                         + \c sha384withRSAEncryption
                         + \c sha512withRSAEncryption
 @param keyLength        Length of key to derive; the maximum value is
                         (2^32 - 1) bytes.
 @param effectiveKeyBits Specify "1" to ensure encryption.
 @param pPassword        Pointer to password to use for key derivation.
 @param passwordLen      Length in bytes of password (\p password).
 @param pSalt            Pointer to salt to use for key derivation.
 @param saltLen          Length in bytes of the salt (\p salt).
 @param iterCount        Iteration count to use for key derivation.
 @param pIv              Initialization vector whose first pAlgo->blockSize bytes
                         are appended to the derived key.
 @param pPlainText       Buffer holding the plaintext message to encrypt.
 @param ptLen            Length in bytes of plaintext message, \p plainText.
 @param pCipherText      Buffer to hold the resulting cipherText. It must
                         have enough space for a padded message.
 @param ctBufferLen      Length of the \c pCipherText buffer in bytes.
 @param pCtLen           Contents will be set to the number of bytes contained
                         in the resulting ciphertext.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS PKCS5_encryptV2_Alt(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte encryptionAlgo, ubyte digestAlg,
    ubyte4 keyLength, sbyte4 effectiveKeyBits,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount, const ubyte *pIv,
    ubyte *pPlainText, ubyte4 ptLen,
    ubyte *pCipherText, ubyte4 ctBufferLen,
    ubyte4 *pCtLen);

#endif

#ifdef __cplusplus
}
#endif


#endif /* __PPKCS5_HEADER__ */

