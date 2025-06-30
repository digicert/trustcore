/*
 * crypto_interface_pkcs5.h
 *
 * Cryptographic Interface header file for PKCS5 methods.
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
 @file       crypto_interface_pkcs5.h
 @brief      Cryptographic Interface header file for declaring PKCS5 functions.
 @details    Add details here.

 @filedoc    crypto_interface_pkcs5.h
 */

#ifndef __CRYPTO_INTERFACE_PKCS5_HEADER__
#define __CRYPTO_INTERFACE_PKCS5_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


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
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF1(
    MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
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
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2(
    MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterationCount, ubyte digestAlg,
    const ubyte *pPassword, ubyte4 passwordLen,
    ubyte4 dkLen, ubyte *pRetDerivedKey);


/**
 @brief      Decrypts a ciphertext buffer originally encrypted with either PBES1
             or PBES2 encryption as defined in RFC&nbsp;2898.

 @details    Decrypts a ciphertext buffer originally encrypted with either PBES1
             or PBES2 encryption as defined in RFC&nbsp;2898.

 @param subType             PKCS5_PBES2 or one of the enum values from pkcs_key.h:
                            + \c PCKS8_EncryptionType_pkcs5_v1_md2_des
                            + \c PCKS8_EncryptionType_pkcs5_v1_md5_des
                            + \c PCKS8_EncryptionType_pkcs5_v1_md2_rc2
                            + \c PCKS8_EncryptionType_pkcs5_v1_md5_rc2
                            + \c PCKS8_EncryptionType_pkcs5_v1_sha1_des
                            + \c PCKS8_EncryptionType_pkcs5_v1_sha1_rc2
 @param cs
 @param pPBEParam
 @param pEncrypted
 @param pPassword           Pointer to password to use for decryption.
 @param passwordLen         Length in bytes of password (\p password).
 @param ppPrivateKeyInfo
 @param pPrivateKeyInfoLen

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_decrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte subType, CStream cs,
    ASN1_ITEMPTR pPBEParam, ASN1_ITEMPTR pEncrypted,
    const ubyte *pPassword, sbyte4 passwordLen,
    ubyte **ppPrivateKeyInfo,
    sbyte4 *pPrivateKeyInfoLen);


/**
 @brief    Decrypt data that is PKCS5 V2 encrypted and in a raw buffer form.
 @details  Decrypt data that is PKCS5 V2 encrypted and in a raw buffer form.

 @param pAsn1PBE          The PBE params to use for the decryption in a raw buffer ASN1 form.
 @param pbeLen            The length of the \c pAsn1PBE buffer in bytes.
 @param pData             The data to be encrypted in a raw buffer form.
 @param dataLen           The length of the \c pData buffer in bytes.
 @param password          Buffer containing the password that the data was originally
                          encrypted with.
 @param passwordLen       Length in bytes of the password data.
 @param pPrivateKeyInfo   Buffer to hold the decrypted data.
 @param privKeyInfoBufferLen Length of the \c pPrivateKeyInfo buffer in bytes.
 @param pPrivKeyInfoLen      Contents will be set to the actual length of the private key info.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
*/
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_decryptV2( 
    MOC_SYM(hwAccelDescr hwAccelCtx)
    const ubyte *pAsn1PBE, ubyte4 pbeLen,
    ubyte *pData, ubyte4 dataLen,
    const ubyte* pPassword, sbyte4 passwordLen,
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

 @param pkcs5SubType     PKCS8 encryption type; any of the \c PKCS8EncryptionType
                         enum values from pkcs_key.h:
                         + \c PCKS8_EncryptionType_pkcs5_v1_md2_des
                         + \c PCKS8_EncryptionType_pkcs5_v1_md5_des
                         + \c PCKS8_EncryptionType_pkcs5_v1_md2_rc2
                         + \c PCKS8_EncryptionType_pkcs5_v1_md5_rc2
                         + \c PCKS8_EncryptionType_pkcs5_v1_sha1_des
                         + \c PCKS8_EncryptionType_pkcs5_v1_sha1_rc2
 @param pPassword        Pointer to password to use for key derivation.
 @param passwordLen      Length in bytes of password (\p pPassword).
 @param pSalt            Pointer to salt to use for key derivation.
 @param saltLen          Length in bytes of the salt (\p salt).
 @param iterCount        Iteration count to use for key derivation.
 @param pPlainText       On input, pointer to plaintext message to encrypt.\n
                         On return, pointer to encrypted ciphertext.
 @param ptLen            Length in bytes of plaintext message, \p plainText. On
                         return, the ciphertext will have the same length.

 @return     \c OK (0) if successful; otherwise a negative number error code
             definition from merrors.h. To retrieve a string containing an
             English text error identifier corresponding to the function's
             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_encryptV1(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte pkcs5SubType,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount,
    ubyte *pPlainText, ubyte4 ptLen);


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
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_PKCS5_encryptV2_Alt(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte encryptionAlgo, ubyte digestAlg,
    ubyte4 keyLength, sbyte4 effectiveKeyBits,
    const ubyte *pPassword, ubyte4 passwordLen,
    const ubyte *pSalt, ubyte4 saltLen,
    ubyte4 iterCount, const ubyte *pIv,
    ubyte *pPlainText, ubyte4 ptLen,
    ubyte *pCipherText, ubyte4 ctBufferLen,
    ubyte4 *pCtLen);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_PKCS5_HEADER__ */
