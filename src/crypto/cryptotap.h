/*
 * cryptotap.h
 *
 * Declarations and definitions for functions that are available to NanoTap
 * prividers. This is an API that allows someone to call on NanoCrypto
 * functionality without knowing anything about NanoCrypto.
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

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../tap/tap_common.h"

#ifndef __CRYPTO_TAP_HEADER__
#define __CRYPTO_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_TAP__

/* An RSA Padding scheme for the Special TAP RSA encryption or verification
 * functions is really a function. This is the signature of such a function.
 * <p>Do not call a PaddingScheme directly, only use it as an argument to the
 * call to CT_RsaPublicEncrypt, or CT_RsaVerifySignature.
 * <p>Note that an implementation of this typedef does not actually perform
 * padding or unpadding, it just returns data to the caller so that it can
 * properly call the MocAsymKey functions that perform RSA.
 */
typedef MSTATUS (*MCTRsaPad) (
  ubyte4 operation,
  void *pInputInfo,
  void *pOutputInfo
  );

/* Call on the Padding scheme to build the AlgId for encrypting, using the info
 * given. Allocate space for the algId and return it in the outputInfo. The
 * caller frees that memory.
 */
#define MCT_RSA_PAD_OP_ALG_ID_ENC   1
/* Call on the Padding scheme to build the AlgId for verifying, using the info
 * given. Allocate space for the algId and return it in the outputInfo. The
 * caller frees that memory.
 */
#define MCT_RSA_PAD_OP_ALG_ID_VFY   2

/* The digestAlg is for verification, which digest algorithm was used to digest
 * the data to sign.
 * The padDigestAlg is for OAEP or PSS, the algorithm used during padding
 * operations.
 * The mgfDigestAlg is the algorithm used by MGF1.
 * The saltLen is for PSS.
 * The trailerField is for PSS.
 * The pLabel and labelLen is for OAEP.
 */
typedef struct
{
  ubyte4   digestAlg;
  ubyte4   padDigestAlg;
  ubyte4   mgfDigestAlg;
  ubyte4   saltLen;
  ubyte4   trailerField;
  ubyte   *pLabel;
  ubyte4   labelLen;
} MCTAlgIdInputInfo;

/* The MCTRsaPad will allocate memory for the AlgId, build the alg ID and deposit
 * the buffer at pAlgId. The caller frees it using DIGI_FREE.
 * The MCTRsaPad will allocate memory for the list of supported symmetric
 * algorithms, fill it and deposit the buffer at pSupportedSym. The caller frees
 * it using DIGI_FREE.
 */
typedef struct
{
  ubyte                *pAlgId;
  ubyte4                algIdLen;
  MSymOperatorAndInfo  *pSupportedSym;
  ubyte4                count;
} MCTAlgIdOutputInfo;

/** Use this as the MCTRsaPad argument in a call to CT_RsaPublicEncrypt or
 * CT_RsaVerifySignature when you want the function to pad data following the
 * methods described in PKCS 1 version 1.5 (see, for example, RFC 8017).
 * <p>Although this is a function, do not call it directly, only use it as an
 * argument in functions that take an MCTRsaPad.
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 */
MOC_EXTERN MSTATUS CT_RSA_PAD_PKCS_1_5 (
  ubyte4 operation,
  void *pInputInfo,
  void *pOutputInfo
  );

/** Use this as the MCTRsaPad argument in a call to CT_RsaPublicEncrypt when you
 * want the function to pad data following the methods of OAEP (Optimal
 * Asymmetric Encryption Padding, described in PKCS 1 version 2, see, for
 * example, RFC 8017).
 * <p>Although this is a function, do not call it directly, only use it as an
 * argument in functions that take an MCTRsaPad.
 * <p>With OAEP, you also need a digest algorithm (call this the OAEP digest),
 * mask generating function (MGF), and a "PSource". This implementation supports
 * only SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512 as the OAEP digest.
 * Currenly, only one MGF has been defined, called MGF1, and that is all this
 * implementation supports. MGF1 takes a digest as an argument. Most of the time,
 * the MGF1 digest is the same as the OAEP digest, but they can be different.
 * This implementation supports the same set of digest algorithms for the MGF1
 * digest as the OAEP digest. Currently there is  only PSource defined,
 * "specified" (a byte array), and that is all this implementation supports.
 * <p>The defaults are SHA-1, MGF1 with SHA-1, and specified-empty (meaning no
 * PSource).
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 */
MOC_EXTERN MSTATUS CT_RSA_PAD_OAEP (
  ubyte4 operation,
  void *pInputInfo,
  void *pOutputInfo
  );

/** Use this as the MCTRsaPad argument in a call to CT_RsaPublicVerify when you
 * want the function to unpad data following the methods of PSS (Probabilistic
 * Signature Scheme, described in PKCS 1 version 2, see, for example, RFC 8017).
 * <p>Although this is a function, do not call it directly, only use it as an
 * argument in functions that take an MCTRsaPad.
 * <p>With PSS, you also need a digest algorithm (call this the PSS digest), mask
 * generating function (MGF), a salt length, and trailer field. Furthermore, the
 * PSS digest must be the same algorithm used to digest the data to sign. For
 * example, if you want to sign using RSA with SHA-256 and PSS, you digest the
 * data to sign using SHA-256, and you use SHA-256 as the PSS digest.
 * <p>This implementation supports only SHA-1, SHA-224, SHA-256, SHA-384, and
 * SHA-512 as the PSS digest. Currenly, only one MGF has been defined, called
 * MGF1, and that is all this implementation supports. MGF1 takes a digest as an
 * argument. Most of the time, the MGF1 digest is the same as the PSS digest, but
 * they can be different. This implementation supports the same set of digest
 * algorithms for the MGF1 digest as the PSS digest. If the salt length is too
 * long, PSS cannot work (how long is too long? that depends on the digest used
 * on the data to sign and the key size, but 20 works for any digest and key size
 * supported by NanoCrypto). The trailer field is one byte and is not arbitrary.
 * You must use a value defined in a standard. Only one value has been defined in
 * PKCS 1 version 2 (trailerFieldBC = 0xBC), although other standards have
 * indicated the possibility of other values.
 * <p>The defaults are SHA-1, MGF1 with SHA-1, saltLen of 20, and a trailer field
 * of 0xBC.
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 */
MOC_EXTERN MSTATUS CT_RSA_PAD_PSS (
  ubyte4 operation,
  void *pInputInfo,
  void *pOutputInfo
  );

/** Use this value as the oaepDigest, pssDigest, or mgfDigest arg in a call to
 * CT_RsaPublicEncrypt or CT_RsaVerifySignature to specify SHA-1.
 * <p>This is the same value as ht_sha1 (see mss/src/crypto/crypto.h)
 */
#define CT_DIGEST_SHA1            5
/** Use this value as the oaepDigest, pssDigest, or mgfDigest arg in a call to
 * CT_RsaPublicEncrypt or CT_RsaVerifySignature to specify SHA-224.
 * <p>This is the same value as ht_sha224 (see mss/src/crypto/crypto.h)
 */
#define CT_DIGEST_SHA224          14
/** Use this value as the oaepDigest, pssDigest, or mgfDigest arg in a call to
 * CT_RsaPublicEncrypt or CT_RsaVerifySignature to specify SHA-256.
 * <p>This is the same value as ht_sha256 (see mss/src/crypto/crypto.h)
 */
#define CT_DIGEST_SHA256          11
/** Use this value as the oaepDigest, pssDigest, or mgfDigest arg in a call to
 * CT_RsaPublicEncrypt or CT_RsaVerifySignature to specify SHA-384.
 * <p>This is the same value as ht_sha384 (see mss/src/crypto/crypto.h)
 */
#define CT_DIGEST_SHA384          12
/** Use this value as the oaepDigest, pssDigest, or mgfDigest arg in a call to
 * CT_RsaPublicEncrypt or CT_RsaVerifySignature to specify SHA-512.
 * <p>This is the same value as ht_sha512 (see mss/src/crypto/crypto.h)
 */
#define CT_DIGEST_SHA512          13

/** Use this value as the saltLen arg in a call to CT_RsaVerifySignature if the
 * Padding Scheme is PSS and you want to use the default salt length of 20.
 */
#define CT_DEFAULT_SALT_LEN       20
/** Use this value as the trailerField arg in a call to CT_RsaVerifySignature if
 * the Padding Scheme is PSS and you want to use the default trailer field of
 * 0xBC.
 */
#define CT_DEFAULT_TRAILER_FIELD  0xBC

/** @brief Perform RSA encryuption using a public key.
 * @details This function allows the caller to encrypt data using NanoCrypto, yet
 * also using an RSA public key in "TAP format". In other words, if a NanoTap
 * provider has an RSA public key as a TAP_RSAPublicKey, and needs to call a
 * function that will perform RSA encryption, yet does not want to implement RSA
 * in software, this is a function that can be called which will "convert" the
 * key data into NanoCrypto form, then call on NanoCrypto to execute the
 * encryption.
 * <p>This function will perform either PKCS #1 version 1.5 padding or OAEP
 * from PKCS #1 version 2  (see, for example, RFC 8017). OAEP stands for Optimal
 * Asymmetric Encryption Padding.
 * <p>The caller supplies the key and data to encrypt, the function will allocate
 * a buffer to hold the encrypted data and return it. It is the responsibility of
 * the caller to free that memory using DIGI_FREE (see mss/src/common/mstdlib.h).
 * <p>The caller can also supply a random object, as both PKCS 1.5 padding and
 * OAEP use random bytes. If no random object is provided, the function will use
 * the global random (created during the call to DIGICERT_initialize or
 * DIGICERT_initDigicert).
 * <p>The caller specifies which padding scheme to use with the PaddingScheme
 * argument. It must be either CT_RSA_PAD_PKCS_1_5 or CT_RSA_PAD_OAEP.
 * <p>If you choose OAEP, the function will use MGF1 and specified as the
 * PSource, but you must specify the OAEP digest and MGF1 digest, and you can
 * provide a "label" for the specified PSource. You set the oaepDigest and
 * mgfDigest args to one of the CT_DIGEST_ values (such as CT_DIGEST_SHA256). If
 * you have a label for the PSource, then pass it as the pLabel and labelLen
 * args.
 * <p>If you choose OAEP and want to use the default digest, MGF, and PSource,
 * then pass CT_DIGEST_SHA1 as the oaepDigest and mgfDigest, and NULL/0 as the
 * pLabel/labelLen.
 * <p>If you choose PKCS_1_5 as the padding scheme, there is no further
 * information needed and the oaepDigest, mgfDigest, pLabel, and labelLen args
 * are ignored.
 * <p>Note that if you choose OAEP, all digesting will be performed in software.
 * With this function, you do not have the option of using any other
 * implementation of the digest algorithms chosen.
 * <p>Note that the data to encrypt will have a maximum length. For PKCS 1
 * version 1.5, the max length is keyLen - 11. For example, with a 2048-bit key,
 * the keyLen is 256, so the max plaintext length is 245 bytes. For OAEP, the max
 * length is keyLen - ((2 * hLen) + 2) where hLen is the length of the
 * oaepDigest. For example, with a 2048-bit key and SHA-256, the max length is
 * 256 - ((2 * 32) + 2) = 256 - 66 = 190 bytes.
 *
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 *  + \c \__ENABLE_DIGICERT_SYM__
 *
 * @param [in]   pPubKey           Pointer to TAP_RSAPublicKey struct containing
 *                                 the RSA public key data used to encrypt.
 * @param [in]   pPlaintext        The data to encrypt.
 * @param [in]   plaintextLen      The length, in bytes, of the data to encrypt.
 * @param [in]   pRandom           A random object. If NULL, the function will
 *                                 use the global random.
 * @param [in]   PaddingScheme     Either CT_RSA_PAD_PKCS_1_5 or CT_RSA_PAD_OAEP.
 * @param [in]   oaepDigest        If using OAEP, this is the digest algorithm
 *                                 used by the OAEP operations, it must be one of
 *                                 the CT_DIGEST_ values. If you want to use the
 *                                 default, pass in CT_DIGEST_SHA1.
 * @param [in]   mgfDigest         If using OAEP, this is the digest algorithm
 *                                 used by the MGF1, it must be one of the
 *                                 CT_DIGEST_ values. If you want to use the
 *                                 default, pass in CT_DIGEST_SHA1.
 * @param [in]   pLabel            If using OAEP, this is an optional PSource.
 *                                 The default is NULL.
 * @param [in]   labelLen          The length, in bytes, of the pLabel. The
 *                                 default is 0.
 * @param [out]  ppCiphertext      The address where the function will deposit a
 *                                 pointer to allocated data containing the
 *                                 encrypted result. The caller must free this
 *                                 memory using DIGI_FREE.
 * @param [out]  pCiphertextLen    The address where the function will deposit
 *                                 the length, in bytes, of the ciphertext result.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 *
 * @memory On success, memory is allocated for ppCiphertest and must be freed by
 * calling DIGI_FREE.
 */
MOC_EXTERN MSTATUS CT_RsaPublicEncrypt (
  TAP_RSAPublicKey *pPubKey,
  ubyte *pPlaintext,
  ubyte4 plaintextLen,
  randomContext *pRandom,
  MCTRsaPad PaddingScheme,
  ubyte4 oaepDigest,
  ubyte4 mgfDigest,
  ubyte *pLabel,
  ubyte4 labelLen,
  ubyte **ppCiphertext,
  ubyte4 *pCiphertextLen
  );

/** @brief Perform RSA signature verification using a public key.
 * @details This function allows the caller to verify a signature using
 * NanoCrypto, yet also using an RSA public key in "TAP format". In other words,
 * if a NanoTap provider has an RSA public key as a TAP_RSAPublicKey, and needs
 * to call a function that will perform RSA verification, yet does not want to
 * implement RSA in software, this is a function that can be called which will
 * "convert" the key data into NanoCrypto form, then call on NanoCrypto to
 * execute the verification.
 * <p>This function will perform either PKCS #1 version 1.5 padding or PSS
 * from PKCS #1 version 2  (see, for example, RFC 8017). PSS stands for
 * Probabilistic Signing Scheme.
 * <p>The caller supplies the key, the digest of the data to verify (and a flag
 * indicateing which digest algorithm it is), and a pointer to a byteBoolean. The
 * function will determine if the signature is valid and will deposit the result
 * at the address of the byteBoolean.
 * <p>The caller specifies which padding scheme to use with the PaddingScheme
 * argument. It must be either CT_RSA_PAD_PKCS_1_5 or CT_RSA_PAD_PSS.
 * <p>If you choose PSS, the function will use MGF1, but you must specify the PSS
 * digest and MGF1 digest. You also specify the saltLen and trailerField. You set
 * the pssDigest and mgfDigest args to one of the CT_DIGEST_ values (such as
 * CT_DIGEST_SHA256).
 * <p>If you choose PSS and want to use the default digest, MGF, saltLen, and
 * trailer field, then pass CT_DIGEST_SHA1 as the pssDigest and mgfDigest,
 * CT_DEFAULT_SALT_LEN as the saltLen, and CT_DEFAULT_TRAILER_FIELD as the
 * trailerField.
 * <p>Note that the PSS standard specifies that the digest used to hash the data
 * to sign must be the same algorithm as the pssDigest. Almost all uses of PSS
 * will use the same digest algorithm for all purposes.
 * <p>Note that if you choose PSS, all digesting will be performed in software.
 * With this function, you do not have the option of using any other
 * implementation of the digest algorithms chosen.
 * <p>If you choose PKCS_1_5 as the padding scheme, there is no further
 * information needed and the pssDigest, mgfDigest, saltLen, and trailerField
 * args are ignored.
 * <p>Pass in the address of a byteBoolean, the function will go to that address
 * to deposit the result of the verification. If the signature verifies, the
 * function will deposit TRUE, otherwise it will deposit FALSE.
 * <p>Note that the return value is an error code, it is not the result of the
 * verification. If the function returns OK, it still might set *pIsSigValid to
 * FALSE. The function worked, it succeeded at what it set out to do, determine
 * if the signature was valid, which can be "no, it is not valid".
 *
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 *  + \c \__ENABLE_DIGICERT_SYM__
 * <p>This is not compiled if the following build flag is defined.
 *  + \c \__DISABLE_DIGICERT_RSA_VERIFY__
 *
 * @param [in]   pPubKey           Pointer to TAP_RSAPublicKey struct containing
 *                                 the RSA public key data used to verify.
 * @param [in]   pSignature        The data to verify. It should be the same
 *                                 length as the key (e.g. a 2048-bit key is 256
 *                                 bytes long and will generate a 256-byte
 *                                 signature.
 * @param [in]   signatureLen      The length, in bytes, of the signature.
 * @param [in]   digestAlgorithm   What algorithm was used to digest the data to
 *                                 sign. This will be one of the CT_DIGEST_
 *                                 values, such as CT_DIGEST_SHA256.
 * @param [in]   pDigest           The digest of the data to sign.
 * @param [in]   digestLen         The length, in bytes, of the digest of the
 *                                 data to sign.
 * @param [in]   PaddingScheme     Either CT_RSA_PAD_PKCS_1_5 or CT_RSA_PAD_PSS.
 * @param [in]   pssDigest         If using PSS, this is the digest algorithm
 *                                 used by the PSS operations, it must be one of
 *                                 the CT_DIGEST_ values. If you want to use the
 *                                 default, pass in CT_DIGEST_SHA1.
 * @param [in]   mgfDigest         If using PSS, this is the digest algorithm
 *                                 used by the MGF1, it must be one of the
 *                                 CT_DIGEST_ values. If you want to use the
 *                                 default, pass in CT_DIGEST_SHA1.
 * @param [in]   saltLen           If using PSS, this is the length of a salt
 *                                 value which is part of the padding. If you
 *                                 want to use the default, pass in
 *                                 CT_DEFAULT_SALT_LEN.
 * @param [in]   trailerField      The last byte of pad. If you want to use the
 *                                 default, pass in CT_DEFAULT_TRAILER_FIELD
 *                                 (this is the value specified in PKCS 1 version
 *                                 2 and the RFCs).
 * @param [out]  pIsSigValid       The address where the function will deposit
 *                                 the result of the verification, TRUE if the
 *                                 signature verifies, or FALSE otherwise.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CT_RsaVerifySignature (
  TAP_RSAPublicKey *pPubKey,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 digestAlgorithm,
  ubyte *pDigest,
  ubyte4 digestLen,
  MCTRsaPad PaddingScheme,
  ubyte4 pssDigest,
  ubyte4 mgfDigest,
  ubyte4 saltLen,
  ubyte4 trailerField,
  byteBoolean *pIsSigValid
  );

/** @brief Build an RSA Public MocAsymKey using the KeyOperator and key data given.
 * @details This function Builds a new MocAsymKey object using the KeyOperator
 * given. The key data is in the TAP_RSAPublicKey. This function will "convert"
 * that data into a format needed to build the object.
 * <p>The caller passes in the Operator needed. It might be the general RSA
 * software Operator, it might be an Operator that knows about RSA encryption or
 * verification only (e.g. no key pair gen capabilities).
 * <p>The caller passes in a pointer to an AsymmetricKey. This function assumes
 * the caller has initialized it already and will uninitialize it when done with
 * it.
 *
 * <p>This is compiled only if the following build flags are defined.
 *  + \c \__ENABLE_DIGICERT_TAP__
 *  + \c \__ENABLE_DIGICERT_ASYM_KEY__
 *
 * @param [in]      pPubKey           Pointer to TAP_RSAPublicKey struct
 *                                    containing the RSA public key data.
 * @param [in]      KeyOperator       The Operator the function will use to build
 *                                    the key object.
 * @param [in]      pOperatorInfo     The associated info to accompany the
 *                                    Operator.
 * @param [in,out]  pAsymPub          Pointer to initialized AsymmetricKey which
 *                                    the function will set using the key data
 *                                    and Operator.
 *
 * @return     \c OK (0) if successful; otherwise a negative number error code
 *             definition from merrors.h. To retrieve a string containing an
 *             English text error identifier corresponding to the function's
 *             returned error status, use the \c DISPLAY_ERROR macro.
 */
MOC_EXTERN MSTATUS CT_GetMocAsymRsaPubKeyFromTap (
  TAP_RSAPublicKey *pPubKey,
  MKeyOperator KeyOperator,
  void *pOperatorInfo,
  AsymmetricKey *pAsymPub
  );

/* Code shared by OAEP and PSS. This builds the AlgId and supportedSym array.
 * <p>This function assumes the args have been checked.
 */
MOC_EXTERN MSTATUS CT_OaepPssOp (
  ubyte4 variant,
  MCTAlgIdInputInfo *pInput,
  MCTAlgIdOutputInfo *pOutput
  );

/* We'll build a list of supported digest algorithms based on what is compiled.
 */
#define PAD_TAP_SHA_224_COUNT 0
#define PAD_TAP_SHA_224_OP
#define PAD_TAP_SHA_256_COUNT 0
#define PAD_TAP_SHA_256_OP
#define PAD_TAP_SHA_384_COUNT 0
#define PAD_TAP_SHA_384_OP
#define PAD_TAP_SHA_512_COUNT 0
#define PAD_TAP_SHA_512_OP

#if !defined(__DISABLE_DIGICERT_SHA224__)
#undef PAD_TAP_SHA_224_COUNT
#undef PAD_TAP_SHA_224_OP
#define PAD_TAP_SHA_224_COUNT 1
#define PAD_TAP_SHA_224_OP ,{ MSha224SwOperator, NULL }
#endif

#if !defined(__DISABLE_DIGICERT_SHA256__)
#undef PAD_TAP_SHA_256_COUNT
#undef PAD_TAP_SHA_256_OP
#define PAD_TAP_SHA_256_COUNT 1
#define PAD_TAP_SHA_256_OP ,{ MSha256SwOperator, NULL }
#endif

#if !defined(__DISABLE_DIGICERT_SHA384__)
#undef PAD_TAP_SHA_384_COUNT
#undef PAD_TAP_SHA_384_OP
#define PAD_TAP_SHA_384_COUNT 1
#define PAD_TAP_SHA_384_OP ,{ MSha384SwOperator, NULL }
#endif

#if !defined(__DISABLE_DIGICERT_SHA512__)
#undef PAD_TAP_SHA_512_COUNT
#undef PAD_TAP_SHA_512_OP
#define PAD_TAP_SHA_512_COUNT 1
#define PAD_TAP_SHA_512_OP ,{ MSha512SwOperator, NULL }
#endif

#define PAD_TAP_SUPPORTED_COUNT \
    1 + \
    PAD_TAP_SHA_224_COUNT + PAD_TAP_SHA_256_COUNT + \
    PAD_TAP_SHA_384_COUNT + PAD_TAP_SHA_512_COUNT

#define PAD_TAP_SUPPORTED_SYM \
    { MSha1SwOperator, NULL } \
    PAD_TAP_SHA_224_OP \
    PAD_TAP_SHA_256_OP \
    PAD_TAP_SHA_384_OP \
    PAD_TAP_SHA_512_OP

#endif /* __ENABLE_DIGICERT_TAP__ */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_TAP_HEADER__ */
