/**
 * @file  tap_data_protect.h
 *
 * @brief APIs for data protection and key derivation schemes.
 *
 * @filedoc tap_data_protect.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#ifndef __TAP_DATA_PROTECT_HEADER__
#define __TAP_DATA_PROTECT_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_TDP_KDF_NIST_CTR  0
#define MOC_TDP_KDF_NIST_FB   1
#define MOC_TDP_KDF_NIST_DP   2
#define MOC_TDP_KDF_HMAC      3
#define MOC_TDP_KDF_ANSI_X963 4

#define MOC_TDP_AES_128_CTR     0
#define MOC_TDP_AES_192_CTR     1
#define MOC_TDP_AES_256_CTR     2
#define MOC_TDP_AES_128_CBC     3
#define MOC_TDP_AES_192_CBC     4
#define MOC_TDP_AES_256_CBC     5
#define MOC_TDP_CHACHA20        6

#define MOC_TDP_HMAC_SHA256     0
/* 1 to 4 reserved for HMAC using SHA1 to SHA512 if later needed */
#define MOC_TDP_POLY1305        5
#define MOC_TDP_BLAKE2B         6
#define MOC_TDP_BLAKE2S         7

#define MOC_TDP_MAX_NUM_USES 127
#define MOC_TDP_SINGLE_REUSABLE_KEY 0

#define MOC_TDP_MIN_SEED_LEN 8
#define MOC_TDP_MAX_SEED_LEN 64

#ifndef MOC_TDP_FINGERPRINT_MAX_LEN
#define MOC_TDP_FINGERPRINT_MAX_LEN 64
#endif

#ifndef MOC_TDP_MAX_LABEL_LEN
#define MOC_TDP_MAX_LABEL_LEN 64
#endif

#ifndef MOC_TDP_HMAC_KEY_LEN
#define MOC_TDP_HMAC_KEY_LEN 32
#endif

#ifndef MOC_TDP_BLAKE2_KEY_LEN
#define MOC_TDP_BLAKE2_KEY_LEN 32
#endif

#ifndef MOC_TDP_BLAKE2_OUT_LEN
#define MOC_TDP_BLAKE2_OUT_LEN 32
#endif

#define MOC_TDP_POLY1305_OUT_LEN 16 /* no macro for it in poly1305.h */

#define MOC_TRP_MAX_ADD_DATA_LEN 255

/**
 * Structure that will hold one of the device's unique identifiers.
 * <p> pLabel is a C-style string containing the name of the identifier,
 *     for example "Serial Number".
 * <p> pValue is a byte array containing the value of the identifier.
 * <p> valueLen is the length of pValue in bytes.
 */
typedef struct
{
    sbyte pLabel[MOC_TDP_MAX_LABEL_LEN];
    ubyte pValue[MOC_TDP_FINGERPRINT_MAX_LEN];
    ubyte4 valueLen;

} FingerprintElement;

/**
 * Opaque structure defining a Fingerprint Context.
 */
typedef struct _FP_CTX FP_CTX;

/**
 * Context structure for use with the data protection streaming APIs.
 * <p> ctxType  The type of context, ie a cipher algorithm or mac algorithm.
 * <p> algoCtx  Pointer to the cipher or mac algorithm's context structure.
 * <p> pNextIv  Buffer to hold the next IV for CBC mode operations.
 * <p> The fingerprint context used for key generation.
 */
typedef struct {

    ubyte4 ctxType;
    BulkCtx algoCtx;
    ubyte pNextIv[16];
    FP_CTX *pFPctx;

} DP_STREAM_CTX;

/**
 * @brief Allocates and initializes a fingerprint context (\c FP_CTX).
 *
 * @details Allocates and initializes a fingerprint context (\c FP_CTX). Be sure to call
 *          \c TAP_DP_freeFingerprintCtx to zero and free the context when done.
 *
 * @param ppCtx    Pointer to the location that will recieve the new allocated context.
 * @param numUses  The number of times this context can be used to protect or unprotect data.
 *                 This is essentially the number of symmetric keys that will be generated and
 *                 each one may only be used once. However, if you instead wish to generate only
 *                 one symmetric key that can re-used as many times as you wish, set numUses to
 *                 MOC_TDP_SINGLE_REUSABLE_KEY.
 * @param additionalProtectionMode  Reserved for future usage.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_initFingerprintCtx(FP_CTX **ppCtx, ubyte4 numUses, ubyte additionalProtectionMode);

/**
 * @brief Generates key material from a device's fingerprint (ie unique identifiers).
 *
 * @details Generates key material from a device's fingerprint (ie unique identifiers).
 *
 * @param pCtx     Pointer to a previoulsy initialized \c FP_CTX.
 * @param kdfAlgo  The key derivation algorithm (KDF) to be used internally.
 *                 For non-export edition this can be any one of the macros
 *
 *                 MOC_TDP_KDF_NIST_CTR
 *                 MOC_TDP_KDF_NIST_FB
 *                 MOC_TDP_KDF_NIST_DP
 *                 MOC_TDP_KDF_HMAC
 *                 MOC_TDP_KDF_ANSI_X963
 *
 *                 For export edition this must be the macro MOC_TDP_KDF_HMAC.
 *
 * @param pElements       Pointer to an array of \c FingerprintElements uniquely identifying the device.
 * @param numElements     The number of elements in the pElements array. This must be at least one.
 * @param pInitialSeed    Byte array containing the initial seed to be used in the KDF scheme.
 * @param initialSeedLen  The length of pInitialSeed in bytes.
 * @param pAdditionalProtection  Pointer to a context reserved for future usage.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_FingerprintDevice(FP_CTX *pCtx, ubyte kdfAlgo, FingerprintElement *pElements, ubyte4 numElements,
                                         ubyte *pInitialSeed, ubyte4 initialSeedLen, void *pAdditionalProtection);

/**
 * @brief Protects data by encrypting it with a symmetric cipher and key material generated by
 *        a previous call to the \c TAP_DP_FingerprintDevice API.
 *
 * @details Protects data by encrypting it with a symmetric cipher and key material generated by
 *          a previous call to the \c TAP_DP_FingerprintDevice API. For each instance of an FP_CTX, if numUses is not
 *          set to MOC_TDP_SINGLE_REUSABLE_KEY, then you may only call \c TAP_DP_Encrypt and \c TAP_DP_Sign
 *          a combined number of times equal to \c numUses.
 *
 * @param pCtx     Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param symAlgo  The symmetric key algorithm and key strength to be used to encrypt the data.
 *                 This should be one of the macros
 *
 *                 MOC_TDP_AES_128_CTR
 *                 MOC_TDP_AES_192_CTR
 *                 MOC_TDP_AES_256_CTR
 *                 MOC_TDP_AES_128_CBC
 *                 MOC_TDP_AES_192_CBC
 *                 MOC_TDP_AES_256_CBC
 *                 MOC_TDP_CHACHA20
 *
 * @param pDataIn  The data to be encrypted as a byte array.
 * @param dataLen  The length of pDataIn in bytes. Some symmetric algorithms may put restrictions
 *                 on this length (for example AES-CBC requires this length to be a multiple of 16).
 * @param pDataOut Pointer to the location will hold the resulting protected data. There must be space
 *                 for dataLen bytes. In-place encryption, ie using the same location for pDataIn and
 *                 pDataOut, is allowed.
 * @param pOutLen  Will be set to the number of bytes actually written to the pDataOut buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_Encrypt(FP_CTX *pCtx, ubyte symAlgo, ubyte *pDataIn, ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen);

/**
 * @brief Recovers protected data by decrypting it with a symmetric cipher and key material generated by
 *        a previous call to the \c TAP_DP_FingerprintDevice API.
 *
 * @details Recovers protected data by decrypting it with a symmetric cipher and key material generated by
 *          a previous call to the \c TAP_DP_FingerprintDevice API. For each instance of an FP_CTX, if numUses is not
 *          set to MOC_TDP_SINGLE_REUSABLE_KEY, then you may only call \c TAP_DP_Decrypt and \c TAP_DP_Verify
 *          a combined number of times equal to \c numUses.
 *
 * @warning        For numUses not equal to MOC_TDP_SINGLE_REUSABLE_KEY, multiple calls to
 *                 \c TAP_DP_Decrypt and \c TAP_DP_Verify must ordered in the same manner as when data
 *                 protection was done via \c TAP_DP_Encrypt and \c TAP_DP_Sign respectively. This is
 *                 to ensure that the generated symmetric keys are used in the correct order.
 *
 * @param pCtx     Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param symAlgo  The symmetric key algorithm and key strength to be used to decrypt the data.
 *                 This should be one of the macros
 *
 *                 MOC_TDP_AES_128_CTR
 *                 MOC_TDP_AES_192_CTR
 *                 MOC_TDP_AES_256_CTR
 *                 MOC_TDP_AES_128_CBC
 *                 MOC_TDP_AES_192_CBC
 *                 MOC_TDP_AES_256_CBC
 *                 MOC_TDP_CHACHA20
 *
 * @param pDataIn  The data to be decrypted as a byte array.
 * @param dataLen  The length of pDataIn in bytes. Some symmetric algorithms may put restrictions
 *                 on this length (for example AES-CBC requires this length to be a multiple of 16).
 * @param pDataOut Pointer to the location will hold the resulting unprotected data. There must be space
 *                 for dataLen bytes. In-place decryption, ie using the same location for pDataIn and
 *                 pDataOut, is allowed.
 * @param pOutLen  Will be set to the number of bytes actually written to the pDataOut buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_Decrypt(FP_CTX *pCtx, ubyte symAlgo, ubyte *pDataIn, ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen);

/**
 * @brief Signs data using the specified symmetric key mac algorithm.
 *
 * @details Signs data using the specified symmetric key mac algorithm. The symmetric key must have been
 *          previously generated by the \c TAP_DP_FingerprintDevice API. For each instance of an FP_CTX, if numUses is not
 *          set to MOC_TDP_SINGLE_REUSABLE_KEY, then you may only call \c TAP_DP_Encrypt and \c TAP_DP_Sign
 *          a combined number of times equal to \c numUses.
 *
 * @param pCtx     Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param macAlgo  The mac algorithm to be used to sign the data. This should be one of the
 *                 following macros. Note the mac algorithm must also be enabled at buildtime.
 *
 *                 MOC_TDP_HMAC_SHA256
 *                 MOC_TDP_POLY1305
 *                 MOC_TDP_BLAKE2B
 *                 MOC_TDP_BLAKE2S
 *
 * @param pData           The data to be signed as a byte array.
 * @param dataLen         The length of pData in bytes.
 * @param pAdditionalData Optional buffer of additional data. This data will included in the signature processing
 *                        and can be recovered from the signature via the \c TAP_DP_ExtractAdditionalData API.
 * @param addDataLen      The length of pAdditionalData in bytes. This can be no bigger than 255.
 * @param pSig            Pointer to the location will hold the resulting signature.
 * @param pSigLen         Will be set to the number of bytes actually written to the pSig buffer, or if pSig is
 *                        NULL this will be set to the number of bytes needed for the pSig buffer.
 *
 * @return           \c OK (0) if successful, otherwise a negative number error
 *                   code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_Sign(FP_CTX *pCtx, ubyte macAlgo, ubyte *pData, ubyte4 dataLen, ubyte *pAdditionalData, ubyte4 addDataLen, ubyte *pSig, ubyte4 *pSigLen);

/**
 * @brief Verifies data using the specified symmetric key mac algorithm.
 *
 * @details Verifies data using the specified symmetric key mac algorithm. The symmetric key must have been
 *          previously generated by the \c TAP_DP_FingerprintDevice API. For each instance of an FP_CTX, if numUses is not
 *          set to MOC_TDP_SINGLE_REUSABLE_KEY, then you may only call \c TAP_DP_Decrypt and \c TAP_DP_Verify
 *          a combined number of times equal to \c numUses.
 *
 * @warning        For numUses not equal to MOC_TDP_SINGLE_REUSABLE_KEY, multiple calls to
 *                 \c TAP_DP_Decrypt and \c TAP_DP_Verify must ordered in the same manner as when data
 *                 protection was done via \c TAP_DP_Encrypt and \c TAP_DP_Sign respectively. This is
 *                 to ensure that the generated symmetric keys are used in the correct order.
 *
 * @param pCtx     Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param macAlgo  The mac algorithm to be used to verify the data. This should be one of the
 *                 following macros. Note the mac algorithm must also be enabled at buildtime.
 *
 *                 MOC_TDP_HMAC_SHA256
 *                 MOC_TDP_POLY1305
 *                 MOC_TDP_BLAKE2B
 *                 MOC_TDP_BLAKE2S
 *
 * @param pData         The data to be verified as a byte array.
 * @param dataLen       The length of pData in bytes.
 * @param pSig          The signature to be verified.
 * @param sigLen        The length of pSig in bytes.
 * @param pVerifyStatus Contents will be set to the verification status. This is 0 for a valid signature and non-zero for an
 *                      invalid signature.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 *
 * @warning        Make sure to check both a return status of OK and a pVerifyStatus of 0 before accepting
 *                 that a signature is valid.
 */
MOC_EXTERN MSTATUS TAP_DP_Verify(FP_CTX *pCtx, ubyte macAlgo, ubyte *pData, ubyte4 dataLen, ubyte *pSig, ubyte4 sigLen, ubyte4 *pVerifyStatus);

/**
 * @brief Extracts the additional data that was used as input to the \c TAP_DP_Sign routine.
 *
 * @details Validates a signature is of the correct form and extracts the additional data
 *          that was used as input to the \c TAP_DP_Sign routine.
 *
 * @param pSig             Pointer to the signature from which the additional data will be extracted.
 * @param sigLen           The length of the pSig buffer in bytes.
 * @param ppAdditionalData Location that will hold the newly allocated buffer of additional data. Be
 *                         sure to free this buffer when done with it.
 * @param pAddDataLen      Will be set to the number of bytes of additional data.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_ExtractAdditionalData(ubyte *pSig, ubyte4 sigLen, ubyte **ppAdditionalData, ubyte4 *pAddDataLen);

/**
 * @brief Zeros and frees a previously initialized fingerprint context (\c FP_CTX).
 *
 * @details Zeros and frees a previously initialized fingerprint context (\c FP_CTX).
 *
 * @param ppCtx    Pointer to the location that contains the context to be freed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_freeFingerprintCtx(FP_CTX **ppCtx);

/**
 * @brief   Initializes a stream context for a cipher algorithm for encryption or decryption.
 *
 * @details Initializes a stream context for a cipher algorithm for encryption or decryption.
 *          This method allocates memory for an internal cipher context so be sure to call
 *          \c TAP_DP_streamFinal to free such memory.
 *
 * @param pCtx     Pointer to the The context to be initialized.
 * @param pFPctx   Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param symAlgo  The symmetric key algorithm and key strength to be used to encrypt the data.
 *                 This should be one of the macros
 *
 *                 MOC_TDP_AES_128_CTR
 *                 MOC_TDP_AES_192_CTR
 *                 MOC_TDP_AES_256_CTR
 *                 MOC_TDP_AES_128_CBC
 *                 MOC_TDP_AES_192_CBC
 *                 MOC_TDP_AES_256_CBC
 *                 MOC_TDP_CHACHA20
 *
 * @param encrypt  Enter TRUE (or nonzero) to initialize the stream context for encryption.
 *                 Enter FALSE (or zero) to initialize the stream context for decryption.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_streamInitCipher(DP_STREAM_CTX *pCtx, FP_CTX *pFPctx, ubyte symAlgo, sbyte4 encrypt);

/**
 * @brief   Initializes a stream context for a mac algorithm for signature generation or verification.
 *
 * @details Initializes a stream context for a mac algorithm for signature generation or verification.
 *          This method allocates memory for an internal cipher context so be sure to call
 *          \c TAP_DP_streamFinal or \c TAP_DP_verifyFinal to free such memory.
 *
 * @param pCtx     Pointer to the The context to be initialized.
 * @param pFPctx   Pointer to a \c FP_CTX that has been initialized and device fingerprinted.
 * @param macAlgo  The mac algorithm to be used. This should be one of the
 *                 following macros. Note the mac algorithm must also be enabled at buildtime.
 *
 *                 MOC_TDP_HMAC_SHA256
 *                 MOC_TDP_POLY1305
 *                 MOC_TDP_BLAKE2B
 *                 MOC_TDP_BLAKE2S
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_streamInitMac(DP_STREAM_CTX *pCtx, FP_CTX *pFPctx, ubyte macAlgo);

/**
 * @brief   Updates a stream context with data.
 *
 * @details Updates a stream context with data. If the context is for encryption or decryption
 *          This will encrypt or decrypt the data. If the context is for a mac algorithm this
 *          will update the inner mac context.
 *
 * @param pCtx     Pointer to a previously initialized context.
 * @param pDataIn  Buffer holding the input data.
 * @param dataLen  The length of the input data in bytes. Some ciphers (AES-CBC for example) may
 *                 restrict this length to a multiple of the blocksize.
 * @param pDataOut Buffer to hold the resulting output. This should be NULL for a mac algorithm context.
 *                 This must be the same size as the \c pDataIn buffer, and may be the same buffer
 *                 as pDataIn for inplace encryption or decryption.
 * @param pDataOutLen  Contents will be set to the number of bytes actually written to the pDataOut buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_streamUpdate(DP_STREAM_CTX *pCtx, ubyte *pDataIn, ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pDataOutLen);

/**
 * @brief   Finalizes a stream context and outputs any remaining results.
 *
 * @details Finalizes a stream context. This will output the resulting MAC for a context initialized
 *          with a mac algorithm.
 *
 * @param pCtx            Pointer to a previously initialized and updated context.
 * @param pAdditionalData Optional buffer of additional data. This data will included in the signature processing
 *                        and can be recovered from the signature via the \c TAP_DP_ExtractAdditionalData API.
 *                        This should be NULL if the context is for an encryption or decryption algorithm.
 * @param addDataLen      The length of pAdditionalData in bytes. This can be no bigger than 255.
 * @param pDataOut        Buffer to hold the resulting output. This should be NULL for a cipher algorithm context
 *                        and must be non-NULL for a mac algorithm context.
 * @param pDataOutLen     Contents will be set to the number of bytes actually written to the pDataOut buffer.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_streamFinal(DP_STREAM_CTX *pCtx, ubyte *pAdditionalData, ubyte4 addDataLen, ubyte *pDataOut, ubyte4 *pDataOutLen);

/**
 * @brief   Finalizes a stream context to verify a signature.
 *
 * @details Finalizes a stream context to verify a signature.
 *
 * @param pCtx            Pointer to a previously initialized and updated context.
 * @param pSig            Pointer to the signature to be verified.
 * @param sigLen          The length of the signature in bytes.
 * @param pVerifyStatus   Contents will be set to the verification status. This is 0 for a valid signature and non-zero for an
 *                        invalid signature.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MOC_EXTERN MSTATUS TAP_DP_verifyFinal(DP_STREAM_CTX *pCtx, ubyte *pSig, ubyte4 sigLen, ubyte4 *pVerifyStatus);

#ifdef __cplusplus
}
#endif

#endif /* __TAP_DATA_PROTECT_HEADER__ */
