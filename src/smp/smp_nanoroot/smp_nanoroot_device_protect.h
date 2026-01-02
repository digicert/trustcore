/*
 * smp_nanoroot_device_protect.h
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


#ifndef __SMP_NanoROOT_DEVICE_PROTECT_HEADER__
#define __SMP_NanoROOT_DEVICE_PROTECT_HEADER__

#if (defined (__ENABLE_MOCANA_SMP__) && defined (__ENABLE_MOCANA_SMP_NANOROOT__))

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"

#define NanoROOTKDF_NIST_CTR  0
#define NanoROOTKDF_NIST_FB   1
#define NanoROOTKDF_NIST_DP   2
#define NanoROOTKDF_HMAC      3
#define NanoROOTKDF_ANSI_X963 4

#define NanoROOTAES_128_CTR     0
#define NanoROOTAES_192_CTR     1
#define NanoROOTAES_256_CTR     2
#define NanoROOTAES_128_CBC     3
#define NanoROOTAES_192_CBC     4
#define NanoROOTAES_256_CBC     5
#define NanoROOTCHACHA20        6

#define NanoROOTHMAC_SHA256     0
/* 1 to 4 reserved for HMAC using SHA1 to SHA512 if later needed */
#define NanoROOTPOLY1305        5
#define NanoROOTBLAKE2B         6
#define NanoROOTBLAKE2S         7

#define NanoROOTMAX_NUM_USES 127
#define NanoROOTSINGLE_REUSABLE_KEY 0

#define NanoROOTMIN_SEED_LEN 8
#define NanoROOTMAX_SEED_LEN 64

#ifndef NanoROOT_MAX_VALUE_LEN
#define NanoROOT_MAX_VALUE_LEN 256
#endif

#ifndef NanoROOT_MAX_LABEL_LEN
#define NanoROOT_MAX_LABEL_LEN 256
#endif

#ifndef NanoROOTHMAC_KEY_LEN
#define NanoROOTHMAC_KEY_LEN 32
#endif

#ifndef NanoROOTBLAKE2_KEY_LEN
#define NanoROOTBLAKE2_KEY_LEN 32
#endif

#ifndef NanoROOTBLAKE2_OUT_LEN
#define NanoROOTBLAKE2_OUT_LEN 32
#endif

#define NanoROOTPOLY1305_OUT_LEN 16 /* no macro for it in poly1305.h */

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
    sbyte pLabel[NanoROOT_MAX_LABEL_LEN];
    ubyte4 labelLen;
    ubyte pValue[NanoROOT_MAX_VALUE_LEN];
    ubyte4 valueLen;
} NROOTKdfElement;

typedef signed int hwAccelDescr;

/**
 * Opaque structure defining a Fingerprint Context.
 */
typedef struct _NROOT_FP_CTX
{
    ubyte *pRunningSeed;
    ubyte *pKeyMaterial;
    ubyte4 numUses;
    ubyte4 usesSoFar;
    ubyte state;
    byteBoolean reusableKey;
    hwAccelDescr hwAccelCtx;

} _NROOT_FP_CTX;

typedef struct _NROOT_FP_CTX NROOT_FP_CTX;

/**
 * @brief Allocates and initializes a fingerprint context (\c NROOT_FP_CTX).
 *
 * @details Allocates and initializes a fingerprint context (\c NROOT_FP_CTX). Be sure to call
 *          \c NanoROOT_freeFingerprintCtx to zero and free the context when done.
 *
 * @param ppCtx    Pointer to the location that will recieve the new allocated context.
 * @param numUses  The number of times this context can be used to protect or unprotect data.
 *                 This is essentially the number of symmetric keys that will be generated and
 *                 each one may only be used once. However, if you instead wish to generate only
 *                 one symmetric key that can re-used as many times as you wish, set numUses to
 *                 NanoROOTSINGLE_REUSABLE_KEY.
 * @param additionalProtectionMode  Reserved for future usage.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MSTATUS NanoROOT_initFingerprintCtx(NROOT_FP_CTX **ppCtx, ubyte4 numUses, ubyte additionalProtectionMode);

/**
 * @brief Generates key material from a device's fingerprint (ie unique identifiers).
 *
 * @details Generates key material from a device's fingerprint (ie unique identifiers).
 *
 * @param pCtx     Pointer to a previoulsy initialized \c NROOT_FP_CTX.
 * @param kdfAlgo  The key derivation algorithm (KDF) to be used internally.
 *                 For non-export edition this can be any one of the macros
 *
 *                 NanoROOTKDF_NIST_CTR
 *                 NanoROOTKDF_NIST_FB
 *                 NanoROOTKDF_NIST_DP
 *                 NanoROOTKDF_HMAC
 *                 NanoROOTKDF_ANSI_X963
 *
 *                 For export edition this must be the macro NanoROOTKDF_HMAC.
 *
 * @param pElements       Pointer to an array of \c NROOTKdfElements uniquely identifying the device.
 * @param numElements     The number of elements in the pElements array. This must be at least one.
 * @param pInitialSeed    Byte array containing the initial seed to be used in the KDF scheme.
 * @param initialSeedLen  The length of pInitialSeed in bytes.
 * @param pAdditionalProtection  Pointer to a context reserved for future usage.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MSTATUS NanoROOT_FingerprintDevice(NROOT_FP_CTX *pCtx, ubyte kdfAlgo, NROOTKdfElement *pElements, ubyte4 numElements,
                                         ubyte *pInitialSeed, ubyte4 initialSeedLen, void *pAdditionalProtection);

/**
 * @brief Protects data by encrypting it with a symmetric cipher and key material generated by
 *        a previous call to the \c NanoROOT_FingerprintDevice API.
 *
 * @details Protects data by encrypting it with a symmetric cipher and key material generated by
 *          a previous call to the \c NanoROOT_FingerprintDevice API. For each instance of an NROOT_FP_CTX, if numUses is not
 *          set to NanoROOTSINGLE_REUSABLE_KEY, then you may only call \c NanoROOT_Encrypt and \c NanoROOT_Sign
 *          a combined number of times equal to \c numUses.
 *
 * @param pCtx     Pointer to a \c NROOT_FP_CTX that has been initialized and device fingerprinted.
 * @param symAlgo  The symmetric key algorithm and key strength to be used to encrypt the data.
 *                 This should be one of the macros
 *
 *                 NanoROOTAES_128_CTR
 *                 NanoROOTAES_192_CTR
 *                 NanoROOTAES_256_CTR
 *                 NanoROOTAES_128_CBC
 *                 NanoROOTAES_192_CBC
 *                 NanoROOTAES_256_CBC
 *                 NanoROOTCHACHA20
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
MSTATUS NanoROOT_Encrypt(NROOT_FP_CTX *pCtx, ubyte symAlgo, ubyte *pCredData, ubyte4 credLen, ubyte *pDataIn,
                            ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen);

/**
 * @brief Recovers protected data by decrypting it with a symmetric cipher and key material generated by
 *        a previous call to the \c NanoROOT_FingerprintDevice API.
 *
 * @details Recovers protected data by decrypting it with a symmetric cipher and key material generated by
 *          a previous call to the \c NanoROOT_FingerprintDevice API. For each instance of an NROOT_FP_CTX, if numUses is not
 *          set to NanoROOTSINGLE_REUSABLE_KEY, then you may only call \c NanoROOT_Decrypt and \c NanoROOT_Verify
 *          a combined number of times equal to \c numUses.
 *
 * @warning        For numUses not equal to NanoROOTSINGLE_REUSABLE_KEY, multiple calls to
 *                 \c NanoROOT_Decrypt and \c NanoROOT_Verify must ordered in the same manner as when data
 *                 protection was done via \c NanoROOT_Encrypt and \c NanoROOT_Sign respectively. This is
 *                 to ensure that the generated symmetric keys are used in the correct order.
 *
 * @param pCtx     Pointer to a \c NROOT_FP_CTX that has been initialized and device fingerprinted.
 * @param symAlgo  The symmetric key algorithm and key strength to be used to decrypt the data.
 *                 This should be one of the macros
 *
 *                 NanoROOTAES_128_CTR
 *                 NanoROOTAES_192_CTR
 *                 NanoROOTAES_256_CTR
 *                 NanoROOTAES_128_CBC
 *                 NanoROOTAES_192_CBC
 *                 NanoROOTAES_256_CBC
 *                 NanoROOTCHACHA20
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
MSTATUS NanoROOT_Decrypt(NROOT_FP_CTX *pCtx, ubyte symAlgo, ubyte *pCredData, ubyte4 credLen, ubyte *pDataIn,
                            ubyte4 dataLen, ubyte *pDataOut, ubyte4 *pOutLen);

/**
 * @brief Zeros and frees a previously initialized fingerprint context (\c NROOT_FP_CTX).
 *
 * @details Zeros and frees a previously initialized fingerprint context (\c NROOT_FP_CTX).
 *
 * @param ppCtx    Pointer to the location that contains the context to be freed.
 *
 * @return         \c OK (0) if successful, otherwise a negative number error
 *                 code from merrors.h
 */
MSTATUS NanoROOT_freeFingerprintCtx(NROOT_FP_CTX **ppCtx);

#endif /* __ENABLE_MOCANA_SMP__ && __ENABLE_MOCANA_SMP_NANOROOT__ */

#endif /* __SMP_NanoROOT_DEVICE_PROTECT_HEADER__ */
