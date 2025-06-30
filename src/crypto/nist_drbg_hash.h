/*
 * nist_drbg_hash.h
 *
 * Implementation of the RNGs described in NIST 800-90
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
 * @file       nist_drbg_hash.h
 *
 * @brief      Header file for the NanoCrypto NIST Deterministic Random Bit Generator.
 *
 * @details    Header file for the NanoCrypto NIST Deterministic Random Bit Generator.
 *
 * @flags      To enable this file's methods define the following flag:
 *             + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @filedoc    nist_drbg_hash.h
 */

/*------------------------------------------------------------------*/

#ifndef __NIST_DRBG_HASH_HEADER__
#define __NIST_DRBG_HASH_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/hw_accel.h"
#include "../common/mrtos.h"

/* Value from NIST SP800-90A 10.1 Table 2 */
#define MOCANA_HASH_DRBG_MAX_SEED_LEN_BITS 888
#define MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES (MOCANA_HASH_DRBG_MAX_SEED_LEN_BITS/8)

#include "../cap/capdecl.h"

#if defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
#include "../crypto_interface/crypto_interface_nist_drbg_hash_priv.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief       Function pointer type for a method that hashes input data in one shot.
 *
 * @details     Function pointer type for a method that hashes input data in one shot.
 *
 * @inc_file    nist_drbg_hash.h
 *
 * @param pInput    Buffer holding the input data.
 * @param inputLen  The length of the input data in bytes.
 * @param pOutput   Buffer to hold the resulting output.
 *
 * @flags       To enable this method define the following flag:
 *              + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return      Must return \c OK (0) if successful and non-zero if unsuccessful.
 *
 * @callbackdoc nist_drbg_hash.h
 */
typedef MSTATUS (*DrbgHashMethod)(ubyte *pInput, ubyte4 inputLen, ubyte *pOutput);

typedef struct NIST_HASH_DRBG_Ctx
{
    DrbgHashMethod hashMethod;
    RTOS_MUTEX pMutex;
    ubyte4 hashOutLen;
    ubyte4 seedLenBytes;
    ubyte4 securityStrengthBytes;
    ubyte pV[MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES + 1];
    ubyte pC[MOCANA_HASH_DRBG_MAX_SEED_LEN_BYTES + 1];
    ubyte pReseedCtr[8];
    MocSymCtx pMocSymCtx;
    ubyte enabled;
        
} NIST_HASH_DRBG_Ctx;
    
/*------------------------------------------------------------------*/

/**
 * @brief   Allocates and seeds a new hash drbg context.
 *
 * @details Allocates and seeds a new hash drbg context. Please be sure
 *          to call \c NIST_HASHDRBG_deleteContext to free this context when
 *          done with it.
 *
 * @param ppNewContext        Pointer to the location that will receive the newly allocated and seeded context.
 * @param pEntropyInput       Buffer of input entropy (also known as the seed).
 * @param entropyInputLen     The length of the input entropy in bytes.
 * @param pNonce              Optional. Buffer holding the nonce as a byte array.
 * @param nonceLen            The length of the nonce in bytes.
 * @param pPersonalization    Optional. Buffer holding the personalization data as a byte array.
 * @param personalizationLen  The length of the personalization data in bytes.
 * @param hashMethod          Function pointer to the hashing method to be used.
 * @param hashOutLenBytes     The output length of the hashMethod chosen.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN MSTATUS NIST_HASHDRBG_newSeededContext(MOC_SYM(hwAccelDescr hwAccelCtx)
                            NIST_HASH_DRBG_Ctx **ppNewContext,
                            ubyte *pEntropyInput,
                            ubyte4 entropyInputLen,
                            ubyte *pNonce,
                            ubyte4 nonceLen,
                            ubyte *pPersonalization,
                            ubyte4 personalizationLen,
                            DrbgHashMethod hashMethod,
                            ubyte4 hashOutLenBytes);

/**
 * @brief   Deletes a hash drbg context.
 *
 * @details Zeroes and frees memory allocated for a hash drbg context.
 *
 * @param ppContext   Pointer to the location of the context to be deleted.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN MSTATUS NIST_HASHDRBG_deleteContext( MOC_SYM(hwAccelDescr hwAccelCtx)
                            NIST_HASH_DRBG_Ctx **ppContext);

/**
 * @brief   Reseeds a previously existing hash drbg context.
 *
 * @details Reseeds a previously existing hash drbg context.
 *
 * @param pContext            Pointer to the context to be reseeded.
 * @param pEntropyInput       Buffer of input entropy (also known as the seed).
 * @param entropyInputLen     The length of the input entropy in bytes.
 * @param pAdditionalInput    Optional. Buffer holding additional input data as a byte array.
 * @param additionalInputLen  The length of the additional input data in bytes.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN MSTATUS NIST_HASHDRBG_reSeed(MOC_SYM(hwAccelDescr hwAccelCtx)
                            NIST_HASH_DRBG_Ctx *pContext,
                            ubyte *pEntropyInput,
                            ubyte4 entropyInputLen,
                            ubyte *pAdditionalInput,
                            ubyte4 additionalInputLen);

/**
 * @brief   Generates deterministic bits from a seeded drbg hash context with
 *          an additional data input option.
 *
 * @details Generates deterministic bits from a seeded drbg hash context with
 *          an additional data input option. The number of bits requested and
 *          output will actually be measured in bytes.
 *
 * @param pContext            Pointer to a previously seeded context.
 * @param pAdditionalInput    Optional. Buffer holding additional input data as a byte array.
 * @param additionalInputLen  The length of the additional input data in bytes.
 * @param pOutput             Buffer to hold the resulting output bytes.
 * @param outputLenBytes      The number of output bytes requested.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN MSTATUS NIST_HASHDRBG_generate(MOC_SYM(hwAccelDescr hwAccelCtx)
                            NIST_HASH_DRBG_Ctx *pContext,
                            ubyte *pAdditionalInput,
                            ubyte4 additionalInputLen,
                            ubyte *pOutput,
                            ubyte4 outputLenBytes);

/**
 * @brief   Generates deterministic bits from a seeded drbg hash context.
 *
 * @details Generates deterministic bits from a seeded drbg hash context. The
 *          number of bits requested and output will actually be measured in bytes.
 *          For generating bits from additional input use \c NIST_HASHDRBG_generate
 *          instead.
 *
 * @param pContext            Pointer to a previously seeded context.
 * @param pOutput             Buffer to hold the resulting output bytes.
 * @param outputLenBytes      The number of output bytes requested.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN MSTATUS NIST_HASHDRBG_numberGenerator(MOC_SYM(hwAccelDescr hwAccelCtx)
                            NIST_HASH_DRBG_Ctx *pRandomContext,
                            ubyte *pBuffer,
                            sbyte4 bufferLen);

/**
 * @brief   Generates deterministic bits in an \c RNGFun function pointer form.
 *
 * @details Generates deterministic bits in an \c RNGFun function pointer form.
 *          Please see random.h for a description of this form. The
 *          number of bits requested and output will actually be measured in bytes.
 *
 * @param pRngFunArg      Pointer to a previously seeded hash drbg context.
 * @param length          The number of output bytes requested.
 * @param pBuffer         Buffer to hold the resulting output bytes.
 *
 * @flags   To enable this method define the following flag:
 *          + \c \__ENABLE_MOCANA_NIST_DRBG_HASH__
 *
 * @return  \c OK (0) if successful; otherwise a negative number error code
 *          definition from merrors.h.
 *
 * @funcdoc nist_drbg_hash.h
 */
MOC_EXTERN sbyte4 NIST_HASHDRBG_rngFun(MOC_SYM(hwAccelDescr hwAccelCtx)
                            void *pRngFunArg,
                            ubyte4 length, ubyte *pBuffer);

    
#ifdef __cplusplus
}
#endif

#endif /* __NIST_DRBG_HASH_HEADER__ */

