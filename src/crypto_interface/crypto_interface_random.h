/*
 * crypto_interface_random.h
 *
 * Cryptographic Interface header file for declaring RANDOM functions
 * for the Crypto Interface.
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
@file       crypto_interface_random.h
@brief      Cryptographic Interface header file for declaring RANDOM functions.
@details    Add details here.

@filedoc    crypto_interface_random.h
*/
#ifndef __CRYPTO_INTERFACE_RANDOM_HEADER__
#define __CRYPTO_INTERFACE_RANDOM_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/** This function is used to register a function pointer for entropy collection.
 * Random operators frequently prefer (or are bound by their APIs) to use a
 * function pointer for collection entropy. After registration, the callback
 * will be used to perform the initial seeding upon a call to
 * CRYPTO_INTERFACE_RANDOM_acquireContextEx. It should be noted this function
 * is not thread safe. Make sure to register any entropy functions before a
 * call to CRYPTO_INTERFACE_RANDOM_acquireContextEx. If you would like the
 * global rng to use this for entropy, you must register it before the call
 * to MOCANA_initialize.
 *
 * @param EntropyFunc Function pointer to be used to collect entropy for the
 *                    initial seeding of a random object.
 * @param entropyLen  Number of bytes of entropy to collect for each call, must
 *                    be greater than the security strength of the underlying
 *                    block cipher.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_registerEntropyFunc (
  MGetEntropyFunc EntropyFunc,
  ubyte4 entropyLen
  );

/** This function is used to register a function pointer for retrieving the
 * personalization string. After registration, the callback will be used as
 * input to the initial seeding upon a call to
 * CRYPTO_INTERFACE_RANDOM_acquireContextEx. It should be noted this function
 * is not thred safe. Make sure to register any callback functions before a
 * call to CRYPTO_INTERFACE_RANDOM_acquireContextEx. If you would like the
 * global rng to use this for entropy, you must register it before the call
 * to MOCANA_initialize.
 *
 * @param GetPersoStr Function pointer to be used to retrieve the personalization
 *                    string for use in the initial seeding of a random object.
 *
 * @return            \c OK (0) if successful; otherwise a negative number
 *                    error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_regsterGetPersoStrCallback (
  MGetPersoStrCallback GetPersoStr
  );

/** This function unregisters and sets registered functions back to defaults. 
 * This includes those registered by \c CRYPTO_INTERFACE_registerEntropyFunc
   \c CRYPTO_INTERFACE_regsterGetPersoStrCallback and the entropy length.
*/
MOC_EXTERN void CRYPTO_INTERFACE_unregisterFuncs (void);

/** This function is used to acquire an AES based CTR-DRBG random context. Any
 * function pointers registered will be invoked during this call to retrieve the
 * entropy and personalization string. If they have not been registered then the
 * mocana defaults are used. The key length to use will be the Mocana default value
 * of NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES.
 *
 * @param ppRandomContext Pointer to the location that will recieve the newly
 *                        allocated random context.
 * @param algoId          Must be MODE_DRBG_CTR to recieve a crypto interface DRBG.
 *
 * @return                \c OK (0) if successful; otherwise a negative number
 *                        error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_acquireContextEx (
  randomContext **ppRandomContext,
  ubyte algoId
  );

/** This function is used to release and free a random context previously
 * created using CRYPTO_INTERFACE_RANDOM_acquireContextEx.
 *
 * @param pp_randomContext Pointer to the random context being freed.
 *
 * @return                 \c OK (0) if successful; otherwise a negative number
 *                         error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_releaseContextEx (
  randomContext **pp_randomContext
  );

/** This function is used to add individual bits of entropy into the
 * entropy pool. Note the bits do not get added exactly as is, the pool
 * gets continously stirred so this should not be used for vector tests.
 * Once enough bits have been added to make a full seed, the pool will
 * be extracted into a buffer and provided to the random object as a
 * reseed request.
 *
 * @param pRandomContext Pointer to the random context to be reseeded.
 * @param entropyBit     The entropy bit to be added to the pool.
 *
 * @return                 \c OK (0) if successful; otherwise a negative number
 *                         error code definition from merrors.h.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_addEntropyBitEx (
  randomContext *pRandomContext,
  ubyte entropyBit
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RANDOM_HEADER__ */