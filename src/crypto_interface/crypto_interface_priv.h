 /*
 * crypto_interface_priv.h
 *
 * Private declarations and definitions for the
 * Mocana Cryptographic Interface
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
@file       crypto_interface_priv.h
@brief      Private declarations and definitions for the Mocana Cryptographic Interface.
@details    Add details here.

@filedoc    crypto_interface_priv.h
*/
#ifndef __DIGICERT_CRYPTO_INTERFACE_PRIV_HEADER__
#define __DIGICERT_CRYPTO_INTERFACE_PRIV_HEADER__

#include "../common/initmocana.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_INTERFACE_ALGO_DISABLED    0
#define CRYPTO_INTERFACE_ALGO_ENABLED     1

/*----------------------------------------------------------------------------*/

/* An enum list associating each algorithm with a particular index */
typedef enum {
  moc_alg_md2          = 0,
  moc_alg_md4          = 1,
  moc_alg_md5          = 2,
  moc_alg_sha1         = 3,
  moc_alg_sha224       = 4,
  moc_alg_sha256       = 5,
  moc_alg_sha384       = 6,
  moc_alg_sha512       = 7,
  moc_alg_aes          = 8,
  moc_alg_aes_ecb      = 9,
  moc_alg_aes_cbc      = 10,
  moc_alg_aes_cfb      = 11,
  moc_alg_aes_cfb1     = 12,
  moc_alg_aes_ofb      = 13,
  moc_alg_aes_ctr      = 14,
  moc_alg_aes_gcm      = 15,
  moc_alg_aes_ccm      = 16,
  moc_alg_aes_xts      = 17,
  moc_alg_aes_eax      = 18,
  moc_alg_des          = 19,
  moc_alg_des_ecb      = 20,
  moc_alg_des_cbc      = 21,
  moc_alg_tdes         = 22,
  moc_alg_tdes_ecb     = 23,
  moc_alg_tdes_cbc     = 24,
  moc_alg_arc2_cbc     = 25,
  moc_alg_hmac         = 26,
  moc_alg_ctr_drbg_aes = 27,
  moc_alg_fips186      = 28,
  moc_alg_arc4         = 29,
  moc_alg_rc5          = 30,
  moc_alg_aes_cmac     = 31,
  moc_alg_nist_kdf     = 32,
  moc_alg_poly1305     = 33,
  moc_alg_chacha20     = 34,
  moc_alg_chachapoly   = 35,
  moc_alg_hmac_kdf     = 36,
  moc_alg_aes_xcbc     = 37,
  moc_alg_blowfish_cbc = 38,
  moc_alg_blake2b      = 39,
  moc_alg_blake2s      = 40,
  moc_alg_pkcs5_pbe    = 41,
  moc_alg_sha3         = 42,
  moc_alg_ansix9_63_kdf= 43,
  moc_alg_aes_kw       = 44,
  moc_alg_drbg_hash    = 45
} cryptoInterfaceSymAlgo;

/* The number of symmetric algorithms in the list */
#define MOC_CRYPTO_INTERFACE_NUM_SYM_ALGOS 46

typedef enum {
  moc_alg_dh                                   = 0,
  moc_alg_rsa                                  = 1,
  moc_alg_dsa                                  = 2,
  moc_alg_ecc_p192                             = 3,
  moc_alg_ecc_p224                             = 4,
  moc_alg_ecc_p256                             = 5,
  moc_alg_ecc_p384                             = 6,
  moc_alg_ecc_p521                             = 7,
  moc_alg_ecc_x25519                           = 8,
  moc_alg_ecc_x448                             = 9,
  moc_alg_ecc_ed25519                          = 10,
  moc_alg_ecc_ed448                            = 11,
  moc_alg_qs_kem_mlkem                         = 12,         
  moc_alg_qs_sig_mldsa                         = 13,
  moc_alg_qs_sig_fndsa                         = 14,
  moc_alg_qs_sig_slhdsa                        = 15
} cryptoInterfaceKeyAlgo;

/* The number of asymmetric algorithms in the list */
#define MOC_CRYPTO_INTERFACE_NUM_KEY_ALGOS 16

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

/* An element of the algorithm table, contains an indication if that algorithm
 * has a viable alternate implementation in the mocctx, and the index of that
 * operator in the mocctx. */
typedef struct
{
  ubyte algoEnabled;
  ubyte mocCtxIndex;
} AlgoTableElement;

/* Initialize the Crypto Interface Core.
 *
 * NOTE: This function is designed to be called by DIGICERT_initialize(), where it
 * is guaranteed to be called from within mutex locked code. This function builds
 * a table of information about each algorithm which is then used by the crypto
 * interface layer. That table can always be accessed without any threading
 * issues, however this one time construction is not inherently thread safe
 * and therefore must be called from a thread safe context.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_initializeCore (intBoolean isMultiThreaded);

/* Uninitialize the Crypto Interface Core */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_uninitializeCore (void);

/* Initialize TAP Extern library */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_initializeTAPExtern(void);

/* Uninit the TAP Extern library */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_freeTAPExtern(void);

/**
 * Register a MocCtx with the Crypto Interface core.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_registerMocCtx (
  MocCtx pMocCtx
  );

/**
 * Unregister a MocCtx with the Crypto Interface core.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_unregisterMocCtx (
  MocCtx pMocCtx
  );

/**
 * Retrieve a reference to the MocCtx previously registered with the Crypto
 * Interface core.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getRegisteredMocCtx (
  MocCtx *ppMocCtx
  );

/**
 * Retrieve a reference to the MocCtx previously built during the Crypto
 * Interface initialization. This should only be used by the individual
 * Crypto Interface implementation files for each algorithm.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getMocCtx (
  MocCtx *ppMocCtx
  );

/**
 * Retrieve a reference to the MocCtx previously built during the Crypto
 * Interface initialization for TAP operators. This should only be
 * used by the individual Crypto Interface implementation files for
 * each algorithm.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getTapMocCtx (
  MocCtx *ppMocCtx
  );

/**
 * Check if a particular symmetric algorithm has an operator implementation and
 * optionally return the index into the MocCtx at which the implementing operator
 * was found.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkSymAlgoStatus (
  cryptoInterfaceSymAlgo symAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  );


/**
 * Check if a particular symmetric algorithm has a TAP operator implementation and
 * optionally return the index into the MocCtx at which the implementing operator
 * was found.
 */
MSTATUS CRYPTO_INTERFACE_checkTapSymAlgoStatus (
  cryptoInterfaceSymAlgo symAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  );

/**
 * Check if a particular asymmetric algorithm has an operator implementation and
 * optionally return the index into the MocCtx at which the implementing operator
 * was found.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkAsymAlgoStatus (
  cryptoInterfaceKeyAlgo keyAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  );

/**
 * Check if a particular asymmetric algorithm has a TAP operator implementation and
 * optionally return the index into the MocCtx at which the implementing operator
 * was found.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_checkTapAsymAlgoStatus (
  cryptoInterfaceKeyAlgo keyAlgo,
  ubyte4 *pAlgoStatus,
  ubyte4 *pAlgoIndex
  );

/**
 * Create a new MocSymCtx from a symmetric algorithm index and load key data
 * if available.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_createAndLoadSymKey (
  ubyte4 algoIndex,
  void *pOperatorInfo,
  ubyte *pKeyMaterial,
  ubyte4 keyMaterialLen,
  MocSymCtx *ppNewSymCtx
  );

/**
 * Free an RSA or ECC key shell and its underlying CAP keys.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_freeAsymKeys (
  void **ppKeyShell,
  MocAsymKey pPublicKey,
  MocAsymKey pPrivateKey
  );

/**
 * Get current IV of symmetric cipher.
 */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getIv(
  MOC_SYM(hwAccelDescr hwAccelCtx) MocSymCtx pCtx,
  ubyte *pIv
  );
#ifdef __cplusplus
}
#endif

#endif  /* __DIGICERT_CRYPTO_INTERFACE_PRIV_HEADER__ */
