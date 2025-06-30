/*
 * crypto_hash_fips.h
 *
 * Header file for FIPS hash algo suites.
 *
 * Copyright Digicert 2024. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

/**
 * @file       crypto_hash_fips.h
 *
 * @brief      Header file for FIPS hash algo suites.
 *
 * @filedoc    crypto_hash_fips.h
 */

/*------------------------------------------------------------------*/

#ifndef __CRYPTO_HASH_FIPS_HEADER__
#define __CRYPTO_HASH_FIPS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

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
MOC_EXTERN MSTATUS CRYPTO_FIPS_getRSAHashAlgo(ubyte rsaAlgoId, const BulkHashAlgo **ppBulkHashAlgo);

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
MOC_EXTERN MSTATUS CRYPTO_FIPS_getECCHashAlgo(ubyte eccAlgoId, BulkHashAlgo **ppBulkHashAlgo);

#ifdef __cplusplus
}
#endif


#endif /* __CRYPTO_HASH_FIPS_HEADER__ */