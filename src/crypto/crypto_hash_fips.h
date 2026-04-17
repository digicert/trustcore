/*
 * crypto_hash_fips.h
 *
 * Header file for FIPS hash algo suites.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 *    See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 *    See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
