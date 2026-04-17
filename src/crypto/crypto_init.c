/*
 * crypto_init.c
 *
 * Crypto Initialization Code.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ecc.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

/*------------------------------------------------------------------*/

/* If the primeec odd signed combs are globally enabled, create the mutexes for them */
#if defined(__ENABLE_DIGICERT_ECC__) && \
    defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
    !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
#define MOC_INIT_ECC_MUTEXES(_status)                                          \
    _status = CRYPTO_INTERFACE_EC_createCombMutexes();
#elif defined(__ENABLE_DIGICERT_ECC__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define MOC_INIT_ECC_MUTEXES(_status)                                          \
    _status = EC_createCombMutexes();
#else
#define MOC_INIT_ECC_MUTEXES(_status)
#endif

/*----------------------------------------------------------------------------*/

/* If the primeec odd signed combs are globally enabled free them and their mutexes */
#if defined(__ENABLE_DIGICERT_ECC__) && \
    defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
   !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
#define DIGI_FREE_COMBS_AND_MUTEXES(_status)                                    \
    _status = CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes();
#elif defined(__ENABLE_DIGICERT_ECC__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#define DIGI_FREE_COMBS_AND_MUTEXES(_status)                                    \
    _status = EC_deleteAllCombsAndMutexes();
#else
#define DIGI_FREE_COMBS_AND_MUTEXES(_status)
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_DIGI_init(void)
{
    MSTATUS status = OK;

    MOC_INIT_ECC_MUTEXES(status)

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_DIGI_free(void)
{
    MSTATUS status = OK;

    DIGI_FREE_COMBS_AND_MUTEXES(status)

    return status;
}

