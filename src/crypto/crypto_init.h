/*
 * crypto_init.h
 *
 * Crypto Initialization Header
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

/*------------------------------------------------------------------*/

#ifndef __CRYPTO_INIT_HEADER__
#define __CRYPTO_INIT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/* Performs any initialization that crypto may need (mutex/table creation etc.) */
MOC_EXTERN MSTATUS CRYPTO_DIGI_init(void);

/* Performs any cleanup that crypto may need (freeing tables etc.) */
MOC_EXTERN MSTATUS CRYPTO_DIGI_free(void);

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INIT_HEADER__ */