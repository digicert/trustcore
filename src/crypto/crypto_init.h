/*
 * crypto_init.h
 *
 * Crypto Initialization Header
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