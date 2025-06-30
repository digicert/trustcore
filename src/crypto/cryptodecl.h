/*
 * capdecl.h
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
 * This file contains forward declarations that may
 * be neccessary for NanoCrypto.
 */

#ifndef __CRYPTO_DECL_HEADER__
#define __CRYPTO_DECL_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

typedef const struct PrimeField* PrimeFieldPtr;
typedef const struct PFE    *ConstPFEPtr;
typedef struct PFE          *PFEPtr;
typedef const struct PrimeEllipticCurve* PEllipticCurvePtr;

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_DECL_HEADER__ */