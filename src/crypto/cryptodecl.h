/*
 * capdecl.h
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