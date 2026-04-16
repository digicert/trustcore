/*
 * vlong_priv.h
 * Very Long Integer Library Private Header
 *
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
 */

#include "../common/moptions.h"

#ifndef __VLONG_PRIV_HEADER__
#define __VLONG_PRIV_HEADER__

/* Build dependent macros to use the fastest available implementation */
#if !defined( __ALTIVEC__) && !defined(__DISABLE_DIGICERT_KARATSUBA__) && !defined(__ENABLE_DIGICERT_BI_MUL_ASM__)
#define VLONG_FAST_MULT   fasterUnsignedMultiplyVlongs
#define VLONG_FAST_SQR     fasterUnsignedSqrVlong
#else
#define VLONG_FAST_MULT   fastUnsignedMultiplyVlongs
#define VLONG_FAST_SQR    fastUnsignedSqrVlong
#endif

#endif /* __VLONG_PRIV_HEADER__ */
