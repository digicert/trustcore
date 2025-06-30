/**
 * vlong_priv.h
 * Very Long Integer Library Private Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../common/moptions.h"

#ifndef __VLONG_PRIV_HEADER__
#define __VLONG_PRIV_HEADER__

/* Build dependent macros to use the fastest available implementation */
#if !defined( __ALTIVEC__) && !defined(__DISABLE_MOCANA_KARATSUBA__) && !defined(__ENABLE_MOCANA_BI_MUL_ASM__)
#define VLONG_FAST_MULT   fasterUnsignedMultiplyVlongs
#define VLONG_FAST_SQR     fasterUnsignedSqrVlong
#else
#define VLONG_FAST_MULT   fastUnsignedMultiplyVlongs
#define VLONG_FAST_SQR    fastUnsignedSqrVlong
#endif

#endif /* __VLONG_PRIV_HEADER__ */
