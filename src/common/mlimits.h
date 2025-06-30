/*
 * mlimits.h
 *
 * Mocana Limits Definitions
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __MLIMITS_HEADER__
#define __MLIMITS_HEADER__

#define SBYTE_MIN       ((sbyte)(~((~((ubyte)0)) >> 1)))
#define SBYTE_MAX       ((sbyte)((~((ubyte)0)) >> 1))

#define UBYTE_MIN       (0)
#define UBYTE_MAX       (~((ubyte)0))

#define SBYTE2_MIN      ((sbyte2)(~((~((ubyte2)0)) >> 1)))
#define SBYTE2_MAX      ((sbyte2)((~((ubyte2)0)) >> 1))

#define UBYTE2_MIN      (0)
#define UBYTE2_MAX      (~((ubyte2)0))

#define SBYTE4_MIN      ((sbyte4)(~((~((ubyte4)0)) >> 1)))
#define SBYTE4_MAX      ((sbyte4)((~((ubyte4)0)) >> 1))

#define UBYTE4_MIN      (0)
#define UBYTE4_MAX      (~((ubyte4)0))

#endif /* __MLIMITS_HEADER__ */
