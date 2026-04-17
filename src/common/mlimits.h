/*
 * mlimits.h
 *
 * DigiCert Limits Definitions
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
