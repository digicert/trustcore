/*
 * asm_math.h
 *
 * Math Definitions
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

#if defined (__ASM_COLDFIRE_DIABDATA__)
#include "math_coldfire.h"

#elif defined(__ASM_386__)
#include "math_386.h"

#elif defined(__ASM_ARM__)
#include "math_arm.h"

#elif defined(__ASM_386_GCC__)
#include "math_386_gcc.h"

#elif defined(__ASM_PPC__)
#include "math_ppc.h"

#elif defined(__ASM_M68K_CROSSCODE__)
#include "math_m68k.h"

#elif defined(__ASM_MC68360_GCC__)
#include "math_mc68360.h"

#elif defined(__ASM_MIPS__)
#include "math_mips.h"

#elif defined(__ASM_H8S__)
#include "math_h8s.h"

#elif defined(__ASM_ULTRASPARC__)
#include "math_ultrasparc.h"

#elif defined(__ASM_CAVIUM__)
#include "math_cavm64.h"

#elif defined(__ASM_COLDFIRE_GHS__)
#include "math_coldfire_ghs.h"

#endif
