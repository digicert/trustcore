/*
 * fips_utils.h
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

#ifndef __FIPS_UTILS_HEADER__
#define __FIPS_UTILS_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/random.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
/*
 *  Initialize the Random context with external entropy and optionally force FIPS self tests.
 *  Control the FIPS algo related with macros found in .c file.
 */
MOC_EXTERN MSTATUS FIPS_UTILS_initialize(randomContext* pRandomContext);

/*
 *  Initialize the Random context with external entropy.
 */
MOC_EXTERN MSTATUS FIPS_UTILS_getInitialEntropy(randomContext* pRandomContext);
#endif /* __ENABLE_DIGICERT_FIPS_MODULE__ */

#ifdef __cplusplus
}
#endif

#endif
