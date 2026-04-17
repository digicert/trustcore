/*
 * smp_tap_tee.h
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

/**
@file       smp_tap_tee.h
@ingroup    nanosmp_tree
@brief      TEE specific header file
@details    This header file contains structures required to work with NanoSMP
            and helper function declarations required by TAP APIs.
*/

#ifndef __SMP_TAP_TEE_HEADER__
#define __SMP_TAP_TEE_HEADER__

#define TEE_UNDEFINED 0
#define TEE_SECURE_STORAGE 1

/* The following macros should be updated to reflect the number
   of Trusted Applications (TAs) listed above and the max index
   value. */
#define TEE_NUM_TRUSTED_APPLICATIONS 1
#define TEE_MAX_TRUSTED_APPLICATION_ID 1

#endif /* __SMP_TAP_TEE_HEADER__ */
