/*
 * smp_tap_tee.h
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
