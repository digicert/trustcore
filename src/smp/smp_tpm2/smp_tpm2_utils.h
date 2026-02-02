/**
 * smp_tpm2_utils.h
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
 * @file smp_tpm2_utils.h
 *
 * @ingroup smp_functions
 *
 * @brief Security Module Provider Utility functions for TPM2
 * @details This file contains utility functions needed by SMP-TPM2
 *
 * @flags
 * This file requires that the following flags be defined:
 *    + \c \__ENABLE_DIGICERT_SMP__
 */

/*------------------------------------------------------------------*/

#ifndef __SMP_TPM2_UTILS_HEADER__
#define __SMP_TPM2_UTILS_HEADER__

#include "../../smp/smp_tpm2/tpm2_lib/tpm_common/tss2_error.h"

/**
 * @ingroup smp_functions
 *
 * @details Function to map TSS2_RC to MSTATUS code
 *
 * @param [in] smpErrorCode   Return-Code received from TPM2 layer
 *
 * @return MSTATUS return code corresponding to smpErrorCode
 *
 */
MSTATUS SMP_TPM2_UTILS_getMocanaError(TSS2_RC smpErrorCode);


#endif
