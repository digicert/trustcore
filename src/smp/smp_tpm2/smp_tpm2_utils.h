/**
 * smp_tpm2_utils.h
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
