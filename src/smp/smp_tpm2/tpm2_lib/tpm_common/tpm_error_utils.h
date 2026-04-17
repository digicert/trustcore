/**
 * @file tpm_error_utils.h
 *
 * @ingroup tpm_tree
 *
 * @brief Error utility functions needed by TPM 1.2 code.
 * @details Error utility functions needed by TPM 1.2 code.
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
 * @flags
 *  To enable this file's functions, the following flags must be defined in moptions.h:
 *  + \c \__ENABLE_DIGICERT_TPM2__
 *
 */
#ifndef __TPM_ERROR_UTILS_H
#define __TPM_ERROR_UTILS_H

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../tpm_common/tss2_error.h"

/**
 * @ingroup tpm_functions
 *
 * @brief Print out text string for a TPM 2.0 return code.
 * @details Helper/Debug function to print out text string for a TPM 2.0 return code.
 *
 * @param [in] rc  TPM 2.0 TSS2_RC code
 *
 * @return String containing return code description
 */
char *tss2_err_string(TSS2_RC rc);

#endif /* __ENABLE_DIGICERT_TPM2__ */
#endif /* __TPM_ERROR_UTILS_H */
