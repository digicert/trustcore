/**
 * @file tpm_error_utils.h
 *
 * @ingroup tpm_tree
 *
 * @brief Error utility functions needed by TPM 1.2 code.
 * @details Error utility functions needed by TPM 1.2 code.
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
