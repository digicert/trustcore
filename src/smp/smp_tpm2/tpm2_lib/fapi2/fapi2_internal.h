/**
 * @file fapi2_internal.h
 * @brief This file includes all header files included by fapi. This file
 * must not be included by applications.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_INTERNAL_H__
#define __FAPI2_INTERNAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"

#include "../sapi2/sapi2.h"
#include "fapi2_context_internal.h"
#include "fapi2_utils_internal.h"
#include "fapi2_asym_internal.h"
#include "fapi2_data_internal.h"
#include "fapi2_ea_internal.h"

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_INTERNAL_H__ */
