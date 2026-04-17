/**
 * @file fapi2.h
 * @brief This file includes all fapi header files to ease the burden on
 * applications from including individual header files.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __FAPI2_H__
#define __FAPI2_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "../tpm_common/tss2_error.h"

#include "fapi2_types.h"
#include "fapi2_context.h"
#include "fapi2_admin.h"
#include "fapi2_mgmt.h"
#include "fapi2_asym.h"
#include "fapi2_data.h"
#include "fapi2_rng.h"
#include "fapi2_nv.h"
#include "fapi2_sym.h"
#include "fapi2_credential.h"
#include "fapi2_attestation.h"
#include "fapi2_integrity.h"
#include "fapi2_testing.h"
#include "fapi2_utils.h"
#include "fapi2_hmac.h"

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_H__ */
