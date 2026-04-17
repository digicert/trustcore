/**
 * @file sapi2.h
 * @brief This file includes all headers from sapi2 required
 * by upper layer software for convenience.
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
#ifndef __SAPI2_H__
#define __SAPI2_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "sapi2_context.h"
#include "sapi2_asym.h"
#include "sapi2_capability.h"
#include "sapi2_ctx_mgmt.h"
#include "sapi2_hierarchy.h"
#include "sapi2_integrity.h"
#include "sapi2_nv.h"
#include "sapi2_object.h"
#include "sapi2_rng.h"
#include "sapi2_session.h"
#include "sapi2_signature.h"
#include "sapi2_sym.h"
#include "sapi2_testing.h"
#include "sapi2_sequence.h"
#include "sapi2_attestation.h"
#include "sapi2_enhanced_auth.h"
#include "sapi2_utils.h"
#include "sapi2_sym_hmac.h"

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_H__ */
