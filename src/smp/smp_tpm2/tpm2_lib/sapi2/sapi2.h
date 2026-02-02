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
