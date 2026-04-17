/**
 * @file sapi2_hmac.h
 * @brief This file contains SAPI2 HMAC related functions for TPM2.
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
#ifndef __SAPI2_HMAC_H__
#define __SAPI2_HMAC_H__

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "sapi2_session.h"

/**
 * @private
 * @internal
 *
 */

MSTATUS
SAPI2_HMAC_computeCmdRspHMAC(MOCTPM2_SESSION *pSession, TPM2B_AUTH *pAuth,
        TPM2B_DIGEST *pCRPHash, TPM2B_DIGEST *pResult);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /*u __SAPI2_HMAC_H__ */
