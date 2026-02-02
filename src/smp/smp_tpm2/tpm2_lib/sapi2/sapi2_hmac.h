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
