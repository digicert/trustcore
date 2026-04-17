/**
 * @file sapi2_sym_hmac.h
 * @brief This file contains code required to execute TPM2 symmetric HMAC
 * commands.
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
#ifndef __SAPI2_SYM_HMAC_H__
#define __SAPI2_SYM_HMAC_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_MAX_BUFFER *pInData;
    TPM2_ALG_ID hashAlg;
    TPM2B_AUTH *pAuthObjectHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} HmacIn;

typedef struct {
    TPM2B_DIGEST outData;
} HmacOut;

MOC_EXTERN TSS2_RC SAPI2_SYM_Hmac(
        SAPI2_CONTEXT *pSapiContext,
        HmacIn *pIn,
        HmacOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_SYM_HMAC_H__ */

