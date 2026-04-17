/*
 * ossl_tap.h
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

#ifndef OSSL_TAP_H
#define OSSL_TAP_H

#include "common/mtypes.h"
#include "common/mdefs.h"
#include "common/moptions.h"
#include "common/merrors.h"
#include "common/mrtos.h"
#include "crypto/hw_accel.h"
#include "crypto/sha1.h"
#include "common/base64.h"
#include "common/sizedbuffer.h"
#include "common/random.h"
#include "common/vlong.h"
#include "crypto/rsa.h"
#include "crypto/pubcrypto.h"
#include "crypto/secmod/moctap.h"
#include "tap/tap.h"
#include "tap/tap_smp.h"

#if defined(__ENABLE_DIGICERT_TPM__)

/**
@brief      Associate the given TAP handle with the key

@details    This callback allows the application to bind a key to a TAP handle,
            created by the application.

@param  mh  MOCTAP HANDLE defined and initialized by the application.
@param  ctx Current SSL CTX state object.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

*/
MOC_EXTERN sbyte4 OSSL_KeyAssociateTapContext(MOCTAP_HANDLE mh, SSL_CTX* ctx);
#endif /* __ENABLE_DIGICERT_TPM__ */

#endif /* OSSL_TAP_H */
