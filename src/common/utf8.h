/*
 * utf8.h
 *
 * Code for handling UTF-8 values
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
 */

#ifndef __UTF8_HEADER__
#define __UTF8_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mdefs.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS UTF8_validateEncoding(
    ubyte *pData,
    ubyte4 dataLen,
    byteBoolean *pIsValid);

#ifdef __cplusplus
}
#endif

#endif /* __UTF8_HEADER__ */
