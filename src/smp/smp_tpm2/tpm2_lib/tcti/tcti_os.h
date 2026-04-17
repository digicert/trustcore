/*  tcti_os.h
 *
 *  This file includes definitions for the TCTI layer for the OS specific port
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

#ifndef __TCTI_OS_H__
#define __TCTI_OS_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../../../../common/mtypes.h"
#include "../tpm_common/tss2_error.h"
#include "tcti.h"

typedef struct {
    TSS2_RC (* contextInit)(TctiContextInitIn *pIn, void **ppTctiOsContext);
    TSS2_RC (* contextUnint)(void **ppTctiOsContext);
    TSS2_RC (* transmitRecieve)(void *pTctiOsCtx, TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut);
} TCTI_OS_OPS;

#endif /* __ENABLE_DIGICERT_TPM2__  */
#endif /* __TCTI_OS_H__ */
