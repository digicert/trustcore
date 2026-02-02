/*  tcti_os.h
 *
 *  This file includes definitions for the TCTI layer for the OS specific port
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
