/*  tcti.h
 *
 *  This file includes definitions for the TCTI layer
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

#ifndef __TCTI_H__
#define __TCTI_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../../../../common/mtypes.h"
#include "../tpm_common/tss2_error.h"

typedef struct _TCTI_CONTEXT TCTI_CONTEXT;

typedef struct {
    ubyte4 serverNameLen;
    ubyte *pServerName;
    ubyte2 serverPort;
} TctiContextInitIn;

typedef struct {
    ubyte4 transmitBufLen;
    ubyte *pTransmitBuf;
    ubyte4 receiveBufLen;
    ubyte *pReceiveBuf;
} TctiTransmitRecieveIn;

typedef struct {
    ubyte4 recievedLen;
} TctiTransmitRecieveOut;

extern byteBoolean gShouldReuseContext;

TSS2_RC TSS2_TCTI_contextInit(TctiContextInitIn *pIn, TCTI_CONTEXT **ppTctiContext);
TSS2_RC TSS2_TCTI_contextUninit(TCTI_CONTEXT **ppTctiContext);
MOC_EXTERN TSS2_RC TSS2_TCTI_sharedContextInit(TctiContextInitIn *pIn);
MOC_EXTERN TSS2_RC TSS2_TCTI_sharedContextUninit();
TSS2_RC TSS2_TCTI_transmitReceive(TCTI_CONTEXT *pTctiCtx, TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut);

#endif /* __ENABLE_DIGICERT_TPM2__ */
#endif /* __TCTI_H__ */
