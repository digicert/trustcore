/*
 * http_process.h
 *
 * HTTP Process Header File
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

#ifndef __HTTP_CLIENT_PROCESS_HEADER__
#define __HTTP_CLIENT_PROCESS_HEADER__

/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS HTTP_CLIENT_PROCESS_initProcess(httpContext *pHttpContext);

MOC_EXTERN MSTATUS
HTTP_CLIENT_PROCESS_sendRequest(httpContext *pHttpContext,
                          intBoolean isContinueFromBlock);

/* pCookie is an opaque cookie interpretable by the application */
MOC_EXTERN MSTATUS
HTTP_CLIENT_PROCESS_sendRequestEx(httpContext *pHttpContext,
                          intBoolean isContinueFromBlock, void* pCookie);

MOC_EXTERN intBoolean
HTTP_CLIENT_PROCESS_isDoneSendingRequest(httpContext *pHttpContext);

/* state machine to process response */
MOC_EXTERN MSTATUS
HTTP_CLIENT_PROCESS_receiveResponse(httpContext *pHttpContext,
                          ubyte *pData, ubyte4 dataLength,
                          intBoolean isContinueFromBlock);

#endif /* __HTTP_CLIENT_PROCESS_HEADER__ */
