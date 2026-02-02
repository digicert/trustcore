/*
 * http_process.h
 *
 * HTTP Process Header File
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
