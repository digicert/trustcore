/*
 * http_transfer_coding.h
 *
 * HTTP transfer_coding Header File
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

#ifndef __HTTP_TRANSFER_CODING_HEADER__
#define __HTTP_TRANSFER_CODING_HEADER__

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
HTTP_TRANSFER_CODING_isChunked(httpContext *pHttpContext);
MOC_EXTERN MSTATUS
HTTP_TRANSFER_CODING_decodeChunked(httpContext *pHttpContext, ubyte **ppData, ubyte4* pDataLength, byteBoolean *pIsDone);
MOC_EXTERN MSTATUS
HTTP_TRANSFER_CODING_encodeChunked(httpContext *pHttpContext,  ubyte** ppDataToSend, ubyte4 *pDataLength, byteBoolean isDone);

#endif /* __HTTP_CONTEXT_HEADER__ */
