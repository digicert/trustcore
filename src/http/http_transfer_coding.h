/*
 * http_transfer_coding.h
 *
 * HTTP transfer_coding Header File
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
