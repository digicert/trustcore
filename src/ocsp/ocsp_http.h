/*
 * ocsp_http.h
 *
 * OCSP with HTTP (async) as the transport
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

/**
@file       ocsp_http.h
@brief      NanoCert OCSP HTTP %client developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by OCSP HTTP client developer API functions.

@since 5.3
@version 5.3 and later

@flags
To enable this file's definitions, you must define the following flag in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@filedoc    ocsp_http.h
*/
#ifndef __OCSP_HTTP_HEADER__
#define __OCSP_HTTP_HEADER__

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCSP_TCP_CONNECT_TIMEOUT_MS
#define OCSP_TCP_CONNECT_TIMEOUT_MS   5000
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS OCSP_CLIENT_httpInit(httpContext **ppHttpContext, ocspContext *pOcspContext);

MOC_EXTERN MSTATUS OCSP_CLIENT_sendRequest(ocspContext *pOcspContext, httpContext *pHttpContext, ubyte *pRequest, ubyte4 requestLen);

MOC_EXTERN MSTATUS OCSP_CLIENT_recv(ocspContext *pOcspContext, httpContext *pHttpContext, intBoolean *isDone, ubyte **ppResponse, ubyte4 *pResponseLen);

MOC_EXTERN MSTATUS OCSP_CLIENT_httpUninit(httpContext **ppHttpContext);


#ifdef __cplusplus
}
#endif

#endif /* (defined(__ENABLE_DIGICERT_OCSP_CLIENT__)) */
#endif /* __OCSP_HTTP_HEADER__ */
