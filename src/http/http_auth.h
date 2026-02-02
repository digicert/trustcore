/*
 * http_auth.h
 *
 * HTTP Authentication Header File
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

#ifndef __HTTP_AUTH_HEADER__
#define __HTTP_AUTH_HEADER__

/*------------------------------------------------------------------*/

typedef enum httpAuthScheme
{
    BASIC,
    DIGEST,
    UNKNOWN
} httpAuthScheme;

/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
HTTP_AUTH_generateAuthorization(httpContext *pHttpContext, ubyte4 *pIndex,
                            ubyte **ppRetAuthString, ubyte4 *pRetAuthStringLength);

MOC_EXTERN MSTATUS
HTTP_AUTH_generateBasicAuthorization(httpContext *pHttpContext,
                            ubyte *pUsername, ubyte4 userNameLength,
                            ubyte *pPassword, ubyte4 passwordLength,
                            ubyte **ppRetAuthString, ubyte4 *pRetAuthStringLength);

/* if unvalidated, returns a 4xx status code and set the challenge in response header */
MOC_EXTERN MSTATUS
HTTP_AUTH_validateAuthorization(httpContext *pHttpContext, ubyte4 *pStatusCode);

#endif /* __HTTP_AUTH_HEADER__ */
