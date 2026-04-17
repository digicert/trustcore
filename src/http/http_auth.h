/*
 * http_auth.h
 *
 * HTTP Authentication Header File
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
