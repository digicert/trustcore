/*
    ssl_serv_request.h

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

*/

#ifndef __SSL_SERV_REQUEST_HEADER__
#define __SSL_SERV_REQUEST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

sbyte4 SSL_SERV_doRequest( sbyte4 connectionInstance, intBoolean* stopRequest);
sbyte4 HTTP_SERV_doRequest( TCP_SOCKET socket, intBoolean* stopRequest);


#ifdef __cplusplus
}
#endif

#endif

