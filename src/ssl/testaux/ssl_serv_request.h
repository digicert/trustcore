/*
    ssl_serv_request.h

 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*

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

