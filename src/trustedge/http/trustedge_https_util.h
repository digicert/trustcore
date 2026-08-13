/*
 * trustedge_https_util.h
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

/*------------------------------------------------------------------*/

#ifndef __TRUSTEDGE_HTTPS_UTIL_HEADER__
#define __TRUSTEDGE_HTTPS_UTIL_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "trustedge_https_client.h"

#define HTTPS_PREFIX                "https://"

#define USER_AGENT                  "Digicert TrustEdge Client Daemon"

#define CONTENT_TYPE_JSON           "application/json"
#define CONTENT_TYPE_OCTETS         "application/json;application/octet-stream"
#define CONNECTION_KEEP_ALIVE       "keep-alive"

/* TRUSTEDGE_HTTPS_UTIL_parseAuth : Read and parse the auth file in the
 *   devcreds directory
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 *     sbyte* authFile :: The name of the file to parse
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_parseAuth(HttpsClientCtx *pCtx, sbyte* authFile);

/* TRUSTEDGE_HTTPS_UTIL_start : Initialize http and ssl
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_start(HttpsClientCtx *pHttpsClientCtx);

/* TRUSTEDGE_HTTPS_UTIL_runClient : Start http and ssl
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_runClient(HttpsClientCtx *pHttpsClientCtx);

/* TRUSTEDGE_HTTPS_UTIL_freeClient : Free http and ssl worker memory
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 */
void
TRUSTEDGE_HTTPS_UTIL_freeClient(HttpsClientCtx *pHttpsClientCtx);

/* TRUSTEDGE_HTTPS_UTIL_stop : Shut down http and ssl
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_stop(HttpsClientCtx *pHttpsClientCtx);

/* TRUSTEDGE_HTTPS_UTIL_keepMsg : Write the request or response message
 *                         into the indicated location
 *
 *   Parameters :
 *     sbyte *fileName :: The name of the file to create
 *     sbyte *msg      :: The message to save
 *     sbyte *msgLen   :: Length of the message to save
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_keepMsg(char *fileName, sbyte *msg, ubyte4 msgLen);

/* TRUSTEDGE_HTTPS_UTIL_keepMsg : Write the request or response message
 *                         into the indicated location
 *
 *   Parameters :
 *     sbyte *fileName :: The name of the file to create
 *     sbyte *srcFileName :: The name of the file to copy
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_keepMsgFromFile(char *fileName, char *srcFileName );

/* TRUSTEDGE_HTTPS_UTIL_parseDownloadURI : Break the server-provided download
 *                                  URI into usable pieces.
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 *     sbyte* uri              :: The server-provided download URI
 */
MSTATUS
TRUSTEDGE_HTTPS_UTIL_parseDownloadURI(HttpsClientCtx *pCtx, sbyte* uri);

/* TRUSTEDGE_HTTPS_UTIL_resetFuncPtrs : Reset the global https function pointers.
 *
 */
void
TRUSTEDGE_HTTPS_UTIL_resetFuncPtrs(void);

/* TRUSTEDGE_HTTPS_UTIL_getLowestHttpTimeout : Return the lowest of either
 *                                      the transaction or download timeout.
 *
 *   Parameters :
 *     HttpsClientCtx *pCtx :: The HTTPS component context
 */
ubyte4
TRUSTEDGE_HTTPS_UTIL_getLowestHttpTimeout(HttpsClientCtx *pCtx);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_HTTPS_UTIL_HEADER__ */

