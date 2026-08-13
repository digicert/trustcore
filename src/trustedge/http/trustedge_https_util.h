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
#define CONNECTION_KEEP_ALIVE       "keep-alive"

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

