/*
 * tp_version.h
 *
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
 */

#ifndef TP_VERSION_H
#define TP_VERSION_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These values are automatically set according to their
 * cmake variables.
 */
#define TP_BUILD_PLATFORM_STR    "Linux"
#define TP_BUILD_TAPINFO_STR     "TAP-Off"
#define TP_BUILD_TYPE_STR        "Debug"
#define TP_BUILD_VERSION_STR     "1.0.0.0"
#define TP_BUILD_IDENTITY_STR    ""
#define TP_BUILD_DATE_STR        "2026-01-21 11:16"
#define CURR_YEAR                2026

/*------------------------------------------------------------------*/

#define TP_MAX_VERSION_LEN 256  /* Plenty of room for a version string */

MOC_EXTERN MSTATUS TP_getVersion (
  ubyte *pRetBuffer,
  ubyte4 retBufLength);

MOC_EXTERN MSTATUS TP_printVersion (void);

/*------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif


#endif /* TP_VERSION_H */
