/*
 * status_log.h
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
#ifndef __STATUS_LOG_HEADER__
#define __STATUS_LOG_HEADER__

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    STATUS_LOG_STATE_NONE,
    STATUS_LOG_STATE_SUCCESS,
    STATUS_LOG_STATE_FAILURE
} MStatusLogStatus;

typedef struct
{
    MStatusLogStatus status;
    MSTATUS statusCode;
} MStatusLogReport;

MOC_EXTERN MSTATUS STATUS_LOG_filePath(
    sbyte *pFilename,
    sbyte **ppPath);

MOC_EXTERN MSTATUS STATUS_LOG_socketPath(
    sbyte *pIp,
    ubyte2 port,
    sbyte **ppPath);

MOC_EXTERN MSTATUS STATUS_LOG_report(
    sbyte *pStatusLogPath,
    MSTATUS statusCode,
    sbyte *pErrString);

MOC_EXTERN MSTATUS STATUS_LOG_parseReport(
    ubyte *pJson,
    ubyte4 jsonLen,
    MStatusLogReport *pReport);

#ifdef __cplusplus
}
#endif

#endif /* __STATUS_LOG_HEADER__ */
