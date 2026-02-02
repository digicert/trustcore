/*
 * status_loc.h
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
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