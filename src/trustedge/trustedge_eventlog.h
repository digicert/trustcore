/**
 * trustedge_eventlog.h
 *
 * @file trustedge_eventlog.h
 * @brief Windows Event Log integration for TrustEdge
 *
 * Provides functions to log TrustEdge events to the Windows Event Log.
 * Events are visible in Event Viewer under Windows Logs > Application.
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

#ifndef __TRUSTEDGE_EVENTLOG_H__
#define __TRUSTEDGE_EVENTLOG_H__

#ifdef __RTOS_WIN32__

#include "../common/mtypes.h"
#include "../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the Windows Event Log source
 *
 * Registers TrustEdge as an event source with Windows Event Log.
 * Must be called once at startup before logging events.
 *
 * @return OK on success, error code on failure
 */
MSTATUS TRUSTEDGE_eventLogInit(void);

/**
 * @brief Shutdown the Windows Event Log source
 *
 * Deregisters the event source. Call at cleanup.
 */
void TRUSTEDGE_eventLogShutdown(void);

/**
 * @brief Log an informational message
 *
 * @param eventId Event ID from trustedge_events.h
 * @param message Message text (replaces %1)
 */
void TRUSTEDGE_eventLogInfo(DWORD eventId, const char *message);

/**
 * @brief Log an informational message with two parameters
 *
 * @param eventId Event ID from trustedge_events.h
 * @param param1 First parameter (replaces %1)
 * @param param2 Second parameter (replaces %2)
 */
void TRUSTEDGE_eventLogInfo2(DWORD eventId, const char *param1, const char *param2);

/**
 * @brief Log a warning message
 *
 * @param eventId Event ID from trustedge_events.h
 * @param message Message text (replaces %1)
 */
void TRUSTEDGE_eventLogWarning(DWORD eventId, const char *message);

/**
 * @brief Log an error message
 *
 * @param eventId Event ID from trustedge_events.h
 * @param message Message text (replaces %1)
 */
void TRUSTEDGE_eventLogError(DWORD eventId, const char *message);

/**
 * @brief Log an error message with two parameters
 *
 * @param eventId Event ID from trustedge_events.h
 * @param param1 First parameter (replaces %1)
 * @param param2 Second parameter (replaces %2)
 */
void TRUSTEDGE_eventLogError2(DWORD eventId, const char *param1, const char *param2);

/**
 * @brief Log a formatted message (printf-style)
 *
 * Uses TRUSTEDGE_MSG_INFO_GENERIC, TRUSTEDGE_MSG_WARNING_GENERIC, or
 * TRUSTEDGE_MSG_ERROR_GENERIC based on level.
 *
 * @param level 0=Info, 1=Warning, 2=Error
 * @param format Printf-style format string
 * @param ... Arguments
 */
void TRUSTEDGE_eventLogPrintf(int level, const char *format, ...);

/* Log level constants */
#define TRUSTEDGE_LOG_INFO    0
#define TRUSTEDGE_LOG_WARNING 1
#define TRUSTEDGE_LOG_ERROR   2
#define TRUSTEDGE_LOG_DEBUG   3

#ifdef __cplusplus
}
#endif

#endif /* __RTOS_WIN32__ */

#endif /* __TRUSTEDGE_EVENTLOG_H__ */
