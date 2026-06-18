/**
 * trustedge_eventlog.c
 *
 * @file trustedge_eventlog.c
 * @brief Windows Event Log implementation for TrustEdge
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

#include "../common/moptions.h"

#ifdef __RTOS_WIN32__

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>

#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/debug_console.h"
#include "trustedge_eventlog.h"

/* Include generated event definitions - will be in build directory */
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
#include "trustedge_events.h"
#endif

#define TRUSTEDGE_EVENT_SOURCE_NAME "DigiCertTrustEdge"
#define TRUSTEDGE_LOG_BUFFER_SIZE   1024

/* Global event log handle */
static HANDLE g_hEventLog = NULL;

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DEBUG_FORWARD__
/**
 * @brief Forward callback for DEBUG_CONSOLE_printf
 *
 * This callback receives all debug console output and forwards it
 * to the Windows Event Log as informational messages.
 */
static void TRUSTEDGE_eventLogForwardCallback(const sbyte *message)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[1];

  if (g_hEventLog == NULL || message == NULL)
    return;

  /* Skip empty messages or just newlines */
  if (message[0] == '\0' || (message[0] == '\n' && message[1] == '\0'))
    return;

  strings[0] = (const char *)message;

  ReportEventA(g_hEventLog,
               EVENTLOG_INFORMATION_TYPE,
               0,
               TRUSTEDGE_MSG_INFO_GENERIC,
               NULL,
               1,
               0,
               strings,
               NULL);
#else
  (void)message;
#endif
}
#endif /* __ENABLE_DIGICERT_DEBUG_FORWARD__ */

/*------------------------------------------------------------------*/

MSTATUS TRUSTEDGE_eventLogInit(void)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  MSTATUS status = OK;
  DWORD   dwTypes, dwError = 0;
  HKEY    hRegKey = NULL;
  char    szPath[MAX_PATH];
  char    szRegPath[MAX_PATH];

  /* Already initialized? */
  if (g_hEventLog != NULL)
  {
    return OK;
  }

  /* Build registry path */
  _snprintf_s(szRegPath, sizeof(szRegPath), _TRUNCATE,
              "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\%s",
              TRUSTEDGE_EVENT_SOURCE_NAME);

  /* Open/Create registry path */
  dwError = RegCreateKeyA(HKEY_LOCAL_MACHINE, szRegPath, &hRegKey);
  if (0 != dwError)
  {
    /* May fail if not running as admin - continue anyway, 
       events will show without proper formatting */
    goto register_source;
  }

  /* Get path to this executable (contains the message resources) */
  dwError = GetModuleFileNameA(NULL, szPath, MAX_PATH);
  if (0 == dwError)
  {
    status = ERR_BUFFER_TOO_SMALL;
    goto exit;
  }

  /* Register EventMessageFile (path to our .exe with embedded .res) */
  dwError = RegSetValueExA(hRegKey, "EventMessageFile",
                           0, REG_SZ, (BYTE*)szPath,
                           (DWORD)(strlen(szPath) + 1));
  if (0 != dwError)
  {
    /* Continue anyway */
  }

  /* Register supported types */
  dwTypes = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
  dwError = RegSetValueExA(hRegKey, "TypesSupported",
                           0, REG_DWORD, (BYTE*)&dwTypes,
                           sizeof(dwTypes));

register_source:
  /* Register the event source */
  g_hEventLog = RegisterEventSourceA(NULL, TRUSTEDGE_EVENT_SOURCE_NAME);
  if (NULL == g_hEventLog)
  {
    status = ERR_TRUSTEDGE;
  }
  else
  {
#ifdef __ENABLE_DIGICERT_DEBUG_FORWARD__
    /* Register callback to forward DEBUG_CONSOLE_printf output to event log */
    DEBUG_FORWARD_set(TRUSTEDGE_eventLogForwardCallback);
#endif
  }

exit:
  if (NULL != hRegKey)
  {
    RegCloseKey(hRegKey);
  }
  return status;
#else
  return OK;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogShutdown(void)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  if (g_hEventLog != NULL)
  {
    DeregisterEventSource(g_hEventLog);
    g_hEventLog = NULL;
  }
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogInfo(DWORD eventId, const char *message)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[1];
  WORD numStrings = 0;

  if (g_hEventLog == NULL)
    return;

  if (message != NULL)
  {
    strings[0] = message;
    numStrings = 1;
  }

  ReportEventA(g_hEventLog,
               EVENTLOG_INFORMATION_TYPE,
               0,           /* Category */
               eventId,
               NULL,        /* Security ID */
               numStrings,  /* Number of strings */
               0,           /* Binary data size */
               (numStrings > 0) ? strings : NULL,
               NULL);       /* Binary data */
#else
  (void)eventId;
  (void)message;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogInfo2(DWORD eventId, const char *param1, const char *param2)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[2];

  if (g_hEventLog == NULL)
    return;

  strings[0] = param1 ? param1 : "";
  strings[1] = param2 ? param2 : "";

  ReportEventA(g_hEventLog,
               EVENTLOG_INFORMATION_TYPE,
               0,
               eventId,
               NULL,
               2,
               0,
               strings,
               NULL);
#else
  (void)eventId;
  (void)param1;
  (void)param2;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogWarning(DWORD eventId, const char *message)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[1];

  if (g_hEventLog == NULL || message == NULL)
    return;

  strings[0] = message;

  ReportEventA(g_hEventLog,
               EVENTLOG_WARNING_TYPE,
               0,
               eventId,
               NULL,
               1,
               0,
               strings,
               NULL);
#else
  (void)eventId;
  (void)message;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogError(DWORD eventId, const char *message)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[1];

  if (g_hEventLog == NULL || message == NULL)
    return;

  strings[0] = message;

  ReportEventA(g_hEventLog,
               EVENTLOG_ERROR_TYPE,
               0,
               eventId,
               NULL,
               1,
               0,
               strings,
               NULL);
#else
  (void)eventId;
  (void)message;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogError2(DWORD eventId, const char *param1, const char *param2)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  const char *strings[2];

  if (g_hEventLog == NULL)
    return;

  strings[0] = param1 ? param1 : "";
  strings[1] = param2 ? param2 : "";

  ReportEventA(g_hEventLog,
               EVENTLOG_ERROR_TYPE,
               0,
               eventId,
               NULL,
               2,
               0,
               strings,
               NULL);
#else
  (void)eventId;
  (void)param1;
  (void)param2;
#endif
}

/*------------------------------------------------------------------*/

void TRUSTEDGE_eventLogPrintf(int level, const char *format, ...)
{
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  char    buffer[TRUSTEDGE_LOG_BUFFER_SIZE];
  va_list args;
  DWORD   eventId;
  WORD    eventType;
  const char *strings[1];

  if (g_hEventLog == NULL || format == NULL)
    return;

  /* Format the message */
  va_start(args, format);
  _vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
  va_end(args);

  /* Select event ID and type based on level */
  switch (level)
  {
    case TRUSTEDGE_LOG_WARNING:
      eventId = TRUSTEDGE_MSG_WARNING_GENERIC;
      eventType = EVENTLOG_WARNING_TYPE;
      break;
    case TRUSTEDGE_LOG_ERROR:
      eventId = TRUSTEDGE_MSG_ERROR_GENERIC;
      eventType = EVENTLOG_ERROR_TYPE;
      break;
    case TRUSTEDGE_LOG_DEBUG:
      eventId = TRUSTEDGE_MSG_DEBUG;
      eventType = EVENTLOG_INFORMATION_TYPE;
      break;
    case TRUSTEDGE_LOG_INFO:
    default:
      eventId = TRUSTEDGE_MSG_INFO_GENERIC;
      eventType = EVENTLOG_INFORMATION_TYPE;
      break;
  }

  strings[0] = buffer;

  ReportEventA(g_hEventLog,
               eventType,
               0,
               eventId,
               NULL,
               1,
               0,
               strings,
               NULL);
#else
  (void)level;
  (void)format;
#endif
}

#endif /* __RTOS_WIN32__ */
