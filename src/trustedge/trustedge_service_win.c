/**
 * trustedge_service_win.c
 *
 * @file trustedge_service_win.c
 * @brief TrustEdge Windows Service Implementation
 *
 * Implements Windows Service Control Manager (SCM) integration for TrustEdge.
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

#ifdef __RTOS_WIN32__

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "trustedge_service_win.h"
#include "trustedge_eventlog.h"

#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
#include "trustedge_events.h"
#endif

/* Forward declarations for TrustEdge main */
extern int TRUSTEDGE_main(int argc, char *ppArgv[]);

/* Global shutdown flag from trustedge_main.c */
extern volatile int gShutdownClient;

/* Service status and control handle */
static SERVICE_STATUS          g_ServiceStatus = {0};
static SERVICE_STATUS_HANDLE   g_StatusHandle = NULL;
static HANDLE                  g_StopEvent = NULL;

/* Store original arguments for service main */
static int     g_argc = 0;
static char  **g_ppArgv = NULL;

/* Flag to track if running as service */
static int     g_isService = 0;

/* Worker thread handle and exit status */
static HANDLE  g_WorkerThread = NULL;
static int     g_WorkerStatus = 0;

/**
 * @brief Worker thread function that runs TRUSTEDGE_main
 */
static DWORD WINAPI TRUSTEDGE_serviceWorkerThread(LPVOID lpParam)
{
  MOC_UNUSED(lpParam);
  g_WorkerStatus = TRUSTEDGE_main(g_argc, g_ppArgv);
  /* Signal that worker has completed (wakes up the main wait) */
  if (g_StopEvent != NULL)
  {
    SetEvent(g_StopEvent);
  }
  return 0;
}

/**
 * @brief Report service status to SCM
 */
static void TRUSTEDGE_serviceReportStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
  static DWORD dwCheckPoint = 1;

  g_ServiceStatus.dwCurrentState = dwCurrentState;
  g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
  g_ServiceStatus.dwWaitHint = dwWaitHint;

  if (dwCurrentState == SERVICE_START_PENDING)
  {
    g_ServiceStatus.dwControlsAccepted = 0;
  }
  else
  {
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  }

  if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
  {
    g_ServiceStatus.dwCheckPoint = 0;
  }
  else
  {
    g_ServiceStatus.dwCheckPoint = dwCheckPoint++;
  }

  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

/**
 * @brief Service control handler callback
 */
static VOID WINAPI TRUSTEDGE_serviceCtrlHandler(DWORD dwCtrl)
{
  switch (dwCtrl)
  {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
      TRUSTEDGE_serviceReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 3000);
      /* Signal the main thread to stop */
      if (g_StopEvent != NULL)
      {
        SetEvent(g_StopEvent);
      }
      return;

    case SERVICE_CONTROL_INTERROGATE:
      break;

    default:
      break;
  }

  TRUSTEDGE_serviceReportStatus(g_ServiceStatus.dwCurrentState, NO_ERROR, 0);
}

/**
 * @brief Service main entry point (called by SCM)
 */
static VOID WINAPI TRUSTEDGE_serviceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
  int status;

  /* Unused - SCM passes service name; we use original args from g_ppArgv */
  MOC_UNUSED(dwArgc);
  MOC_UNUSED(lpszArgv);

  /* Register the service control handler */
  g_StatusHandle = RegisterServiceCtrlHandler(TRUSTEDGE_SERVICE_NAME, TRUSTEDGE_serviceCtrlHandler);
  if (g_StatusHandle == NULL)
  {
    return;
  }

  /* Initialize service status */
  g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_ServiceStatus.dwServiceSpecificExitCode = 0;

  /* Report initial status */
  TRUSTEDGE_serviceReportStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

  /* Initialize Windows Event Log */
  TRUSTEDGE_eventLogInit();

  /* Create stop event */
  g_StopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (g_StopEvent == NULL)
  {
    TRUSTEDGE_serviceReportStatus(SERVICE_STOPPED, GetLastError(), 0);
    return;
  }

  /* Report running status */
  TRUSTEDGE_serviceReportStatus(SERVICE_RUNNING, NO_ERROR, 0);

  /* Log service started to Windows Event Log */
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  TRUSTEDGE_eventLogInfo(TRUSTEDGE_MSG_SERVICE_STARTED, NULL);
#endif

  /* Set service flag */
  g_isService = 1;

  /* Create worker thread to run TrustEdge main */
  g_WorkerThread = CreateThread(NULL, 0, TRUSTEDGE_serviceWorkerThread, NULL, 0, NULL);
  if (g_WorkerThread == NULL)
  {
    TRUSTEDGE_serviceReportStatus(SERVICE_STOPPED, GetLastError(), 0);
    CloseHandle(g_StopEvent);
    g_StopEvent = NULL;
    g_isService = 0;
    return;
  }

  /* Wait for stop event (triggered by SCM stop/shutdown or worker completion) */
  WaitForSingleObject(g_StopEvent, INFINITE);

  /* Signal TrustEdge to shut down gracefully */
  gShutdownClient = 1;

  /* Wait for worker thread to complete (with timeout to avoid hanging).
   * Note: We do NOT call TerminateThread on timeout - it's unsafe and can leave
   * resources leaked/state inconsistent. Instead, we report the timeout and let
   * SCM handle forcibly terminating the process if needed. */
  if (WaitForSingleObject(g_WorkerThread, 30000) == WAIT_TIMEOUT)
  {
    /* Worker thread did not exit in time - report failure.
     * SCM will forcibly terminate the process after its timeout. */
    status = -1;
  }
  else
  {
    status = g_WorkerStatus;
  }

  /* Cleanup */
  if (g_WorkerThread != NULL)
  {
    CloseHandle(g_WorkerThread);
    g_WorkerThread = NULL;
  }

  if (g_StopEvent != NULL)
  {
    CloseHandle(g_StopEvent);
    g_StopEvent = NULL;
  }

  g_isService = 0;

  /* Log service stopped to Windows Event Log */
#ifdef __ENABLE_TRUSTEDGE_WIN32_EVENTS__
  TRUSTEDGE_eventLogInfo(TRUSTEDGE_MSG_SERVICE_STOPPED, NULL);
#endif

  /* Shutdown Windows Event Log */
  TRUSTEDGE_eventLogShutdown();

  /* Report stopped - set specific exit code for failures so it appears in Event Log */
  g_ServiceStatus.dwServiceSpecificExitCode = (status == 0) ? 0 : (DWORD)status;
  TRUSTEDGE_serviceReportStatus(SERVICE_STOPPED, (status == 0) ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

/**
 * @brief Get the path to the current executable
 */
static MSTATUS TRUSTEDGE_serviceGetExePath(char *pPath, DWORD dwSize)
{
  DWORD result;

  result = GetModuleFileNameA(NULL, pPath, dwSize);
  if (result == 0 || result >= dwSize)
  {
    return ERR_TRUSTEDGE;
  }

  return OK;
}

MSTATUS TRUSTEDGE_serviceInstall(void)
{
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  char szPath[MAX_PATH];
  char szServiceCmd[MAX_PATH + 64];
  SERVICE_DESCRIPTIONA sd;

  /* Get executable path */
  if (OK != TRUSTEDGE_serviceGetExePath(szPath, MAX_PATH))
  {
    fprintf(stderr, "Error: Cannot get executable path\n");
    return ERR_TRUSTEDGE;
  }

  /* Build service command: "path\to\trustedge.exe" --daemon */
  {
    int written = snprintf(szServiceCmd, sizeof(szServiceCmd), "\"%s\" --daemon", szPath);
    if (written < 0 || (size_t)written >= sizeof(szServiceCmd))
    {
      fprintf(stderr, "Error: Executable path too long for service command\n");
      return ERR_TRUSTEDGE;
    }
  }

  /* Open SCM */
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (schSCManager == NULL)
  {
    fprintf(stderr, "Error: OpenSCManager failed (%lu). Run as Administrator.\n", GetLastError());
    return ERR_TRUSTEDGE;
  }

  /* Check if service already exists */
  schService = OpenServiceA(schSCManager, TRUSTEDGE_SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (schService != NULL)
  {
    fprintf(stderr, "Service '%s' is already installed.\n", TRUSTEDGE_SERVICE_NAME);
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return OK;
  }

  /* Create the service */
  schService = CreateServiceA(
    schSCManager,
    TRUSTEDGE_SERVICE_NAME,
    TRUSTEDGE_SERVICE_DISPLAY_NAME,
    SERVICE_ALL_ACCESS,
    SERVICE_WIN32_OWN_PROCESS,
    SERVICE_AUTO_START,             /* Start automatically at boot */
    SERVICE_ERROR_NORMAL,
    szServiceCmd,
    NULL,                           /* No load ordering group */
    NULL,                           /* No tag identifier */
    "Tcpip\0Dnscache\0",            /* Wait for networking and DNS (like Linux After=network.target) */
    NULL,                           /* LocalSystem account */
    NULL                            /* No password */
  );

  if (schService == NULL)
  {
    fprintf(stderr, "Error: CreateService failed (%lu)\n", GetLastError());
    CloseServiceHandle(schSCManager);
    return ERR_TRUSTEDGE;
  }

  /* Set service description */
  sd.lpDescription = TRUSTEDGE_SERVICE_DESCRIPTION;
  if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_DESCRIPTION, &sd))
  {
    fprintf(stderr, "Warning: Failed to set service description (%lu)\n", GetLastError());
  }

  /* Set failure recovery actions (matches Linux Restart=always RestartSec=60) */
  {
    SC_ACTION failureActions[3];
    SERVICE_FAILURE_ACTIONSA sfa;

    /* Restart after 60 seconds on each failure (matching Linux RestartSec=60) */
    failureActions[0].Type = SC_ACTION_RESTART;
    failureActions[0].Delay = 60000;  /* 60 seconds in milliseconds */
    failureActions[1].Type = SC_ACTION_RESTART;
    failureActions[1].Delay = 60000;
    failureActions[2].Type = SC_ACTION_RESTART;
    failureActions[2].Delay = 60000;

    sfa.dwResetPeriod = 86400;  /* Reset failure count after 24 hours */
    sfa.lpRebootMsg = NULL;
    sfa.lpCommand = NULL;
    sfa.cActions = 3;
    sfa.lpsaActions = failureActions;

    if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa))
    {
      fprintf(stderr, "Warning: Failed to set failure recovery actions (%lu)\n", GetLastError());
    }
  }

  /* Enable failure actions even on clean exit (exit code 0)
   * This matches Linux systemd Restart=always behavior */
  {
    SERVICE_FAILURE_ACTIONS_FLAG sfaf;
    sfaf.fFailureActionsOnNonCrashFailures = TRUE;

    if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &sfaf))
    {
      fprintf(stderr, "Warning: Failed to set failure actions flag (%lu)\n", GetLastError());
    }
  }

  fprintf(stdout, "Service '%s' installed successfully.\n", TRUSTEDGE_SERVICE_NAME);
  fprintf(stdout, "  Display Name: %s\n", TRUSTEDGE_SERVICE_DISPLAY_NAME);
  fprintf(stdout, "  Startup Type: Automatic\n");
  fprintf(stdout, "  The service will start automatically on system boot.\n");
  fprintf(stdout, "\nTo start the service:\n");
  fprintf(stdout, "  sc start %s\n", TRUSTEDGE_SERVICE_NAME);
  fprintf(stdout, "  -or-\n");
  fprintf(stdout, "  net start %s\n", TRUSTEDGE_SERVICE_NAME);

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  return OK;
}

MSTATUS TRUSTEDGE_serviceUninstall(void)
{
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  SERVICE_STATUS svcStatus;
  MSTATUS status = OK;

  /* Open SCM */
  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (schSCManager == NULL)
  {
    fprintf(stderr, "Error: OpenSCManager failed (%lu). Run as Administrator.\n", GetLastError());
    return ERR_TRUSTEDGE;
  }

  /* Open the service */
  schService = OpenServiceA(schSCManager, TRUSTEDGE_SERVICE_NAME, 
    SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (schService == NULL)
  {
    DWORD dwErr = GetLastError();
    if (dwErr == ERROR_SERVICE_DOES_NOT_EXIST)
    {
      fprintf(stderr, "Service '%s' is not installed.\n", TRUSTEDGE_SERVICE_NAME);
    }
    else
    {
      fprintf(stderr, "Error: OpenService failed (%lu)\n", dwErr);
    }
    CloseServiceHandle(schSCManager);
    return (dwErr == ERROR_SERVICE_DOES_NOT_EXIST) ? OK : ERR_TRUSTEDGE;
  }

  /* Stop the service if running */
  if (QueryServiceStatus(schService, &svcStatus))
  {
    if (svcStatus.dwCurrentState != SERVICE_STOPPED)
    {
      fprintf(stdout, "Stopping service '%s'...\n", TRUSTEDGE_SERVICE_NAME);
      if (ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus))
      {
        /* Wait for service to stop */
        int waitCount = 0;
        while (svcStatus.dwCurrentState != SERVICE_STOPPED && waitCount < 30)
        {
          Sleep(1000);
          if (!QueryServiceStatus(schService, &svcStatus))
          {
            break;
          }
          waitCount++;
        }
      }
    }
  }

  /* Delete the service */
  if (!DeleteService(schService))
  {
    fprintf(stderr, "Error: DeleteService failed (%lu)\n", GetLastError());
    status = ERR_TRUSTEDGE;
  }
  else
  {
    fprintf(stdout, "Service '%s' uninstalled successfully.\n", TRUSTEDGE_SERVICE_NAME);
  }

  CloseServiceHandle(schService);
  CloseServiceHandle(schSCManager);

  return status;
}

MSTATUS TRUSTEDGE_serviceRun(int argc, char *ppArgv[])
{
  SERVICE_TABLE_ENTRYA DispatchTable[] = {
    { TRUSTEDGE_SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA) TRUSTEDGE_serviceMain },
    { NULL, NULL }
  };

  /* Store arguments for use in ServiceMain */
  g_argc = argc;
  g_ppArgv = ppArgv;

  /* Start service control dispatcher */
  if (!StartServiceCtrlDispatcherA(DispatchTable))
  {
    DWORD dwErr = GetLastError();
    
    /* If not started as a service, run in console mode */
    if (dwErr == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
    {
      /* Running in console mode, not as a service
       * Return special status to indicate caller should run normally
       */
      return ERR_TRUSTEDGE_AGENT_FEATURE_NOT_AVAILABLE;
    }
    
    fprintf(stderr, "Error: StartServiceCtrlDispatcher failed (%lu)\n", dwErr);
    return ERR_TRUSTEDGE;
  }

  return OK;
}

int TRUSTEDGE_serviceIsInstalled(void)
{
  SC_HANDLE schSCManager = NULL;
  SC_HANDLE schService = NULL;
  int isInstalled = 0;

  schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
  if (schSCManager != NULL)
  {
    schService = OpenServiceA(schSCManager, TRUSTEDGE_SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (schService != NULL)
    {
      isInstalled = 1;
      CloseServiceHandle(schService);
    }
    CloseServiceHandle(schSCManager);
  }

  return isInstalled;
}

int TRUSTEDGE_serviceIsRunningAsService(void)
{
  return g_isService;
}

#endif /* __RTOS_WIN32__ */
