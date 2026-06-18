/**
 * trustedge_service_win.h
 *
 * @file trustedge_service_win.h
 * @brief TrustEdge Windows Service Management
 *
 * Provides Windows Service Control Manager (SCM) integration for TrustEdge.
 * Supports service installation, uninstallation, and running as a Windows service.
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

#ifndef __TRUSTEDGE_SERVICE_WIN_H__
#define __TRUSTEDGE_SERVICE_WIN_H__

#ifdef __RTOS_WIN32__

/*
 * NOTE: This header requires merrors.h to be included before it.
 * The caller (trustedge_main.c) includes moptions.h and merrors.h first.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Service configuration */
#define TRUSTEDGE_SERVICE_NAME          "DigiCertTrustEdge"
#define TRUSTEDGE_SERVICE_DISPLAY_NAME  "DigiCert TrustEdge Agent"
#define TRUSTEDGE_SERVICE_DESCRIPTION   "Manages device identity and certificates via DigiCert Device Trust Manager"

/**
 * @brief Install TrustEdge as a Windows service
 *
 * Registers TrustEdge with the Windows Service Control Manager.
 * The service is configured with Automatic startup type.
 *
 * @return OK on success, error code on failure
 */
MSTATUS TRUSTEDGE_serviceInstall(void);

/**
 * @brief Uninstall TrustEdge Windows service
 *
 * Stops and removes the TrustEdge service from SCM.
 *
 * @return OK on success, error code on failure
 */
MSTATUS TRUSTEDGE_serviceUninstall(void);

/**
 * @brief Run TrustEdge as a Windows service
 *
 * Entry point when running in service mode (--daemon).
 * Registers with SCM and starts the service control dispatcher.
 *
 * @param argc Argument count
 * @param ppArgv Argument values
 * @return OK on success, error code on failure
 */
MSTATUS TRUSTEDGE_serviceRun(int argc, char *ppArgv[]);

/**
 * @brief Check if TrustEdge service is installed
 *
 * @return TRUE if service is installed, FALSE otherwise
 */
int TRUSTEDGE_serviceIsInstalled(void);

/**
 * @brief Check if running in service context
 *
 * @return TRUE if running as a service, FALSE otherwise
 */
int TRUSTEDGE_serviceIsRunningAsService(void);

#ifdef __cplusplus
}
#endif

#endif /* __RTOS_WIN32__ */

#endif /* __TRUSTEDGE_SERVICE_WIN_H__ */
