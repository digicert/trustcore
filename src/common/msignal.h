/**
 * @file   msignal.h
 * @brief  Mocana Signal Handling Abstraction Layer
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

/*------------------------------------------------------------------*/

#ifndef __MSIGNAL_HEADER__
#define __MSIGNAL_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#include "merrors.h"

/*------------------------------------------------------------------*/

/* Platform-agnostic signal definitions */
#define MSIGINT      2  /* Interrupt signal (Ctrl+C) */
#define MSIGTERM    15  /* Termination signal */

/*------------------------------------------------------------------*/

/* Signal handler callback function type */
typedef void (*funcPtrSignalHandlerCallback)(int sig);

/*------------------------------------------------------------------*/

#if defined(__RTOS_WIN32__)

#define SIGNAL_registerHandler     WIN32_registerHandler

#elif defined(__RTOS_LINUX__)

#define SIGNAL_registerHandler     LINUX_registerHandler

#endif

/*------------------------------------------------------------------*/

/**
 * @brief Register a signal handler for the specified signal.
 *
 * @param sig      Signal number (MSIGINT or MSIGTERM)
 * @param handler  Callback function to handle the signal
 *
 * @return OK on success, error code on failure
 */
MOC_EXTERN MSTATUS SIGNAL_registerHandler(
    int sig,
    funcPtrSignalHandlerCallback handler);

/*------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __MSIGNAL_HEADER__ */
