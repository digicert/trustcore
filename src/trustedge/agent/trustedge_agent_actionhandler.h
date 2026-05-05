/*
 * trustedge_agent_actionhandler.h
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

#ifndef __TRUSTEDGE_AGENT_LINUX_HEADER__
#define __TRUSTEDGE_AGENT_LINUX_HEADER__

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__RTOS_ZEPHYR__)
#define TRUSTEDGE_launchActionHandler               TRUSTEDGE_launchActionHandlerZephyr
#define TRUSTEDGE_actionHandlerGenerateArgs         TRUSTEDGE_actionHandlerGenerateArgsZephyr
#define TRUSTEDGE_actionHandlerDeleteArgs           TRUSTEDGE_actionHandlerDeleteArgsZephyr
#elif defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)) /* TODO: What to map to for FreeRTOS ESP32? */
#define TRUSTEDGE_launchActionHandler               TRUSTEDGE_launchActionHandlerLinux
#define TRUSTEDGE_actionHandlerGenerateArgs         TRUSTEDGE_actionHandlerGenerateArgsLinux
#define TRUSTEDGE_actionHandlerDeleteArgs           TRUSTEDGE_actionHandlerDeleteArgsLinux
#elif defined(__RTOS_WIN32__)
#define TRUSTEDGE_launchActionHandler               TRUSTEDGE_launchActionHandlerWindows
#define TRUSTEDGE_actionHandlerGenerateArgs         TRUSTEDGE_actionHandlerGenerateArgsWindows
#define TRUSTEDGE_actionHandlerDeleteArgs           TRUSTEDGE_actionHandlerDeleteArgsWindows
#else
#error UNSUPPORTED PLATFORM
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_launchActionHandler(
    TrustEdgeArtifactAction *pAction,
    sbyte *pFile,
    TrustEdgeAgentCtx *pCtx
);

MOC_EXTERN sbyte** TRUSTEDGE_actionHandlerGenerateArgs(
    TrustEdgeArtifactAction *pAction
);


MOC_EXTERN void TRUSTEDGE_actionHandlerDeleteArgs(
    TrustEdgeArtifactAction *pAction
);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_LINUX_HEADER__ */
