/*
 * trustedge_agent_threadx.c
 *
 * ThreadX/AzureRTOS stubs for TrustEdge OTA update action handlers.
 * Process launching is not supported on this platform; these functions
 * return failure so the cert-enrollment MQTT path continues unaffected.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 * Licensed under AGPL v3 or a DigiCert commercial license.
 */

#if defined(__RTOS_THREADX__) || defined(__RTOS_AZURE__)

#include "../../common/common_utils.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

extern MSTATUS TRUSTEDGE_launchActionHandlerThreadX(
    TrustEdgeArtifactAction *pAction,
    sbyte *pFile,
    TrustEdgeAgentCtx *pCtx
)
{
    (void)pAction;
    (void)pFile;
    (void)pCtx;
    return ERR_TRUSTEDGE_AGENT_ACTION_FAILED;
}

extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsThreadX(TrustEdgeArtifactAction *pAction)
{
    (void)pAction;
    return NULL;
}

void TRUSTEDGE_actionHandlerDeleteArgsThreadX(TrustEdgeArtifactAction *pAction)
{
    (void)pAction;
}

#endif /* __RTOS_THREADX__ || __RTOS_AZURE__ */
