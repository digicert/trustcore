/*
 * trustedge_agent_zephyr.c
 *
 * Zephyr specific functionality for update packages
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

/* trustedge_agent_linux.c
 *
 * linux specific functionality for update packages
 *
*/
#if defined(__RTOS_LINUX__) && defined(__RTOS_ZEPHYR__)

#include "../../common/common_utils.h"
#include "../../trustedge/utils/trustedge_utils.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_updatepolicy.h"

extern MSTATUS TRUSTEDGE_launchActionHandlerZephyr(
    TrustEdgeArtifactAction *pAction,
    sbyte *pFile,
    TrustEdgeAgentCtx *pCtx
)
{
    MOC_UNUSED(pAction);
    MOC_UNUSED(pFile);
    MOC_UNUSED(pCtx);
    return ERR_NOT_IMPLEMENTED;
}

extern sbyte** TRUSTEDGE_actionHandlerGenerateArgsZephyr(TrustEdgeArtifactAction *pAction)
{
    /* not needed */
    MOC_UNUSED(pAction);
    return NULL;
}

void TRUSTEDGE_actionHandlerDeleteArgsZephyr(TrustEdgeArtifactAction *pAction)
{
    /* not needed */
    MOC_UNUSED(pAction);
}

#endif /* __RTOS_ZEPHYR__ */
