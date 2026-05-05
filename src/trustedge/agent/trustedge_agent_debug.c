/*
 * trustedge_agent_debug.c
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

#include "../../trustedge/agent/trustedge_agent_debug.h"

#if defined(__ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__)

extern MSTATUS TRUSTEDGE_agentKeepMsg(
    TrustEdgeAgentCtx *pAgentCtx,
    sbyte *pFilename,
    ubyte *pData,
    ubyte4 dataLen)
{
    MOC_UNUSED(pAgentCtx);
    MSTATUS status = OK;

    /* TODO: Write to debug directory */
#if 0
    if (NULL != pAgentCtx->pDebugDir)
    {
        

        status = COMMON_UTILS_constructString(
            pAgentCtx->pDebugDir, PATH_SEP, pFilename, &pPath);
        if (OK != status)
        {
            goto exit;
        }

        status = DIGICERT_writeFile(pPath, pData, dataLen);
    }
#else
    status = DIGICERT_writeFile(pFilename, pData, dataLen);
#endif

    return status;
}

#endif /* __ENABLE_DIGICERT_TRUSTEDGE_AGENT_DEBUG_INTERNALS__ */
