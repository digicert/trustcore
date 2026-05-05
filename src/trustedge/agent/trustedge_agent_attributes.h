/*
 * trustedge_agent_attributes.h
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

#ifndef __TRUSTEDGE_AGENT_ATTRIBUTES_HEADER__
#define __TRUSTEDGE_AGENT_ATTRIBUTES_HEADER__

#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../common/msg_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_agentCustomerAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    sbyte *pAttributeFile);

MOC_EXTERN MSTATUS TRUSTEDGE_agentInventoryAttributes(
    TrustEdgeAgentCtx *pAgentCtx,
    byteBoolean overwrite);

MOC_EXTERN MSTATUS TRUSTEDGE_agentReplaceWithAttribute(
    TrustEdgeAgentCtx *pAgentCtx,
    ubyte *pExpr,
    ubyte4 exprLen,
    ubyte **ppVal,
    ubyte4 *pValLen);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_ATTRIBUTES_HEADER__ */
