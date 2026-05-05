/*
 * trustedge_agent_persist.h
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

#ifndef __TRUSTEDGE_AGENT_PERSIST_HEADER__
#define __TRUSTEDGE_AGENT_PERSIST_HEADER__

#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../common/mfmgmt.h"
#include "../../common/common_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistConfiguration(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistLoadConfiguration(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistDelete(
    TrustEdgeConfig *pConfig);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistCertSpec(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pCertSpec,
    ubyte4 certSpecLen,
    sbyte *pKeySource,
    ubyte4 keySourceLen,
    sbyte *pKeyAlgorithm,
    ubyte4 keyAlgorithmLen,
    sbyte *pKeyAlias);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistCertSpecAddCert(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    ubyte *pCSR,
    ubyte4 csrLen,
    sbyte *pCertAlias,
    ubyte *pCert,
    ubyte4 certLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistCertSpecAddOrUpdateRenewRequestTime(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId);

MOC_EXTERN MSTATUS TRUSTEDGE_agentPersistCertSpecUpdate(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    ubyte *pCert,
    ubyte4 certLen);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_PERSIST_HEADER__ */
