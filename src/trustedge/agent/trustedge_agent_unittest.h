/*
 * trustedge_agent_unittest.h
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

#include "trustedge_agent.h"
#include "trustedge_agent_priv.h"

MOC_EXTERN MSTATUS TRUSTEDGE_agentParseCertificateSpecification_unit(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCreateNBirthMsg_unit(
    TrustEdgeAgentCtx *pCtx,
    ubyte **ppNBirthMsg,
    ubyte4 *pNBirthMsgLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentParsePendingPolicies_unit(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pJson,
    ubyte4 jsonLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCreateJWSAuth_unit(
    TrustEdgeAgentCtx *pCtx,
    sbyte **ppJWSAuth);

MOC_EXTERN MSTATUS TRUSTEDGE_agentMqttConnect_unit(
    TrustEdgeAgentCtx *pCtx,
    TCP_SOCKET *pSocket,
    sbyte4 *pSSLConnInst,
    certStorePtr pStore);

MOC_EXTERN MSTATUS TRUSTEDGE_agentParseIssuedCertificate_unit(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pBody,
    ubyte4 bodyLen);
