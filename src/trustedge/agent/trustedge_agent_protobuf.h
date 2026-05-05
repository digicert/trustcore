/*
 * trustedge_agent_protobuf.h
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

#ifndef __TRUSTEDGE_AGENT_PROTOBUF_HEADER__
#define __TRUSTEDGE_AGENT_PROTOBUF_HEADER__

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/protobuf.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_agentProtobufProcess(
    TrustEdgeAgentCtx *pAgentCtx,
    ubyte *pPayload,
    ubyte4 payloadLen,
    byteBoolean finished);

MOC_EXTERN MSTATUS TRUSTEDGE_agentProtobufCreate(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pUUID,
    ubyte *pBodyMsg,
    ubyte4 bodyMsgLen,
    ubyte **ppPBMsg,
    ubyte4 *pPBMsgLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentProtobufLoadMetricFile(
    TrustEdgeAgentCtx *pAgentCtx,
    FileChoice fileChoice);

MOC_EXTERN MSTATUS TRUSTEDGE_agentProtobufPrintMessage(
    ubyte *pMsg,
    ubyte4 msgLen);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_PROTOBUF_HEADER__ */
