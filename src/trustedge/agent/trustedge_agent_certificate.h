/*
 * trustedge_agent_certificate.h
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

#ifndef __TRUSTEDGE_AGENT_CERTIFICATE_HEADER__
#define __TRUSTEDGE_AGENT_CERTIFICATE_HEADER__

#include <stdio.h>

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/common_utils.h"
#include "../../common/base64.h"
#include "../../common/mime_parser.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto/ecc.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/cert_store.h"
#include "../../crypto/crypto_utils.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto_interface/crypto_interface_sha512.h"
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/crypto_interface_ecc.h"
#include "../../trustedge/agent/trustedge_agent_priv.h"
#include "../../trustedge/agent/trustedge_agent_protobuf.h"
#include "../../mqtt/mqtt_client.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS TRUSTEDGE_agentCertificateRenewAll(
    TrustEdgeAgentCtx *pCtx);

MOC_EXTERN MSTATUS TRUSTEDGE_agentParseCertificateRenew(
    TrustEdgeAgentCtx *pCtx,
    ubyte *pBody,
    ubyte4 bodyLen);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCertificateAnyRenewalPending(
    TrustEdgeAgentCtx *pCtx,
    byteBoolean *pIsPending);

MOC_EXTERN MSTATUS TRUSTEDGE_agentCertificateRenewalPending(
    TrustEdgeAgentCtx *pCtx,
    sbyte *pId,
    byteBoolean *pIsPending);

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_AGENT_CERTIFICATE_HEADER__ */
