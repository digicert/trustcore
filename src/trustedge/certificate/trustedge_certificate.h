/*
 * trustedge_certificate.h
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

#ifndef __TRUSTEDGE_CERTIFICATE_HEADER__
#define __TRUSTEDGE_CERTIFICATE_HEADER__

#include "../../common/moptions.h"
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    CERT_MODE,
    SCEP_MODE,
    EST_MODE
} E_CertEnrollMode;

typedef enum {
    TE_AGENT_INVALID_MODE,
    TE_AGENT_CLI_MODE,
    TE_AGENT_DAEMON_MODE,
    TE_AGENT_REST_API_MODE
} E_TEAgentMode;

#if !defined(__DISABLE_TRUSTEDGE_SCEP__) || !defined(__DISABLE_TRUSTEDGE_EST__)

typedef MSTATUS ((*funcPtrResourceUpdateHandler)(void *pResource));

typedef struct
{
    sbyte *pOperation;
    sbyte *pURI;
    sbyte *pPassword;
    sbyte *pAlgo;
    sbyte *pKeyAlias;
    sbyte *pKeySource;
    sbyte *pKeyOutFormat;
    sbyte *pPkcs8Attrs;
    sbyte *pPkcs8Pass;
    sbyte *pPkcs8EncAlgo;
    sbyte *pPkcs12Attrs;
    sbyte *pPkcs12IntPass;
    sbyte *pPkcs12PriPass;
    sbyte *pPkcs12KeyPass;
    sbyte *pPkcs12EncAlgo;
    sbyte *pKeyStore;
    sbyte *pReqFile;
    ubyte4 sleepInterval;
    ubyte4 renewalHours;
    sbyte *pCertThumbPrint;
    ubyte *pCertSerialNum;
    ubyte *pCertIssuer;
    TimeDate pCertExpiry;
    intBoolean reuseKey;
#ifndef __DISABLE_TRUSTEDGE_SCEP__
    sbyte *pCepCert;
    sbyte *pCertAlias;
#endif
#ifndef __DISABLE_TRUSTEDGE_EST__
    sbyte  *pIP;
    sbyte  *pPort;
    sbyte  *pName;
    sbyte  *pFQDN;
    sbyte  *pTlsCert;
    sbyte  *pRekeyAlias;
    sbyte  *pCAPrefix;
    sbyte  *pAuthScheme;
#endif
#ifdef __ENABLE_DIGICERT_TAP__
    ubyte4 modNum;
    ubyte4 tapProvider;
    sbyte  *pKeyUsage;
    sbyte  *pSignScheme;
    sbyte  *pEncScheme;
#endif
} TrustEdgeServiceCtx;
#endif

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_CERTIFICATE_HEADER__ */
