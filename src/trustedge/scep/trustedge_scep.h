/**
 * trustedge_scep.h
 *
 * @brief Trustedge scep tool
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
 */

#ifndef __TRUSTEDGE_SCEP_HEADER__
#define __TRUSTEDGE_SCEP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define PKI_OPERATION_ENROLL "PKCSReq"
#define PKI_OPERATION_RENEW  "RenewalReq"
#define PKI_OPERATION_REKEY  "RekeyReq"
#define GET_CLIENT_CERT      "GetCert"
#define GET_CRL              "GetCRL"
#define GET_CA_CERT          "GetCACert"
#define GET_NEXT_CA_CERT     "GetNextCACert"
#define GET_CA_CAPS          "GetCACaps"

typedef struct _ScepServiceCtx
{
    byteBoolean serviceMode;
    ubyte4 cmdStatus;
    SCEP_failInfo failInfo;
    ubyte *pCSRAttrBuffer;
    ubyte4 csrAttrBufferLen;
    sbyte4 maxRetryCount;
    byteBoolean reuseKey;
} ScepServiceCtx;

typedef struct _TrustEdgeScepCtx
{
    sbyte *pScepServerUrl;
    sbyte *pFilePath;
    sbyte *pKeyAlias;
    sbyte *pCertAlias;
    ubyte serverType;
    byteBoolean supportsPost;
    sbyte *pChallengePass;
    sbyte *pPkiOperation;
    const ubyte *pEncAlgoOid;
    const ubyte *pHashOid;
    ubyte4 hashId;
    byteBoolean oaep;
    sbyte *pLabel;
    ubyte4 oaepHashId;
    sbyte *pCepCertFileName;      /* SCEP-Addon/RA Certificate - CEP Encryption */
    ScepServiceCtx serviceCtx;
#if 0
    /* still hardcoded names, at least for now */
    sbyte *caCertFileName;       /* CA certificate. For Windows NDES is the RA(SCEP server) use the RA cert with key usage Digital signature */
    sbyte *adminCertFileName;    /* Admin certificate. */
    sbyte *exchangeCertFileName; /* RA Certificate that is the Enrollment Agent */
#endif

} TrustEdgeScepCtx;
#if !defined(__DISABLE_TRUSTEDGE_SCEP__)
MOC_EXTERN MSTATUS TRUSTEDGE_SCEP_main(KeyGenArgs *pKeyArgs, TrustEdgeScepCtx *pScepArgs, TrustEdgeServiceCtx *pSrvCtx, void *pTapArgs);
#endif

#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_SCEP_HEADER__ */
