/*
 * ssh_rsa.h
 *
 * SSH RSA Host Keys
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

#ifndef __SSH_RSA_HEADER__
#define __SSH_RSA_HEADER__

#ifndef MIN_SSH_RSA_SIZE
#define MIN_SSH_RSA_SIZE                (2048)
#endif


/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_buildRsaCertificate(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen);

#ifdef __ENABLE_DIGICERT_SSH_SERVER__
/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_buildRsaHostBlobCertificate(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen, ubyte4 hashLen);
#endif

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_buildRsaSignature(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte **ppSignature, ubyte4 *pSignatureLength, ubyte *pInDataToSign, ubyte4 inDataToSignLen, ubyte *pAlgorithmName, ubyte4 algorithmNameLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_calcRsaSignatureLength(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_buildRsaSha1Signature(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte **ppSignature, ubyte4 *pSignatureLength, ubyte *pInDataToSign, ubyte4 inDataToSignLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_extractRsaCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey, ubyte4 index, vlong **ppVlongQueue);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_RSA_verifyRsaSignature(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isServer, ubyte *pExpectedPlainText, ubyte4 expectedPlainTextLen, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

#endif /* __SSH_RSA_HEADER__ */
