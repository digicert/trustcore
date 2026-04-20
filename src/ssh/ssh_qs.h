/*
 * ssh_qs.h
 *
 * SSH QS Host Keys
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

#ifndef __SSH_QS_HEADER__
#define __SSH_QS_HEADER__

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_verifyAlgorithmName(const sshStringBuffer *pQsEntryName, sbyte4 *pFound);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_verifyAlgorithmNameEx(const ubyte *pQsName, ubyte4 qsName, sbyte4 *pFound);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_getQsAlgorithmName(ubyte4 qsAlgoId, ubyte4 isCertificate, sshStringBuffer **ppAlgoName);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_getQsIdsByName(const sshStringBuffer* pQsEntryName, ubyte4 *pQsAlgoId);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_extractQsKey(MOC_HASH(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey *pPublicKey, ubyte4 index, vlong **ppVlongQueue);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_buildQsKey(AsymmetricKey *pPublicKey, intBoolean isCertificate,
                                     intBoolean isServer, ubyte **ppPublicKeyBlob, ubyte4 *pPublicKeyBlobLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_calcQsSignatureLength(AsymmetricKey *pKey, intBoolean isCertificate, ubyte4 *pSignatureLength);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_buildQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate,
                                           intBoolean isServer, const ubyte* hash,
                                           ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS SSH_QS_verifyQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey, intBoolean isServer, const ubyte* hash, ubyte4 hashLen, sshStringBuffer* pSignature, intBoolean *pIsGoodSignature, vlong **ppVlongQueue);

#endif /* __SSH_QS_HEADER__ */
