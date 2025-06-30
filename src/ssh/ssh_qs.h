/*
 * ssh_qs.h
 *
 * SSH QS Host Keys
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 *
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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
