/*
 * ssh_qs.c
 *
 * SSH QS Host Keys
 *
 * These are Post Quantum algorithms.
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

#include "../common/moptions.h"

#if ((defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)) && (defined(__ENABLE_DIGICERT_PQC__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/prime.h"
#include "../common/memory_debug.h"
#include "../common/sizedbuffer.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha1.h"
#include "../ssh/ssh_str.h"
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_str_house.h"
#endif
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
#include "../ssh/client/sshc_str_house.h"
#endif
#include "../ssh/ssh_qs.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#endif

typedef struct QsEntry
{
    sshStringBuffer*        pQsName;
    ubyte4                  qsAlgoId;
    intBoolean              isCertificate;

} QsEntry;

static QsEntry g_qsNames[] =
{
#ifdef __ENABLE_DIGICERT_SSH_SERVER__
        {   &ssh_mldsa44_signature, cid_PQC_MLDSA_44, FALSE },
        {   &ssh_mldsa65_signature, cid_PQC_MLDSA_65, FALSE },
        {   &ssh_mldsa87_signature, cid_PQC_MLDSA_87, FALSE },
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
        {   &ssh_cert_mldsa44_signature, cid_PQC_MLDSA_44, TRUE },
        {   &ssh_cert_mldsa65_signature, cid_PQC_MLDSA_65, TRUE },
        {   &ssh_cert_mldsa87_signature, cid_PQC_MLDSA_87, TRUE },
#endif
#endif
#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
        {   &sshc_mldsa44_signature, cid_PQC_MLDSA_44, FALSE },
        {   &sshc_mldsa65_signature, cid_PQC_MLDSA_65, FALSE },
        {   &sshc_mldsa87_signature, cid_PQC_MLDSA_87, FALSE },
#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
        {   &sshc_cert_mldsa44_signature, cid_PQC_MLDSA_44, TRUE },
        {   &sshc_cert_mldsa65_signature, cid_PQC_MLDSA_65, TRUE },
        {   &sshc_cert_mldsa87_signature, cid_PQC_MLDSA_87, TRUE },
#endif
#endif
};

/* total number of algorithms */
#define SSH_QS_ALGOS sizeof(g_qsNames)/sizeof(QsEntry)

static QsEntry* getQsEntryReference(ubyte4 qsIndex)
{
    if (qsIndex < SSH_QS_ALGOS)
        return &g_qsNames[qsIndex];
    return NULL;
}


/*------------------------------------------------------------------*/

static QsEntry*
SSH_QS_getQsEntryByName(const sshStringBuffer* pQsEntryName)
{
    QsEntry *pEntry;
    ubyte4 i = 0;
    sbyte4 cmpRes;

    while (NULL != (pEntry = getQsEntryReference(i++)))
    {
        if (pQsEntryName->stringLen == pEntry->pQsName->stringLen)
        {
            cmpRes = -1;
            if (OK > DIGI_MEMCMP(pQsEntryName->pString, pEntry->pQsName->pString, pEntry->pQsName->stringLen, &cmpRes))
                return NULL;

            if (0 == cmpRes)
            {
                /* found */
                break;
            }
        }
    }

    return pEntry;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_QS_getQsIdsByName(const sshStringBuffer* pQsEntryName, ubyte4 *pQsAlgoId)
{
    MSTATUS status = OK;
    QsEntry *pEntry;

    if ((NULL == pQsEntryName) || (NULL == pQsAlgoId))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pQsAlgoId = 0;

    pEntry = SSH_QS_getQsEntryByName(pQsEntryName);
    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *pQsAlgoId = pEntry->qsAlgoId;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static QsEntry*
SSH_QS_getQsEntryByIds(ubyte4 qsAlgoId, intBoolean isCertificate)
{
    QsEntry *pEntry;
    ubyte4 i = 0;

    while (NULL != (pEntry = getQsEntryReference(i++)))
    {
        if ((qsAlgoId == pEntry->qsAlgoId) &&
            (isCertificate == pEntry->isCertificate))
        {
            break;
        }
    }
    return pEntry;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_QS_getNameLengthFromIds(ubyte4 qsAlgId, intBoolean isCertificate, ubyte4 *pNameLen)
{
    MSTATUS status = OK;
    QsEntry *pEntry;

    if (NULL == pNameLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEntry = SSH_QS_getQsEntryByIds(qsAlgId, isCertificate);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *pNameLen = DIGI_NTOHL(pEntry->pQsName->pString);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_QS_getNameFromIds(ubyte4 qsAlgId, intBoolean isCertificate, ubyte *pName, ubyte4 nameLen)
{
    MSTATUS status = OK;
    QsEntry *pEntry;
    ubyte4 expectedNameLen;
    sshStringBuffer *pAlgoName = NULL;

    pEntry = SSH_QS_getQsEntryByIds(qsAlgId, isCertificate);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    pAlgoName = pEntry->pQsName;
    expectedNameLen = DIGI_NTOHL(pAlgoName->pString);

    if (expectedNameLen > nameLen)
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    status = DIGI_MEMCPY(pName, pAlgoName->pString + 4, expectedNameLen);

exit:

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SSH_QS_verifyAlgorithmNameEx(const ubyte *pQsName, ubyte4 qsName, sbyte4 *pFound)
{
    MSTATUS status;
    sbyte4 found;
    sshStringBuffer* pAlgoName = NULL;

    if ((NULL == pQsName) || (NULL == pFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = -1;

    status = SSH_STR_makeStringBuffer(&(pAlgoName), qsName + 4);
    if (OK != status)
        goto exit;

    BIGEND32(pAlgoName->pString, qsName);

    status = DIGI_MEMCPY(pAlgoName->pString + 4, pQsName, qsName);
    if (OK != status)
        goto exit;

    found = -1;
    status = SSH_QS_verifyAlgorithmName(pAlgoName, pFound);

exit:

    if (NULL != pAlgoName)
    {
        SSH_STR_freeStringBuffer(&(pAlgoName));
    }
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SSH_QS_verifyAlgorithmName(const sshStringBuffer *pQsEntryName, sbyte4 *pFound)
{
    MSTATUS status = OK;
    QsEntry *pEntry;

    if ((NULL == pQsEntryName) || (NULL == pFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = -1;

    pEntry = SSH_QS_getQsEntryByName(pQsEntryName);
    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *pFound = 0;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_QS_getQsAlgorithmName(ubyte4 qsAlgoId, ubyte4 isCertificate, sshStringBuffer **ppAlgoName)
{
    MSTATUS status = OK;
    QsEntry *pEntry;

    if (NULL == ppAlgoName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEntry = SSH_QS_getQsEntryByIds(qsAlgoId, isCertificate);
    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *ppAlgoName = pEntry->pQsName;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*  This function takes a qs key with the following format:
 *      string  "ssh-<qs>"
 *      byte[n] qs_key_blob
 * 
 *  <qs>         is the QS algorithm information (for example mldsa44).
 *  qs_key_blob  value consists of 4 bytes containing length of
 *               public key, followed by key bytes.
 */
extern MSTATUS
SSH_QS_extractQsKey(MOC_HASH(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                            ubyte4 index, vlong** ppVlongQueue)
{
    sshStringBuffer*        pQsMethod = NULL;
    QS_CTX                  *pQsCtx = NULL;
    ubyte4                  index1 = 4;
    QsEntry                *pEntry;
    MSTATUS                 status;

    if ((NULL == pPublicKeyBlob) || (NULL == pPublicKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get algorithm name */
    if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                     pPublicKeyBlob->stringLen,
                                                     &index1, &pQsMethod)))
    {
        goto exit;
    }

    /* verify qs algorithm is supported */
    pEntry = SSH_QS_getQsEntryByName(pQsMethod);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, pEntry->qsAlgoId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pPublicKeyBlob->pString + index1 + 4,
        pPublicKeyBlob->stringLen - index1 - 4);
    if (OK != status)
        goto exit;

    pPublicKey->type = akt_qs;
    pPublicKey->pQsCtx = pQsCtx;
    pQsCtx = NULL;

exit:

    if (NULL != pQsMethod)
    {
        (void) SSH_STR_freeStringBuffer(&pQsMethod);
    }
    if (NULL != pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
    }

    return status;

} /* SSH_QS_extractQsKey */


/*------------------------------------------------------------------*/

/*  This function builds a qs key with the following format:
 *      string  "ssh-<qs>"
 *      byte[n] qs_key_blob
 * 
 *  <qs>         is the QS algorithm information (for example mldsa44).
 *  qs_key_blob  value consists of 4 bytes containing length of
 *               public key, followed by key bytes.
 */
extern MSTATUS
SSH_QS_buildQsKey(AsymmetricKey *pKey, intBoolean isCertificate,
                  intBoolean isServer, ubyte **ppPublicKeyBlob, ubyte4 *pPublicKeyBlobLen)
{
    MSTATUS status;
    ubyte4 qsAlgId;
    ubyte4 qsKeyLen;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen;
    ubyte *pTmpBuf;
    ubyte *pAlgoName = NULL;
    ubyte4 algoNameLen;

    if ((NULL == pKey) || (NULL == ppPublicKeyBlob) || (NULL == pPublicKeyBlobLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((akt_qs != pKey->type & 0xff) || (NULL == pKey->pQsCtx))
    {
        status = ERR_SSH_EXPECTED_QS_KEY;
        goto exit;
    }

    *ppPublicKeyBlob = NULL;
    *pPublicKeyBlobLen = 0;

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = SSH_QS_getNameLengthFromIds(qsAlgId, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = SSH_QS_getNameFromIds(qsAlgId, isCertificate, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pKey->pQsCtx, &qsKeyLen);
    if (OK != status)
        goto exit;

    keyBlobLen = 4 + algoNameLen + 4 + qsKeyLen;

    status = DIGI_MALLOC((void **) &pKeyBlob, keyBlobLen + 4);
    if (OK != status)
        goto exit;

    pTmpBuf = pKeyBlob;
    
    BIGEND32(pTmpBuf, keyBlobLen);
    pTmpBuf += 4;
    
    BIGEND32(pTmpBuf, algoNameLen);
    pTmpBuf += 4;

    status = DIGI_MEMCPY(pTmpBuf, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    pTmpBuf += algoNameLen;

    BIGEND32(pTmpBuf, qsKeyLen);
    pTmpBuf += 4;

    status = CRYPTO_INTERFACE_QS_getPublicKey(pKey->pQsCtx, pTmpBuf, qsKeyLen);
    if (OK != status)
        goto exit;

    pTmpBuf = NULL;
    *ppPublicKeyBlob = pKeyBlob;
    *pPublicKeyBlobLen = (keyBlobLen + 4);
    pKeyBlob = NULL;

exit:

    if (NULL != pAlgoName)
    {
        (void) DIGI_FREE((void **) &pAlgoName);
    }

    if (NULL != pKeyBlob)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBlob, keyBlobLen + 4);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*  returns value of the largest possible qs signature. */
extern MSTATUS
SSH_QS_calcQsSignatureLength(AsymmetricKey *pKey, intBoolean isCertificate, ubyte4 *pSignatureLength)
{
    MSTATUS status;
    ubyte4 qsSigLen;
    ubyte4 algoNameLen;

    if ((NULL == pKey) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pSignatureLength = 0;

    if (akt_qs != pKey->type)
    {
        status = ERR_SSH_EXPECTED_QS_KEY;
        goto exit;
    }

    status = SSH_QS_getNameLengthFromIds(pKey->pQsCtx->alg, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pKey->pQsCtx, &qsSigLen);
    if (OK != status)
        goto exit;

    *pSignatureLength = 4 + (4 + algoNameLen) + (4 + qsSigLen);

exit:
    return status;
}

/*------------------------------------------------------------------*/

/*  This function builds a signature with the following format:
 *      string  "ssh-<qs>"
 *      byte[n] qs_signature_blob
 * 
 *  <qs>         is the QS algorithm information (for example mldsa44).
 *  qs_key_blob  value consists of 4 bytes containing length of
 *               public key, followed by key bytes.
 */
extern MSTATUS
SSH_QS_buildQsSignature(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate,
                              intBoolean isServer, const ubyte* pHash,
                              ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength)
{
    MSTATUS status;
    ubyte *pSigBuf = NULL;
    ubyte4 sigBufLen;
    ubyte4 qsAlgId;
    ubyte *pAlgoName = NULL;
    ubyte4 algoNameLen;
    ubyte *pQsSig = NULL;
    ubyte4 qsSigLen;
    ubyte *pTmpBuf = NULL;
    ubyte4 tmpBufLen;

    if ((NULL == pKey) || (NULL == pHash) || (NULL == ppSignature) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_qs != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_QS_KEY;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = SSH_QS_getNameLengthFromIds(qsAlgId, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = SSH_QS_getNameFromIds(qsAlgId, isCertificate, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_signAlloc(MOC_HASH(hwAccelCtx) pKey->pQsCtx,
        RANDOM_rngFun, g_pRandomContext, (ubyte *) pHash, hashLen, &pQsSig, &qsSigLen);
    if (OK != status)
        goto exit;

    /* have sufficient data to generate signature */
    sigBufLen = (4 + algoNameLen) + (4 + qsSigLen);

    status = DIGI_MALLOC((void **) &pSigBuf, sigBufLen + 4);
    if (OK != status)
        goto exit;

    pTmpBuf = pSigBuf;
    tmpBufLen = sigBufLen + 4;

    BIGEND32(pTmpBuf, sigBufLen);
    pTmpBuf += 4;
    tmpBufLen -= 4;

    BIGEND32(pTmpBuf, algoNameLen);
    pTmpBuf += 4;
    tmpBufLen -= 4;

    status = DIGI_MEMCPY(pTmpBuf, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    pTmpBuf += algoNameLen;
    tmpBufLen -= algoNameLen;

    BIGEND32(pTmpBuf, qsSigLen);
    pTmpBuf += 4;
    tmpBufLen -= 4;

    status = DIGI_MEMCPY(pTmpBuf, pQsSig, qsSigLen);
    if (OK != status)
        goto exit;
    
    tmpBufLen -= qsSigLen;

    if (0 != tmpBufLen)
    {
        status = ERR_SSH_TRANSPORT;
        goto exit;
    }

    *ppSignature = pSigBuf; pSigBuf = NULL;
    *pSignatureLength = sigBufLen + 4;
    
exit:

    if (NULL != pAlgoName)
    {
        (void) DIGI_FREE((void **) &pAlgoName);
    }
    if (NULL != pQsSig)
    {
        (void) DIGI_MEMSET_FREE(&pQsSig, qsSigLen);
    }
    if (NULL != pSigBuf)
    {
        (void) DIGI_MEMSET_FREE(&pSigBuf, sigBufLen + 4);
    }

    return status;
}


/*------------------------------------------------------------------*/

/*  This function verifies a signature with the following format:
 *      string  "ssh-<qs>"
 *      byte[n] qs_signature_blob
 * 
 *  <qs>         is the QS algorithm information (for example mldsa44).
 *  qs_key_blob  value consists of 4 bytes containing length of
 *               public key, followed by key bytes.
 */
extern MSTATUS
SSH_QS_verifyQsSignature(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey,
                               intBoolean isServer, const ubyte* hash, ubyte4 hashLen,
                               sshStringBuffer* pSignature, intBoolean *pIsGoodSignature,
                               vlong **ppVlongQueue)
{
    MSTATUS status;
    sshStringBuffer *pQsName = NULL;
    sshStringBuffer *pQsSig = NULL;
    ubyte4 index;
    ubyte4 sigResult;
    ubyte4 qsSigLen;
    sbyte4 exists = -1;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    index = 4;
    status = SSH_STR_copyStringFromPayload(pSignature->pString,
                                           pSignature->stringLen,
                                           &index, &pQsName);
    if (OK != status)
        goto exit;

    status = SSH_QS_verifyAlgorithmName((const sshStringBuffer *) pQsName, &exists);
    if (OK != status)
        goto exit;

    if (0 != exists)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    status = SSH_STR_copyStringFromPayload(pSignature->pString,
                                           pSignature->stringLen,
                                           &index, &pQsSig);
    if (OK != status)
        goto exit;

    /* get length of signature from payload */
    qsSigLen = DIGI_NTOHL(pQsSig->pString);

    sigResult = 1;
    status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(hwAccelCtx) pPublicKey->pQsCtx, (ubyte *) hash, hashLen,
        pQsSig->pString + 4, qsSigLen, &sigResult);
    if (OK != status)
        goto exit;

    if (0 == sigResult)
        *pIsGoodSignature = 1;
    else
        *pIsGoodSignature = 0;

exit:

    if (NULL != pQsName)
    {
        (void) SSH_STR_freeStringBuffer(&pQsName);
    }
    if (NULL != pQsSig)
    {
        (void) SSH_STR_freeStringBuffer(&pQsSig);
    }

    return status;

} /* SSH_QS_verifyQsSignature */

#endif /* ((defined(__ENABLE_DIGICERT_PQC__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__))) */
