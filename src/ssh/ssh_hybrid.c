/*
 * ssh_hybrid.c
 *
 * SSH Hybrid Host Keys
 *
 * These are a combination of a classical algorithm and Post Quantum
 * algorithm.
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

#if ((defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)) && (defined(__ENABLE_MOCANA_PQC__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__)))

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
#include "../crypto/ecc.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/sha1.h"
#include "../ssh/ssh_str.h"
#ifdef __ENABLE_MOCANA_SSH_SERVER__
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_str_house.h"
#endif
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
#include "../ssh/client/sshc_str_house.h"
#endif
#include "../ssh/ssh_ecdsa.h"
#include "../ssh/ssh_hybrid.h"
#include "../ssh/ssh_mpint.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_ecc.h"
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif

typedef struct HybridEntry
{
    sshStringBuffer*        pHybridName;
    ubyte4                  keyType;
    ubyte4                  qsAlgoId;
    ubyte4                  curveId; /* used only when keyType == akt_ecc */
    intBoolean              isCertificate;
} HybridEntry;

static HybridEntry g_hybridNames[] =
{
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        {   &ssh_mldsa44_p256_signature,          akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_P256,    FALSE },
        {   &ssh_mldsa65_p256_signature,          akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_P256,    FALSE },
        {   &ssh_mldsa87_p384_signature,          akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_P384,    FALSE },
        {   &ssh_mldsa44_ed25519_signature,       akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_Ed25519, FALSE },
        {   &ssh_mldsa65_ed25519_signature,       akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_Ed25519, FALSE },
        {   &ssh_mldsa87_ed448_signature,         akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_Ed448,   FALSE },
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
        {   &ssh_cert_mldsa44_p256_signature,     akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_P256,    TRUE },
        {   &ssh_cert_mldsa65_p256_signature,     akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_P256,    TRUE },
        {   &ssh_cert_mldsa87_p384_signature,     akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_P384,    TRUE },
        {   &ssh_cert_mldsa44_ed25519_signature,  akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_Ed25519, TRUE },
        {   &ssh_cert_mldsa65_ed25519_signature,  akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_Ed25519, TRUE },
        {   &ssh_cert_mldsa87_ed448_signature,    akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_Ed448,   TRUE },
#endif
#endif
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        {   &sshc_mldsa44_p256_signature,         akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_P256,    FALSE },
        {   &sshc_mldsa65_p256_signature,         akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_P256,    FALSE },
        {   &sshc_mldsa87_p384_signature,         akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_P384,    FALSE },
        {   &sshc_mldsa44_ed25519_signature,      akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_Ed25519, FALSE },
        {   &sshc_mldsa65_ed25519_signature,      akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_Ed25519, FALSE },
        {   &sshc_mldsa87_ed448_signature,        akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_Ed448,   FALSE },
#ifdef __ENABLE_MOCANA_PRE_DRAFT_PQC__
        {   &sshc_cert_mldsa44_p256_signature,    akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_P256,    TRUE },
        {   &sshc_cert_mldsa65_p256_signature,    akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_P256,    TRUE },
        {   &sshc_cert_mldsa87_p384_signature,    akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_P384,    TRUE },
        {   &sshc_cert_mldsa44_ed25519_signature, akt_ecc,    cid_PQC_MLDSA_44,  cid_EC_Ed25519, TRUE },
        {   &sshc_cert_mldsa65_ed25519_signature, akt_ecc,    cid_PQC_MLDSA_65,  cid_EC_Ed25519, TRUE },
        {   &sshc_cert_mldsa87_ed448_signature,   akt_ecc,    cid_PQC_MLDSA_87,  cid_EC_Ed448,   TRUE },
#endif
#endif
};

/* total number of algorithms */
#define SSH_HYBRID_ALGOS sizeof(g_hybridNames)/sizeof(HybridEntry)

static HybridEntry* getHybridEntryReference(ubyte4 hybridIndex)
{
    if (hybridIndex < SSH_HYBRID_ALGOS)
        return &g_hybridNames[hybridIndex];
    return NULL;
}


/*------------------------------------------------------------------*/

static HybridEntry*
SSH_HYBRID_getHybridEntryByName(const sshStringBuffer* pHybridEntryName)
{
    MSTATUS status = OK;
    HybridEntry *pEntry;
    ubyte4 i = 0;
    sbyte4 cmpRes;

    while (NULL != (pEntry = getHybridEntryReference(i++)))
    {
        if (pHybridEntryName->stringLen == pEntry->pHybridName->stringLen)
        {
            cmpRes = -1;
            if (OK > MOC_MEMCMP(pHybridEntryName->pString, pEntry->pHybridName->pString, pEntry->pHybridName->stringLen, &cmpRes))
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
SSH_HYBRID_getHybridIdsByName(const sshStringBuffer* pHybridEntryName, ubyte4 *pCurveId, ubyte4 *pQsAlgoId)
{
    MSTATUS status = OK;
    ubyte4 eccIndex;
    ubyte4 qsIndex;
    HybridEntry *pEntry;

    if ((NULL == pHybridEntryName) || (NULL == pCurveId) || (NULL == pQsAlgoId))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pCurveId = 0;
    *pQsAlgoId = 0;

    pEntry = SSH_HYBRID_getHybridEntryByName(pHybridEntryName);
    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *pCurveId = pEntry->curveId;
    *pQsAlgoId = pEntry->qsAlgoId;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static HybridEntry*
SSH_HYBRID_getHybridEntryByIds(ubyte4 curveId, ubyte4 qsAlgoId, intBoolean isCertificate)
{
    HybridEntry *pEntry;
    ubyte4 i = 0;

    while (NULL != (pEntry = getHybridEntryReference(i++)))
    {
        if ((curveId == pEntry->curveId)  && (qsAlgoId == pEntry->qsAlgoId) &&
            (isCertificate == pEntry->isCertificate))
        {
            break;
        }
    }
    return pEntry;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_HYBRID_getNameLengthFromIds(ubyte4 curveId, ubyte4 qsAlgId, intBoolean isCertificate, ubyte4 *pNameLen)
{
    MSTATUS status = OK;
    HybridEntry *pEntry;

    if (NULL == pNameLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEntry = SSH_HYBRID_getHybridEntryByIds(curveId, qsAlgId, isCertificate);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *pNameLen = MOC_NTOHL(pEntry->pHybridName->pString);

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_HYBRID_getNameFromIds(ubyte4 curveId, ubyte4 qsAlgId, intBoolean isCertificate, ubyte *pName, ubyte4 nameLen)
{
    MSTATUS status = OK;
    HybridEntry *pEntry;
    ubyte4 expectedNameLen;
    sshStringBuffer *pAlgoName = NULL;

    pEntry = SSH_HYBRID_getHybridEntryByIds(curveId, qsAlgId, isCertificate);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    pAlgoName = pEntry->pHybridName;
    expectedNameLen = MOC_NTOHL(pAlgoName->pString);

    if (expectedNameLen > nameLen)
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    status = MOC_MEMCPY(pName, pAlgoName->pString + 4, expectedNameLen);
    if (OK != status)
        goto exit;

exit:
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS SSH_HYBRID_verifyAlgorithmNameEx(const ubyte *pHybridName, ubyte4 hybridName, sbyte4 *pFound)
{
    MSTATUS status;
    sbyte4 found;
    sshStringBuffer* pAlgoName = NULL;

    if ((NULL == pHybridName) || (NULL == pFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = -1;

    status = SSH_STR_makeStringBuffer(&(pAlgoName), hybridName + 4);
    if (OK != status)
        goto exit;

    BIGEND32(pAlgoName->pString, hybridName);

    status = MOC_MEMCPY(pAlgoName->pString + 4, pHybridName, hybridName);
    if (OK != status)
        goto exit;

    found = -1;
    status = SSH_HYBRID_verifyAlgorithmName(pAlgoName, pFound);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pAlgoName)
    {
        SSH_STR_freeStringBuffer(&(pAlgoName));
    }
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS SSH_HYBRID_verifyAlgorithmName(const sshStringBuffer *pHybridEntryName, sbyte4 *pFound)
{
    MSTATUS status = OK;
    HybridEntry *pEntry;

    if ((NULL == pHybridEntryName) || (NULL == pFound))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFound = -1;

    pEntry = SSH_HYBRID_getHybridEntryByName(pHybridEntryName);
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
SSH_HYBRID_getHybridAlgorithmName(ubyte4 curveId, ubyte4 qsAlgoId, ubyte4 isCertificate, sshStringBuffer **ppAlgoName)
{
    MSTATUS status = OK;
    HybridEntry *pEntry;

    if (NULL == ppAlgoName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEntry = SSH_HYBRID_getHybridEntryByIds(curveId, qsAlgoId, isCertificate);
    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    *ppAlgoName = pEntry->pHybridName;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*  This function takes a hybrid key with the following format:
 *      string  "ssh-<qs>-<ecc>"
 *      string  concatenated hybrid key.
 * 
 *  <ecc> is the ECC curve information.
 *  <qs>  is the QS algorithm information.
 */
extern MSTATUS
SSH_HYBRID_extractHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                            ubyte4 index, vlong** ppVlongQueue)
{
    sshStringBuffer*        pHybridMethod = NULL;
    QS_CTX                  *pQsCtx = NULL;
    ECCKey                  *pEccKey = NULL;
    ubyte4                  index1 = 4;
    HybridEntry             *pEntry;
    ubyte4                  qsLen;
    MSTATUS                 status;

    if ((NULL == pPublicKeyBlob) || (NULL == pPublicKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get algorithm name */
    if (OK > (status = SSH_STR_copyStringFromPayload(pPublicKeyBlob->pString,
                                                     pPublicKeyBlob->stringLen,
                                                     &index1, &pHybridMethod)))
    {
        goto exit;
    }

    /* verify hybrid algorithm is supported */
    pEntry = SSH_HYBRID_getHybridEntryByName(pHybridMethod);

    if (NULL == pEntry)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    /* QS portion */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, pEntry->qsAlgoId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &qsLen);
    if (OK != status)
        goto exit; 

    index1 += 4;
    status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pPublicKeyBlob->pString + index1, qsLen);
    if (OK != status)
        goto exit;

    /* ECC portion */
    status = CRYPTO_INTERFACE_EC_newKeyAux(pEntry->curveId, &pEccKey);
    if (OK != status)
        goto exit;

    index1 += qsLen;
    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pEccKey, pPublicKeyBlob->pString + index1,
                                                     pPublicKeyBlob->stringLen - index1, NULL, 0);
    if (OK != status)
        goto exit;
    
    pPublicKey->key.pECC = pEccKey; pEccKey = NULL;
    pPublicKey->type = akt_hybrid;
    pPublicKey->pQsCtx = pQsCtx; pQsCtx = NULL;
    pPublicKey->clAlg = pEntry->curveId;

exit:

    SSH_STR_freeStringBuffer(&pHybridMethod);

    if (NULL != pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
    }
    if (NULL != pEccKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pEccKey);
    }

    return status;

} /* SSH_HYBRID_extractHybridKey */


/*------------------------------------------------------------------*/

/*  This function builds a hybrid key with the following format:
 *      string  "ssh-<qs>-<ecc>"
 *      string  concatenated hybrid key.
 * 
 *  <ecc> is the ECC curve information.
 *  <qs>  is the QS algorithm information.
 */
extern MSTATUS
SSH_HYBRID_buildHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate,
                          intBoolean isServer, ubyte **ppPublicKeyBlob, ubyte4 *pPublicKeyBlobLen)
{
    MSTATUS status;
    ubyte4 qsAlgId;
    ubyte4 qsLen;
    ubyte4 eccLen;
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

    if ((akt_hybrid != pKey->type & 0xff) || (NULL == pKey->pQsCtx))
    {
        status = ERR_SSH_EXPECTED_HYBRID_KEY;
        goto exit;
    }

    *ppPublicKeyBlob = NULL;
    *pPublicKeyBlobLen = 0;

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_getNameLengthFromIds(pKey->clAlg, qsAlgId, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = MOC_MALLOC((void **) &pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_getNameFromIds(pKey->clAlg, qsAlgId, isCertificate, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId (pKey->clAlg, &eccLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pKey->pQsCtx, &qsLen);
    if (OK != status)
        goto exit; 

    keyBlobLen = 4 + algoNameLen + 4 + (qsLen + eccLen);

    status = MOC_MALLOC((void **) &pKeyBlob, keyBlobLen + 4);
    if (OK != status)
        goto exit;

    pTmpBuf = pKeyBlob;
    
    BIGEND32(pTmpBuf, keyBlobLen);
    pTmpBuf += 4;
    
    BIGEND32(pTmpBuf, algoNameLen);
    pTmpBuf += 4;

    status = MOC_MEMCPY(pTmpBuf, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    pTmpBuf += algoNameLen;

    BIGEND32(pTmpBuf, (qsLen + eccLen));
    pTmpBuf += 4;

    status = CRYPTO_INTERFACE_QS_getPublicKey(pKey->pQsCtx, pTmpBuf, qsLen);
    if (OK != status)
        goto exit;

    pTmpBuf += qsLen;
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx) pKey->key.pECC, pTmpBuf, eccLen);
    if (OK != status)
        goto exit;

    pTmpBuf = NULL;
    *ppPublicKeyBlob = pKeyBlob;
    *pPublicKeyBlobLen = (keyBlobLen + 4);
    pKeyBlob = NULL;

exit:

    if (NULL != pAlgoName)
        MOC_FREE((void **) &pAlgoName);

    if (NULL != pKeyBlob)
        MOC_MEMSET_FREE(&pKeyBlob, keyBlobLen + 4);

    return status;
}

/*------------------------------------------------------------------*/

/*  returns value of the largest possible hybrid signature. */
extern MSTATUS
SSH_HYBRID_calcHybridSignatureLength(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate, ubyte4 *pSignatureLength)
{
    MSTATUS status;
    ubyte4 elementLen;
    ubyte4 sigLen;
    ubyte4 algoNameLen;
    ubyte4 qsAlgId;

    if ((NULL == pKey) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pSignatureLength = 0;

    if (akt_hybrid != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_HYBRID_KEY;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_getNameLengthFromIds(pKey->clAlg, qsAlgId, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pKey, FALSE, &sigLen);
    if (OK != status)
        goto exit;

    /* algoName and sigLen as strings, concatenated into a string */
    *pSignatureLength = (4 + (4 + algoNameLen) + (4 + sigLen));

exit:

    return status;
}

/*------------------------------------------------------------------*/

/*  This function builds a signature with the following format:
 *      string  "ssh-<qs>-<ecc>"
 *      string  composite_signature_blob
 * 
 *  <qs>  is the QS algorithm information.
 *  <ecc> is the ECC curve information.
 */
extern MSTATUS
SSH_HYBRID_buildHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isCertificate,
                                intBoolean isServer, const ubyte* pHash,
                                ubyte4 hashLen, ubyte **ppSignature, ubyte4 *pSignatureLength)
{
    MSTATUS status;
    ubyte *pSigBuf = NULL;
    ubyte4 sigBufLen;
    ubyte4 sigLen;
    ubyte4 qsAlgId;
    ubyte *pAlgoName = NULL;
    ubyte4 algoNameLen;
    ubyte *pPtr;

    if ((NULL == pKey) || (NULL == pHash) || (NULL == ppSignature) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_hybrid != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_HYBRID_KEY;
        goto exit;
    }
    
    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_getNameLengthFromIds(pKey->clAlg, qsAlgId, isCertificate, &algoNameLen);
    if (OK != status)
        goto exit;

    status = MOC_MALLOC((void **) &pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_getNameFromIds(pKey->clAlg, qsAlgId, isCertificate, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pKey, FALSE, &sigLen);
    if (OK != status)
        goto exit;

    /* have sufficient data to generate signature */
    sigBufLen = 4 + algoNameLen + 4 + sigLen;

    status = MOC_MALLOC((void **) &pSigBuf, sigBufLen + 4);
    if (OK != status)
        goto exit;

    pPtr = pSigBuf;
    BIGEND32(pPtr, sigBufLen);
    pPtr += 4;

    BIGEND32(pPtr, algoNameLen);
    pPtr += 4;

    status = MOC_MEMCPY(pPtr, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    pPtr += algoNameLen;

    BIGEND32(pPtr, sigLen);
    pPtr += 4;

    status = CRYPTO_INTERFACE_QS_compositeSign(MOC_ASYM(hwAccelCtx) pKey, FALSE, RANDOM_rngFun, g_pRandomContext, pAlgoName, algoNameLen,
                                               (ubyte *) pHash, hashLen, pPtr, sigLen, &sigLen);
    if (OK != status)
        goto exit;

    *ppSignature = pSigBuf; pSigBuf = NULL;
    *pSignatureLength = (sigBufLen + 4);
    
exit:

    if (NULL != pAlgoName)
        (void) MOC_FREE((void **) &pAlgoName);

    if (NULL != pSigBuf)
        (void) MOC_MEMSET_FREE(&pSigBuf, sigBufLen + 4);

    return status;
}

/*------------------------------------------------------------------*/

/*  This function verifies a signature with the following format:
 *      string  "ssh-<qs>-<ecc>"
 *      string  composite_signature_blob
 * 
 *  <qs>  is the QS algorithm information.
 *  <ecc> is the ECC curve information.
 */
extern MSTATUS
SSH_HYBRID_verifyHybridSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey,
                               intBoolean isServer, const ubyte* hash, ubyte4 hashLen,
                               sshStringBuffer* pSignature, intBoolean *pIsGoodSignature,
                               vlong **ppVlongQueue)
{
    MSTATUS status;
    sshStringBuffer *pName = NULL;
    sshStringBuffer *pSig = NULL;
    ubyte4 sigLen = 0;
    ubyte4 expSigLen = 0;
    ubyte4 index;
    ubyte4 vStatus = 1;

    sbyte4 exists = -1;

    if (NULL == pPublicKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    index = 4;
    status = SSH_STR_copyStringFromPayload(pSignature->pString,
                                           pSignature->stringLen,
                                           &index, &pName);
    if (OK != status)
        goto exit;

    status = SSH_HYBRID_verifyAlgorithmName((const sshStringBuffer *) pName, &exists);
    if (OK != status)
        goto exit;

    if (0 != exists)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    status = SSH_STR_copyStringFromPayload(pSignature->pString,
                                           pSignature->stringLen,
                                           &index, &pSig);
    if (OK != status)
        goto exit;

    /* get length of signature from payload */
    sigLen = MOC_NTOHL(pSig->pString);

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pPublicKey, FALSE, &expSigLen);
    if (OK != status)
        goto exit;

    if (sigLen != expSigLen)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;        
    }

    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(hwAccelCtx) pPublicKey, FALSE, pName->pString + 4, pName->stringLen - 4,
                                                 (ubyte *) hash, hashLen, pSig->pString + 4, sigLen, &vStatus);
    if (OK != status)
        goto exit;

    if (0 == vStatus)
        *pIsGoodSignature = 1;
    else
        *pIsGoodSignature = 0;

exit:
    
    if (NULL != pName)
        SSH_STR_freeStringBuffer(&pName);
    
    if (NULL != pSig)    
        SSH_STR_freeStringBuffer(&pSig);

    return status;
} /* SSH_HYBRID_verifyHybridSignature */

#endif /* ((defined(__ENABLE_MOCANA_PQC__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__))) */
