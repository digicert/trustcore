/*
 * ssh_dss.c
 *
 * SSH DSS/DSA Host Keys
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

#if ((defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__)))

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
#include "../crypto/dsa.h"
#include "../crypto/sha1.h"

#ifndef __DISABLE_MOCANA_SHA256__
#include "../crypto/sha256.h"
#endif

#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ssh/ssh_str.h"
#include "../ssh/ssh_mpint.h"
#ifdef __ENABLE_MOCANA_SSH_SERVER__
#include "../ssh/ssh_utils.h"
#include "../ssh/ssh.h"
#include "../ssh/ssh_str_house.h"
#endif
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
#include "../ssh/client/sshc_str_house.h"
#endif
#include "../ssh/ssh_dss.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#endif

/*------------------------------------------------------------------*/

#define SIGNATURE_RS_LEN        (PRIVATE_KEY_BYTE_SIZE * 2)


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_DSS_buildDssCertificate(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                            intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen)
{
    ubyte*  pStringP = NULL;
    ubyte*  pStringQ = NULL;
    ubyte*  pStringG = NULL;
    ubyte*  pStringY = NULL;
    ubyte4  index;
    sbyte4  lenP, lenQ, lenG, lenY;
    MDsaKeyTemplate template = { 0 };
    MSTATUS status;

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_dsa != pKey->type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pKey->key.pDSA, &template, MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pKey->key.pDSA, &template, MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(template.pP);
    DEBUG_RELABEL_MEMORY(template.pQ);
    DEBUG_RELABEL_MEMORY(template.pG);
    DEBUG_RELABEL_MEMORY(template.pY);

    /* create mpint string versions */
    status = SSH_mpintByteStringFromByteString(template.pP, template.pLen, 0, &pStringP, &lenP);
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pQ, template.qLen, 0, &pStringQ, &lenQ);
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pG, template.gLen, 0, &pStringG, &lenG);
    if (OK != status)
        goto exit;

    status = SSH_mpintByteStringFromByteString(template.pY, template.yLen, 0, &pStringY, &lenY);
    if (OK != status)
        goto exit;

    /* save variables */
    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        *pRetLen = ssh_dss_signature.stringLen + (ubyte4)lenP + (ubyte4)lenQ + (ubyte4)lenG + (ubyte4)lenY;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        *pRetLen = sshc_dss_signature.stringLen + (ubyte4)lenP + (ubyte4)lenQ + (ubyte4)lenG + (ubyte4)lenY;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    status = MOC_MALLOC((void **) ppCertificate, 4 + *pRetLen);
    if (OK != status)
        goto exit;

    (*ppCertificate)[0] = (ubyte)(*pRetLen >> 24);
    (*ppCertificate)[1] = (ubyte)(*pRetLen >> 16);
    (*ppCertificate)[2] = (ubyte)(*pRetLen >>  8);
    (*ppCertificate)[3] = (ubyte)(*pRetLen);
    *pRetLen += 4;
    index     = 4;

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        MOC_MEMCPY((*ppCertificate) + index, ssh_dss_signature.pString, (sbyte4)ssh_dss_signature.stringLen);
        index += ssh_dss_signature.stringLen;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        MOC_MEMCPY((*ppCertificate) + index, sshc_dss_signature.pString, (sbyte4)sshc_dss_signature.stringLen);
        index += sshc_dss_signature.stringLen;
#endif
    }

    MOC_MEMCPY((*ppCertificate) + index, pStringP, lenP);
    index += (ubyte4)lenP;

    MOC_MEMCPY((*ppCertificate) + index, pStringQ, lenQ);
    index += (ubyte4)lenQ;

    MOC_MEMCPY((*ppCertificate) + index, pStringG, lenG);
    index += (ubyte4)lenG;

    MOC_MEMCPY((*ppCertificate) + index, pStringY, lenY);

exit:
    if (NULL != pStringP)
        MOC_FREE((void **)&pStringP);

    if (NULL != pStringQ)
        MOC_FREE((void **)&pStringQ);

    if (NULL != pStringG)
        MOC_FREE((void **)&pStringG);

    if (NULL != pStringY)
        MOC_FREE((void **)&pStringY);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(NULL, &template);
#else
    DSA_freeKeyTemplate(NULL, &template);
#endif

    return status;
} /* SSH_DSS_buildDssCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_DSS_buildDssSignature(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer,
                          vlong *pM, ubyte **ppSignature, ubyte4 *pSignatureLength, vlong **ppVlongQueue)
{
    ubyte*  pSignature = NULL;
    ubyte*  pR1 = NULL;
    ubyte*  pS1 = NULL;
    ubyte4  r1Len;
    ubyte4  s1Len;
    ubyte*  pMsg = NULL;
    sbyte4  msgLen;
    ubyte4  hashLen = 20;
    ubyte4  index;
#ifndef __DISABLE_MOCANA_SHA256__
    sbyte4  cipherTextLen;
#endif
    MSTATUS status = OK;

    *pSignatureLength = 0;


    if (akt_dsa != pKey->type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

    if (NULL == pKey->key.pDSA)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#ifndef __DISABLE_MOCANA_SHA256__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) pKey->key.pDSA, &cipherTextLen);
#else
    status = DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) pKey->key.pDSA, &cipherTextLen);
#endif
    if (OK != status)
        goto exit;

    /* cipherTextLen is in bytes */
    if (2048 == (8*cipherTextLen))
    {
        hashLen = SHA256_RESULT_SIZE;
    }
#endif

#ifdef __ENABLE_MOCANA_DSA__
    intBoolean verify;
    status = VLONG_byteStringFromVlong(pM, NULL, &msgLen);
    if (OK != status)
        goto exit;

    status = MOC_MALLOC((void **)&pMsg, msgLen);
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong(pM, pMsg, &msgLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_computeSignatureAux(MOC_DSA(hwAccelCtx) g_pRandomContext, pKey->key.pDSA,
        pMsg, msgLen, &verify, &pR1, &r1Len, &pS1, &s1Len, ppVlongQueue);
#else
    status = DSA_computeSignatureAux(MOC_DSA(hwAccelCtx) g_pRandomContext, pKey->key.pDSA,
        pMsg, msgLen, &verify, &pR1, &r1Len, &pS1, &s1Len, ppVlongQueue);
#endif
    if (OK != status)
        goto exit;
#endif

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        index = ssh_dss_signature.stringLen + 4 + (hashLen * 2);
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        index = sshc_dss_signature.stringLen + 4 + (hashLen *2);
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    status = MOC_MALLOC((void **) &pSignature, 4 + index);
    if (OK != status)
        goto exit;

    pSignature[0] = (ubyte)(index >> 24);
    pSignature[1] = (ubyte)(index >> 16);
    pSignature[2] = (ubyte)(index >>  8);
    pSignature[3] = (ubyte)(index);
    index = 4;

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        if (OK > (status = MOC_MEMCPY(pSignature + index, ssh_dss_signature.pString, (sbyte4)ssh_dss_signature.stringLen)))
            goto exit;
        index += ssh_dss_signature.stringLen;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        if (OK > (status = MOC_MEMCPY(pSignature + index, sshc_dss_signature.pString, (sbyte4)sshc_dss_signature.stringLen)))
            goto exit;
        index += sshc_dss_signature.stringLen;
#endif
    }

    /* write length r & s */
    pSignature[index]     = 0;
    pSignature[index + 1] = 0;
    pSignature[index + 2] = 0;
    pSignature[index + 3] = (ubyte)(hashLen * 2);
    index += 4;

    /* copy r & s to signature blob */
    status = MOC_MEMCPY(pSignature + index, pR1, hashLen);
    if (OK != status)
        goto exit;
    index += hashLen;

    status = MOC_MEMCPY(pSignature + index, pS1, hashLen);
    if (OK != status)
        goto exit;
    index += hashLen;

    /* save variables */
    *ppSignature      = pSignature;
    pSignature        = NULL;
    *pSignatureLength = index;

exit:
    if (NULL != pSignature)
        MOC_FREE((void **) &pSignature);

    if (NULL != pMsg)
        MOC_FREE((void **) &pMsg);

    if (NULL != pR1)
        MOC_FREE((void **) &pR1);

    if (NULL != pS1)
        MOC_FREE((void **) &pS1);

    return status;

} /* SSH_DSS_buildDssSignature */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_DSS_calcDssSignatureLength(AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength, ubyte4 hashLen)
{
    MOC_UNUSED(pKey);

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        *pSignatureLength = 4 + ssh_dss_signature.stringLen + 4 + (hashLen * 2);
#else
        return ERR_SSH_CONFIG;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        *pSignatureLength = 4 + sshc_dss_signature.stringLen + 4 + (hashLen * 2);
#else
        return ERR_SSH_CONFIG;
#endif
    }

    return OK;

} /* SSH_DSS_calcDssSignatureLength */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_DSS_extractDssCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                              ubyte4 index, vlong **ppVlongQueue)
{
    /* note: index should be in correct position */
    ubyte   *pP = NULL;
    ubyte4  pLen;
    ubyte   *pQ = NULL;
    ubyte4  qLen;
    ubyte   *pG = NULL;
    ubyte4  gLen;
    ubyte   *pY = NULL;
    ubyte4  yLen;
    MDsaKeyTemplate template;
    ubyte4              index1;
    MSTATUS             status;

    if (akt_dsa != pPublicKey->type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

    if (NULL == pPublicKey->key.pDSA)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* verify p */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString + index,
        pPublicKeyBlob->stringLen - index, &pP, &pLen);
    if (OK != status)
        goto exit;

    index += (pLen + 4);
    if (index >= pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pP);

    /* verify q */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString + index,
        pPublicKeyBlob->stringLen - index, &pQ, &qLen);
    if (OK != status)
        goto exit;

    index += (qLen + 4);

    if (index >= pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pQ);

    /* verify g */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString + index,
        pPublicKeyBlob->stringLen - index, &pG, &gLen);
    if (OK != status)
        goto exit;

    index += (gLen + 4);

    if (index >= pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pG);

    /* verify y */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString + index,
        pPublicKeyBlob->stringLen - index, &pY, &yLen);
    if (OK != status)
        goto exit;

    index += (yLen + 4);
    if (index != pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    DEBUG_RELABEL_MEMORY(pY);

    template.pP = pP;
    template.pLen = pLen;
    template.pQ = pQ;
    template.qLen = qLen;
    template.pG = pG;
    template.gLen = gLen;
    template.pY = pY;
    template.yLen = yLen;
    template.pX = NULL;
    template.xLen = 0;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, &template);
#else
    status = DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, &template);
#endif
    if (OK != status)
        goto exit;

exit:
    if (NULL != pP)
        MOC_FREE((void **) &pP);

    if (NULL != pQ)
        MOC_FREE((void **) &pQ);

    if (NULL != pG)
        MOC_FREE((void **) &pG);

    if (NULL != pY)
        MOC_FREE((void **) &pY);

#if 0
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(NULL, &template);
#else
    DSA_freeKeyTemplate(NULL, &template);
#endif
#endif

    return status;

} /* SSH_DSS_extractDssCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_DSS_verifyDssSignature(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pPublicKey,
                           intBoolean isServer, vlong *pM, sshStringBuffer* pSignature,
                           intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    sshStringBuffer*    tempString = NULL;
    sshStringBuffer*    rsString   = NULL;
    ubyte4              index      = 4;     /* skip past signature-string-length field */
    sbyte4              result     = -1;    /* default to signature format error */
    MSTATUS             status;
    ubyte4 sigLen = 20;
    sbyte4 cipherTextLen = 0;
    ubyte *pMsg = NULL;
    ubyte4 msgLen;

    *pIsGoodSignature = FALSE;

    if (akt_dsa != pPublicKey->type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

    if (NULL == pPublicKey->key.pDSA)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, &cipherTextLen);
#else
    status = DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, &cipherTextLen);
#endif
    if (OK != status)
        goto exit;

    if (2048 == (8 * cipherTextLen))
    {
        sigLen = SHA256_RESULT_SIZE;
    }

    /* fetch signature type */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &tempString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(tempString);
    DEBUG_RELABEL_MEMORY(tempString->pString);

    /* check signature type */
    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        if (OK > (status = MOC_MEMCMP(tempString->pString, ssh_dss_signature.pString, ssh_dss_signature.stringLen, &result)))
            goto exit;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        if (OK > (status = MOC_MEMCMP(tempString->pString, sshc_dss_signature.pString, sshc_dss_signature.stringLen, &result)))
            goto exit;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    if (0 != result)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    /* fetch r & s */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &rsString)))
        goto exit;

    DEBUG_RELABEL_MEMORY(rsString);
    DEBUG_RELABEL_MEMORY(rsString->pString);

    if ((pSignature->stringLen != index) || ( ((2*sigLen)+4) != rsString->stringLen))
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    /* extract the values */
    status = VLONG_byteStringFromVlong(pM, NULL, (sbyte4 *) &msgLen);
    if (OK != status)
        goto exit;

    status = MOC_MALLOC((void **)&pMsg, msgLen);
    if (OK != status)
        goto exit;

    status = VLONG_byteStringFromVlong(pM, pMsg, (sbyte4 *) &msgLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_verifySignatureAux(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, pMsg, msgLen,
        4 + rsString->pString, sigLen, 4 + sigLen + rsString->pString, sigLen,
        pIsGoodSignature, ppVlongQueue);
#else
    status = DSA_verifySignatureAux(MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, pMsg, msgLen,
        4 + rsString->pString, sigLen, 4 + sigLen + rsString->pString, sigLen,
        pIsGoodSignature, ppVlongQueue);
#endif
    if (OK != status)
        goto exit;
exit:
    SSH_STR_freeStringBuffer(&tempString);
    SSH_STR_freeStringBuffer(&rsString);

    if (NULL != pMsg)
    {
        MOC_FREE((void **) &pMsg);
    }

    return status;

} /* SSH_DSS_verifyDssSignature */

#endif /* ((defined(__ENABLE_MOCANA_SSH_DSA_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__))) */

