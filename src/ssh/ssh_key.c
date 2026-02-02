/**
 * @file  ssh_key.c
 * @brief SSH encoding and decoding functions
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

/*----------------------------------------------------------------------------*/
#include "../crypto/pubcrypto.h"
#include "../ssh/ssh_mpint.h"
#include "../ssh/ssh_key.h"
#include "../ssh/ssh_str.h"
#include "../common/base64.h"
#include "../crypto/pubcrypto.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/crypto_interface_rsa.h"
#include "../crypto_interface/crypto_interface_pubcrypto_priv.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto_interface/crypto_interface_ecc.h"
#endif
#endif

extern MSTATUS
SSH_KEY_setInteger(ubyte *pPayload, ubyte4 payloadLength, ubyte4 *pBufIndex, ubyte4 integerValue)
{
    MSTATUS status = OK;

    if (payloadLength < (*pBufIndex + 4))
    {
        /* not enough room to set integer */
        status = ERR_SFTP_PAYLOAD_TOO_SMALL;
        goto exit;
    }

    pPayload += (*pBufIndex);

    pPayload[0] = (ubyte)(integerValue >> 24);
    pPayload[1] = (ubyte)(integerValue >> 16);
    pPayload[2] = (ubyte)(integerValue >> 8);
    pPayload[3] = (ubyte)(integerValue);

    *pBufIndex += 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_KEY_getInteger(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex, ubyte4 *pRetInteger)
{
    ubyte4  retInteger;
    MSTATUS status = OK;

    if (bufSize < (*pBufIndex + 4))
    {
        /* not enough bytes to get */
        status = ERR_SFTP_BAD_PAYLOAD_LENGTH;
        goto exit;
    }

    pBuffer += (*pBufIndex);

    retInteger  = ((ubyte4)pBuffer[3]);
    retInteger |= ((ubyte4)pBuffer[2]) << 8;
    retInteger |= ((ubyte4)pBuffer[1]) << 16;
    retInteger |= ((ubyte4)pBuffer[0]) << 24;

    *pRetInteger = retInteger;
    *pBufIndex  += 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
parsePublicKeyFileStyle1(sbyte* pKeyFile, ubyte4 fileSize,
                         ubyte** ppDecodeFile, ubyte4 *pDecodedLength)
{
    ubyte4  signatureSize = 0;
    ubyte4  index;
    MSTATUS status;

    /* Skip leading key format data - "ssh-dss" or "ssh-rsa" or "ecdsa-sha2-nistpXXX"
       or "ssh-ed25519".
       Don't need to check the key format here since its already part of encoded key
       we will check it later, see SSH_UTILS_sshParseAuthPublicKeyFile */
    /*while ((signatureSize < fileSize) && (' ' != pKeyFile[signatureSize]))
        signatureSize++;*/

    pKeyFile += signatureSize;
    fileSize -= signatureSize;

    /* skip past algorithm identifier */
    while ((' ' != *pKeyFile) && (0 < fileSize))
    {
        pKeyFile++;
        fileSize--;
    }

    if (fileSize == 0)
    {
        status = ERR_SSH_MISSING_KEY_FILE;
        goto exit;
    }
    /* skip past white space */
    pKeyFile++;
    fileSize--;

    /* purge trailing user name information */
    for (index = 0; index < fileSize; index++)
        if (' ' == pKeyFile[index])
            break;

    if ((0 == index) || (fileSize <= index))
    {
        status = ERR_FILE_MISSING_KEY_DATA;
        goto exit;
    }

    fileSize = index;

    /* decode the public key data */
    status = BASE64_decodeMessage((ubyte *)pKeyFile, fileSize, ppDecodeFile, pDecodedLength);

exit:
    return status;

} /* parsePublicKeyFileStyle1 */


/*------------------------------------------------------------------*/

static MSTATUS
fetchLine(sbyte *pSrc,  ubyte4 *pSrcIndex, ubyte4 srcLength,
          sbyte *pDest, ubyte4 *pDestIndex)
{
    MSTATUS status = OK;

    pSrc += (*pSrcIndex);

    if ('-' == *pSrc)
    {
        /* handle '---- XXX ----' lines */
        /* seek CR or LF */
        while ((*pSrcIndex < srcLength) && ((0x0d != *pSrc) && (0x0a != *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }

        /* skip CR and LF */
        while ((*pSrcIndex < srcLength) && ((0x0d == *pSrc) || (0x0a == *pSrc)))
        {
            (*pSrcIndex)++;
            pSrc++;
        }
    }
    else
    {
        sbyte4  result;

        DIGI_MEMCMP((ubyte *)pSrc, (ubyte *)"Comment:", 8, &result);

        if (0 == result)
        {
            intBoolean  continuationFlag;

            do
            {
                continuationFlag = FALSE;

                /* seek CR or LF */
                while ((*pSrcIndex < srcLength) && ((0x0d != *pSrc) && (0x0a != *pSrc)))
                {
                    if ('\\' == *pSrc)
                        continuationFlag = TRUE;
                    else if ((0x20 != *pSrc) && (0x09 != *pSrc))
                        continuationFlag = FALSE;       /* for malformed line-continuation */

                    (*pSrcIndex)++;
                    pSrc++;
                }

                /* skip to next line */
                if ((*pSrcIndex < srcLength) && (0x0d == *pSrc))
                {
                    (*pSrcIndex)++;
                    pSrc++;

                    if ((*pSrcIndex < srcLength) && (0x0a == *pSrc))
                    {
                        (*pSrcIndex)++;
                        pSrc++;
                    }
                }
                else if ((*pSrcIndex < srcLength) && (0x0a == *pSrc))
                {
                    (*pSrcIndex)++;
                    pSrc++;

                    if ((*pSrcIndex < srcLength) && (0x0d == *pSrc))
                    {
                        (*pSrcIndex)++;
                        pSrc++;
                    }
                }
            }
            while ((*pSrcIndex < srcLength) && (TRUE == continuationFlag));
        }
        else
        {
            pDest += (*pDestIndex);

            /* handle base64 encoded data line */
            while ((*pSrcIndex < srcLength) &&
                   ((0x20 != *pSrc) && (0x0d != *pSrc) && (0x0a != *pSrc)))
            {
                *pDest = *pSrc;

                (*pSrcIndex)++;
                (*pDestIndex)++;
                pSrc++;
                pDest++;
            }

            /* skip to next line */
            while ((*pSrcIndex < srcLength) &&
                   ((0x20 == *pSrc) || (0x0d == *pSrc) || (0x0a == *pSrc) || (0x09 == *pSrc)))
            {
                (*pSrcIndex)++;
                pSrc++;
            }
        }
    }

    return status;

} /* fetchLine */


/*------------------------------------------------------------------*/

static MSTATUS
parsePublicKeyFileStyle2(sbyte* pKeyFile, const ubyte4 fileSize,
                         ubyte** ppDecodeFile, ubyte4 *pDecodedLength)
{
    sbyte*  pBase64Mesg = NULL;
    ubyte4  srcIndex    = 0;
    ubyte4  destIndex   = 0;
    MSTATUS status;

    status = DIGI_MALLOC((void **) &pBase64Mesg, fileSize);
    if (OK != status)
        goto exit;


    while (fileSize > srcIndex)
    {
        if (OK > (status = fetchLine(pKeyFile, &srcIndex, fileSize, pBase64Mesg, &destIndex)))
            goto exit;
    }

    status = BASE64_decodeMessage((ubyte *)pBase64Mesg, destIndex, ppDecodeFile, pDecodedLength);

exit:
    if (NULL != pBase64Mesg)
        DIGI_FREE((void **) &pBase64Mesg);

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_KEY_GENERATION__
#ifdef  __ENABLE_DIGICERT_ECC__
static MSTATUS
SSH_KEY_exportECCKey(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                    ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    ubyte4  keyLength;
    ubyte4  bufferLength;
    ubyte4  index = 0;
    ubyte*  pBuffer = NULL;
    ubyte4  curveId;
    ECCKey* pECCContext;
    MSTATUS status;

    if ((NULL == pKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((akt_ecc != pKey->type) && (akt_ecc_ed != pKey->type))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    pECCContext = pKey->key.pECC;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pECCContext, &keyLength);
#else
    status = EC_getPointByteStringLenEx(pECCContext, &keyLength);
#endif
    if (OK != status)
        goto exit;

    if (akt_ecc == pKey->type)
    {
        /* first 4 bytes are length of identifier 
         * next 8 bytes are identifier: "nistpXXX"
         * next 4 bytes are used for key length */
        bufferLength = 4 + 8 + 4 + keyLength;
    }
    else
    {
        /* first 4 bytes are used for key length  */
        bufferLength = 4 + keyLength;
    }
    
    status = DIGI_MALLOC((void **) &pBuffer, bufferLength);
    if (OK != status)
        goto exit;

    if (akt_ecc == pKey->type)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCContext, &curveId);
#else
        status = EC_getCurveIdFromKey(pECCContext, &curveId);
#endif
        if (OK != status)
            goto exit;

        status = SSH_KEY_setInteger(pBuffer, bufferLength, &index, 8);
        if (OK != status)
            goto exit;

        switch(curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case cid_EC_P192:
                status = DIGI_MEMCPY(pBuffer + index, "nistp192", 8);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
            case cid_EC_P224:
                status = DIGI_MEMCPY(pBuffer + index, "nistp224", 8);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case cid_EC_P256:
                status = DIGI_MEMCPY(pBuffer + index, "nistp256", 8);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case cid_EC_P384:
                status = DIGI_MEMCPY(pBuffer + index, "nistp384", 8);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case cid_EC_P521:
                status = DIGI_MEMCPY(pBuffer + index, "nistp521", 8);
                break;
#endif
            default:
                status = ERR_BAD_KEY_TYPE;
        }
        if (OK != status)
            goto exit;

        index += 8;
    }

    /* write key length to pBuffer */
    status = SSH_KEY_setInteger(pBuffer, bufferLength, &index, keyLength);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx) pECCContext, pBuffer + index, keyLength);
#else
    status = EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) pECCContext, pBuffer + index, keyLength);
#endif
    if (OK != status)
        goto exit;

    *ppRetKeyBlob = pBuffer;
    pBuffer = NULL;
    *pRetKeyBlobLength = bufferLength;

exit:
    if (NULL != pBuffer)
        DIGI_FREE((void **) &pBuffer);

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC__ */


/*------------------------------------------------------------------*/

static MSTATUS
SSH_KEY_exportRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                     ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    RSAKey *p_rsaDescr      = NULL;

    ubyte*  pKeyBlob        = NULL;
    ubyte*  pMpintStringE   = NULL;
    ubyte*  pMpintStringN   = NULL;
    sbyte4  mpintByteSizeE  = 0;
    sbyte4  mpintByteSizeN  = 0;
    ubyte4  keySize         = 0;
    ubyte4  index;
    MRsaKeyTemplate template = { 0 };
    MSTATUS status = ERR_BAD_KEY_TYPE;

    if ((NULL == pKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
        return ERR_NULL_POINTER;

    if (akt_rsa != pKey->type)
        goto exit;

    p_rsaDescr = pKey->key.pRSA;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) p_rsaDescr, &template,
        MOC_GET_PUBLIC_KEY_DATA);
#else
    status = RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx) p_rsaDescr, &template,
        MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    /* e */
    status = SSH_mpintByteStringFromByteString(template.pE, template.eLen, 0, &pMpintStringE, &mpintByteSizeE);
    if (OK != status)
        goto exit;

    /* n */
    status = SSH_mpintByteStringFromByteString(template.pN, template.nLen, 0, &pMpintStringN, &mpintByteSizeN);
    if (OK != status)
        goto exit;

    keySize = mpintByteSizeE + mpintByteSizeN;

    if (0 == keySize)
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    status = DIGI_MALLOC((void **) &pKeyBlob, keySize);
    if (OK != status)
        goto exit;

    /* e */
    if (OK > (status = DIGI_MEMCPY(pKeyBlob, pMpintStringE, mpintByteSizeE)))
        goto exit;
    index = mpintByteSizeE;

    /* n */
    if (OK > (status = DIGI_MEMCPY(index + pKeyBlob, pMpintStringN, mpintByteSizeN)))
        goto exit;

    *ppRetKeyBlob       = pKeyBlob;
    *pRetKeyBlobLength  = keySize;

    pKeyBlob            = NULL;

exit:
    if (NULL != pMpintStringE)
        FREE(pMpintStringE);

    if (NULL != pMpintStringN)
        FREE(pMpintStringN);

    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(p_rsaDescr, &template);
#else
    RSA_freeKeyTemplate(p_rsaDescr, &template);
#endif

    return status;
}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_DSA__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
static MSTATUS
SSH_KEY_exportDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
                    ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    ubyte4  bufferLength;
    ubyte*  buffer = NULL;
    DSAKey* pDSAContext;
    DSAKey* pDSAPubContext = NULL;
    MDsaKeyTemplate template = {0};
    MSTATUS status;

    if ((NULL == pKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_dsa != pKey->type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

    pDSAContext = pKey->key.pDSA;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAContext, &template, MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAContext, &template, MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pDSAPubContext);
#else
    status = DSA_createKey(&pDSAPubContext);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pDSAPubContext, &template);
#else
    status = DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) pDSAPubContext, &template);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) pDSAPubContext, NULL, &bufferLength);
#else
    status = DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) pDSAPubContext, NULL, &bufferLength);
#endif
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &buffer, bufferLength);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) pDSAPubContext, buffer, &bufferLength);
#else
    status = DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) pDSAPubContext, buffer, &bufferLength);
#endif
    if (OK != status)
        goto exit;

    *ppRetKeyBlob = buffer;
    buffer = NULL;
    *pRetKeyBlobLength = bufferLength;

exit:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(NULL, &template);
#else
    DSA_freeKeyTemplate(NULL, &template);
#endif

    if (NULL != pDSAPubContext)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pDSAPubContext, NULL);
#else
        DSA_freeKey(&pDSAPubContext, NULL);
#endif
    }

    if (NULL != buffer)
        DIGI_FREE((void **) &buffer);

    return status;
}
#endif /* __ENABLE_DIGICERT_DSA__ */

#ifdef __ENABLE_DIGICERT_PQC__
/*  public key format:
 *  4   bytes for algorithm name length
 *  n   bytes for algorithm name
 *  4   bytes for QS public key length
 *  q   bytes for QS public key
 **/
static MSTATUS
SSH_KEY_exportQsKey(MOC_HASH(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength, ubyte4 *pQsAlgId)
{
    ubyte *pQsPubKey = NULL;
    ubyte4 qsPubKeyLen;
    MSTATUS status;
    ubyte *pOutputBuff = NULL;
    ubyte *pTmpBuff;
    ubyte tmpBuffLen;
    ubyte4 outputBuffLen;
    ubyte4 index;
    ubyte4 qsAlgId = 0;

    if ((NULL == pKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pKey->pQsCtx, &pQsPubKey, &qsPubKeyLen);
    if (OK != status)
        goto exit;

    /* write buffer */
    outputBuffLen = 4 + qsPubKeyLen;

    status = DIGI_MALLOC((void **) &pOutputBuff, outputBuffLen);
    if (OK != status)
        goto exit;

    pTmpBuff = pOutputBuff;
    tmpBuffLen = outputBuffLen;

    index = 0;
    status = SSH_KEY_setInteger(pTmpBuff, tmpBuffLen, &index, qsPubKeyLen);
    if (OK != status)
        goto exit;

    pTmpBuff += index;
    tmpBuffLen -= index;

    status = DIGI_MEMCPY(pTmpBuff, pQsPubKey, qsPubKeyLen);
    if (OK != status)
        goto exit;

    *ppRetKeyBlob = pOutputBuff;
    *pRetKeyBlobLength = outputBuffLen;
    pOutputBuff = NULL;

    if (NULL != pQsAlgId)
        *pQsAlgId = qsAlgId;

exit:

    if (NULL != pQsPubKey)
        DIGI_FREE((void **) &pQsPubKey);

    if (NULL != pOutputBuff)
        DIGI_FREE((void **) &pOutputBuff);

    return status;
}
#endif

/*------------------------------------------------------------------*/

/*  public key format:
 *  4   bytes for algorithm name length
 *  n   bytes for algorithm name
 *  4   bytes for Composite public key length
 *  m   bytes for Composite public key
 **/
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
static MSTATUS
SSH_KEY_exportHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey, ubyte **ppRetKeyBlob, ubyte4 *pRetKeyBlobLength, ubyte4 *pCurveId, ubyte4 *pQsAlgId)
{
    ubyte4 qsPubKeyLen;
    ubyte4 ecPubKeyLen;
    MSTATUS status;
    ubyte *pOutputBuff = NULL;
    ubyte *pTmpBuff;
    ubyte tmpBuffLen;
    ubyte4 outputBuffLen;
    ubyte4 index;
    ubyte4 qsAlgId = 0;

    if ((NULL == pKey) || (NULL == ppRetKeyBlob) || (NULL == pRetKeyBlobLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pKey->pQsCtx, &qsPubKeyLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId (pKey->clAlg, &ecPubKeyLen);
    if (OK != status)
        goto exit;

    /* write buffer */
    outputBuffLen = 4 + qsPubKeyLen + ecPubKeyLen;

    status = DIGI_MALLOC((void **) &pOutputBuff, outputBuffLen);
    if (OK != status)
        goto exit;

    pTmpBuff = pOutputBuff;
    tmpBuffLen = outputBuffLen;

    index = 0;
    status = SSH_KEY_setInteger(pTmpBuff, tmpBuffLen, &index, qsPubKeyLen + ecPubKeyLen);
    if (OK != status)
        goto exit;

    pTmpBuff += index;
    tmpBuffLen -= index;

    status = CRYPTO_INTERFACE_QS_getPublicKey(pKey->pQsCtx, pTmpBuff, qsPubKeyLen);
    if (OK != status)
        goto exit;

    pTmpBuff += qsPubKeyLen;
    tmpBuffLen -= qsPubKeyLen;
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux(MOC_ECC(hwAccelCtx) pKey->key.pECC, pTmpBuff, tmpBuffLen);
    if (OK != status)
        goto exit;

    *ppRetKeyBlob = pOutputBuff;
    *pRetKeyBlobLength = outputBuffLen;
    pOutputBuff = NULL;

    if (NULL != pQsAlgId)
        *pQsAlgId = qsAlgId;

    if (NULL != pCurveId)
        *pCurveId = pKey->clAlg;

exit:

    if (NULL != pOutputBuff)
        (void) DIGI_FREE((void **) &pOutputBuff);

    return status;
}
#endif

/*------------------------------------------------------------------*/

/* pCurveId is set to a curve ID value when pRetKeyType is set to akt_ecc
 * or akt_ecc_ed. If pCurveId is provided and pRetKeyType is not akt_ecc
 * or akt_ecc_ed, pCurveId is set to 0.
 * pQsAlgId is set if the pRetKeyType is set to akt_hybrid or akt_qs.
 */
extern MSTATUS
SSH_KEY_extractPublicKey(MOC_ASYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyBlob, ubyte4 keyBlobLength,
                         ubyte **ppRetPublicKeyBlob, ubyte4 *pRetPublicKeyBlobLength,
                         ubyte4 *pRetKeyType, ubyte4 *pCurveId, ubyte4 *pQsAlgId)
{
    AsymmetricKey       key;
    MSTATUS             status;
#ifdef __ENABLE_DIGICERT_ECC__
    ubyte4              curveId;
#endif

    if ((NULL == ppRetPublicKeyBlob) || (NULL == pRetPublicKeyBlobLength) ||
        (NULL == pRetKeyType))
        return ERR_NULL_POINTER;

    if (NULL != pCurveId)
    {
        *pCurveId = 0;
    }

    *pRetKeyType = akt_undefined;

    if (OK > (status = CRYPTO_initAsymmetricKey(&key)))
        goto exit;

    status = CRYPTO_deserializeAsymKey(MOC_ASYM(hwAccelCtx) (ubyte *)pKeyBlob, keyBlobLength, NULL, &key);
    if (OK != status)
        goto exit;

    status = ERR_BAD_KEY_TYPE;

    if ((akt_ecc == key.type) || (akt_ecc_ed == key.type))
    {
#ifdef __ENABLE_DIGICERT_ECC__
        if (NULL == pCurveId)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(key.key.pECC, &curveId);
#else
        status = EC_getCurveIdFromKey(key.key.pECC, &curveId);
#endif
        if (OK != status)
            goto exit;

        *pCurveId = curveId;

        status = SSH_KEY_exportECCKey(MOC_ECC(hwAccelCtx) &key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength);
#else
        status = ERR_CRYPTO_ECC_DISABLED;
        goto exit;
#endif
    }
    else if (akt_rsa == key.type)
    {
        status = SSH_KEY_exportRSAKey(MOC_RSA(hwAccelCtx) &key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength);
    }
    else if (akt_dsa == key.type)
    {
#if defined(__ENABLE_DIGICERT_DSA__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
        status = SSH_KEY_exportDSAKey(MOC_DSA(hwAccelCtx) &key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength);
#else
        status = ERR_CRYPTO_DSA_DISABLED;
        goto exit;
#endif
    }
    else if (akt_qs == key.type)
    {
#ifdef __ENABLE_DIGICERT_PQC__
        status = SSH_KEY_exportQsKey(MOC_HASH(hwAccelCtx) &key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength, pQsAlgId);
#else
        MOC_UNUSED(pQsAlgId);
        status = ERR_CRYPTO_QS_DISABLED;
#endif
    }
    else if (akt_hybrid == key.type)
    {
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
        status = SSH_KEY_exportHybridKey(MOC_ASYM(hwAccelCtx) &key, ppRetPublicKeyBlob, pRetPublicKeyBlobLength, pCurveId, pQsAlgId);
#else
        MOC_UNUSED(pQsAlgId);
        status = ERR_CRYPTO_QS_HYBRID_DISABLED;
#endif
    }

    if (OK > status)
        goto exit;

    *pRetKeyType = key.type;

exit:
    CRYPTO_uninitAsymmetricKey(&key, NULL);

    return status;
}

extern MSTATUS
SSH_KEY_generateHostKeyFileAsymKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen)
{
    MSTATUS status;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, publicKeyPem, &pKeyBlob, &keyBlobLen);
    if (OK != status)
        goto exit;

    status = SSH_KEY_generateHostKeyFile(pKeyBlob, keyBlobLen, ppRetHostFile,
        pRetHostFileLen);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS SSH_KEY_getKeySshStringBuffer(ubyte4 keyType, ubyte4 curveId, ubyte4 qsAlgId,
    sshStringBuffer **ppAlgorithmName)
{
    MSTATUS status;
    sshStringBuffer *pTemp = NULL;
    ubyte *pAlgoName;
    ubyte4 algoNameLen = 0;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte pAlgoBuffer[64] = {0}; /* buffer for pqc and composite names */
#endif
    ubyte4 index = 0;

    if (NULL == ppAlgorithmName)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = OK;
    *ppAlgorithmName = NULL;
    switch(keyType)
    {
        case akt_dsa:
        {
            pAlgoName = (ubyte *) "ssh-dss";
            break;
        }
        case akt_rsa:
        {
            pAlgoName = (ubyte *) "ssh-rsa";
            break;
        }
        case akt_ecc:
        {
#if defined(__ENABLE_DIGICERT_ECC__)
            switch(curveId)
            {
#ifdef __ENABLE_DIGICERT_ECC_P192__
                case cid_EC_P192:
                    pAlgoName = (ubyte *) "ecdsa-sha2-nistp192";
                    break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
                case cid_EC_P224:
                    pAlgoName = (ubyte *) "ecdsa-sha2-nistp224";
                    break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
                case cid_EC_P256:
                    pAlgoName = (ubyte *) "ecdsa-sha2-nistp256";
                    break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
                case cid_EC_P384:
                    pAlgoName = (ubyte *) "ecdsa-sha2-nistp384";
                    break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
                case cid_EC_P521:
                    pAlgoName = (ubyte *) "ecdsa-sha2-nistp521";
                    break;
#endif
                default:
                    status = ERR_BAD_KEY_TYPE;
            }
            if (OK != status)
                goto exit;
#else
            status = ERR_CRYPTO_ECC_DISABLED;
#endif
            break;
        }
        case akt_ecc_ed:
        {
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
            if (cid_EC_Ed25519 != curveId)
            {
                status = ERR_BAD_KEY_TYPE;
                goto exit;
            }

            pAlgoName = (ubyte *) "ssh-ed25519";
#else
            status = ERR_CRYPTO_ECC_DISABLED;
#endif
            break;
        }
        case akt_qs:
        {
#ifdef __ENABLE_DIGICERT_PQC__

            (void) DIGI_MEMCPY(pAlgoBuffer, (ubyte *) "ssh-", 4);

            switch (qsAlgId)
            { 
                case cid_PQC_MLDSA_44:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa44", DIGI_STRLEN("mldsa44"));
                    break;
                case cid_PQC_MLDSA_65:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa65", DIGI_STRLEN("mldsa65"));
                    break;
                case cid_PQC_MLDSA_87:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa87", DIGI_STRLEN("mldsa87"));
                    break;
                default:
                    status = ERR_BAD_KEY_TYPE;
                    goto exit;                                     
            }

            pAlgoName = pAlgoBuffer;
#else
            status = ERR_CRYPTO_QS_DISABLED;
#endif
            break;
        }
        case akt_hybrid:
        {
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__

            (void) DIGI_MEMCPY(pAlgoBuffer, (ubyte *) "ssh-", 4);

            switch (qsAlgId)
            { 
                case cid_PQC_MLDSA_44:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa44-", DIGI_STRLEN("mldsa44-"));
                    break;
                case cid_PQC_MLDSA_65:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa65-", DIGI_STRLEN("mldsa65-"));
                    break;
                case cid_PQC_MLDSA_87:
                    (void) DIGI_MEMCPY(pAlgoBuffer + 4, (ubyte *) "mldsa87-", DIGI_STRLEN("mldsa87-"));
                    break;
                default:
                    status = ERR_BAD_KEY_TYPE;
                    goto exit;                                     
            }

            switch (curveId)
            {
                case cid_EC_P256:

                    (void) DIGI_MEMCPY(pAlgoBuffer + 12, (ubyte *) "es256", 5);
                    break;

                case cid_EC_P384:

                    (void) DIGI_MEMCPY(pAlgoBuffer + 12, (ubyte *) "es384", 5);
                    break;

                case cid_EC_Ed25519:

                    (void) DIGI_MEMCPY(pAlgoBuffer + 12, (ubyte *) "ed25519", 7);
                    break;

                case cid_EC_Ed448:

                    (void) DIGI_MEMCPY(pAlgoBuffer + 12, (ubyte *) "ed448", 5);
                    break;

                default:
                    status = ERR_BAD_KEY_TYPE;
                    goto exit; 
            } 

            pAlgoName = pAlgoBuffer;
#else
            status = ERR_CRYPTO_QS_HYBRID_DISABLED;
#endif
            break;
        }
        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }
    if (OK != status)
        goto exit;
    /* create sshc_ecdsa_signature values here */
    
    algoNameLen = DIGI_STRLEN((sbyte *) pAlgoName);
    status = SSH_STR_makeStringBuffer(&pTemp, algoNameLen + 4);
    if (OK != status)
        goto exit;

    status = SSH_KEY_setInteger(pTemp->pString, 4, &index, algoNameLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pTemp->pString + 4, pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    pTemp->stringLen = 4 + algoNameLen;

    *ppAlgorithmName = pTemp;
    pTemp = NULL;
exit:
    SSH_STR_freeStringBuffer(&pTemp);

#ifdef __ENABLE_DIGICERT_PQC__
    if (algoNameLen > 0)
    {
        (void) DIGI_MEMSET(pAlgoBuffer, 0x00, algoNameLen);
    }
#endif
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SSH_KEY_generateBase64EncodedPublicKey(MOC_ASYM(hwAccelDescr hwAccelCtx)
    ubyte *pKeyBlob, ubyte4 keyBlobLength, sshStringBuffer **ppAlgorithmName,
    ubyte **ppBase64EncodedPublicKey, ubyte4 *pBased64EncodedPublicKeyLen)
{
    sshStringBuffer *pTempSignature = NULL;
    ubyte*  pPreEncodedMesg = NULL;
    ubyte4  preEncodedMesgLen;
    ubyte*  pBase64EncodedMesg = NULL;
    ubyte4  base64EncodedMesgLen;
    ubyte4  publicKeyBlobLen;
    ubyte*  pPublicKeyBlob = NULL;
    ubyte4  keyType;
    ubyte4  curveId;
    ubyte4  qsAlgId = 0;
    MSTATUS status = OK;

    /* get public key from private key + keyType and curveId */
    if (OK > (status = SSH_KEY_extractPublicKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength, &pPublicKeyBlob, &publicKeyBlobLen, 
                                                &keyType, &curveId, &qsAlgId)))
        goto exit;

    /* using keyType and curveId, get algorithm identifier */
    status = SSH_KEY_getKeySshStringBuffer(keyType, curveId, qsAlgId, &pTempSignature);
    if (OK != status)
        goto exit;

    /* allocate buffer */
    preEncodedMesgLen = publicKeyBlobLen + pTempSignature->stringLen;
    status = DIGI_MALLOC((void **) &pPreEncodedMesg, preEncodedMesgLen);
    if (OK != status)
        goto exit;

    /* copy buffer to beginning.. */
    DIGI_MEMCPY(pPreEncodedMesg, pTempSignature->pString, pTempSignature->stringLen);
    DIGI_MEMCPY(pPreEncodedMesg + pTempSignature->stringLen, pPublicKeyBlob, publicKeyBlobLen);

    if (0 > (status = BASE64_encodeMessage(pPreEncodedMesg, preEncodedMesgLen, &pBase64EncodedMesg, &base64EncodedMesgLen)))
        goto exit;

    *ppBase64EncodedPublicKey = pBase64EncodedMesg;
    *pBased64EncodedPublicKeyLen = base64EncodedMesgLen;
    *ppAlgorithmName = pTempSignature;
exit:

    if (NULL != pPreEncodedMesg)
        DIGI_FREE((void **) &pPreEncodedMesg);

    if (NULL != pPublicKeyBlob)
        DIGI_FREE((void **) &pPublicKeyBlob);

    return status;
}


/*------------------------------------------------------------------*/
#define SSH_HOST_KEY_ROW_LEN  (72)

extern MSTATUS
SSH_KEY_generateHostKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength, ubyte **ppRetHostFile, ubyte4 *pRetHostFileLen)
{
    sshStringBuffer *pTemp = NULL;
    ubyte*          pRetMesg = NULL;
    ubyte4          retMesgLen;
    ubyte*          pFinalFile = NULL;
    ubyte*          pEncoded = NULL;
    ubyte4          extraBufLen;
    ubyte* pHeader = (ubyte *)"---- BEGIN SSH2 PUBLIC KEY ----\n";
    ubyte4 headerLen = DIGI_STRLEN((sbyte *)pHeader);
    ubyte* pFooter = (ubyte *)"---- END SSH2 PUBLIC KEY ----\n";
    ubyte4 footerLen = DIGI_STRLEN((sbyte *)pFooter);
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status = OK;

    if (NULL == pKeyBlob)
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    *ppRetHostFile   = NULL;
    *pRetHostFileLen = 0;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    status = SSH_KEY_generateBase64EncodedPublicKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength,
        &pTemp, &pRetMesg, &retMesgLen);
    if (OK != status)
        goto exit;

    pEncoded = pRetMesg;

    /* extra buffer space for carriage return */
    extraBufLen = (ubyte4)(retMesgLen / SSH_HOST_KEY_ROW_LEN) + (((retMesgLen % SSH_HOST_KEY_ROW_LEN) > 0) ? 1 : 0);

    *pRetHostFileLen = headerLen + retMesgLen + extraBufLen + footerLen;

    /* alloc code to make it the file look good */
    if (NULL == (*ppRetHostFile = pFinalFile = MALLOC(*pRetHostFileLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* a leading comment is required */
    DIGI_MEMCPY(pFinalFile, pHeader, headerLen);
    pFinalFile += headerLen;

    /* dup out the base64 text, maximum 72 key characters per line */
    while (SSH_HOST_KEY_ROW_LEN < retMesgLen)
    {
        DIGI_MEMCPY(pFinalFile, pEncoded, SSH_HOST_KEY_ROW_LEN);
        retMesgLen -= SSH_HOST_KEY_ROW_LEN;
        pFinalFile += SSH_HOST_KEY_ROW_LEN;
        pEncoded += SSH_HOST_KEY_ROW_LEN;

        pFinalFile[0] = '\n';
        pFinalFile += 1;
    }

    if (0 < retMesgLen)
    {
        DIGI_MEMCPY(pFinalFile, pEncoded, retMesgLen);
        pFinalFile += retMesgLen;

        pFinalFile[0] = '\n';
        pFinalFile += 1;
    }

    /* add a tail */
    DIGI_MEMCPY(pFinalFile, pFooter, footerLen);

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (NULL != pRetMesg)
        BASE64_freeMessage(&pRetMesg);

nocleanup:
    return status;
}

extern MSTATUS
SSH_KEY_generateServerAuthKeyFileAsymKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                                     ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen)
{
    MSTATUS status;
    ubyte *pKeyBlob = NULL;
    ubyte4 keyBlobLen;

    status = CRYPTO_serializeAsymKey(MOC_ASYM(hwAccelCtx) pKey, publicKeyPem, &pKeyBlob, &keyBlobLen);
    if (OK != status)
        goto exit;

    status = SSH_KEY_generateServerAuthKeyFile(pKeyBlob, keyBlobLen, ppRetEncodedAuthKey,
        pRetEncodedAuthKeyLen);
    if (OK != status)
        goto exit;

exit:
    if (NULL != pKeyBlob)
        DIGI_FREE((void **) &pKeyBlob);
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_KEY_generateServerAuthKeyFile(ubyte *pKeyBlob, ubyte4 keyBlobLength,
                                     ubyte **ppRetEncodedAuthKey, ubyte4 *pRetEncodedAuthKeyLen)
{
    sshStringBuffer *pIdentifier = NULL;
    ubyte*  pBase64EncodedMesg = NULL;
    ubyte4  base64EncodedMesgLen;
    ubyte*  pEncodedMesg = NULL;
    ubyte4  encodedMesgLen;
    ubyte*  pAlgoName;
    ubyte4 algoNameLen = 0;
    MSTATUS status = OK;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    status = SSH_KEY_generateBase64EncodedPublicKey(MOC_ASYM(hwAccelCtx) pKeyBlob, keyBlobLength,
        &pIdentifier, &pBase64EncodedMesg, &base64EncodedMesgLen);
    if (OK != status)
        goto exit;

    pAlgoName = pIdentifier->pString + 4;
    algoNameLen = pIdentifier->stringLen - 4;

    /* identifier + white space + base64 key material + CRLF */
    encodedMesgLen = (algoNameLen) + 1 + base64EncodedMesgLen + 2;

    status = DIGI_MALLOC((void **) &pEncodedMesg, encodedMesgLen);
    if (OK != status)
        goto exit;

    *ppRetEncodedAuthKey   = pEncodedMesg;
    *pRetEncodedAuthKeyLen = encodedMesgLen;

    /* add algorithm identifier */
    DIGI_MEMCPY(pEncodedMesg, pAlgoName, algoNameLen);
    pEncodedMesg += (algoNameLen);

    /* add whitespace separating identifier and BASE64 encoded key */
    *pEncodedMesg = ' ';
    pEncodedMesg++;

    /* base64 public key blob */
    DIGI_MEMCPY(pEncodedMesg, pBase64EncodedMesg, base64EncodedMesgLen);
    pEncodedMesg += base64EncodedMesgLen;

    /* add newline at end of file */
    DIGI_MEMCPY(pEncodedMesg, (ubyte *)" \n", 2);

    /* mark null to prevent bad free */
    pEncodedMesg = NULL;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if (pBase64EncodedMesg)
        BASE64_freeMessage(&pBase64EncodedMesg);

    if (NULL != pEncodedMesg)
        DIGI_FREE((void **) &pEncodedMesg);

    SSH_STR_freeStringBuffer(&pIdentifier);
nocleanup:
    return status;
}
#endif /* __DISABLE_DIGICERT_KEY_GENERATION__ */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
extern MSTATUS
SSH_KEY_parseEccPublicKey(sbyte* pKeyBlob, ubyte4 keyBlobLength, ubyte4 keyType, ubyte4 curveId,
    ubyte4 *pBytesRead, AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte4 keyLength;
    ubyte4 retrievedKeyLength;
    ubyte4 retrievedIdentifierLength;
    ubyte4 index;
    ubyte4 bytesRead;
    sbyte4 res;
    hwAccelDescr hwAccelCtx;

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto exit;

     if ((NULL == pKeyBlob) || (NULL == pBytesRead) || (NULL == pKey))
     {
        status = ERR_NULL_POINTER;
        goto exit;
     }

     *pBytesRead = bytesRead = 0;

    /* Allocate key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &(pKey->key.pECC));
#else
    status = EC_newKeyEx(curveId, &(pKey->key.pECC));
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId(curveId, &keyLength);
#else
    status = EC_getPointByteStringLenByCurveId(curveId, &keyLength);
#endif
    if (OK != status)
        goto exit;

    if (akt_ecc == keyType)
    {
        index = 0;
        status = SSH_KEY_getInteger((ubyte *) pKeyBlob, keyBlobLength, &index,
            &retrievedIdentifierLength);
        if (OK != status)
            goto exit;

        if (8 != retrievedIdentifierLength)
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        pKeyBlob += index;
        keyBlobLength -= index;
        bytesRead += index;

        res = -1;
        switch (curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case cid_EC_P192:
                status = DIGI_MEMCMP((void *) pKeyBlob, (void *) "nistp192", 8, &res);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
            case cid_EC_P224:
                status = DIGI_MEMCMP((void *) pKeyBlob, (void *) "nistp224", 8, &res);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
            case cid_EC_P256:
                status = DIGI_MEMCMP((void *) pKeyBlob, (void *) "nistp256", 8, &res);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
            case cid_EC_P384:
                status = DIGI_MEMCMP((void *) pKeyBlob, (void *) "nistp384", 8, &res);
                break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
            case cid_EC_P521:
                status = DIGI_MEMCMP((void *) pKeyBlob, (void *) "nistp521", 8, &res);
                break;
#endif
            default:
                status = ERR_BAD_KEY_BLOB;
        }
        if (OK != status)
            goto exit;

        if (0 != res)
        {
            status = ERR_BAD_KEY_BLOB;
            goto exit;
        }

        pKeyBlob += retrievedIdentifierLength;
        keyBlobLength -= retrievedIdentifierLength;
        bytesRead += retrievedIdentifierLength;
    }

    index = 0;
    status = SSH_KEY_getInteger((ubyte *) pKeyBlob, keyBlobLength, &index, &retrievedKeyLength);
    if (OK != status)
        goto exit;

    if (retrievedKeyLength != keyLength)
    {
        status = ERR_BAD_KEY_BLOB;
        goto exit;
    }

    /* move past length bytes */
    pKeyBlob += index;
    keyBlobLength -= index;
    bytesRead += index;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) pKey->key.pECC,
        (ubyte *) pKeyBlob, keyBlobLength, NULL, 0);
#else
    status = EC_setKeyParametersEx(MOC_ECC(hwAccelCtx) pKey->key.pECC,
        (ubyte *) pKeyBlob, keyBlobLength, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    bytesRead += keyBlobLength;
    *pBytesRead = bytesRead;
exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);
    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_KEY_sshParseAuthPublicKey(sbyte* pKeyBlob, ubyte4 keyBlobLength,
                                     AsymmetricKey *p_keyDescr)
{
    ubyte*  signatureType[] = {
        (ubyte *) "ssh-dss",
        (ubyte *) "ssh-rsa",
        (ubyte *) "rsa-sha2-256",
        (ubyte *) "rsa-sha2-512",
        (ubyte *) "ecdsa-sha2-nistp192",
        (ubyte *) "ecdsa-sha2-nistp224",
        (ubyte *) "ecdsa-sha2-nistp256",
        (ubyte *) "ecdsa-sha2-nistp384",
        (ubyte *) "ecdsa-sha2-nistp521",
        (ubyte *) "ssh-ed25519",
#ifdef __ENABLE_DIGICERT_PQC__
        (ubyte *) "ssh-mldsa44",
        (ubyte *) "ssh-mldsa65",
        (ubyte *) "ssh-mldsa87",
#endif
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
        (ubyte *) "ssh-mldsa44-es256",
        (ubyte *) "ssh-mldsa65-es256",
        (ubyte *) "ssh-mldsa87-es384",
        (ubyte *) "ssh-mldsa44-ed25519",
        (ubyte *) "ssh-mldsa65-ed25519",
        (ubyte *) "ssh-mldsa87-ed448",
#endif
        NULL
    };
    ubyte*            pAlgoName = NULL;
    ubyte4            algoNameLen;
    ubyte4            keyBlobNameLen;
    sbyte4            result;
    ubyte4            keyType;
    ubyte4            index;
    ubyte4            index1;
#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__))
    ubyte*            pN = NULL;
    ubyte4            nLen;
    ubyte*            pE = NULL;
    ubyte4            eLen;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    ubyte4            curveId = 0;
#endif
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
    ubyte4            keyLength;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX            *pQsCtx = NULL;
    ubyte4            qsPubKeyLen = 0;
    ubyte4            qsAlgId = 0;
#endif
    MSTATUS           status;
#ifdef __ENABLE_DIGICERT_DSA__
    MDsaKeyTemplate dsaTemplate = {0};
#endif
    hwAccelDescr    hwAccelCtx;

    if (NULL == p_keyDescr || NULL == pKeyBlob)
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSH, &hwAccelCtx)))
        goto nocleanup;

    status = CRYPTO_uninitAsymmetricKey(p_keyDescr, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(p_keyDescr);
    if (OK != status)
        goto exit;

    /* verify & skip past algorithm identifier */
    index = 0;
    while (NULL != signatureType[index])
    {
        pAlgoName = signatureType[index];
        algoNameLen = DIGI_STRLEN((const sbyte *)pAlgoName);
        
        index1 = 0;
        status = SSH_KEY_getInteger((ubyte *) pKeyBlob, keyBlobLength, &index1, &keyBlobNameLen);
        if (OK != status)
            goto exit;

        result = -1;
        if (keyBlobNameLen == algoNameLen)
        {
            status = DIGI_MEMCMP((ubyte *) pKeyBlob + 4, pAlgoName, algoNameLen, &result);
            if (OK != status)
                goto exit;
        }

        if (0 == result)
            break;

        index++;
    }

    switch (index)
    {
#ifdef __ENABLE_DIGICERT_DSA__
        case 0:
            keyType = akt_dsa;
            break;
#endif
#ifdef __ENABLE_DIGICERT_SSH_RSA_SUPPORT__
        case 1:
        case 2:
        case 3:
            keyType = akt_rsa;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case 4:
            keyType = akt_ecc;
            curveId = cid_EC_P192;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
        case 5:
            keyType = akt_ecc;
            curveId = cid_EC_P224;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
        case 6:
            keyType = akt_ecc;
            curveId = cid_EC_P256;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
        case 7:
            keyType = akt_ecc;
            curveId = cid_EC_P384;
            break;
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
        case 8:
            keyType = akt_ecc;
            curveId = cid_EC_P521;
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
        case 9:
            keyType = akt_ecc_ed;
            curveId = cid_EC_Ed25519;
            break;
#endif
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case 10:
            keyType = akt_qs;
            qsAlgId = cid_PQC_MLDSA_44;
            break;
        case 11:
            keyType = akt_qs;
            qsAlgId = cid_PQC_MLDSA_65;
            break;
        case 12:
            keyType = akt_qs;
            qsAlgId = cid_PQC_MLDSA_87;
            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
        case 13:
            keyType = akt_hybrid;
            curveId = cid_EC_P256;
            qsAlgId = cid_PQC_MLDSA_44;
            break;
        case 14:
            keyType = akt_hybrid;
            curveId = cid_EC_P256;
            qsAlgId = cid_PQC_MLDSA_65;
            break;
        case 15:
            keyType = akt_hybrid;
            curveId = cid_EC_P384;
            qsAlgId = cid_PQC_MLDSA_87;
            break;
        case 16:
            keyType = akt_hybrid;
            curveId = cid_EC_Ed25519;
            qsAlgId = cid_PQC_MLDSA_44;
            break;
        case 17:
            keyType = akt_hybrid;
            curveId = cid_EC_Ed25519;
            qsAlgId = cid_PQC_MLDSA_65;
            break;
        case 18:
            keyType = akt_hybrid;
            curveId = cid_EC_Ed448;
            qsAlgId = cid_PQC_MLDSA_87;
            break;
#endif
        default:
            status = ERR_BAD_KEY_TYPE;
            goto exit;
    }

    if(NULL != pAlgoName)
    {
        pKeyBlob      += (algoNameLen + 4);
        keyBlobLength -= (algoNameLen + 4);
    }

    if (akt_dsa == keyType)
    {
#if (defined(__ENABLE_DIGICERT_SSH_DSA_SUPPORT__))
        if (OK > (status = DSA_createKey(&(p_keyDescr->key.pDSA))))
            goto exit;

        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &dsaTemplate.pP, &dsaTemplate.pLen);
        if (OK != status)
            goto exit;

        if (keyBlobLength < (4 + dsaTemplate.pLen))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

        pKeyBlob += (4 + dsaTemplate.pLen);
        keyBlobLength -= (4 + dsaTemplate.pLen);

        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &dsaTemplate.pQ, &dsaTemplate.qLen);
        if (OK != status)
            goto exit;

        if (keyBlobLength < (4 + dsaTemplate.qLen))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

        pKeyBlob += (4 + dsaTemplate.qLen);
        keyBlobLength -= (4 + dsaTemplate.qLen);

        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &dsaTemplate.pG, &dsaTemplate.gLen);
        if (OK != status)
            goto exit;

        if (keyBlobLength < (4 + dsaTemplate.gLen))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

        pKeyBlob += (4 + dsaTemplate.gLen);
        keyBlobLength -= (4 + dsaTemplate.gLen);

        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &dsaTemplate.pY, &dsaTemplate.yLen);
        if (OK != status)
            goto exit;

        if (keyBlobLength < (4 + dsaTemplate.yLen))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

        pKeyBlob += (4 + dsaTemplate.yLen);
        keyBlobLength -= (4 + dsaTemplate.yLen);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) p_keyDescr->key.pDSA, &dsaTemplate);
#else
        status = DSA_setKeyParametersAux(MOC_DSA(hwAccelCtx) p_keyDescr->key.pDSA, &dsaTemplate);
#endif
        if (OK != status)
            goto exit;
#else
        p_keyDescr->type = akt_undefined;
        goto exit;
#endif
    }
    else if (akt_rsa == keyType)
    {
#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__))
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > (status = CRYPTO_INTERFACE_RSA_createKeyAux(&(p_keyDescr->key.pRSA))))
            goto exit;
#else
        if (OK > (status = RSA_createKey(&(p_keyDescr->key.pRSA))))
            goto exit;
#endif

        DEBUG_RELABEL_MEMORY(p_keyDescr->key.pRSA);

        /* e */
        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &pE, &eLen);
        if (OK != status)
            goto exit;

        pKeyBlob += (4 + eLen);
        if (0 >= (sbyte4)(keyBlobLength = (keyBlobLength - eLen - 4)))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

        /* n */
        status = SSH_getByteStringFromMpintBytes((ubyte *) pKeyBlob, keyBlobLength, &pN, &nLen);
        if (OK != status)
            goto exit;

        pKeyBlob += (4 + nLen);
        if (0 != (keyBlobLength = (keyBlobLength - nLen - 4)))
        {
            status = ERR_FILE_MISSING_KEY_DATA;
            goto exit;
        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = CRYPTO_INTERFACE_RSA_setPublicKeyData(MOC_RSA(hwAccelCtx) p_keyDescr->key.pRSA, pE, eLen, pN, nLen, NULL);
#else
        status = RSA_setPublicKeyData(MOC_RSA(hwAccelCtx) p_keyDescr->key.pRSA, pE, eLen, pN, nLen, NULL);
#endif
        if (OK != status)
            goto exit;
#else
        p_keyDescr->type = akt_undefined;
        goto exit;
#endif
    }
    else if((akt_ecc == keyType) || (akt_ecc_ed == keyType))
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__
        index = 0;
        status = SSH_KEY_parseEccPublicKey(pKeyBlob, keyBlobLength, keyType, curveId, &index, p_keyDescr);
#else
        p_keyDescr->type = akt_undefined;
        goto exit;
#endif
    }
    else if(akt_qs == keyType)
    {
#ifdef __ENABLE_DIGICERT_PQC__
        ubyte4 expPubLen = 0;

        status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlgId);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &expPubLen);
        if (OK != status)
            goto exit;

        index = 0;
        status = SSH_KEY_getInteger((ubyte *) pKeyBlob, keyBlobLength, &index, &qsPubKeyLen);
        if (OK != status)
            goto exit;

        if (qsPubKeyLen != expPubLen)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        pKeyBlob += 4;
        status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pKeyBlob, qsPubKeyLen);
        if (OK != status)
            goto exit;

        p_keyDescr->pQsCtx = pQsCtx;
        pQsCtx = NULL;
#else
        p_keyDescr->type = akt_undefined;
        goto exit;
#endif
    }
    else if(akt_hybrid == keyType)
    {
#if defined(__ENABLE_DIGICERT_PQC_COMPOSITE__)
        ubyte4 compositeLen = 0;
        ubyte4 expPubLen = 0;

        status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &pQsCtx, qsAlgId);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pQsCtx, &qsPubKeyLen);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId (curveId, &keyLength);
        if (OK != status)
            goto exit;

        /* expected is the qs portion concatenated with the ecc portion */
        expPubLen = qsPubKeyLen + keyLength;
        index = 0;
        status = SSH_KEY_getInteger((ubyte *) pKeyBlob, keyBlobLength, &index, &compositeLen);
        if (OK != status)
            goto exit;

        if (compositeLen != expPubLen)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* QS portion */
        pKeyBlob += 4;
        status = CRYPTO_INTERFACE_QS_setPublicKey(pQsCtx, pKeyBlob, qsPubKeyLen);
        if (OK != status)
            goto exit;

        pKeyBlob += qsPubKeyLen;

        /* ECC portion */
        status = CRYPTO_INTERFACE_EC_newKeyAux(curveId, &p_keyDescr->key.pECC);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_EC_setKeyParametersAux(MOC_ECC(hwAccelCtx) p_keyDescr->key.pECC, pKeyBlob, keyLength, NULL, 0);
        if (OK != status)
            goto exit;

        p_keyDescr->clAlg = curveId;
        p_keyDescr->pQsCtx = pQsCtx; pQsCtx = NULL;
#else
        p_keyDescr->type = akt_undefined;
        goto exit;
#endif
    }

    p_keyDescr->type = keyType;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSH, &hwAccelCtx);

    if ((OK != status) && (NULL != p_keyDescr))
    {
        CRYPTO_uninitAsymmetricKey(p_keyDescr, NULL);
    }

#if (defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__))
    if (NULL != pE)
        DIGI_FREE((void **) &pE);

    if (NULL != pN)
        DIGI_FREE((void **) &pN);
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pQsCtx)
        CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
#endif

#ifdef __ENABLE_DIGICERT_DSA__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(NULL, &dsaTemplate);
#else
    DSA_freeKeyTemplate(NULL, &dsaTemplate);
#endif
#endif

nocleanup:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_KEY_sshParseAuthPublicKeyFile(sbyte* pKeyFile, ubyte4 fileSize,
                                     AsymmetricKey *p_keyDescr)
{
    ubyte*            pRecall     = NULL;
    ubyte4            decodedKeyLength;
    MSTATUS           status;

    if (NULL == p_keyDescr  || NULL == pKeyFile)
    {
        status = ERR_NULL_POINTER;
        goto nocleanup;
    }

    status = CRYPTO_uninitAsymmetricKey(p_keyDescr, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(p_keyDescr);
    if (OK != status)
        goto exit;

    if (0 < fileSize && (sbyte) '-' != *pKeyFile)
    {
        status = parsePublicKeyFileStyle1(pKeyFile, fileSize, &pRecall, &decodedKeyLength);
        if (OK > status)
            goto exit;
    }
    else
    {
        status = parsePublicKeyFileStyle2(pKeyFile, fileSize, &pRecall, &decodedKeyLength);
        if (OK > status)
            goto exit;
    }

    status = SSH_KEY_sshParseAuthPublicKey((sbyte *) pRecall, decodedKeyLength, p_keyDescr);

exit:
    if (NULL != pRecall)
        DIGI_FREE((void **) &pRecall);

    if ((OK != status) && (NULL != p_keyDescr))
    {
        CRYPTO_uninitAsymmetricKey(p_keyDescr, NULL);
    }

nocleanup:
    return status;

} /* SSH_KEY_sshParseAuthPublicKeyFile */
