/*
 * crypto_interface_qs_composite.c
 *
 * @brief Composite signature APIs for quantum safe and classical crypto.
 * @details Composite signature APIs for quantum safe and classical crypto.
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

#if defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_PQC_SIG__) && defined(__ENABLE_DIGICERT_PQC_SIG_STREAMING__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/rsa.h"
#include "../crypto/ecc.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"

#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"

/* bytes holding the length of the pqc signature */
#define QS_COMPOSITE_LEN_OFFSET 4 

/* The prefix "CompositeAlgorithmSignatures2025" */
static const ubyte gpPrefix[32] = 
{
    0x43, 0x6F, 0x6D, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x65, 0x41, 0x6C, 0x67, 0x6F, 0x72, 0x69, 0x74, 
    0x68, 0x6D, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x32, 0x30, 0x32, 0x35,
};
#define QS_COMPOSITE_PREFIX_LEN 32

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeGetSigLen(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    ubyte4 *pSignatureLen
)
{
    MSTATUS status;
    ubyte4 qsSigLen = 0;
    ubyte4 len = 0;

    if (NULL == pKey || NULL == pSignatureLen)
        return ERR_NULL_POINTER;
    
    if (akt_hybrid != pKey->type)
        return ERR_INVALID_ARG;

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pKey->pQsCtx, &qsSigLen);
    if (OK != status)
        goto exit;

    if(pKey->clAlg < cid_RSA_2048_PKCS15) /* if ECC */
    {
        /* for all valid curves including Ed, signature is double (encoded) element len */
        status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pKey->key.pECC, &len);
        if (OK != status)
            goto exit;

        len *= 2;
    }
    else
    {
        status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pKey->key.pRSA, (sbyte4 *) &len);
        if (OK != status)
            goto exit;
    }

    if (addLenPrefix)
    {
        len += QS_COMPOSITE_LEN_OFFSET;
    }
    len += qsSigLen;
    
    *pSignatureLen = len;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_QS_compositePrepareMessage(
    ubyte *pDomain,
    ubyte4 domainLen,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte **ppMessagePrime,
    ubyte4 *pMessagePrimeLen)
{
    MSTATUS status = OK;
    ubyte *pMprime = NULL;
    ubyte4 mPrimeLen = 0;
    ubyte *pPtr;

    /* internal method, but validate message and domain here */
    if ((NULL == pMessage && messageLen) || (NULL == pDomain && domainLen))
        return ERR_NULL_POINTER;

    /* Now create M' = Prefix || Domain || len(ctx) || ctx || M */
    mPrimeLen = QS_COMPOSITE_PREFIX_LEN + domainLen + 1 + messageLen;

    status = DIGI_MALLOC((void **) &pMprime, mPrimeLen);
    if (OK != status)
        goto exit;

    pPtr = pMprime;
    (void) DIGI_MEMCPY(pPtr, gpPrefix, QS_COMPOSITE_PREFIX_LEN);
    pPtr += QS_COMPOSITE_PREFIX_LEN;

    if (domainLen > 0)
    {
        (void) DIGI_MEMCPY(pPtr, pDomain, domainLen);
        pPtr += domainLen;
    }

    /* ctxLen */
    *pPtr++ = 0;

    if (messageLen > 0)
    {
        (void) DIGI_MEMCPY(pPtr, pMessage, messageLen);
    }

    *ppMessagePrime = pMprime; pMprime = NULL;
    *pMessagePrimeLen = mPrimeLen;

exit:

    if (NULL != pMprime)
    {
        (void) DIGI_MEMSET_FREE(&pMprime, mPrimeLen);
    }

    return status;    
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeSign(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pDomain,
    ubyte4 domainLen,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
)
{
    MSTATUS status, fstatus;
    ubyte4 tempLen = 0;
    ubyte4 sigLen = 0;
    ubyte *pMprime = NULL;
    ubyte4 mPrimeLen = 0;
    ubyte hashAlgo = ht_sha256; /* default */
    ubyte4 lenPrefixOffset = 0;

    /* rest of input validations will be made by the calls below */
    if (NULL == pSignatureLen)
        return ERR_NULL_POINTER;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pKey, addLenPrefix, &sigLen);
    if (OK != status)
        goto exit;

    if (NULL == pSignature || bufferSize < sigLen)
    {
        status = ERR_BUFFER_TOO_SMALL;
        *pSignatureLen = sigLen;
        goto exit;
    }
 
    /* check for algs that use sha384 instead */
    if (cid_EC_P384 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg || cid_RSA_4096_PSS == pKey->clAlg)
        hashAlgo = ht_sha384;

    status = CRYPTO_INTERFACE_QS_compositePrepareMessage(pDomain, domainLen, pMessage, messageLen, &pMprime, &mPrimeLen);
    if (OK != status)
        goto exit;

    /*  mldsaSig = ML-DSA.Sign( mldsaSK, M', ctx=Domain ) 
        Recall domain is after the prefix in the messasge */
    status = CRYPTO_INTERFACE_QS_SIG_streamingInit(pKey->pQsCtx, TRUE, 0, pDomain, domainLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pKey->pQsCtx, pMprime, mPrimeLen);
    if (OK != status)
        goto exit;

    if (addLenPrefix)
    {
        lenPrefixOffset = QS_COMPOSITE_LEN_OFFSET;
    }

    /* perform the qs signature, skip over the first 4 bytes of the buffer, ie leave space for the length */
    status = CRYPTO_INTERFACE_QS_SIG_streamingSignFinal(pKey->pQsCtx, rngFun, rngArg, pSignature + lenPrefixOffset,
                                                        bufferSize - lenPrefixOffset, &tempLen);
    /* don't indicate an error yet if it failed */

    if (addLenPrefix)
    {
        /* Little endian 4 byte length */
        pSignature[0] = (ubyte) (tempLen & 0xff);
        pSignature[1] = (ubyte) ((tempLen >> 8) & 0xff); 
        pSignature[2] = (ubyte) ((tempLen >> 16) & 0xff); 
        pSignature[3] = (ubyte) ((tempLen >> 24) & 0xff); 
    }

    /* tradSig = Trad.Sign( tradSK, M' ) */
    if ( pKey->clAlg < cid_RSA_2048_PKCS15 ) /* ECC */
    {
        fstatus = CRYPTO_INTERFACE_ECDSA_signMessageExt(MOC_ECC(hwAccelCtx) pKey->key.pECC, rngFun, rngArg, hashAlgo,
                                                       pMprime, mPrimeLen, pSignature + lenPrefixOffset + tempLen,
                                                       bufferSize - lenPrefixOffset - tempLen, &tempLen, NULL);
    }
    else if (cid_RSA_2048_PKCS15 == pKey->clAlg || cid_RSA_3072_PKCS15 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg)
    {
        fstatus = CRYPTO_INTERFACE_RSA_signData(MOC_RSA(hwAccelCtx) pKey->key.pRSA, pMprime, mPrimeLen, hashAlgo,
                                                pSignature + lenPrefixOffset + tempLen, NULL);
    }
    else /* PSS */
    {
        ubyte *pTempSig = NULL;
        ubyte4 tempSigLen = 0;

        fstatus = CRYPTO_INTERFACE_PKCS1_rsaPssSign(MOC_RSA(hwAccelCtx) (randomContext *) rngArg, pKey->key.pRSA, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo,
                                                    (const ubyte *) pMprime, mPrimeLen, ht_sha384 == hashAlgo ? SHA384_RESULT_SIZE : SHA256_RESULT_SIZE, 
                                                    &pTempSig, &tempSigLen);
        if (OK == fstatus)
        {
            (void) DIGI_MEMCPY(pSignature + lenPrefixOffset + tempLen, pTempSig, tempSigLen);
        }

        if (NULL != pTempSig)
        {
            (void) DIGI_MEMSET_FREE(&pTempSig, tempSigLen);
        }
    }
    
    if (OK != (status | fstatus))
    {
        (void) DIGI_MEMSET(pSignature, 0x00, sigLen);
        status = ERR_INVALID_INPUT; /* need to keep constant time, can't give more desciptive error */
    }

exit:

    if (NULL != pMprime)
    {
        (void) DIGI_MEMSET_FREE(&pMprime, mPrimeLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_QS_compositeVerify(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    AsymmetricKey *pKey,
    byteBoolean addLenPrefix,
    ubyte *pDomain,
    ubyte4 domainLen,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyStatus
)
{
    MSTATUS status;
    ubyte4 sigLen = 0;
    ubyte4 expQsSigLen = 0;
    ubyte *pMprime = NULL;
    ubyte4 mPrimeLen = 0;
    ubyte hashAlgo = ht_sha256; /* default */
    ubyte4 lenPrefixOffset = 0;
    ubyte4 vStatus = 1;

    /* rest of input validations will be made by the calls below */
    if (NULL == pVerifyStatus)
        return ERR_NULL_POINTER;

    *pVerifyStatus = 1;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pKey, addLenPrefix, &sigLen);
    if (OK != status)
        goto exit;

    if (signatureLen != sigLen)
    {
        /*  *pVerifyStatus = 1 still */
        goto exit;
    }

    /* check for algs that use sha384 instead */
    if (cid_EC_P384 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg || cid_RSA_4096_PSS == pKey->clAlg)
        hashAlgo = ht_sha384;

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pKey->pQsCtx, &expQsSigLen);
    if (OK != status)
        goto exit;

    if (addLenPrefix)
    {
        ubyte4 tempLen;

        /* check the initial length of qs sig */
        tempLen = ((ubyte4) pSignature[0]) | (((ubyte4)pSignature[1]) << 8) | 
                  (((ubyte4)pSignature[2]) << 16) | (((ubyte4)pSignature[3]) << 24);

        /* public key operation, ok to goto exit once we know the signature is invalid */
        if (tempLen != expQsSigLen)
        {
            /*  *pVerifyStatus = 1 still */
            goto exit;
        }

        lenPrefixOffset = QS_COMPOSITE_LEN_OFFSET;
    }

    status = CRYPTO_INTERFACE_QS_compositePrepareMessage(pDomain, domainLen, pMessage, messageLen, &pMprime, &mPrimeLen);
    if (OK != status)
        goto exit;

    /*  mldsaSig = ML-DSA.Verify( pk1, M', s1, ctx=Domain )
        Recall domain is after the prefix in the messasge */
    status = CRYPTO_INTERFACE_QS_SIG_streamingInit(pKey->pQsCtx, TRUE, 0, pDomain, domainLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_streamingUpdate(pKey->pQsCtx, pMprime, mPrimeLen);
    if (OK != status)
        goto exit;

    /* perform the qs signature, skip over the first 4 bytes of the buffer, ie leave space for the length */
    status = CRYPTO_INTERFACE_QS_SIG_streamingVerifyFinal(pKey->pQsCtx, pSignature + lenPrefixOffset, expQsSigLen, &vStatus);
    if (OK != status)
        goto exit;

    if (vStatus)
    {
        *pVerifyStatus = vStatus;
        goto exit;
    }
 
    /* Trad.Verify( pk2, M', s2) */
    if ( pKey->clAlg < cid_RSA_2048_PKCS15 ) /* ECC */
    {
        status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(MOC_ECC(hwAccelCtx) pKey->key.pECC, hashAlgo, pMprime, mPrimeLen, 
                                                        pSignature + lenPrefixOffset + expQsSigLen, 
                                                        signatureLen - lenPrefixOffset - expQsSigLen, pVerifyStatus, NULL);
    }
    else if (cid_RSA_2048_PKCS15 == pKey->clAlg || cid_RSA_3072_PKCS15 == pKey->clAlg || cid_RSA_4096_PKCS15 == pKey->clAlg)
    {
        intBoolean validBool = FALSE;
        status = CRYPTO_INTERFACE_RSA_verifyData(MOC_RSA(hwAccelCtx) pKey->key.pRSA, pMprime, mPrimeLen, hashAlgo,
                                                 pSignature + lenPrefixOffset + expQsSigLen,
                                                 signatureLen - lenPrefixOffset - expQsSigLen, &validBool, NULL);
        if (FALSE == validBool)
        {
            *pVerifyStatus = 1;
        }
        else
        {
            *pVerifyStatus = 0;
        }
    }
    else /* PSS */
    {

        status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify(MOC_RSA(hwAccelCtx) (randomContext *) pKey->key.pRSA, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo,
                                                    (const ubyte *) pMprime, mPrimeLen, (const ubyte *) pSignature + lenPrefixOffset + expQsSigLen,
                                                    signatureLen - lenPrefixOffset - expQsSigLen,
                                                    ht_sha384 == hashAlgo ? SHA384_RESULT_SIZE : SHA256_RESULT_SIZE, pVerifyStatus);
    }
    
exit:

    if (NULL != pMprime)
    {
        (void) DIGI_MEMSET_FREE(&pMprime, mPrimeLen);
    }
    
    return status;
}
#endif /* defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_PQC_SIG__) && defined(__ENABLE_DIGICERT_PQC_SIG_STREAMING__) */
