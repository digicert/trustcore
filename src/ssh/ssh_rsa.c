/*
 * ssh_rsa.c
 *
 * SSH RSA Host Keys
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

#if ((defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__)))

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
#include "../crypto/rsa.h"
#include "../crypto/sha1.h"
#ifdef __ENABLE_MOCANA_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../common/sizedbuffer.h"
#include "../crypto/cert_store.h"
#include "../ssh/ssh_str.h"
#ifdef __ENABLE_MOCANA_SSH_SERVER__
#include "../ssh/ssh.h"
#include "../ssh/ssh_str_house.h"
#endif
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
#include "../ssh/client/sshc_str_house.h"
#endif
#include "../ssh/ssh_rsa.h"
#include "../ssh/ssh_mpint.h"

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_rsa.h"
#endif

/*------------------------------------------------------------------*/
static ubyte mRSASSA_PKCS_v1_5[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14 };
static ubyte mRSASSA_PKCS_v1_5_sha256[] = { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
static ubyte mRSASSA_PKCS_v1_5_sha512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };



/*------------------------------------------------------------------*/

extern MSTATUS
SSH_RSA_buildRsaCertificate(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                            intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen)
{
    ubyte*  pStringE = NULL;
    ubyte*  pStringN = NULL;
    RSAKey* pPub = NULL;
    ubyte4  index;
    sbyte4  lenE, lenN;
    MSTATUS status;
    MRsaKeyTemplate template = {0};

    if ((NULL == pKey) || (NULL == ppCertificate) || (NULL == pRetLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_rsa != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_getRSAPublicKey ((AsymmetricKey*)pKey, &pPub);
    if (OK != status)
        goto exit;
#else
    pPub = pKey->key.pRSA;
#endif

    /* if pPub is NULL, RSA_getKeyParametersAlloc will return ERR_NULL_POINTER */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) pPub, &template, MOC_GET_PUBLIC_KEY_DATA)))
        goto exit;
#else
    if (OK > (status = RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx) pPub, &template, MOC_GET_PUBLIC_KEY_DATA)))
        goto exit;
#endif

    if (OK > (status = SSH_mpintByteStringFromByteString(template.pE, template.eLen, 0, &pStringE, &lenE)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pStringE);

    if (OK > (status = SSH_mpintByteStringFromByteString(template.pN, template.nLen, 0, &pStringN, &lenN)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pStringN);

    /* save variables */
    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        *pRetLen = ssh_rsa_signature.stringLen + (ubyte4)lenE + (ubyte4)lenN;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        *pRetLen = sshc_rsa_signature.stringLen + (ubyte4)lenE + (ubyte4)lenN;
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    if (NULL == (*ppCertificate = MALLOC(4 + *pRetLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    (*ppCertificate)[0] = (ubyte)(*pRetLen >> 24);
    (*ppCertificate)[1] = (ubyte)(*pRetLen >> 16);
    (*ppCertificate)[2] = (ubyte)(*pRetLen >>  8);
    (*ppCertificate)[3] = (ubyte)(*pRetLen);
    *pRetLen += 4;
    index     = 4;

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        MOC_MEMCPY((*ppCertificate) + index, ssh_rsa_signature.pString, (sbyte4)ssh_rsa_signature.stringLen);
        index += ssh_rsa_signature.stringLen;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        MOC_MEMCPY((*ppCertificate) + index, sshc_rsa_signature.pString, (sbyte4)sshc_rsa_signature.stringLen);
        index += sshc_rsa_signature.stringLen;
#endif
    }

    MOC_MEMCPY((*ppCertificate) + index, pStringE, lenE);
    index += (ubyte4)lenE;

    MOC_MEMCPY((*ppCertificate) + index, pStringN, lenN);

exit:
    if (NULL != pStringE)
        FREE(pStringE);

    if (NULL != pStringN)
        FREE(pStringN);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pPub, &template);
#else
    RSA_freeKeyTemplate(pPub, &template);
#endif

    if ((NULL != pKey) && (akt_tap_rsa == pKey->type) && (NULL != pPub))
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pPub, NULL);
#else
        RSA_freeKey(&pPub, NULL);
#endif
    }

    return status;

} /* SSH_RSA_buildRsaCertificate */

#ifdef __ENABLE_MOCANA_SSH_SERVER__
extern MSTATUS
SSH_RSA_buildRsaHostBlobCertificate(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                            intBoolean isServer, ubyte **ppCertificate, ubyte4 *pRetLen, ubyte4 hashLen)
{
    ubyte*  pStringE = NULL;
    ubyte*  pStringN = NULL;
    RSAKey*  pPub = NULL;
    ubyte4  index;
    sbyte4  lenE, lenN;
    MSTATUS status;
    MRsaKeyTemplate template = {0};

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_rsa != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

#if (defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_getRSAPublicKey ((AsymmetricKey*)pKey, &pPub);
    if (OK != status)
        goto exit;
#else
    pPub = pKey->key.pRSA;
#endif

    /* if pPub is NULL, RSA_getKeyParametersAlloc will return ERR_NULL_POINTER */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(MOC_RSA(hwAccelCtx) pPub, &template, MOC_GET_PUBLIC_KEY_DATA)))
        goto exit;
#else
    if (OK > (status = RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx) pPub, &template, MOC_GET_PUBLIC_KEY_DATA)))
        goto exit;
#endif

    /* create mpint string versions */
    if (OK > (status = SSH_mpintByteStringFromByteString(template.pE, template.eLen, 0, &pStringE, &lenE)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pStringE);

    if (OK > (status = SSH_mpintByteStringFromByteString(template.pN, template.nLen, 0, &pStringN, &lenN)))
        goto exit;

    DEBUG_RELABEL_MEMORY(pStringN);


    /* save variables */
    if (isServer)
    {
        *pRetLen = ssh_rsa_signature.stringLen + (ubyte4)lenE + (ubyte4)lenN;
    }
    else
    {
        status = ERR_SSH_CONFIG;
        goto exit;
    }
    if (NULL == (*ppCertificate = MALLOC(4 + *pRetLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    (*ppCertificate)[0] = (ubyte)(*pRetLen >> 24);
    (*ppCertificate)[1] = (ubyte)(*pRetLen >> 16);
    (*ppCertificate)[2] = (ubyte)(*pRetLen >>  8);
    (*ppCertificate)[3] = (ubyte)(*pRetLen);
    *pRetLen += 4;
    index     = 4;

    if (isServer)
    {
        MOC_MEMCPY((*ppCertificate) + index, ssh_rsa_signature.pString, (sbyte4)ssh_rsa_signature.stringLen);
        index += ssh_rsa_signature.stringLen;
    }

    MOC_MEMCPY((*ppCertificate) + index, pStringE, lenE);
    index += (ubyte4)lenE;

    MOC_MEMCPY((*ppCertificate) + index, pStringN, lenN);

exit:
    if (NULL != pStringE)
        FREE(pStringE);

    if (NULL != pStringN)
        FREE(pStringN);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pPub, &template);
#else
    RSA_freeKeyTemplate(pPub, &template);
#endif

    if ((NULL != pKey) && (akt_tap_rsa == pKey->type) && (NULL != pPub))
    {
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKeyAux(&pPub, NULL);
#else
        RSA_freeKey(&pPub, NULL);
#endif
    }

    return status;

} /* SSH_RSA_buildRsaHostBlobCertificate */
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_RSA_buildRsaSignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                          AsymmetricKey *pKey,
                          intBoolean isServer,
                          ubyte **ppSignature, ubyte4 *pSignatureLength,
                          ubyte *pInDataToSign, ubyte4 inDataToSignLen,
                          ubyte *pAlgorithmName, ubyte4 algorithmNameLen)

{
    RSAKey* pRSAKey = NULL;
    sshStringBuffer *pSignatureIdentifier = NULL;
#ifdef __ENABLE_MOCANA_CHECK_RSA_BAD_SIGNATURE__
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    AsymmetricKey pubKey = {0};
#endif
    AsymmetricKey *pPubKey = NULL;
    sshStringBuffer signatureToVerify;
    intBoolean isSignatureValid = FALSE;
#endif
    ubyte*  pSignature = NULL;
    ubyte4  signatureLen;
    ubyte4  rsaSignatureLen;
    ubyte4  index;
    ubyte*  pDataToSign = NULL;
    vlong*  pVlongQueue = NULL;
    sbyte4  cmpRes;

    ubyte* pSignDataPrefix =  mRSASSA_PKCS_v1_5;
    ubyte4 signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5);

    MSTATUS status = OK;

    if((NULL == pKey) || (NULL == ppSignature) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (inDataToSignLen == 64)
    {
        pSignDataPrefix = mRSASSA_PKCS_v1_5_sha512;
        signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5_sha512);
    }
    else if (inDataToSignLen > 20)
    {
        pSignDataPrefix = mRSASSA_PKCS_v1_5_sha256;
        signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5_sha256);
    }

    *ppSignature = NULL;
    *pSignatureLength = 0;

    if ((akt_rsa != (pKey->type & 0xff)))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    if (NULL == (pRSAKey = pKey->key.pRSA))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDataToSign = MALLOC(signDataPrefixLen + inDataToSignLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMCPY(pDataToSign, pSignDataPrefix, signDataPrefixLen);
    MOC_MEMCPY(signDataPrefixLen + pDataToSign, pInDataToSign, inDataToSignLen);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#else
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#endif

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        if (64 == inDataToSignLen)
        {
            pSignatureIdentifier = &ssh_rsasha512_signature;
        }
        else if (inDataToSignLen > 20)
        {
            cmpRes = -1;
            /* if length doesn't match, we might be using different algorithm */
            if (algorithmNameLen == (ssh_rsasha256_signature.stringLen - 4))
            {
                status = MOC_MEMCMP(ssh_rsasha256_signature.pString + 4, pAlgorithmName, algorithmNameLen, &cmpRes);
                if (OK != status)
                    goto exit;
            }

            if (0 == cmpRes)
            {
                /* for rsa-sha2-256 algorithm, the signature format identifier is the same as algorithm name */
                pSignatureIdentifier = &ssh_rsasha256_signature;
            }
            else
            {
                /* if length doesn't match, nothing else to check */
                if (algorithmNameLen != (ssh_rsa2048_cert_sign_signature.stringLen - 4))
                {
                    status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
                    goto exit;
                }

                /* check if we are using x509v3-rsa2048-sha256 signature algorithm */
                status = MOC_MEMCMP(ssh_rsa2048_cert_sign_signature.pString + 4, pAlgorithmName, algorithmNameLen, &cmpRes);
                if (OK != status)
                    goto exit;

                if (0 == cmpRes)
                {
                    /* if so, the signature format identifier is "rsa2048-sha256" */
                    pSignatureIdentifier = &ssh_rsasha256_cert_signature;
                }
            }
        }
        else
        {
            pSignatureIdentifier = &ssh_rsa_signature;
        }
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        if (64 == inDataToSignLen)
        {
            pSignatureIdentifier = &sshc_rsa2048sha512_signature;
        }
        else if (inDataToSignLen > 20)
        {
            cmpRes = -1;
            /* if length doesn't match, we might be using different algorithm */
            if (algorithmNameLen == (sshc_rsa2048sha256_signature.stringLen - 4))
            {
                status = MOC_MEMCMP(sshc_rsa2048sha256_signature.pString + 4, pAlgorithmName, algorithmNameLen, &cmpRes);
                if (OK != status)
                    goto exit;
            }

            if (0 == cmpRes)
            {
                /* for rsa-sha2-256 algorithm, the signature format identifier is the same as algorithm name */
                pSignatureIdentifier = &sshc_rsa2048sha256_signature;
            }
            else
            {
                /* if length doesn't match, nothing else to check */
                if (algorithmNameLen != (sshc_rsa2048_cert_sign_signature.stringLen - 4))
                {
                    status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
                    goto exit;
                }

                /* check if we are using x509v3-rsa2048-sha256 signature algorithm */
                status = MOC_MEMCMP(sshc_rsa2048_cert_sign_signature.pString + 4, pAlgorithmName, algorithmNameLen, &cmpRes);
                if (OK != status)
                    goto exit;

                if (0 == cmpRes)
                {
                    /* if so, the signature format identifier is "rsa2048-sha256" */
                    pSignatureIdentifier = &sshc_rsa2048sha256_cert_signature;
                }
            }
        }
        else
        {
            pSignatureIdentifier = &sshc_rsa_signature;
        }
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    }

    /* no signature algorithm found */
    if (NULL == pSignatureIdentifier)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    signatureLen = pSignatureIdentifier->stringLen + 4 + rsaSignatureLen;

    if (NULL == (pSignature = MALLOC(4 + signatureLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pSignature[0] = (ubyte)(signatureLen >> 24) & 0xff;
    pSignature[1] = (ubyte)(signatureLen >> 16) & 0xff;
    pSignature[2] = (ubyte)(signatureLen >>  8) & 0xff;
    pSignature[3] = (ubyte)(signatureLen) & 0xff;
    index = 4;

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
        if (OK > (status = MOC_MEMCPY(pSignature + index, pSignatureIdentifier->pString, (sbyte4)pSignatureIdentifier->stringLen)))
            goto exit;
        index += pSignatureIdentifier->stringLen;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        if (OK > (status = MOC_MEMCPY(pSignature + index, pSignatureIdentifier->pString, (sbyte4)pSignatureIdentifier->stringLen)))
            goto exit;
        index += pSignatureIdentifier->stringLen;
#endif
    }

    /* write rsa pkcs#1.5 length */
    pSignature[index++] = (ubyte)(rsaSignatureLen >> 24) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen >> 16) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen >>  8) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen)       & 0xff;

    /* compute signature */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(hwAccelCtx)
                                       pRSAKey, pDataToSign, signDataPrefixLen + inDataToSignLen,
                                       pSignature + index, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx)
                                       pRSAKey, pDataToSign, signDataPrefixLen + inDataToSignLen,
                                       pSignature + index, &pVlongQueue)))
    {
        goto exit;
    }
#endif

#ifdef __ENABLE_MOCANA_CHECK_RSA_BAD_SIGNATURE__
    signatureToVerify.pString = pSignature;
    signatureToVerify.stringLen = signatureLen + 4;

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_getPublicKey((AsymmetricKey *) pKey, &pubKey);
    if (OK != status)
        goto exit;
    pPubKey = &pubKey;
#else
    pPubKey = pKey;
#endif

    status = SSH_RSA_verifyRsaSignature(MOC_RSA(hwAccelCtx) pPubKey, isServer, pInDataToSign, inDataToSignLen, &signatureToVerify, &isSignatureValid, NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == isSignatureValid)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

#endif /* __ENABLE_MOCANA_CHECK_RSA_BAD_SIGNATURE__ */

    /* save variables */
    *ppSignature      = pSignature;
    pSignature        = NULL;
    *pSignatureLength = index + rsaSignatureLen;

exit:
#if defined(__ENABLE_MOCANA_CHECK_RSA_BAD_SIGNATURE__) && defined(__ENABLE_MOCANA_CRYPTO_INTERFACE__)
    if (akt_tap_rsa == pKey->type)
    {
        CRYPTO_uninitAsymmetricKey(&pubKey, NULL);
    }
#endif

    if (NULL != pDataToSign)
        FREE(pDataToSign);

    if (NULL != pSignature)
        FREE(pSignature);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSH_RSA_buildRsaSignature */


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_X509V3_SIGN_SUPPORT__) && defined(__ENABLE_MOCANA_SSH_SERVER__))
extern MSTATUS
SSH_RSA_buildRsaSha1Signature(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey,
                          ubyte **ppSignature, ubyte4 *pSignatureLength,
                          ubyte *pInDataToSign, ubyte4 inDataToSignLen)
{
    RSAKey* pRSAKey;
    ubyte*  pSignature = NULL;
    ubyte4  signatureLen;
    ubyte4  rsaSignatureLen;
    ubyte4  index;
    ubyte*  pDataToSign = NULL;
    vlong*  pVlongQueue = NULL;
    MSTATUS status = OK;

    *ppSignature = NULL;
    *pSignatureLength = 0;

    if (akt_rsa != pKey->type)
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    if (NULL == (pRSAKey = pKey->key.pRSA))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pDataToSign = MALLOC(sizeof(mRSASSA_PKCS_v1_5) + inDataToSignLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMCPY(pDataToSign, mRSASSA_PKCS_v1_5, sizeof(mRSASSA_PKCS_v1_5));
    MOC_MEMCPY(sizeof(mRSASSA_PKCS_v1_5) + pDataToSign, pInDataToSign, inDataToSignLen);

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#else
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#endif

    signatureLen = ssh_rsa_sha1_signature.stringLen + 4 + rsaSignatureLen;

    if (NULL == (pSignature = MALLOC(4 + signatureLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pSignature[0] = (ubyte)(signatureLen >> 24) & 0xff;
    pSignature[1] = (ubyte)(signatureLen >> 16) & 0xff;
    pSignature[2] = (ubyte)(signatureLen >>  8) & 0xff;
    pSignature[3] = (ubyte)(signatureLen) & 0xff;
    index = 4;

    if (OK > (status = MOC_MEMCPY(pSignature + index, ssh_rsa_sha1_signature.pString, (sbyte4)ssh_rsa_sha1_signature.stringLen)))
        goto exit;
    index += ssh_rsa_sha1_signature.stringLen;

    /* write rsa pkcs#1.5 length */
    pSignature[index++] = (ubyte)(rsaSignatureLen >> 24) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen >> 16) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen >>  8) & 0xff;
    pSignature[index++] = (ubyte)(rsaSignatureLen)       & 0xff;

    /* compute signature */

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageAux(MOC_RSA(hwAccelCtx)
                                       pRSAKey, pDataToSign, sizeof(mRSASSA_PKCS_v1_5) + SHA1_RESULT_SIZE,
                                       pSignature + index, &pVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx)
                                       pRSAKey, pDataToSign, sizeof(mRSASSA_PKCS_v1_5) + SHA1_RESULT_SIZE,
                                       pSignature + index, &pVlongQueue)))
    {
        goto exit;
    }
#endif

    /* save variables */
    *ppSignature      = pSignature;
    pSignature        = NULL;
    *pSignatureLength = index + rsaSignatureLen;

exit:
    if (NULL != pDataToSign)
        FREE(pDataToSign);

    if (NULL != pSignature)
        FREE(pSignature);

    VLONG_freeVlongQueue(&pVlongQueue);

    return status;

} /* SSH_RSA_buildRsaSha1Signature */
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_RSA_calcRsaSignatureLength(MOC_RSA(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, intBoolean isServer, ubyte4 *pSignatureLength)
{
    RSAKey* pRSAKey = NULL;
    ubyte4  rsaSignatureLen;
    MSTATUS status = OK;

    if((NULL == pKey) || (NULL == pSignatureLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pSignatureLength = 0;

    if (akt_rsa != (pKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    if (NULL == (pRSAKey = pKey->key.pRSA))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#else
    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *) &rsaSignatureLen);
    if(OK != status)
        goto exit;
#endif

    if (isServer)
    {
#ifdef __ENABLE_MOCANA_SSH_SERVER__
#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
            *pSignatureLength = 4 + ssh_rsasha256_cert_signature.stringLen + 4 + rsaSignatureLen;
#else
            *pSignatureLength = 4 + ssh_rsasha256_signature.stringLen + 4 + rsaSignatureLen;
#endif
#else
        status = ERR_SSH_CONFIG;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
            *pSignatureLength = 4 + sshc_rsa2048sha256_cert_signature.stringLen + 4 + rsaSignatureLen;
#else
            *pSignatureLength = 4 + sshc_rsa2048sha256_signature.stringLen + 4 + rsaSignatureLen;
#endif
#else
        status = ERR_SSH_CONFIG;
#endif
    }

exit:
    return status;

} /* SSH_RSA_calcRsaSignatureLength */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_RSA_extractRsaCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) sshStringBuffer* pPublicKeyBlob, AsymmetricKey* pPublicKey,
                              ubyte4 index, vlong **ppVlongQueue)
{
    /* note: index should be in correct position */
    sshStringBuffer*    pKeyFormat = NULL;
    ubyte*              e          = NULL;
    ubyte*              n          = NULL;
    ubyte4              index1;
    MSTATUS             status;
    RSAKey*             pKey = NULL;
    ubyte4              eLen = 0;
    ubyte4              nLen = 0;

    if ((NULL == pPublicKey) || (NULL == pPublicKeyBlob))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_rsa != pPublicKey->type)
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    pKey = pPublicKey->key.pRSA;
    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* verify e */
    /* get E from mpintBytes */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString   + index,
                                             pPublicKeyBlob->stringLen - index,
                                             &e, &index1);
    if(OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(e);

    eLen = index1;
    index += index1 + 4;
    if (index >= pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

    /* verify n */
    status = SSH_getByteStringFromMpintBytes(pPublicKeyBlob->pString   + index,
                                             pPublicKeyBlob->stringLen - index,
                                             &n, &index1);
    if(OK != status)
        goto exit;

    DEBUG_RELABEL_MEMORY(n);

    nLen = index1;
    index += index1;
    /* the first 4 bytes of the public key are the length */
    if (index + 4 != pPublicKeyBlob->stringLen)
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_setPublicKeyData(MOC_RSA(hwAccelCtx) pKey, e, eLen, n, nLen, NULL);
    if(OK != status)
        goto exit;
#else
    status = RSA_setPublicKeyData(MOC_RSA(hwAccelCtx) pKey, e, eLen, n, nLen, NULL);
    if(OK != status)
        goto exit;
#endif

    pKey = NULL;

exit:
    MOC_FREE((void**)&e);
    MOC_FREE((void**)&n);
    SSH_STR_freeStringBuffer(&pKeyFormat);

    return status;

} /* SSH_RSA_extractRsaCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_RSA_verifyRsaSignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                           AsymmetricKey *pPublicKey,
                           intBoolean isServer,
                           ubyte *pExpectedPlainText, ubyte4 expectedPlainTextLen,
                           sshStringBuffer* pSignature, intBoolean *pIsGoodSignature,
                           vlong **ppVlongQueue)
{
    sshStringBuffer*    tempString   = NULL;
    sshStringBuffer*    rsaSignature = NULL;
    ubyte*              pPlainText   = NULL;
    ubyte4              plainTextLen;
    ubyte4              index      = 4;     /* skip past signature-string-length field */
    ubyte4              cipherLen;
    sbyte4              result = 1;
    MSTATUS             status = ERR_NULL_POINTER;

    ubyte* pSignDataPrefix =  mRSASSA_PKCS_v1_5;
    ubyte4 signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5);

    if((NULL == pPublicKey) || (NULL == pExpectedPlainText) || (NULL == pSignature) || (NULL == pIsGoodSignature))
        goto exit;


    if ( 64 == expectedPlainTextLen)
    {
        pSignDataPrefix = mRSASSA_PKCS_v1_5_sha512;
        signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5_sha512);
    }
    else if (expectedPlainTextLen > 20)
    {
        pSignDataPrefix = mRSASSA_PKCS_v1_5_sha256;
        signDataPrefixLen = sizeof(mRSASSA_PKCS_v1_5_sha256);
    }

    *pIsGoodSignature = FALSE;

    if (akt_rsa != (pPublicKey->type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    if (NULL == pPublicKey->key.pRSA)
    {
        status = ERR_NULL_POINTER;
        goto exit;
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
        if (64 == expectedPlainTextLen)
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, ssh_rsasha512_signature.pString, ssh_rsasha512_signature.stringLen, &result)))
                goto exit;
        }
        else if (expectedPlainTextLen > 20)
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, ssh_rsasha256_signature.pString, ssh_rsasha256_signature.stringLen, &result)))
                goto exit;

            /* check if this signature corresponds to x509v3-rsa2048-sha256 */
            if (0 != result)
            {
                if (OK > (status = MOC_MEMCMP(tempString->pString, ssh_rsasha256_cert_signature.pString, ssh_rsasha256_cert_signature.stringLen, &result)))
                    goto exit;
            }
        }
        else
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, ssh_rsa_signature.pString, ssh_rsa_signature.stringLen, &result)))
                goto exit;
        }
#else
        status = ERR_SSH_CONFIG;
        goto exit;
#endif
    } else {
#ifdef __ENABLE_MOCANA_SSH_CLIENT__
        if (64 == expectedPlainTextLen)
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, sshc_rsa2048sha512_signature.pString, sshc_rsa2048sha512_signature.stringLen, &result)))
                goto exit;
        }
        else if (expectedPlainTextLen > 20)
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, sshc_rsa2048sha256_signature.pString, sshc_rsa2048sha256_signature.stringLen, &result)))
                goto exit;

            /* check if this signature corresponds to x509v3-rsa2048-sha256 */
            if (0 != result)
            {
                if (OK > (status = MOC_MEMCMP(tempString->pString, sshc_rsa2048sha256_cert_signature.pString, sshc_rsa2048sha256_cert_signature.stringLen, &result)))
                    goto exit;
            }
        }
        else
        {
            if (OK > (status = MOC_MEMCMP(tempString->pString, sshc_rsa_signature.pString, sshc_rsa_signature.stringLen, &result)))
                goto exit;
        }
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

    /* fetch rsa signature */
    if (OK > (status = SSH_STR_copyStringFromPayload(pSignature->pString, pSignature->stringLen, &index, &rsaSignature)))
        goto exit;

    DEBUG_RELABEL_MEMORY(rsaSignature);
    DEBUG_RELABEL_MEMORY(rsaSignature->pString);

    /* verify signature length consumed all bytes */
    if (index != pSignature->stringLen)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pPublicKey->key.pRSA, (sbyte4 *)&cipherLen)))
        goto exit;
#else
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pPublicKey->key.pRSA, (sbyte4 *)&cipherLen)))
        goto exit;
#endif

    /* check rsa signature length */
    if (4 + cipherLen != rsaSignature->stringLen)
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    if (10 > cipherLen)     /*!-!-!-! to prevent static analyzer warnings, maybe we should have a function to sanity check cipher len?  */
    {
        status = ERR_SSH_MALFORMED_SIGNATURE;
        goto exit;
    }

    if (NULL == (pPlainText = MALLOC(cipherLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* decrypt signature */
#ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_RSA_verifySignatureAux(MOC_RSA(hwAccelCtx) pPublicKey->key.pRSA, 4 + rsaSignature->pString,
                                           pPlainText, &plainTextLen, ppVlongQueue)))
    {
        goto exit;
    }
#else
    if (OK > (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pPublicKey->key.pRSA, 4 + rsaSignature->pString,
                                           pPlainText, &plainTextLen, ppVlongQueue)))
    {
        goto exit;
    }
#endif

    /* verify plaintext */
    if (signDataPrefixLen + expectedPlainTextLen != plainTextLen)
        goto exit;

    if ((OK > (status = MOC_MEMCMP(pPlainText, pSignDataPrefix, signDataPrefixLen, &result))) && (0 != result))
        goto exit;

    status = MOC_MEMCMP(signDataPrefixLen + pPlainText, pExpectedPlainText, expectedPlainTextLen, &result);

    if (0 == result)
        *pIsGoodSignature = TRUE;

exit:
    SSH_STR_freeStringBuffer(&tempString);
    SSH_STR_freeStringBuffer(&rsaSignature);

    if (NULL != pPlainText)
        FREE(pPlainText);

    return status;

} /* SSH_RSA_verifyRsaSignature */


#endif /* ((defined(__ENABLE_MOCANA_SSH_RSA_SUPPORT__)) && (defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__))) */
