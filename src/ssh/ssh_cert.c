/*
 * ssh_cert.c
 *
 * SSH Certificate Processing Center
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

#if (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__))

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/mem_pool.h"
#include "../common/moc_stream.h"
#include "../common/memory_debug.h"
#include "../common/sizedbuffer.h"
#include "../common/absstream.h"
#include "../common/tree.h"
#include "../common/memfile.h"
#include "../crypto/crypto.h"
#include "../crypto/dsa.h"
#include "../crypto/dh.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/cert_store.h"
#include "../crypto/ca_mgmt.h"
#include "../harness/harness.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/cert_chain.h"
#include "../ssh/ssh_str.h"
#if (defined(__ENABLE_DIGICERT_SSH_SERVER__))
#include "../ssh/ssh_context.h"
#include "../ssh/ssh_str_house.h"
#include "../ssh/ssh.h"
#endif
#if (defined(__ENABLE_DIGICERT_SSH_CLIENT__))
#include "../ssh/client/sshc_str_house.h"
#endif

#if (defined(__ENABLE_DIGICERT_PQC__))
#include "../ssh/ssh_qs.h"
#endif
#if (defined(__ENABLE_DIGICERT_PQC_COMPOSITE__))
#include "../ssh/ssh_hybrid.h"
#endif

#include "../ssh/ssh_dss.h"
#include "../ssh/ssh_rsa.h"
#include "../ssh/ssh_ecdsa.h"
#include "../ssh/ssh_cert.h"
#if (defined(__ENABLE_DIGICERT_SSH_OCSP_SUPPORT__) && defined(__ENABLE_DIGICERT_OCSP_CLIENT__))
#include "../ssh/ssh_ocsp.h"
#endif

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
SSH_CERT_convertAuthTypeToKeyAlgo(ubyte4 authType, ubyte4 qsAlgoId, ubyte4 keySize, ubyte4 *pRetPubKeyType, ubyte4 **ppAlgoIdList, ubyte4 *pAlgoIdListLen)
{
    MSTATUS status = OK;
    ubyte4 *pAlgoIdList = NULL;
    ubyte4 algoIdListLen = 1;  /* We only look for one single algo Id */

    /* essentially an internal method, null checks no necc */
    status = DIGI_CALLOC((void **) &pAlgoIdList, 1, sizeof(ubyte4));
    if (OK != status)
        goto exit;
       
    status = ERR_BAD_KEY_TYPE;
    if (CERT_STORE_AUTH_TYPE_RSA == authType)
    {
        status = OK;
        CERT_STORE_ALGO_ID_SET_KEYTYPE( pAlgoIdList[0], akt_rsa );
        /* Looking for a key in the cert so hashAlgo is not known yet and not needed here */
        *pRetPubKeyType = akt_rsa;
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else if (CERT_STORE_AUTH_TYPE_QS == authType)
    {
        status = OK;
        CERT_STORE_ALGO_ID_SET_KEYTYPE(pAlgoIdList[0], akt_qs);
        CERT_STORE_ALGO_ID_SET_QSALG(pAlgoIdList[0], qsAlgoId);
        *pRetPubKeyType = akt_qs;
    }
#endif
    else if ((CERT_STORE_AUTH_TYPE_ECDSA == authType)
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
        || (CERT_STORE_AUTH_TYPE_HYBRID == authType)
#endif 
            )
    {
        /* only P256, P384, P521 is supported for certificate authentication */
        status = OK;
        switch (keySize)
        {
#ifdef __ENABLE_DIGICERT_ECC__
            case 256:
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoIdList[0], cid_EC_P256 );
                break;

            case 384:
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoIdList[0], cid_EC_P384 );
                break;

            case 521:
                CERT_STORE_ALGO_ID_SET_CURVE( pAlgoIdList[0], cid_EC_P521 );
                break;              
#endif
            default:
                status = ERR_BAD_KEY_TYPE;
        }
        if (OK != status)
            goto exit;

        if (CERT_STORE_AUTH_TYPE_ECDSA == authType)
        {
            /* Looking for a key in the cert so hashAlgo is not known yet and not needed here */
            CERT_STORE_ALGO_ID_SET_KEYTYPE(pAlgoIdList[0], akt_ecc);
            *pRetPubKeyType = akt_ecc;
        }
#ifdef __ENABLE_DIGICERT_PQC_COMPOSITE__
        else
        {
            CERT_STORE_ALGO_ID_SET_KEYTYPE(pAlgoIdList[0], akt_hybrid);
            CERT_STORE_ALGO_ID_SET_QSALG(pAlgoIdList[0], qsAlgoId);
            *pRetPubKeyType = akt_hybrid;
        }
#endif
    }

    *ppAlgoIdList = pAlgoIdList; pAlgoIdList = NULL;
    *pAlgoIdListLen = algoIdListLen;
    
exit:

    if (NULL != pAlgoIdList)
    {
        (void) DIGI_FREE((void **) &pAlgoIdList);
    }

    return status;
}


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSH_DSA_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__)))
MOC_EXTERN MSTATUS
SSH_CERT_buildRawDsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength)
{
    MSTATUS status;

    if (akt_dsa != pContextSSH->hostKey.type)
    {
        status = ERR_SSH_EXPECTED_DSA_KEY;
        goto exit;
    }

    status = SSH_DSS_buildDssCertificate(MOC_DSA(pContextSSH->hwAccelCookie) &pContextSSH->hostKey, TRUE, &(pContextSSH->pHostBlob), &(pContextSSH->hostBlobLength));

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_SSH_RSA_SUPPORT__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__)))
MOC_EXTERN MSTATUS
SSH_CERT_buildRawRsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength)
{
    MSTATUS status;

    if (akt_rsa != (pContextSSH->hostKey.type & 0xff))
    {
        status = ERR_SSH_EXPECTED_RSA_KEY;
        goto exit;
    }

    status = SSH_RSA_buildRsaHostBlobCertificate(MOC_DSA(pContextSSH->hwAccelCookie) &pContextSSH->hostKey,
                                                     TRUE, &(pContextSSH->pHostBlob),
                                                     &(pContextSSH->hostBlobLength), pContextSSH->pHostKeySuites->hashLen);

    DEBUG_RELABEL_MEMORY(pContextSSH->pHostBlob);

exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if ((defined(__ENABLE_DIGICERT_ECC__)) && (defined(__ENABLE_DIGICERT_SSH_SERVER__)))
MOC_EXTERN MSTATUS
SSH_TRANS_buildRawEcdsaCert(sshContext *pContextSSH, ubyte *pCertificate, ubyte4 certificateLength)
{
    MSTATUS status;

    if ((akt_ecc != (pContextSSH->hostKey.type & 0xff)) &&
        (akt_ecc_ed != (pContextSSH->hostKey.type)))
    {
        status = ERR_SSH_EXPECTED_ECC_KEY;
        goto exit;
    }

    status = SSH_ECDSA_buildEcdsaCertificate(MOC_DSA(pContextSSH->hwAccelCookie) &pContextSSH->hostKey,
                                                 TRUE, &(pContextSSH->pHostBlob),
                                                 &(pContextSSH->hostBlobLength));
exit:
    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__))
#if (defined(__ENABLE_DIGICERT_SSH_SERVER__))
static MSTATUS
SSH_CERT_buildRawX509v3Cert(sshContext *pContextSSH, sshStringBuffer *pSshCertType,
                            SizedBuffer *pCertificates, ubyte4 numCertificates,
                            ubyte **ppRetCert, ubyte4 *pRetCertLen)
{
    ubyte4          numOcspResponses = 0;
    ubyte*          pOcspResponse = NULL;
    ubyte4          retOcspResponseLen = 0;
    ubyte*          pMessage = NULL;
    ubyte4          messageSize;
    ubyte4          index = 0;
#ifdef __ENABLE_DIGICERT_SSH_OCSP_SUPPORT__
    ubyte*          pIssuerCert;
    ubyte4          issuerCertLen;
    ASN1_ITEMPTR    pRoot = 0;
    ASN1_ITEMPTR    pIssuer, pSerialNumber;
    CStream         cs;
    MemFile         mf;
    ubyte*          cert;
    void*           pIterator;
    const           ubyte* dn;
#endif
    ubyte4          i;
    MSTATUS         status = OK;

    if ((NULL == pCertificates) || (NULL == ppRetCert) || (NULL == pRetCertLen) || (numCertificates < 1))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /*
     string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" /
             "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]"
     uint32  certificate-count
     string  certificate[1..certificate-count]
     uint32  ocsp-response-count
     string  ocsp-response[0..ocsp-response-count]
     */

#ifdef __ENABLE_DIGICERT_SSH_OCSP_SUPPORT__
    /* get the OCSP response */

    /* If certChain has more than one certificate, then the 0 is leaf certificate and 1 is the issuer */
    if(numCertificates > 1)
    {
        pIssuerCert   = pCertificates[1].data;
        issuerCertLen = pCertificates[1].length;
    }
    else if (numCertificates == 1)
    {
        cert = pCertificates[0].data;

        MF_attach(&mf, pCertificates[0].length, cert);

        CS_AttachMemFile(&cs, &mf);

        if (OK > ( status = ASN1_Parse(cs, &pRoot)))
        {
            goto exit;
        }

        if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pRoot),
                                                                 &pIssuer,
                                                                 &pSerialNumber)))
        {
            goto exit;
        }
                      
        dn = CS_memaccess(cs,pIssuer->dataOffset, pIssuer->length);

        if (OK > (status = (CERT_STORE_findTrustPointBySubjectFirst(pContextSSH->pCertStore,
                                                                    dn, pIssuer->length,
                                                                    (const ubyte **)&pIssuerCert,
                                                                    &issuerCertLen, (const void **)&pIterator))))
        {
            goto exit;
        }
    }

#if (defined(__ENABLE_DIGICERT_OCSP_TIMEOUT_CONFIG__))
    if (OK > (status = SSH_OCSP_getOcspResponse(SSH_sshSettings()->pOcspResponderUrl,
                                                SSH_sshSettings()->ocspTimeout,
                                                pCertificates[0].data,
                                                pCertificates[0].length,
                                                pIssuerCert, issuerCertLen,
                                                &pOcspResponse, &retOcspResponseLen)))
#else
    if (OK > (status = SSH_OCSP_getOcspResponse(SSH_sshSettings()->pOcspResponderUrl,
                                                pCertificates[0].data,
                                                pCertificates[0].length,
                                                pIssuerCert, issuerCertLen,
                                                &pOcspResponse, &retOcspResponseLen)))
#endif
    {
            goto exit;
    }

    /* supporting only 1 certificate for now */
    numOcspResponses = 1;
#else
    retOcspResponseLen = 0;
    numOcspResponses = 0;
#endif /* __ENABLE_DIGICERT_SSH_OCSP_SUPPORT__ */

    /* Compute length of signature, cert count, length of chain,
     *    number of OCSP responses, and OCSP responses
     */
    /* string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" / "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]" */
    messageSize  = pSshCertType->stringLen;

    /* uint32  certificate-count */
    messageSize += sizeof(ubyte4);

    /* string  certificate[1..certificate-count] */
    for (i = 0; i < numCertificates; i++)
        messageSize += sizeof(ubyte4) + pCertificates[i].length;

    /* uint32  ocsp-response-count */
    messageSize += sizeof(ubyte4);

    /* string  ocsp-response[0..ocsp-response-count] */
    if (0 != numOcspResponses)
    {
        /* to store OCSP message length */
        messageSize += sizeof(ubyte4);
        messageSize += retOcspResponseLen;
    }

    if (OK != (status = DIGI_MALLOC((void**)&pMessage, 4 + messageSize)))
        goto exit;

    DIGI_MEMSET(pMessage, 0x00, (messageSize + 4));

    /* string  "x509v3-ssh-dss" / "x509v3-ssh-rsa" / "x509v3-rsa2048-sha256" / "x509v3-ecdsa-sha2-[identifier]" */
    pMessage[0] = (ubyte)(messageSize >> 24);
    pMessage[1] = (ubyte)(messageSize >> 16);
    pMessage[2] = (ubyte)(messageSize >>  8);
    pMessage[3] = (ubyte)(messageSize);
    messageSize += 4; 
    index = 4;

    /* ssh sign algo into the buffer */
    DIGI_MEMCPY(pMessage + index, pSshCertType->pString, (sbyte4)pSshCertType->stringLen);
    index += pSshCertType->stringLen;

    /* uint32  certificate-count */
    pMessage[index + 0] = (ubyte)(numCertificates >> 24);
    pMessage[index + 1] = (ubyte)(numCertificates >> 16);
    pMessage[index + 2] = (ubyte)(numCertificates >>  8);
    pMessage[index + 3] = (ubyte)(numCertificates);
    index += 4;

    /* string  certificate[1..certificate-count] */
    for (i = 0; i < numCertificates; i++)
    {
        ubyte4 certLength = pCertificates[i].length;

        /* Add length of the certificate */
        pMessage[index + 0] = (ubyte)(certLength >> 24);
        pMessage[index + 1] = (ubyte)(certLength >> 16);
        pMessage[index + 2] = (ubyte)(certLength >>  8);
        pMessage[index + 3] = (ubyte)(certLength);
        index += 4;

        /* Copy the cert chain into the buffer */
        DIGI_MEMCPY(pMessage + index, pCertificates[i].data, (sbyte4)pCertificates[i].length);
        index += pCertificates[i].length;
    }


    /* uint32  ocsp-response-count */
    pMessage[index + 0] = (ubyte)(numOcspResponses >> 24);
    pMessage[index + 1] = (ubyte)(numOcspResponses >> 16);
    pMessage[index + 2] = (ubyte)(numOcspResponses >>  8);
    pMessage[index + 3] = (ubyte)(numOcspResponses);
    index += 4;

    /* string  ocsp-response[0..ocsp-response-count] */
    if (0 != numOcspResponses)
    {
        /*!!!!!*/
        pMessage[index + 0] = (ubyte)(retOcspResponseLen >> 24);
        pMessage[index + 1] = (ubyte)(retOcspResponseLen >> 16);
        pMessage[index + 2] = (ubyte)(retOcspResponseLen >>  8);
        pMessage[index + 3] = (ubyte)(retOcspResponseLen);
        index += 4;

        DIGI_MEMCPY(pMessage + index, pOcspResponse, retOcspResponseLen);
        index += retOcspResponseLen;
    }

    *ppRetCert = pMessage; pMessage = NULL;
    *pRetCertLen = messageSize;

exit:
    DIGI_FREE((void**)&pMessage);
    DIGI_FREE((void**)&pOcspResponse);

#ifdef __ENABLE_DIGICERT_SSH_OCSP_SUPPORT__
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }
#endif

    return status;

} /* SSH_CERT_buildRawX509v3Cert */


/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
SSH_CERT_buildCertRSA(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* "x509v3-ssh-rsa" */
    MSTATUS status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &ssh_rsa_cert_sign_signature, pCertificates, numCertificates, &(pContextSSH->pHostBlob), &(pContextSSH->hostBlobLength));

    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
SSH_CERT_buildCertRSA2048(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* "x509v3-rsa2048-sha256" */
    MSTATUS status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &ssh_rsa2048_cert_sign_signature, pCertificates, numCertificates, &(pContextSSH->pHostBlob), &(pContextSSH->hostBlobLength));

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PRE_DRAFT_PQC__
#if defined(__ENABLE_DIGICERT_PQC__)
MOC_EXTERN MSTATUS
SSH_CERT_buildCertQs(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* x509v3-mldsa44 */
    MSTATUS status;
    sshStringBuffer *pAlgoName = NULL;
    ubyte4 algoNameLen;
    sbyte4 exists;

    algoNameLen = pContextSSH->pHostKeySuites->signatureNameLength + 4;
    status = SSH_STR_makeStringBuffer(&pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    BIGEND32(pAlgoName->pString, algoNameLen - 4);

    status = DIGI_MEMCPY(pAlgoName->pString + 4, pContextSSH->pHostKeySuites->pSignatureName, pContextSSH->pHostKeySuites->signatureNameLength);
    if (OK != status)
        goto exit;

    exists = -1;
    status = SSH_QS_verifyAlgorithmName(pAlgoName, &exists);
    if (OK != status)
        goto exit;

    if (0 == exists)
    {
        status = SSH_CERT_buildRawX509v3Cert(pContextSSH, pAlgoName, pCertificates,
                                             numCertificates, &(pContextSSH->pHostBlob),
                                             &(pContextSSH->hostBlobLength));
    }
    else
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
    }

exit:
    if (NULL != pAlgoName)
        SSH_STR_freeStringBuffer(&pAlgoName);
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_PQC_COMPOSITE__)
MOC_EXTERN MSTATUS
SSH_CERT_buildCertHybrid(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* x509v3-mldsa<size>-<curve> */
    MSTATUS status;
    sshStringBuffer *pAlgoName = NULL;
    ubyte4 algoNameLen;
    sbyte4 exists;

    algoNameLen = pContextSSH->pHostKeySuites->signatureNameLength + 4;
    status = SSH_STR_makeStringBuffer(&pAlgoName, algoNameLen);
    if (OK != status)
        goto exit;

    BIGEND32(pAlgoName->pString, algoNameLen - 4);

    status = DIGI_MEMCPY(pAlgoName->pString + 4, pContextSSH->pHostKeySuites->pSignatureName, pContextSSH->pHostKeySuites->signatureNameLength);
    if (OK != status)
        goto exit;

    exists = -1;
    status = SSH_HYBRID_verifyAlgorithmName(pAlgoName, &exists);
    if (OK != status)
        goto exit;

    if (0 == exists)
    {
        status = SSH_CERT_buildRawX509v3Cert(pContextSSH, pAlgoName, pCertificates,
                                             numCertificates, &(pContextSSH->pHostBlob),
                                             &(pContextSSH->hostBlobLength));
    }
    else
    {
        status = ERR_SSH_BAD_PUBLIC_KEY_FORMAT;
    }

exit:
    if (NULL != pAlgoName)
        SSH_STR_freeStringBuffer(&pAlgoName);
    return status;
}
#endif /* __ENABLE_DIGICERT_PQC_COMPOSITE__ */
#endif /* __ENABLE_DIGICERT_PRE_DRAFT_PQC__ */

#if (defined(__ENABLE_DIGICERT_ECC__))
#if (!defined(__DISABLE_DIGICERT_ECC_P256__))

MOC_EXTERN MSTATUS
SSH_CERT_buildCertECDSAP256(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* x509v3-ecdsa-sha2-nistp256 */
    MSTATUS status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &ssh_ecdsa_cert_signature_p256, pCertificates,
                                         numCertificates, &(pContextSSH->pHostBlob),
                                         &(pContextSSH->hostBlobLength));
    return status;
}
#endif

#if (!defined(__DISABLE_DIGICERT_ECC_P384__))
MOC_EXTERN MSTATUS
SSH_CERT_buildCertECDSAP384(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* x509v3-ecdsa-sha2-nistp384 */
    MSTATUS status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &ssh_ecdsa_cert_signature_p384, pCertificates,
                                         numCertificates, &(pContextSSH->pHostBlob),
                                         &(pContextSSH->hostBlobLength));
    return status;
}
#endif

#if (!defined(__DISABLE_DIGICERT_ECC_P521__))
MOC_EXTERN MSTATUS
SSH_CERT_buildCertECDSAP521(sshContext *pContextSSH, SizedBuffer *pCertificates, ubyte4 numCertificates)
{
    /* x509v3-ecdsa-sha2-nistp521 */
    MSTATUS status;

    status = SSH_CERT_buildRawX509v3Cert(pContextSSH, &ssh_ecdsa_cert_signature_p521, pCertificates,
                                         numCertificates, &(pContextSSH->pHostBlob),
                                         &(pContextSSH->hostBlobLength));
    return status;
}
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#endif /* __ENABLE_DIGICERT_SSH_SERVER__  */
#endif /* __ENABLE_DIGICERT_SSH_X509V3_RFC_6187_SUPPORT__ */

#endif /* (defined(__ENABLE_DIGICERT_SSH_SERVER__) || defined(__ENABLE_DIGICERT_SSH_CLIENT__)) */

