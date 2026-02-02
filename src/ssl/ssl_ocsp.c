/*
 * ssl_ocsp.c
 *
 * OCSP code to be used in SSL Extensions to support ocsp stapling
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

#if defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

#include <stdio.h>
#if defined(__RTOS_LINUX__)
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/datetime.h"
#include "../common/sizedbuffer.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_store.h"
#include "../crypto/cert_chain.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../common/base64.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/asn1cert.h"
#include "../common/uri.h"
#include "../common/mudp.h"
#include "../common/mtcp.h"
#include "../common/debug_console.h"
#include "../http/http_context.h"
#include "../http/http.h"
#include "../http/http_common.h"
#include "../http/client/http_request.h"
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ocsp/ocsp_message.h"
#include "../ocsp/client/ocsp_client.h"
#include "../ocsp/ocsp_http.h"
#include "../ocsp/ocsp_store.h"
#include "../common/mem_pool.h"
#include "../common/hash_value.h"
#include "../common/hash_table.h"
#include "../ssl/ssl.h"
#include "../harness/harness.h"
#include "../ssl/sslsock.h"
#include "../ssl/ssl_ocsp.h"


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_OCSP_initContext(void** ppContext)
{
    MSTATUS status  = OK;
    ocspContext *pOcspContext = NULL;

    if (OK > (status = OCSP_CONTEXT_createContextLocal(&pOcspContext, OCSP_CLIENT)))
        goto exit;

    *ppContext = (void *)pOcspContext;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSL_OCSP_createResponderIdList(void* pContext, char** ppTrustedResponderCertPath,
    ubyte4 trustedResponderCertCount, ubyte** ppRetRespIdList, ubyte4* pRetRespIdListLen)
{
    MSTATUS      status = OK;

    ResponderID* pResponderId = NULL;
    DER_ITEMPTR  pRespId     = NULL;
    ubyte*       pRetData    = NULL;
    ubyte4       retDataLen  = 0;
    ubyte        i, offset;

    ocspContext* pOcspContext = (ocspContext *)pContext;

    if (NULL == (pOcspContext->pOcspSettings->pTrustedResponders = MALLOC(sizeof(OCSP_certInfo)*
                                                                   trustedResponderCertCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for (i = 0; i < trustedResponderCertCount; i++)
    {
        if (NULL == ppTrustedResponderCertPath[i])
        {
            status = ERR_OCSP_INIT_FAIL;
            goto exit;
        }

        if (OK > (status = DIGICERT_readFile(ppTrustedResponderCertPath[i],
                                           &pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath,
                                           &pOcspContext->pOcspSettings->pTrustedResponders[i].certLen)))
        {
            /* File read failed */
            goto exit;
        }
    }

    pOcspContext->pOcspSettings->trustedResponderCount = trustedResponderCertCount;

    if (NULL == (pResponderId = MALLOC(sizeof(ResponderID) * pOcspContext->pOcspSettings->trustedResponderCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Now get the common name to be put in Responder Id */
    for (i = 0; i < pOcspContext->pOcspSettings->trustedResponderCount; i++)
    {
        ubyte4 subjectNameOffset;
        ubyte4 subjectNameLen;

        /* Create RespondeId structure */
        if (OK > (status = DER_AddSequence(NULL, &pRespId)))
            goto exit;

        if (OK > (status = DER_AddTag(pRespId, 1, &pRespId)))
            goto exit;


        if (OK > (status = CA_MGMT_extractCertASN1Name(pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath,
                                                       pOcspContext->pOcspSettings->pTrustedResponders[i].certLen,
                                                       TRUE, FALSE, &subjectNameOffset,
                                                       &subjectNameLen)))
        {
            goto exit;
        }

        if (OK > (status = DER_AddItem(pRespId, SEQUENCE|CONSTRUCTED, subjectNameLen,
                                       pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath,
                                       &pRespId)))
        {
            goto exit;
        }

        if (OK > (status = DER_Serialize(pRespId, (ubyte **) &pResponderId[0].pResponderID,
                (ubyte4 *)&pResponderId[0].responderIDlen)))
        {
            goto exit;
        }

        retDataLen += pResponderId[0].responderIDlen;

        if (pRespId)
        {
            TREE_DeleteTreeItem((TreeItem *) pRespId);
            pRespId = NULL;
        }

    }

    if (NULL == (pRetData = MALLOC(retDataLen)))
    {
        status =  ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET(pRetData, 0x00, retDataLen);

    offset = 0;

    /* copy contents */
    for (i = 0; i < pOcspContext->pOcspSettings->trustedResponderCount; i++)
    {

        DIGI_MEMCPY(pRetData + offset, pResponderId[i].pResponderID,  pResponderId[i].responderIDlen);
        offset += pResponderId[i].responderIDlen;
    }

    *ppRetRespIdList = pRetData;
    *pRetRespIdListLen = retDataLen;

exit:
    /* Need to free data here */
    if (pResponderId)
    {
        for (i = 0; i < pOcspContext->pOcspSettings->trustedResponderCount; i++)
        {
            if (pResponderId[i].pResponderID)
                FREE (pResponderId[i].pResponderID);
        }

        FREE (pResponderId);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_OCSP_createExtensionsList(extensions* pExts,
                              ubyte4 extCount,
                              ubyte** ppRetExtensionsList,
                              ubyte4* pRetExtensionListLen)
{
    MSTATUS         status      = OK;
    DER_ITEMPTR     pExtensions = NULL;
    ubyte           count       = 0;
    ubyte*          pExt        = NULL;
    ubyte4          extLen      = 0;

    if (0 < extCount)
    {
        if (OK > (status = DER_AddSequence(NULL, &pExtensions)))
            goto exit;

        for (count = 0; count < extCount; count++)
        {
            if (OK > (status = OCSP_MESSAGE_addExtension(pExtensions, pExts+count)))
                goto exit;
        }

        if (OK > (status = DER_Serialize(pExtensions, &pExt, &extLen)))
            goto exit;

        *ppRetExtensionsList = pExt;
        *pRetExtensionListLen = extLen;
    }

exit:
    if (pExtensions)
    {
        TREE_DeleteTreeItem((TreeItem *) pExtensions);
        pExtensions = NULL;
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_OCSP_addCertificateAndIssuer(
    SSLSocket* pSSLSock, ubyte4 certChainIndex, ValidationConfig *pConfig)
{
    MSTATUS status;
    ocspContext *pOcspContext = NULL;
    certChainPtr pCertChain = NULL;
    const ubyte *serverCertData;
    ubyte4 serverCertLen;
    const ubyte *issuerCertData;
    ubyte4 issuerCertLen;
    ubyte4 certNum;

    if ((NULL == pSSLSock) || (NULL == pSSLSock->pOcspContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pOcspContext = pSSLSock->pOcspContext;
    pCertChain = pSSLSock->pCertChain;
    /* Get the total number of certificates in the chain.
     */
    status = CERTCHAIN_numberOfCertificates(pCertChain, &certNum);
    if (OK > status)
    {
        goto exit;
    }

    /* Ensure there is at least a single certificate.
     */
    if (0 == certNum)
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    if (NULL != pOcspContext->pOcspSettings->pCertInfo)
    {
        ubyte4 i;

        for (i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
        {
            if (NULL != pOcspContext->pOcspSettings->pCertInfo[i].pCert)
            {
                status = DIGI_FREE(
                    (void **) &(pOcspContext->pOcspSettings->pCertInfo[i].pCert));
                if (OK > status)
                {
                    goto exit;
                }
            }
        }

        status = DIGI_FREE((void **) &(pOcspContext->pOcspSettings->pCertInfo));
        if (OK > status)
        {
            goto exit;
        }
    }

    if (NULL != pOcspContext->pOcspSettings->pIssuerCertInfo)
    {
        ubyte4 i;

        for (i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
        {
            if (NULL != pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath)
            {
                status = DIGI_FREE(
                    (void **) &(pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath));
                if (OK > status)
                {
                    goto exit;
                }
            }
        }

        status = DIGI_FREE(
            (void **) &(pOcspContext->pOcspSettings->pIssuerCertInfo));
        if (OK > status)
        {
            goto exit;
        }
    }

    /* Set to 1 for the single certificate that the OCSP response will be
     * validated for.
     */
    pOcspContext->pOcspSettings->certCount = 1;

    status = DIGI_MALLOC(
        (void **) &(pOcspContext->pOcspSettings->pCertInfo),
        sizeof(OCSP_singleRequestInfo) * pOcspContext->pOcspSettings->certCount);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MEMSET(
        (ubyte *) pOcspContext->pOcspSettings->pCertInfo, 0x00,
        sizeof(OCSP_singleRequestInfo) * pOcspContext->pOcspSettings->certCount);
    if (OK > status)
    {
        goto exit;
    }

    /* Get the certificate from the specified index */
    status = CERTCHAIN_getCertificate(
        pCertChain, certChainIndex, &serverCertData, &serverCertLen);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MALLOC(
        (void **) &(pOcspContext->pOcspSettings->pCertInfo[0].pCert),
        serverCertLen);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pOcspContext->pOcspSettings->pCertInfo[0].pCert, serverCertData,
        serverCertLen);
    if (OK > status)
    {
        goto exit;
    }

    pOcspContext->pOcspSettings->pCertInfo[0].certLen = serverCertLen;

    /* Get the issuer certificate.
     */
    if(certChainIndex == (certNum - 1))
    {
        /* This leg is to handle the last certificate. If this is the last
         * certificate in the chain then the issuer will either be itself if it
         * is self-signed, otherwise it should be located in the validation
         * config.
         */
        intBoolean isComplete = FALSE;

        status = CERTCHAIN_isComplete(pCertChain, &isComplete);
        if (OK > status)
        {
            goto exit;
        }

        if (TRUE == isComplete)
        {
            /* The certificate chain is complete on its own. The current
             * certificate should be self-signed.
             */
            issuerCertData = serverCertData;
            issuerCertLen = serverCertLen;
        }
        else
        {
            if (NULL == pConfig)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            /* Certificate chain is not complete, get the issuer certificate
             * from the validation config.
             */
            issuerCertData = pConfig->anchorCert;
            issuerCertLen = pConfig->anchorCertLen;
        }

    }
    else
    {
        /* If this is not the last certificate in the certificate chain then
         * then next certificate is the issuer.
         */
        status = CERTCHAIN_getCertificate(
            pCertChain, certChainIndex + 1, &issuerCertData, &issuerCertLen);
        if (OK > status)
        {
            goto exit;
        }
    }

    status = DIGI_MALLOC(
        (void **) &(pOcspContext->pOcspSettings->pIssuerCertInfo),
        sizeof(OCSP_singleRequestInfo) * pOcspContext->pOcspSettings->certCount);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MEMSET(
        (ubyte *) pOcspContext->pOcspSettings->pIssuerCertInfo, 0x00,
        sizeof(OCSP_singleRequestInfo) * pOcspContext->pOcspSettings->certCount);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MALLOC(
        (void **) &(pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath),
        issuerCertLen);
    if (OK > status)
    {
        goto exit;
    }

    status = DIGI_MEMCPY(
        pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath,
        issuerCertData, issuerCertLen);
    if (OK > status)
    {
        goto exit;
    }

    pOcspContext->pOcspSettings->pIssuerCertInfo[0].certLen = issuerCertLen;

exit:

    return status;
}

/*------------------------------------------------------------------*/

/* The method is called from the SSL client when it processes the server certificate
    to add the SSL server certificate and the issuer certificate to the OCSP context
    Note: If responder cert is not the issuer or issued by the isser user must config the trustedresponder cert*/

extern MSTATUS
SSL_OCSP_addCertificates(SSLSocket* pSSLSock)
{
    MSTATUS      status         = OK;
    ocspContext *pOcspContext   = pSSLSock->pOcspContext;
    certChainPtr pCertChain     = pSSLSock->pCertChain;
    const ubyte* serverCertData;
    ubyte4      serverCertLen;
    const ubyte* issuerCertData;
    ubyte4      issuerCertLen;
    ubyte4      certNum;
    ASN1_ITEMPTR pServerCert = NULL;
    
    if (OK > (status = CERTCHAIN_numberOfCertificates(pCertChain, &certNum)))
        goto exit;

    if (0 < certNum)
    {
        pOcspContext->pOcspSettings->certCount = 1;
    }
    else
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }
    
    if (NULL == (pOcspContext->pOcspSettings->pCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo)*
                                                                pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    
    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspContext->pOcspSettings->pCertInfo, 0x00, sizeof(OCSP_singleRequestInfo))))
        goto exit;
    
    
    /*Get SSL server certificate*/
    if (OK > (status = (CERTCHAIN_getCertificate(pCertChain, 0, &serverCertData, &serverCertLen))))
        goto exit;
    

    if (NULL == (pOcspContext->pOcspSettings->pCertInfo[0].pCert = MALLOC(serverCertLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pOcspContext->pOcspSettings->pCertInfo[0].pCert,serverCertData, serverCertLen);

    pOcspContext->pOcspSettings->pCertInfo[0].certLen = serverCertLen;
    
    
    if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo) *
                                                                pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspContext->pOcspSettings->pIssuerCertInfo, 0x00, sizeof(OCSP_singleRequestInfo))))
        goto exit;
    
    /*Get issuer certificate*/
    
    if(1 == certNum) /*Only server certificate is provided, no chain*/
    {
        
        MemFile         mf;
        CStream         cs;
        ValidationConfig      vc = {0};
        
        MF_attach(&mf, serverCertLen, (ubyte*) serverCertData);
        CS_AttachMemFile(&cs, &mf);
        
        if (OK > (status = ASN1_Parse(cs, &pServerCert)))
        {
            goto exit;
        }
        
        /*Check if server certificate is root cert*/
        status = X509_isRootCertificate(ASN1_FIRST_CHILD(pServerCert), cs);
        switch (status)
        {
            case OK: /*Set issuer cert to server cert*/
                if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath = MALLOC(serverCertLen)))
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMCPY(pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath,serverCertData, serverCertLen);
                pOcspContext->pOcspSettings->pIssuerCertInfo[0].certLen = serverCertLen;
                break;
                
            case ERR_FALSE: /*Look for issuer in certstore*/
                vc.pCertStore = pSSLSock->pCertStore;
                if (OK > (status = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie) pCertChain, &vc)))
                {
                    if (status == ERR_CERT_CHAIN_NO_TRUST_ANCHOR)
                    {
                        /* isser certificate is not in the cert store */
                        status = ERR_OCSP_MISSING_ISSUER_CERT;
                    }
                    goto exit;
                    
                }
                else
                {
                    /* isser certificate was found in the cert store */
                    if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath = MALLOC(vc.anchorCertLen)))
                    {
                        status = ERR_MEM_ALLOC_FAIL;
                        goto exit;
                    }
                    DIGI_MEMCPY(pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath,vc.anchorCert, vc.anchorCertLen);
                    pOcspContext->pOcspSettings->pIssuerCertInfo[0].certLen = vc.anchorCertLen;
                    
                }
                break;
                
            default: /*error*/
                goto exit;
        }
        
        
    }
    else /*Server cert chain is provided*/
    {
        /*Get SSL server cert issuer from certificate chain*/
        if (OK > (status = CERTCHAIN_getCertificate(pCertChain,1, &issuerCertData, &issuerCertLen)))
            goto exit;
        
        if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath = MALLOC(issuerCertLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        
        DIGI_MEMCPY(pOcspContext->pOcspSettings->pIssuerCertInfo[0].pCertPath, issuerCertData, issuerCertLen);
        pOcspContext->pOcspSettings->pIssuerCertInfo[0].certLen = issuerCertLen;
    }

exit:

    if (NULL != pServerCert)
    {
        TREE_DeleteTreeItem((TreeItem *) pServerCert);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS SSL_OCSP_getOcspResponse(SSLSocket* pSSLSock,
                                        const SizedBuffer *pCertificates,
                                        sbyte4 certificateCount,
                                        ocspStorePtr pOcspStore,
                                        ubyte** ppResponse,
                                        ubyte4* pRetResponseLen)
{
    MSTATUS status;
    ubyte *pLeafCert = NULL, *pIssuer = NULL;
    ubyte4 leafCertLen = 0, issuerLen = 0;
    ASN1_ITEMPTR pLeafRoot = NULL;
    certDescriptor *pCerts = NULL;
    certChainPtr pSslServerCertChain = NULL;

    if ( (NULL == pSSLSock) || (NULL == pOcspStore) || (NULL == ppResponse) ||
         (NULL == pRetResponseLen) || (NULL == pCertificates) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 >= certificateCount)
    {
        status = ERR_OCSP_INIT_FAIL;
        goto exit;
    }

    pLeafCert = pCertificates[0].data;
    leafCertLen = pCertificates[0].length;

    if (1 == certificateCount)
    {
        MemFile mf;
        CStream cs;

        MF_attach(&mf, leafCertLen, pLeafCert);
        CS_AttachMemFile(&cs, &mf);

        status = ASN1_Parse(cs, &pLeafRoot);
        if (OK > status)
        {
            goto exit;
        }

        status = X509_isRootCertificate(ASN1_FIRST_CHILD(pLeafRoot), cs);
        if (ERR_FALSE == status)
        {
            ValidationConfig vc = { 0 };
            ubyte4 numServerCerts;

            numServerCerts = certificateCount;

            status = DIGI_MALLOC(
                (void **) &pCerts, numServerCerts * sizeof(*pCerts));
            if (OK > status)
            {
                goto exit;
            }

            (*pCerts).pCertificate  = pCertificates[0].data;
            (*pCerts).certLength    = pCertificates[0].length;
            
            vc.pCertStore = pSSLSock->pCertStore;
            
            if (OK > (status = CERTCHAIN_createFromIKE(MOC_ASYM(pSSLSock->hwAccelCookie)
                                                        &pSslServerCertChain, pCerts, numServerCerts)))
                goto exit;
            
            /*Retrieve issuer cert from the cert store*/
            if (OK > (status = CERTCHAIN_validate(MOC_ASYM(pSSLSock->hwAccelCookie) pSslServerCertChain, &vc)))
            {
                if (status == ERR_CERT_CHAIN_NO_TRUST_ANCHOR)
                {
                    /* isser certificate is not in the cert store */
                    /* set status to OK for empty response */
                    status = OK;
                }
                goto exit;
                
            }
            else
            {
                /* isser certificate was found in the cert store */
                pIssuer = (ubyte *) vc.anchorCert;
                issuerLen = vc.anchorCertLen;
            }
        }
        else if (OK != status)
        {
            goto exit;
        }
        else
        {
            pIssuer = pCertificates[0].data;
            issuerLen = pCertificates[0].length;
        }
    }
    else
    {
        pIssuer = pCertificates[1].data;
        issuerLen = pCertificates[1].length;
    }

    /* Call into the OCSP store to retrieve a response.
     */
    status = OCSP_STORE_findResponseByCert(
        pOcspStore, pLeafCert, leafCertLen, pIssuer, issuerLen,
        (sbyte *) pSSLSock->pResponderUrl, pSSLSock->pExts,
        pSSLSock->numOfExtension, ppResponse, pRetResponseLen);

exit:

    if (NULL != pSslServerCertChain)
    {
        CERTCHAIN_delete(&pSslServerCertChain);
    }

    if (NULL != pLeafRoot)
    {
        TREE_DeleteTreeItem((TreeItem *) pLeafRoot);
    }

    if (NULL != pCerts)
    {
        DIGI_FREE((void **) &pCerts);
    }

    return status;
}

/*------------------------------------------------------------------*/

static ubyte4
SSL_OCSP_getChildCount(ASN1_ITEMPTR pItem)
{
    ubyte4       count  = 0;
    ASN1_ITEMPTR pChild = NULL;

    if (!pItem)
        return count;

    pChild = ASN1_FIRST_CHILD(pItem);
    while (pChild)
    {
        count++;
        pChild = ASN1_NEXT_SIBLING(pChild);
    }

    return count;

} /* SSL_OCSP_getChildCount */

/*------------------------------------------------------------------*/

extern MSTATUS
SSL_OCSP_parseExtensions(ubyte* pExtensions, ubyte4 extLen, extensions** ppExts, ubyte4* pExtCount)
{
    MSTATUS status = OK;
    MemFile       memFile;
    CStream       cs;
    ASN1_ITEMPTR  pExtRoot      = NULL;
    ASN1_ITEMPTR  pExtRootChild = NULL;
    extensions*   pTempExts     = NULL;
    ASN1_ITEMPTR  pItem         = NULL;

    MF_attach(&memFile, extLen, pExtensions);
    CS_AttachMemFile(&cs, &memFile);

    if (OK > (status = ASN1_Parse(cs, &pExtRoot)))
        goto exit;

    if (pExtRoot)
    {
        ASN1_ITEMPTR pExt;
        ubyte4       count = 0;

        if (NULL == (pExtRootChild = ASN1_FIRST_CHILD(pExtRoot)))
        {
            status = ERR_OCSP_INVALID_STRUCT;
            goto exit;
        }

        *pExtCount = SSL_OCSP_getChildCount(pExtRootChild);

        if (0 == *pExtCount)
            goto exit;

        if (NULL == (pTempExts = MALLOC((*pExtCount)*sizeof(extensions))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (NULL == (pExt = ASN1_FIRST_CHILD(pExtRootChild)))
        {
            status = ERR_OCSP_INVALID_STRUCT;
            goto exit;
        }

        while (pExt)
        {
            ubyte *buf = NULL;

            if (NULL == (pItem = ASN1_FIRST_CHILD(pExt)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK != ASN1_VerifyType(pItem, OID))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK == ASN1_VerifyOID(pItem, cs, id_pkix_ocsp_nonce_OID))
            {
                (pTempExts+count)->oid = (ubyte *)id_pkix_ocsp_nonce_OID;
            }
            else if (OK == ASN1_VerifyOID(pItem, cs, id_pkix_ocsp_crl_OID))
            {
                (pTempExts+count)->oid = (ubyte *)id_pkix_ocsp_crl_OID;
            }
            else
            {
                /* unknown extension, ignore? */
            }

            if (NULL == (pItem = ASN1_NEXT_SIBLING(pItem)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK == ASN1_VerifyType(pItem, BOOLEAN))
            {
                (pTempExts+count)->isCritical = pItem->data.m_boolVal;
                if (NULL == (pItem = ASN1_NEXT_SIBLING(pItem)))
                {
                    status = ERR_OCSP_INVALID_STRUCT;
                    goto exit;
                }
            }
            else
            {
                (pTempExts+count)->isCritical = FALSE;
            }

            /* unwrap OCTETSTRING */
            if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            buf = (ubyte*)CS_memaccess(cs,
                                       pItem->dataOffset, pItem->length);

            if (NULL ==((pTempExts+count)->value = MALLOC(pItem->length)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY((pTempExts+count)->value, buf, pItem->length);
            (pTempExts+count)->valueLen = pItem->length;

            if (buf)
            {
                CS_stopaccess(cs, buf);
            }

            count = count + 1;
            pExt = ASN1_NEXT_SIBLING(pExt);
        }

        *ppExts   = pTempExts;
        pTempExts = NULL;
    }

exit:
    if (pTempExts)
    {
        ubyte count;

        for (count = 0; count < *pExtCount; count++)
        {
            if ((pTempExts+count)->value)
                FREE ((pTempExts+count)->value);
        }

        FREE (pTempExts);
    }

    if (pExtRoot)
        TREE_DeleteTreeItem((TreeItem*)pExtRoot);

    return status;
}


/*------------------------------------------------------------------*/
/* This method is to be called from the SSL client to validate the OCSP response  */
/* received in the Certificate Status  message from the server                            */

extern MSTATUS
SSL_OCSP_validateOcspResponse(SSLSocket *pSSLSock, ubyte* pResponse, ubyte4 responseLen)
{

    ocspContext*        pOcspContext    = (ocspContext *)pSSLSock->pOcspContext;

    ubyte*              pRequest        = NULL;
    ubyte4              requestLen      = 0;
    extensions*         pExts           = NULL;
    ubyte4              extCount        = 0;

    OCSP_certStatus*    pCertStatus     = NULL;
    OCSP_responseStatus respStatus;
    TimeDate            producedAt;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    OCSP_certID*        pCertId         = NULL;
    TimeDate            thisUpdate;
    TimeDate            nextUpdate;
    byteBoolean         isNextUpdate;
    ubyte               j               = 0;
#endif
    ubyte               i               = 0;

    MSTATUS             status       =  OK;

    if (NULL == pOcspContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pOcspContext->pOcspSettings->hashAlgo                   = sha1_OID;
    pOcspContext->pOcspSettings->shouldAddServiceLocator    = FALSE;
    pOcspContext->pOcspSettings->shouldSign                 = FALSE;
    pOcspContext->pOcspSettings->signingAlgo                = NULL;
    pOcspContext->pOcspSettings->timeSkewAllowed            = 360;
    pOcspContext->pOcspSettings->shouldAddNonce             = FALSE;

    
    /* Populating data in internal format based on user config     */
    if ((0 >= pOcspContext->pOcspSettings->certCount))
    {
       status = ERR_OCSP_INIT_FAIL;
       goto exit;
    }
    
    /* Call the API to generate OCSP request just to make sure our internal state is correct */
    if (OK > (status = OCSP_CLIENT_generateRequest(pOcspContext, pExts, extCount, &pRequest, &requestLen)))
        goto exit;

    /* API to parse the response */
    if (OK > (status = OCSP_CLIENT_parseResponse(pOcspContext, pResponse, responseLen)))
        goto exit;

    /* API to check the OCSP response status */
    if (OK > (status = OCSP_CLIENT_getResponseStatus(pOcspContext,  &respStatus)))
        goto exit;

    if (ocsp_successful == respStatus)
    {

        DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP Response Details:");

        /* API to get the producedAt attribute in the OCSP response */
        if (OK > (status = OCSP_CLIENT_getProducedAt(pOcspContext, &producedAt)))
                goto exit;

        DB_PRINT("Produced At       -> %2d:%2d:%2d %2d %2d %4d \n",producedAt.m_hour,
                                                                  producedAt.m_minute,
                                                                  producedAt.m_second,
                                                                  producedAt.m_day,
                                                                  producedAt.m_month,
                                                                  (producedAt.m_year + 1970));

        if (OK > (status = OCSP_CLIENT_getCurrentCertStatus(pOcspContext, &pCertStatus)))
            goto exit;

        /* Note: Free pCertStatus before exiting to avoid memory leaks */

        if (NULL == pCertStatus)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        switch (pCertStatus->flag)
        {
            case ocsp_good:
                 DB_PRINT("Certificate status-> GOOD\n");
                 break;

            case ocsp_revoked:
                 status       =  ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
                 DB_PRINT("Certificate status-> Revoked\n");
                 DB_PRINT("Revocation Time   -> %2d:%2d:%2d %2d %2d %4d \n",pCertStatus->revocationTime.m_hour,
                                                                           pCertStatus->revocationTime.m_minute,
                                                                           pCertStatus->revocationTime.m_second,
                                                                           pCertStatus->revocationTime.m_day,
                                                                           pCertStatus->revocationTime.m_month,
                                                                           (pCertStatus->revocationTime.m_year + 1970));


                break;

            case ocsp_unknown:
                 status       =  ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
                 DB_PRINT ("Certificate status-> UnKnown\n");
                 break;
        }


        if (OK > status)
        {
            goto exit;
        }

        
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__

        DEBUG_CONSOLE_printf("\nCERT %d\n", i+1);

        /* API to get the certificate specific info present in CertId field of response */
        status = OCSP_CLIENT_getCurrentCertId(pOcspContext,&pCertId);
        if ((OK > status) || (NULL == pCertId))
        {
            goto exit;
        }

        DEBUG_CONSOLE_printf ("Serial Number:    ->");

        for (j = 0; j < pCertId->serialNumberLength; j++)
            DEBUG_CONSOLE_printf(" %X ",pCertId->serialNumber[j]);

        DEBUG_CONSOLE_printf("\n");

        if (OK > (status = OCSP_CLIENT_getCurrentThisUpdate(pOcspContext, &thisUpdate)))
            goto exit;

        DEBUG_CONSOLE_printf ("This Update       -> %2d:%2d:%2d %2d %2d %4d \n",thisUpdate.m_hour,
                                                                  thisUpdate.m_minute,
                                                                  thisUpdate.m_second,
                                                                  thisUpdate.m_day,
                                                                  thisUpdate.m_month,
                                                                  (thisUpdate.m_year + 1970));


        if (OK > (status = OCSP_CLIENT_getCurrentNextUpdate(pOcspContext, &nextUpdate, &isNextUpdate)))
            goto exit;

        if (isNextUpdate)
        {
            DEBUG_CONSOLE_printf ("Next Update       -> %2d:%2d:%2d %2d %2d %4d \n",nextUpdate.m_hour,
                                                                      nextUpdate.m_minute,
                                                                      nextUpdate.m_second,
                                                                      nextUpdate.m_day,
                                                                      nextUpdate.m_month,
                                                                      (nextUpdate.m_year + 1970));



            DEBUG_CONSOLE_printf ("\n");
        }

        if (pCertId)
        {
            if (pCertId->keyHash)
                FREE(pCertId->keyHash);

            if (pCertId->nameHash)
                FREE(pCertId->nameHash);

            if (pCertId->serialNumber)
                FREE(pCertId->serialNumber);

            FREE(pCertId);
        }
#endif


    }
    else
    {
        /* In case the response status is not successful */
        switch (respStatus)
        {
            case ocsp_malformedRequest:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Illegal confirmation request(malformedRequest)");
                 break;
            }

            case ocsp_internalError:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Internal Error in Issuer(internalError)");
                 break;
            }

            case ocsp_tryLater:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Try again later(tryLater)");
                 break;
            }

            case ocsp_sigRequired:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Must sign the request(sigRequired)");
                 break;
            }

            case ocsp_unauthorized:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Request Unauthorized(unauthorized)");
                 break;
            }

            default:
            {
                 DEBUG_PRINTNL(DEBUG_SSL_MESSAGES, (sbyte *)"OCSP_CLIENT: Failed with unknown status");
                 break;
            }

        }
    }
exit:
    if (pCertStatus)
        FREE(pCertStatus);

    /* API to free the context and shutdown DIGICERT OCSP CLIENT */
    if (pRequest)
        FREE(pRequest);

    if (pOcspContext)
    {
        if(pOcspContext->pOcspSettings)
        {
            for ( i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
            {
                if (pOcspContext->pOcspSettings->pCertInfo[i].pCert)
                    DIGI_FREE((void **)&(pOcspContext->pOcspSettings->pCertInfo[i].pCert));

                if (pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath)
                    DIGI_FREE((void **)&(pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath));
            }
        }
    }

    return status;
}
/*------------------------------------------------------------------*/
#endif /* #ifdef __ENABLE_DIGICERT_OCSP_CLIENT__ */
