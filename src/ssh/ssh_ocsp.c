/*
 * ssh_ocsp.c
 *
 * OCSP code to be used in SSH certificate support
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

#if ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__)))

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
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../common/base64.h"
#include "../crypto/cert_chain.h"
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
#include "../ocsp/ocsp_http.h"
#include "../ocsp/client/ocsp_client.h"
#include "../harness/harness.h"

#ifdef __ENABLE_MOCANA_SSH_CLIENT__
#include "./client/sshc.h"
#endif

/*------------------------------------------------------------------*/

typedef struct requestBodyCookieSshOcsp_t
{
    ubyte*    data;
    ubyte4    dataLen;
    ubyte4    curPos;

} requestBodyCookieSshOcsp;


extern MSTATUS
SSH_OCSP_validateOcspResponse(ubyte* pCertificate, ubyte4 certLen,
                              ubyte* pIssuerCert, ubyte4 issuerLen,
                              ubyte* pResponse, ubyte4 responseLen,
                              ubyte* pCertOcspStatus, ubyte* pIsValid);

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_MOCANA_SSH_SERVER__))
extern MSTATUS
#if (defined(__ENABLE_MOCANA_OCSP_TIMEOUT_CONFIG__))
SSH_OCSP_getOcspResponse(sbyte *pResponderUrl, ubyte4 ocspTimeout, ubyte *pCertificate,
                         ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen,
                         ubyte **ppResponse, ubyte4 *pRetResponseLen)
#else
SSH_OCSP_getOcspResponse(sbyte *pResponderUrl, ubyte *pCertificate, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerCertLen,
                         ubyte **ppResponse, ubyte4 *pRetResponseLen)
#endif
{
    /* This method to be called from SSH server code to add OCSP response in the */
    /* Key Exchange Reply Message to be send to the peer */
    ocspContext*        pOcspContext  = NULL;
    httpContext*        pHttpContext  = NULL;

    ubyte*              pRequest      = NULL;
    ubyte4              requestLen    = 0;
    extensions*         pExts         = NULL;
    ubyte4              extCount      = 0;
    intBoolean          isDone        = FALSE;
    OCSP_responseStatus respStatus;
    ubyte               certOcspStatus = 0;
    ubyte               isValid = 0;
    ubyte               i;
    MSTATUS             status = OK;

    /* Create a Client Context */
    if (OK > (status = OCSP_CLIENT_createContext(&pOcspContext)))
        goto exit;

    /* Set the user configuration */
    pOcspContext->pOcspSettings->certCount                  = 1;

    pOcspContext->pOcspSettings->hashAlgo                   = sha1_OID;
    pOcspContext->pOcspSettings->pResponderUrl              = pResponderUrl;
    pOcspContext->pOcspSettings->shouldAddServiceLocator    = FALSE;
    pOcspContext->pOcspSettings->shouldAddNonce             = FALSE;
    pOcspContext->pOcspSettings->shouldSign                 = FALSE;
    pOcspContext->pOcspSettings->signingAlgo                = FALSE;
    pOcspContext->pOcspSettings->timeSkewAllowed            = 360;

#if (defined(__ENABLE_MOCANA_OCSP_TIMEOUT_CONFIG__))
    pOcspContext->pOcspSettings->recvTimeout                = ocspTimeout;
#endif

    /* check if responder URL has been configured */
    if (!pResponderUrl)
    {
        if (OK > (status = OCSP_CLIENT_getResponderIdfromCert(pCertificate, certLen,
                                                              (ubyte** )&pOcspContext->pOcspSettings->pResponderUrl)))
        {
            status = ERR_OCSP_BAD_AIA;
            goto exit;
        }
    }

    /* END OF USER CONFIG                                          */

    if (OK > (status = OCSP_CLIENT_httpInit(&pHttpContext, pOcspContext)))
        goto exit;

    /* Populating data in internal format based on user config     */

    if ((0 >= pOcspContext->pOcspSettings->certCount))
    {
        status = ERR_OCSP_INIT_FAIL;
        goto exit;
    }

    if (NULL == (pOcspContext->pOcspSettings->pCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo)*
                                                                pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = MOC_MEMSET((ubyte *)pOcspContext->pOcspSettings->pCertInfo, 0x00, sizeof(OCSP_singleRequestInfo))))
        goto exit;

    if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo) *
                                                                pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = MOC_MEMSET((ubyte *)pOcspContext->pOcspSettings->pIssuerCertInfo, 0x00, sizeof(OCSP_singleRequestInfo))))
        goto exit;

    for (i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
    {

        if ((NULL == pCertificate) || (NULL == pIssuerCert))
        {
            status = ERR_OCSP_INIT_FAIL;
            goto exit;
        }

        pOcspContext->pOcspSettings->pCertInfo[i].pCert = pCertificate;
        pOcspContext->pOcspSettings->pCertInfo[i].certLen = certLen;
        pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath = pIssuerCert;
        pOcspContext->pOcspSettings->pIssuerCertInfo[i].certLen = issuerCertLen;

    }

    /* Call the API to generate OCSP request */
    if (OK > (status = OCSP_CLIENT_generateRequest(pOcspContext, pExts, extCount, &pRequest, &requestLen)))
        goto exit;

    /* the action is delayed to ensure the connection is up before proceeding further */
    if (OK > (status = MOCANA_writeFile("generatedrequest.der", pRequest, requestLen)))
        goto exit;

    if (OK > (status = OCSP_CLIENT_sendRequest(pOcspContext, pHttpContext, pRequest, requestLen)))
       goto exit;

    while (!isDone)
    {
        if (OK > (status = OCSP_CLIENT_recv(pOcspContext, pHttpContext, &isDone, ppResponse, pRetResponseLen)))
            goto exit;
    }

    /* API to parse the response */
    if (OK > (status = OCSP_CLIENT_parseResponse(pOcspContext, *ppResponse, *pRetResponseLen)))
        goto exit;


    /* API to check the OCSP response status */
    if (OK > (status = OCSP_CLIENT_getResponseStatus(pOcspContext,  &respStatus)))
        goto exit;

    if (ocsp_successful == respStatus)
    {
        status = SSH_OCSP_validateOcspResponse(pCertificate, certLen, pIssuerCert,issuerCertLen ,
                                    *ppResponse, *pRetResponseLen, &certOcspStatus, &isValid);

        if (status == OK)
        {
            if (!isValid)
                status = ERR_OCSP;
            else if (1 == certOcspStatus)
                status = ERR_CERT_REVOKED;
            else if (2 == certOcspStatus)
                status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
        }
    }
exit:

    /* API to free the context and shutdown MOCANA OCSP CLIENT */
    OCSP_CLIENT_releaseContext(&pOcspContext);
    
    if (pHttpContext)
        OCSP_CLIENT_httpUninit(&pHttpContext);

    return status;

} /* SSH_OCSP_getOcspResponse */

#endif /* (defined(__ENABLE_MOCANA_SSH_SERVER__)) */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_OCSP_validateOcspResponse(ubyte *pCertificate, ubyte4 certLen, ubyte *pIssuerCert, ubyte4 issuerLen, ubyte* pResponse, ubyte4 responseLen, ubyte* pCertOcspStatus, ubyte* pIsValid)
{
    /* This method is to be called from the SSH peer to validate the OCSP response    */
    /* received in the KEY EXCHANGE REPLY message from the server                       */
    /* The method takes OCSP response bytes and length of the response as the i/p   */
    /* It returns certStatus (good/revoked/unknown) and boolean (TRUE/FALSE )      */
    /* parameter isValid after checking primarily the time skewn in the response but   */
    /* would also indicate FALSE if the response itself is not successful                        */
    ocspContext*        pOcspContext    = NULL;

    ubyte*              pRequest        = NULL;
    ubyte4              requestLen      = 0;
    extensions*         pExts           = NULL;
    ubyte4              extCount        = 0;

    OCSP_certStatus*    pCertStatus     = NULL;
    OCSP_certID*        pCertId         = NULL;
    OCSP_responseStatus respStatus;

    TimeDate            thisUpdate;
    TimeDate            producedAt;
    TimeDate            nextUpdate;
    byteBoolean         isNextUpdate;

    ubyte               i,j;
    MSTATUS             status       =  OK;

    /* Create a Client Context */
    if (OK > (status = OCSP_CLIENT_createContext(&pOcspContext)))
        goto exit;

    /* Set the user configuration */
    pOcspContext->pOcspSettings->certCount                  = 1;
#if (defined(__ENABLE_MOCANA_SSH_CLIENT__))
    pOcspContext->pOcspSettings->trustedResponderCount      = SSHC_sshClientSettings()->trustedResponderCount;
#endif

#if (defined(__ENABLE_MOCANA_SSH_CLIENT__))
    if (SSHC_sshClientSettings()->trustedResponderCount > 0)
    {
        if (NULL == (pOcspContext->pOcspSettings->pTrustedResponders = MALLOC(sizeof(OCSP_certInfo)*
                                                                       pOcspContext->pOcspSettings->trustedResponderCount)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        for (i=0; i < pOcspContext->pOcspSettings->trustedResponderCount; i++)
        {
            pOcspContext->pOcspSettings->pTrustedResponders[i].certLen =
                                                    SSHC_sshClientSettings()->ocspTrustedResponderCerts[i].certLength;
            pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath =
                                                    SSHC_sshClientSettings()->ocspTrustedResponderCerts[i].pCertificate;
        }
    }
#endif
    pOcspContext->pOcspSettings->hashAlgo                   = sha1_OID;
    pOcspContext->pOcspSettings->shouldAddServiceLocator    = FALSE;
    pOcspContext->pOcspSettings->shouldAddNonce             = FALSE;
    pOcspContext->pOcspSettings->shouldSign                 = FALSE;
    pOcspContext->pOcspSettings->signingAlgo                = FALSE;
    pOcspContext->pOcspSettings->timeSkewAllowed            = 360;

    /* END OF USER CONFIG                                                              */


    /* Populating data in internal format based on user config     */
    if ((0 >= pOcspContext->pOcspSettings->certCount))
    {
       status = ERR_OCSP_INIT_FAIL;
       goto exit;
    }

    if (NULL == (pOcspContext->pOcspSettings->pCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo)*
                                                               pOcspContext->pOcspSettings->certCount)))
    {
       status = ERR_MEM_ALLOC_FAIL;
       goto exit;
    }

    if (OK > (status = MOC_MEMSET((ubyte *)(pOcspContext->pOcspSettings->pCertInfo), 0x00, sizeof(OCSP_singleRequestInfo))))
       goto exit;

    if (NULL == (pOcspContext->pOcspSettings->pIssuerCertInfo = MALLOC(sizeof(OCSP_singleRequestInfo)*
                                                               pOcspContext->pOcspSettings->certCount)))
    {
       status = ERR_MEM_ALLOC_FAIL;
       goto exit;
    }

    if (OK > (status = MOC_MEMSET((ubyte *)(pOcspContext->pOcspSettings->pIssuerCertInfo), 0x00, sizeof(OCSP_singleRequestInfo))))
       goto exit;

    for (i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
    {

       if ((NULL == pCertificate) || (NULL == pIssuerCert))
       {
           status = ERR_OCSP_INIT_FAIL;
           goto exit;
       }

       pOcspContext->pOcspSettings->pCertInfo[i].pCert = pCertificate;
       pOcspContext->pOcspSettings->pCertInfo[i].certLen = certLen;
       pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath = pIssuerCert;
       pOcspContext->pOcspSettings->pIssuerCertInfo[i].certLen = issuerLen;
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

        /* Time skew within configured permissible limits */
        *pIsValid = 1;      /* TRUE */

        DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP Response Details:");

        /* API to get the producedAt attribute in the OCSP response */
        if (OK > (status = OCSP_CLIENT_getProducedAt(pOcspContext, &producedAt)))
                goto exit;

        DB_PRINT ("Produced At       -> %2d:%2d:%2d %2d %2d %4d \n",producedAt.m_hour,
                                                                  producedAt.m_minute,
                                                                  producedAt.m_second,
                                                                  producedAt.m_day,
                                                                  producedAt.m_month,
                                                                  (producedAt.m_year + 1970));

        /* Get the cert status for all the certs in question inside a successful response */
        for (i = 0; i < pOcspContext->pOcspSettings->certCount; i++)
        {
            if (OK > (status = OCSP_CLIENT_getCurrentCertStatus(pOcspContext, &pCertStatus)))
                goto exit;

            /* Note: Free pCertStatus before exiting to avoid memory leaks */

            if (NULL == pCertStatus)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            DB_PRINT("\nCERT %d\n", i+1);

            /* API to get the certificate specific info present in CertId field of response */
            if (OK > (status = OCSP_CLIENT_getCurrentCertId(pOcspContext,&pCertId)))
                goto exit;

                     DB_PRINT ("Serial Number:    ->");

            for (j = 0; j < pCertId->serialNumberLength; j++)
                DB_PRINT(" %X ",pCertId->serialNumber[j]);

            DB_PRINT("\n");

            switch (pCertStatus->flag)
            {
                case ocsp_good:
                     *pCertOcspStatus = 0;
                     DB_PRINT ("Certificate status-> GOOD\n");
                     break;

                case ocsp_revoked:
                     *pCertOcspStatus = 1;
                     DB_PRINT ("Certificate status-> Revoked\n");
                     DB_PRINT ("Revocation Time   -> %2d:%2d:%2d %2d %2d %4d \n",pCertStatus->revocationTime.m_hour,
                                                                               pCertStatus->revocationTime.m_minute,
                                                                               pCertStatus->revocationTime.m_second,
                                                                               pCertStatus->revocationTime.m_day,
                                                                               pCertStatus->revocationTime.m_month,
                                                                               (pCertStatus->revocationTime.m_year + 1970));
                     break;

                case ocsp_unknown:
                     *pCertOcspStatus = 2;
                     DB_PRINT ("Certificate status-> UnKnown\n");
                     break;
            }

            if (OK > (status = OCSP_CLIENT_getCurrentThisUpdate(pOcspContext, &thisUpdate)))
                goto exit;

            DB_PRINT ("This Update       -> %2d:%2d:%2d %2d %2d %4d \n",thisUpdate.m_hour,
                                                                      thisUpdate.m_minute,
                                                                      thisUpdate.m_second,
                                                                      thisUpdate.m_day,
                                                                      thisUpdate.m_month,
                                                                      (thisUpdate.m_year + 1970));


            if (OK > (status = OCSP_CLIENT_getCurrentNextUpdate(pOcspContext, &nextUpdate, &isNextUpdate)))
                goto exit;
            
            if (isNextUpdate)
            {
                DB_PRINT ("Next Update       -> %2d:%2d:%2d %2d %2d %4d \n",nextUpdate.m_hour,
                                                                          nextUpdate.m_minute,
                                                                          nextUpdate.m_second,
                                                                          nextUpdate.m_day,
                                                                          nextUpdate.m_month,
                                                                          (nextUpdate.m_year + 1970));



                DB_PRINT ("\n");
            }

            if (OK > (status = OCSP_CLIENT_goToNextResponse(pOcspContext)))
                goto exit;
        }
    }
    else
    {
        /* In case the response status is not successful */
        switch (respStatus)
        {
            case ocsp_malformedRequest:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Illegal confirmation request(malformedRequest)");
                 break;
            }

            case ocsp_internalError:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Internal Error in Issuer(internalError)");
                 break;
            }

            case ocsp_tryLater:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Try again later(tryLater)");
                 break;
            }

            case ocsp_sigRequired:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Must sign the request(sigRequired)");
                 break;
            }

            case ocsp_unauthorized:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Request Unauthorized(unauthorized)");
                 break;
            }

            default:
            {
                 DEBUG_PRINTNL(DEBUG_SSHC, (sbyte *)"OCSP_CLIENT: Failed with unknown status");
                 break;
            }

        }
        *pIsValid = 0; /* FALSE */

    }
exit:
    /* API to free the context and shutdown MOCANA OCSP CLIENT */
    if (pRequest)
        FREE(pRequest);

    if (pCertStatus)
        FREE(pCertStatus);

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

#if (defined(__ENABLE_MOCANA_SSH_CLIENT__))
    OCSP_CLIENT_releaseContext(&pOcspContext);
#endif

    return status;
}

#endif /* ((defined(__ENABLE_MOCANA_SSH_OCSP_SUPPORT__)) && (defined(__ENABLE_MOCANA_OCSP_CLIENT__))) */
