/**
 * @file  ike2_ocsp.c
 * @brief IKEv2 IKEv2 OCSP Support
 *
 * @flags      Compilation flags required:
 *     To enable this file's functions, the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
 *     +   \c \__ENABLE_IKE_OCSP_EXT__
 *     +   \c \__ENABLE_DIGICERT_OCSP_CLIENT__
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_IKE_SERVER__) && \
    defined(__ENABLE_IKE_OCSP_EXT__) && defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"
#include "../common/random.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/sha1.h"
#include "../crypto/cert_chain.h"
#include "../crypto/cert_store.h"
#include "../harness/harness.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/tree.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"

#include "../http/http_context.h"
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ocsp/ocsp_http.h"
#include "../ocsp/client/ocsp_client.h"

#include "../ipsec/ipsec.h"
#include "../ike/ike.h"
#include "../ike/ike_defs.h"
#include "../ike/ikesa.h"
#include "../ike/ike_cert.h"
#include "../ike/ike_state.h"
#include "../ike/ike_utils.h"

#include "../ike2/ike2_ocsp.h"


/*------------------------------------------------------------------*/

static MSTATUS
cloneTrustedResponders(ocspSettings *pOcspSettings, ocspSettings *pOcspSettings0,
                       IKE_context ctx)
{
    MSTATUS status = OK;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    ubyte *poKIHash = NULL;
#define poKeyInfoHash poKIHash
#else
    ubyte poKeyInfoHash[SHA1_RESULT_SIZE];
#endif
    ASN1_ITEMPTR pxRoot = NULL;

    sbyte4 i, j;
    OCSP_certInfo *pTrustedResponder, *pTrustedResponder0;

    if (NULL == (pTrustedResponder = (OCSP_certInfo *)
                                MALLOC(sizeof(OCSP_certInfo) *
                                       pOcspSettings0->trustedResponderCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pOcspSettings->pTrustedResponders = pTrustedResponder;

    if (OK > (status = DIGI_MEMSET((ubyte *)pTrustedResponder, 0x00,
                                  sizeof(OCSP_certInfo) *
                                  pOcspSettings0->trustedResponderCount)))
        goto exit;

    pTrustedResponder0 = pOcspSettings0->pTrustedResponders;

    for (i = pOcspSettings0->trustedResponderCount; i; i--, pTrustedResponder0++)
    {
        MemFile mf;
        CStream cs;
        ASN1_ITEMPTR pxSubj, pxPKI;
        ubyte4 keyInfoLen;
        ubyte *poKeyInfo;

        if (NULL == pTrustedResponder0->pCertPath)
        {
            status = ERR_OCSP_INIT_FAIL;
            goto exit;
        }

        if (NULL == ctx) goto clone;

        /* get hash of configured trusted responder's public key */
        MF_attach(&mf, pTrustedResponder0->certLen, pTrustedResponder0->pCertPath);
        CS_AttachMemFile(&cs, &mf);

        if (OK > (status = X509_parseCertificate(cs, &pxRoot)) ||
            OK > (status = X509_getCertificateSubject(ASN1_FIRST_CHILD(pxRoot), &pxSubj)))
            goto exit;

        pxPKI = ASN1_NEXT_SIBLING(pxSubj);
        keyInfoLen = pxPKI->length + pxPKI->headerSize;
        poKeyInfo = pTrustedResponder0->pCertPath + (pxPKI->dataOffset - pxPKI->headerSize);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
        if (OK > (status = CRYPTO_ALLOC(ctx->hwAccelCookie, SHA1_RESULT_SIZE,
                                        TRUE, (void**) &poKIHash)))
            goto exit;
#endif
        if (OK > (status = SHA1_completeDigest(MOC_HASH(ctx->hwAccelCookie)
                                               poKeyInfo, keyInfoLen,
                                               poKeyInfoHash)))
            goto exit;

        /* match configured trusted responder against 'ctx->pOcspReq', which
         points to zero or more trusted OCSP responder certificate hashes of
         public keys (received in CERTREQ payload from the peer) */
        for (j = (sbyte4)(ctx->ocspReqLen / SHA1_RESULT_SIZE) - 1; j>=0; j--)
        {
            sbyte4 compareResult;
            if (OK > (status = DIGI_MEMCMP(poKeyInfoHash,
                                          ctx->pOcspReq + (SHA1_RESULT_SIZE * j),
                                          SHA1_RESULT_SIZE, &compareResult)))
                goto exit;

            if (0 == compareResult) break; /* match */
        }
        if (0 > j) continue; /* no match */
clone:
        if (NULL == (pTrustedResponder->pCertPath = (ubyte *)
                                            MALLOC(pTrustedResponder0->certLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        
        
        
        pTrustedResponder->certLen = pTrustedResponder0->certLen;
        ++(pOcspSettings->trustedResponderCount);

        if (OK > (status = DIGI_MEMCPY(pTrustedResponder->pCertPath,
                                      pTrustedResponder0->pCertPath,
                                      pTrustedResponder->certLen)))
            goto exit;

        pTrustedResponder++;
    }

exit:
    if (pxRoot)
        TREE_DeleteTreeItem((TreeItem *)pxRoot);

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    if (poKIHash)
        CRYPTO_FREE(ctx->hwAccelCookie, TRUE, (void**) &poKIHash);
#endif
    return status;
} /* cloneTrustedResponders */


/*------------------------------------------------------------------*/

static MSTATUS
cloneOcspSettings(IKE_context ctx,
                  ocspSettings *pOcspSettings, ocspSettings *pOcspSettings0)
{
    MSTATUS status = OK;

    pOcspSettings->pResponderUrl    = pOcspSettings0->pResponderUrl;
    pOcspSettings->hashAlgo         = pOcspSettings0->hashAlgo;
    pOcspSettings->timeSkewAllowed  = pOcspSettings0->timeSkewAllowed;
    pOcspSettings->shouldSign       = pOcspSettings0->shouldSign;
    pOcspSettings->signingAlgo      = pOcspSettings0->signingAlgo;
    pOcspSettings->shouldAddServiceLocator
                                    = pOcspSettings0->shouldAddServiceLocator;

    if (pOcspSettings0->pSignerCert)
    {
        if (NULL == (pOcspSettings->pSignerCert = (ubyte *)
                                        MALLOC(pOcspSettings0->signerCertLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pOcspSettings->signerCertLen = pOcspSettings0->signerCertLen;

        if (OK > (status = DIGI_MEMCPY(pOcspSettings->pSignerCert,
                                      pOcspSettings0->pSignerCert,
                                      pOcspSettings->signerCertLen)))
            goto exit;
    }

    if (pOcspSettings0->pPrivKey)
    {
        if (NULL == (pOcspSettings->pPrivKey = (ubyte *)
                                            MALLOC(pOcspSettings0->privKeyLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pOcspSettings->privKeyLen = pOcspSettings0->privKeyLen;

        if (OK > (status = DIGI_MEMCPY(pOcspSettings->pPrivKey,
                                      pOcspSettings0->pPrivKey,
                                      pOcspSettings->privKeyLen)))
            goto exit;
    }

    if (pOcspSettings0->pTrustedResponders && ctx->pOcspReq && ctx->ocspReqLen)
    {
        status = cloneTrustedResponders(pOcspSettings, pOcspSettings0, ctx);
    }

exit:
    return status;
} /* cloneOcspSettings */


/*------------------------------------------------------------------*/

static MSTATUS
cloneCertInfo(ocspSettings *pOcspSettings, certDescriptor *pCert, ubyte4 certCount)
{
    MSTATUS status = OK;
    sbyte4 i;

    if (2 > certCount)
    {
        certCount = 2;
        pCert[1] = pCert[0];
    }
    --certCount;

    if (NULL == (pOcspSettings->pCertInfo = (OCSP_singleRequestInfo *)
                            MALLOC(sizeof(OCSP_singleRequestInfo) * certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspSettings->pCertInfo, 0x00,
                                  (sizeof(OCSP_singleRequestInfo) * certCount))))
        goto exit;

    if (NULL == (pOcspSettings->pIssuerCertInfo = (OCSP_certInfo *)
                                    MALLOC(sizeof(OCSP_certInfo) * certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspSettings->pIssuerCertInfo, 0x00,
                                  (sizeof(OCSP_certInfo) * certCount))))
        goto exit;

    pOcspSettings->certCount = certCount;

    for (i = 0; i < (sbyte4)certCount; i++)
    {
        /* store the certificate in question*/
        if (NULL == (pOcspSettings->pCertInfo[i].pCert = (ubyte *)
                                                MALLOC(pCert[i].certLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pOcspSettings->pCertInfo[i].pCert,
                   pCert[i].pCertificate, pCert[i].certLength);
        pOcspSettings->pCertInfo[i].certLen = pCert[i].certLength;

        /* store the issuer certificate of certificate in question*/
        if (NULL == (pOcspSettings->pIssuerCertInfo[i].pCertPath = (ubyte *)
                                                MALLOC(pCert[i+1].certLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pOcspSettings->pIssuerCertInfo[i].pCertPath,
                   pCert[i+1].pCertificate, pCert[i+1].certLength);
        pOcspSettings->pIssuerCertInfo[i].certLen = pCert[i+1].certLength;
    }

exit:
    return status;
} /* cloneCertInfo */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_ocspGetResponse(IKE_context ctx)
{
    
    MSTATUS status = OK;

    IKESA pxSa = ctx->pxSa;
    IKE_certDescr pxCertDesc = pxSa->pCertChain;
    ubyte4 certCount = (ubyte4) pxSa->certChainLen;
    certDescriptor certDesc[IKE_CERT_CHAIN_MAX + 1];
    certChainPtr pCertChain = NULL;
    intBoolean isComplete = FALSE;
    sbyte4 i;

    ocspContext    *pOcspContext    = NULL;
    ocspSettings   *pOcspSettings   = NULL;
    ocspSettings   *pOcspSettings0;
    ubyte          *pUriStr         = NULL;
    ubyte          *pRequest        = NULL;
    ubyte4          requestLen;
    httpContext    *pHttpContext    = NULL;
    ubyte          *pResponse       = NULL;
    ubyte4          responseLen;
    intBoolean      isDone          = FALSE;

    if (NULL == (pOcspSettings = (ocspSettings *) MALLOC(sizeof(ocspSettings))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspSettings, 0x00, sizeof(ocspSettings))))
        goto exit;

    if (OK > (status = OCSP_CLIENT_createContext(&pOcspContext)))
        goto exit;

    pOcspContext->pOcspSettings = pOcspSettings;

    if (NULL != (pOcspSettings0 = pxSa->ikePeerConfig->pOcspSettings))
    {
        if (OK > (status = cloneOcspSettings(ctx, pOcspSettings, pOcspSettings0)))
            goto exit;
    }
    else
    {
        pOcspSettings->hashAlgo        = sha1_OID;
        pOcspSettings->signingAlgo     = sha1withRSAEncryption_OID;
        pOcspSettings->timeSkewAllowed = 360;
    }

    /* find issuer/trust anchor of local host certificate (chain) */
    for (i=0; i < (sbyte4)certCount; i++)
    {
        certDesc[i].pCertificate = pxCertDesc[i].poCertificate;
        certDesc[i].certLength = pxCertDesc[i].wCertLen;
    }

    if (OK > (status = CERTCHAIN_createFromIKE(MOC_ASYM(ctx->hwAccelCookie)
                                               &pCertChain, certDesc, certCount)) ||
        OK > (status = CERTCHAIN_isComplete(pCertChain, &isComplete)))
        goto exit;

    if (!isComplete)
    {
        ValidationConfig vc = { 0 };

        certStorePtr pCertStore;
        if (NULL == (pCertStore = pxSa->ikePeerConfig->ikeCertStore))
        {
            status = ERR_IKE_NO_CERT;
            goto exit;
        }

        vc.pCertStore = pCertStore;

        if (OK > (status = CERTCHAIN_validate(MOC_ASYM(ctx->hwAccelCookie)
                                              pCertChain, &vc)))
            goto exit;

        if (NULL == vc.anchorCert)
        {
            status = ERR_IKE_NO_CERT;
            goto exit;
        }

        certDesc[certCount].pCertificate = vc.anchorCert;
        certDesc[certCount].certLength = vc.anchorCertLen;
        certCount++;
    }
    
    if (OK > (status = cloneCertInfo(pOcspSettings, certDesc, certCount)))
        goto exit;

    /* check if OCSP responder URL has been configured */
    if (NULL == pOcspSettings->pResponderUrl)
    {
        /* if not, get AIA (i.e. OCSP URI) from the leaf cert */
        if ((OK > (status = OCSP_CLIENT_getResponderIdfromCert(
                                                pxCertDesc->poCertificate,
                                                (ubyte4) pxCertDesc->wCertLen,
                                                &pUriStr))) ||
            (NULL == pUriStr))
        {
            status = ERR_OCSP_BAD_AIA;
            goto exit;
        }
        pOcspSettings->pResponderUrl = (sbyte *)pUriStr;
    }

    /* connect to OCSP responder URL and get a response */
    if (OK > (status = OCSP_CLIENT_generateRequest(pOcspContext, NULL, 0,
                                                   &pRequest, &requestLen)))
        goto exit;
    
    if (OK > (status = OCSP_CLIENT_httpInit(&pHttpContext, pOcspContext)))
        goto exit;

    if (OK > (status = OCSP_CLIENT_sendRequest(pOcspContext, pHttpContext,
                                               pRequest, requestLen)))
        goto exit;

    do
    {
        if (OK > (status = OCSP_CLIENT_recv(pOcspContext, pHttpContext, &isDone,
                                            &pResponse, &responseLen)))
        {
            if (status == ERR_TCP_READ_TIMEOUT)
                continue;
            goto exit;
        }
    } while (!isDone);

    ctx->pOcspResp = pResponse;
    ctx->ocspRespLen = (ubyte2)responseLen;

exit:
    OCSP_CLIENT_httpUninit(&pHttpContext);

    if (pRequest) FREE(pRequest);

    OCSP_CLIENT_releaseContext(&pOcspContext);

    if (pOcspSettings) FREE(pOcspSettings);

    if (pUriStr) FREE(pUriStr);

    CERTCHAIN_delete(&pCertChain);

    return status;
} /* IKE_ocspGetResponse */


/*------------------------------------------------------------------*/

static MSTATUS
compareCertId(OCSP_certID *pCertId1, OCSP_certID *pCertId2, sbyte4 *pResult)
{
    MSTATUS status;

    if ((NULL == pCertId1) || (NULL == pCertId2) || (NULL == pResult))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = DIGI_MEMCMP(pCertId1->serialNumber,
                                  pCertId2->serialNumber,
                                  pCertId1->serialNumberLength,
                                  pResult)))
        goto exit;

    if (*pResult) goto exit;

    if (OK > (status = DIGI_MEMCMP(pCertId1->nameHash,
                                  pCertId2->nameHash,
                                  pCertId1->hashLength,
                                  pResult)))
        goto exit;

    if (*pResult) goto exit;

    if (OK > (status = DIGI_MEMCMP(pCertId1->keyHash,
                                  pCertId2->keyHash,
                                  pCertId1->hashLength,
                                  pResult)))
        goto exit;

exit:
    return status;
} /* compareCertId */


/*------------------------------------------------------------------*/

static MSTATUS
freeCertId(OCSP_certID **ppCertId)
{
    MSTATUS status = OK;
    OCSP_certID *pCertId;

    if ((NULL == ppCertId) || (NULL == *ppCertId))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pCertId = *ppCertId;

    if (pCertId->keyHash)
        FREE(pCertId->keyHash);

    if (pCertId->nameHash)
        FREE(pCertId->nameHash);

    if (pCertId->serialNumber)
        FREE(pCertId->serialNumber);

    FREE(pCertId);
    *ppCertId = NULL;

exit:
    return status;
} /* freeCertId */


/*------------------------------------------------------------------*/

extern MSTATUS
IKE_ocspValidateResponse(IKE_context ctx)
{
    MSTATUS status = OK;

    ocspContext    *pOcspContext    = NULL;
    ocspSettings   *pOcspSettings   = NULL;
    ocspSettings   *pOcspSettings0;
    ubyte          *pRequest        = NULL;
    ubyte4          requestLen;

    OCSP_certStatus    *pCertStatus = NULL;
    OCSP_certID        *pCertId     = NULL;
    OCSP_responseStatus respStatus;

    intBoolean bGoodLeafCert = FALSE;

    if (NULL == (pOcspSettings = (ocspSettings *) MALLOC(sizeof(ocspSettings))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspSettings, 0x00, sizeof(ocspSettings))))
        goto exit;

    if (OK > (status = OCSP_CLIENT_createContext(&pOcspContext)))
        goto exit;

    pOcspContext->pOcspSettings = pOcspSettings;

    if (NULL != (pOcspSettings0 = ctx->pxSa->ikePeerConfig->pOcspSettings) &&
        NULL != pOcspSettings0->pTrustedResponders)
    {
        if (OK > (status = cloneTrustedResponders(pOcspSettings, pOcspSettings0,
                                                  NULL)))
            goto exit;
    }

    if (OK > (status = cloneCertInfo(pOcspSettings,
                                     ctx->certificates, (ubyte4) ctx->certNum)))
        goto exit;

    if (OK > (status = OCSP_CLIENT_generateRequest(pOcspContext, NULL, 0,
                                                   &pRequest, &requestLen)))
        goto exit;

    /* Parse response */
    if (OK > (status = OCSP_CLIENT_parseResponse(pOcspContext,
                                                 ctx->pOcspResp,
                                                 ctx->ocspRespLen)))
        goto exit;

    /* API to check the OCSP response status */
    if (OK > (status = OCSP_CLIENT_getResponseStatus(pOcspContext, &respStatus)))
        goto exit;

    if (ocsp_successful == respStatus)
    {
        /* Get status for all certs in question inside a successful response */
        for (;;)
        {
            if (OK > (status = OCSP_CLIENT_getCurrentCertStatus(pOcspContext, &pCertStatus)))
            {
                if (ERR_OCSP_REQUEST_RESPONSE_MISMATCH == status)
                    goto next; /* response is not for any cert in question */

                if (ERR_OCSP_NO_MORE_RESPONSE == status)
                    status = OK; /* no more responses */

                goto exit;
            }

            if (NULL == pCertStatus)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            /* API to get the certificate specific info present in CertId field of response */
            if (OK > (status = OCSP_CLIENT_getCurrentCertId(pOcspContext, &pCertId)))
                goto exit;
            switch (pCertStatus->flag)
            {
            case ocsp_good:
                /* check if the reponse is for the leaf cert in question */
                if (!bGoodLeafCert)
                {
                    sbyte4 compareResult;
                    if (OK > (status = compareCertId(pOcspContext->ocspProcess.
                                                        client.cachedCertId[0],
                                                     pCertId, &compareResult)))
                        goto exit;

                    if (0 == compareResult) bGoodLeafCert = TRUE; /* match */
                }
                debug_printnl("IKE_OCSP: Certificate GOOD");
                break;

            case ocsp_revoked:
                debug_printnl("IKE_OCSP: Certificate Revoked");
                status = ERR_IKE_BAD_CERT;
                goto exit;

            case ocsp_unknown:
                debug_printnl("IKE_OCSP: Certificate Status UnKnown");
                break;
            }

            freeCertId(&pCertId);
            FREE(pCertStatus);
            pCertStatus = NULL;
next:
            if (OK > (status = OCSP_CLIENT_goToNextResponse(pOcspContext)))
                goto exit;
        } /* for */
    }
    else
    {
        /* In case the response status is not successful */
        switch (respStatus)
        {
        case ocsp_malformedRequest:
            debug_printnl("IKE_OCSP: Illegal confirmation request(malformedRequest)");
            break;

        case ocsp_internalError:
            debug_printnl("IKE_OCSP: Internal Error in Issuer(internalError)");
            break;

        case ocsp_tryLater:
            debug_printnl("IKE_OCSP: Try again later(tryLater)");
            break;

        case ocsp_sigRequired:
            debug_printnl("IKE_OCSP: Must sign the request(sigRequired)");
            break;

        case ocsp_unauthorized:
            debug_printnl("IKE_OCSP: Request Unauthorized(unauthorized)");
            break;

        default:
            debug_printnl("IKE_OCSP: Failed with unknown status");
            break;
        }
    }

exit:
    if (!bGoodLeafCert) ctx->pxSa->flags &= ~(IKE_SA_FLAG_CERT_OCSP);

    freeCertId(&pCertId);
    if (pCertStatus) FREE(pCertStatus);

    if (pRequest) FREE(pRequest);

    OCSP_CLIENT_releaseContext(&pOcspContext);

    if (pOcspSettings) FREE(pOcspSettings);

    return status;
} /* IKE_ocspValidateResponse */


#endif /* defined(__ENABLE_DIGICERT_IKE_SERVER__) */

