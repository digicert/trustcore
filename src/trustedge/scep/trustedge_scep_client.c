/*
 * trustedge_scep_client.c
 *
 * SCEP -- Simple Certificate Enrollment Protocol client operations
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
 */
#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/tree.h"
#include "../../common/absstream.h"
#include "../../common/memfile.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../asn1/oiddefs.h"
#include "../../common/uri.h"
#include "../../common/datetime.h"
#include "../../crypto/crypto.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ca_mgmt.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/rsa.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pkcs_common.h"
#include "../../crypto/pkcs7.h"
#include "../../crypto/pkcs10.h"
#include "../../crypto/asn1cert.h"
#include "../../common/base64.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../http/http_common.h"
#include "../../crypto/cert_store.h"
#include "../../cert_enroll/cert_enroll.h"
#include "../../trustedge/scep/trustedge_scep_defn.h"
#include "../../trustedge/scep/trustedge_scep_context.h"
#include "../../trustedge/scep/trustedge_scep_message.h"
#include "../../trustedge/scep/trustedge_scep_client.h"
#include "../../harness/harness.h"

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This typedef (HTTP context message body) is for Mocana internal
 * code use only, and should not be included in the API documentation.
 */
typedef struct requestBodyCookie
{
    ubyte* data;
    ubyte4 dataLen;
    ubyte4 curPos;
} requestBodyCookie;

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This typedef (Cached polling request msg) is for Mocana internal
 * code use only, and should not be included in the API documentation.
 */
typedef struct pollingCookie
{
    ubyte* query;
    ubyte4 queryLen;
    requestBodyCookie *bodyCookie;
} pollingCookie;

/*------------------------------------------------------------------*/

static SCEP_operationsInfo mScepOperations[] =
{
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* PKCSReq */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCertInitial */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCert */
    {{ (ubyte*)"PKIOperation", 12}, TRUE }, /* GetCRL */
    {{ (ubyte*)"RevokeCert",     10}, TRUE },
    {{ (ubyte*)"PublishCRL",     10}, TRUE },
    {{ (ubyte*)"ApproveCertEnroll",     17}, TRUE },
    {{ (ubyte*)"RegisterEndEntity",     17}, TRUE },
    {{ (ubyte*)"GetCACert",     9}, TRUE  },
    {{ (ubyte*)"GetNextCACert",    13}, TRUE },
    {{ (ubyte*)"GetCACertChain",    14}, TRUE },
    {{ (ubyte*)"GetCACaps",     9}, TRUE }
};

/*------------------------------------------------------------------*/

static SCEP_nameStr mScepResponseTypes[] =
{
    { (ubyte*)"application/x-pki-message", 25 },
    { (ubyte*)"application/x-x509-ca-cert", 26 },
    { (ubyte*)"application/x-x509-ca-ra-cert", 29 },
    { (ubyte*)"application/x-x509-ca-ra-cert-chain", 35 },
    { (ubyte*)"application/xml", 15 }
};

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_setRequestBodyCookie(void **ppCookie, ubyte* data, ubyte4 dataLen);

static MSTATUS
SCEP_CLIENT_setPollingCookie(void **ppPollingCookie, ubyte* uri, ubyte4 uriLen, void *pRequestBodyCookie);

/* set cacheRequest param to true when it's useful to cache the request pkiMessage.
* as in the case of pollServer */
static MSTATUS
SCEP_CLIENT_generateRequestWithCache(scepContext *pScepContext, byteBoolean useHttpPOST, ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void** ppCookie, void **ppPollingCookie);

/*------------------------------------------------------------------*/

/**
@brief      Retrieve response header after it has been received from the
            server and processed.

@details    This callback function (used by the HTTP %client) retrieves a
            response header after it has been received from the server and processed.

@ingroup    func_scep_client_http

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing request context and message header.
@param isContinueFromBlock  \c TRUE if the HTTP session was previously blocked:
                              for example, if TCP \c send() could not
                              complete, if waiting for authentication, or
                              application-specific requirements; otherwise
                              \c FALSE. Typically this argument can be
                              ignored, but it may be a useful indicator in
                              threadless environments.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.c
*/
extern sbyte4
SCEP_CLIENT_http_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);
    /* do nothing */
    return OK;
}

/*------------------------------------------------------------------*/

/**
@brief      Retrieve response body from the HTTP %client (for forwarding to
            the application).

@details    This callback function (used by the HTTP %client) retrieves a
            response body after HTTP receives the response from the server
            and parses it. The response body can then be forwarded to the
            application.

@ingroup    func_scep_client_http

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing response context and message.
@param pDataReceived        Pointer to the response body received.
@param dataLength           Number of bytes in the response body
                              (\p DataReceived).
@param isContinueFromBlock  \c TRUE if the HTTP session was previously blocked:
                              for example, if TCP \c send() could not
                              complete, if waiting for authentication, or
                              application-specific requirements; otherwise
                              \c FALSE. Typically this argument can be
                              ignored, but it may be a useful indicator in
                              threadless environments.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.c
*/
extern sbyte4
SCEP_CLIENT_http_responseBodyCallback(httpContext *pHttpContext,
                                         ubyte *pDataReceived,
                                         ubyte4 dataLength,
                                         sbyte4 isContinueFromBlock)
{
    MOC_UNUSED(isContinueFromBlock);
    MSTATUS status = OK;
    ubyte* lengthBuffer = NULL;
    ubyte* newBuffer = NULL;

    /* the index for ContentLength */
    static const ubyte4 index = NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS + ContentLength;

    /* if contentlength known, allocate memory only once */
    if (pHttpContext->receivedPendingDataLength <= 0 &&
        pHttpContext->responseBitmask[index/8] & (1<<(index & 7)))
    {
         sbyte *stop;
         sbyte4 contentLength=0;
         HTTP_stringDescr* strDescr = &(pHttpContext->responses[index]);
         if ((strDescr->httpStringLength) > 0)
         {
             if (NULL == ( lengthBuffer = (ubyte*)MALLOC(strDescr->httpStringLength+1)))
             {
               status = ERR_MEM_ALLOC_FAIL;
               goto exit;
             }
            DIGI_MEMCPY(lengthBuffer, strDescr->pHttpString, strDescr->httpStringLength);
            lengthBuffer[strDescr->httpStringLength] = 0;
            contentLength = DIGI_ATOL((sbyte*)lengthBuffer, (const sbyte**)&stop);
            if (contentLength > 0)
            {
               if (NULL == (pHttpContext->pReceivedPendingData = (ubyte*) MALLOC(contentLength)))
               {
                 status = ERR_MEM_ALLOC_FAIL;
                 goto exit;

               }
               pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData;
            }
         }
         else
         {
             pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = NULL;
         }
     }

     /* accumulate response body in httpContext pReceivedDataPending */
     if (!(pHttpContext->responseBitmask[index/8] & (1<<(index & 7))))
     {
        if (NULL == (newBuffer = (ubyte*)MALLOC(pHttpContext->receivedPendingDataLength+dataLength)))
        {
              status = ERR_MEM_ALLOC_FAIL;
              goto exit;

        }
         if (pHttpContext->receivedPendingDataLength > 0)
         {
             /* copy existing data */
             DIGI_MEMCPY(newBuffer, pHttpContext->pReceivedPendingDataFree, pHttpContext->receivedPendingDataLength);
         }
         DIGI_MEMCPY(newBuffer+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
         if (pHttpContext->pReceivedPendingDataFree)
         {
             FREE(pHttpContext->pReceivedPendingDataFree);
         }
         pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = newBuffer;
     } else
     {
         DIGI_MEMCPY(pHttpContext->pReceivedPendingDataFree+pHttpContext->receivedPendingDataLength, pDataReceived, dataLength);
     }
     pHttpContext->receivedPendingDataLength += dataLength;

exit:
    if (lengthBuffer)
    {
        FREE(lengthBuffer);
    }
    return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Retrieve the body of a request made by a SCEP %client via HTTP
            methods.

@details    This HTTP %client callback function gets the body of a request
            made by a SCEP %client via HTTP methods. Your application can
            forward the data to the SCEP server by calling the appropriate HTTP_REQUEST_* functions (see "HTTP Client Functions").

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing request context and message body.
@param ppDataToSend         On return, pointer to data to send (the HTTP
                              request body).
@param pDataLength          On return, pointer to number of bytes in send buffer
                              (\p ppDataToSend).
@param pRequestBodyCookie   Reference to opaque cookie that points to context
                              information such as bookkeeping or caching data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.c
*/
extern sbyte4
SCEP_CLIENT_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie)
{
    MSTATUS status = OK;
    static const ubyte4 BLOCKSIZE = 2000;
    requestBodyCookie *cookie;


    if (pRequestBodyCookie)
    {
        cookie = (requestBodyCookie*)pRequestBodyCookie;
        *pDataLength = (cookie->dataLen - cookie->curPos) > BLOCKSIZE? BLOCKSIZE : (cookie->dataLen - cookie->curPos);
        if (NULL == (*ppDataToSend = MALLOC(*pDataLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(*ppDataToSend, cookie->data + cookie->curPos, *pDataLength);
        cookie->curPos += (*pDataLength);
        if (cookie->dataLen == cookie->curPos)
        {
            pHttpContext->isBodyDone = TRUE;
        } else
        {
            pHttpContext->isBodyDone = FALSE;
        }
    } else
    {
        *ppDataToSend = NULL;
        *pDataLength = 0;
        pHttpContext->isBodyDone = TRUE;
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_setRequestInfo(scepContext *pScepContext, requestInfo **ppReqInfo)
{
    pkcsCtxInternal*    pPkcsCtx;
    ubyte*              pCertificate;
    ubyte4              certLength;
    hwAccelDescr        hwAccelCtx;
    MSTATUS             status = OK;

    if (OK > (status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SCEP, &hwAccelCtx)))
        return status;

    if (!pScepContext || !ppReqInfo || !*ppReqInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pScepContext->pReqInfo = *ppReqInfo;

    pPkcsCtx = pScepContext->pPkcsCtx;

    if ((*ppReqInfo)->type == scep_PKCSReq && !pPkcsCtx->pRequesterCert)
    {
        /* generate one */
        ubyte4 hashType = ht_sha256; /* default */
        if (pPkcsCtx->digestAlgoOID != NULL) /* digestAlgoOID was set to the same as KeyCtx->gHashAlgo so it'll match */
        {
            if (EqualOID(pPkcsCtx->digestAlgoOID, md5_OID))
            {
                hashType = ht_md5;
            } else if (EqualOID(pPkcsCtx->digestAlgoOID, sha1_OID))
            {
                hashType = ht_sha1;
            } else if (EqualOID(pPkcsCtx->digestAlgoOID, sha224_OID))
            {
                hashType = ht_sha224;
            } else if (EqualOID(pPkcsCtx->digestAlgoOID, sha256_OID))
            {
                hashType = ht_sha256;
            } else if (EqualOID(pPkcsCtx->digestAlgoOID, sha384_OID))
            {
                hashType = ht_sha384;
            } else if (EqualOID(pPkcsCtx->digestAlgoOID, sha512_OID))
            {
                hashType = ht_sha512;
            }
        }

        if (OK > (status = ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelCtx) pPkcsCtx->pKey,
                                                                  (*ppReqInfo)->value.certInfoAndReqAttrs.pCsrCtx->pCertSubjectInfo,
                                                                  hashType,
                                                                  (*ppReqInfo)->value.certInfoAndReqAttrs.pCsrCtx->reqAttr.pExtensions,
                                                                  pPkcsCtx->rngFun, pPkcsCtx->rngFunArg,
                                                                  &pCertificate, &certLength)))
        {
            goto exit;
        }
        /* if ( OK > ( status = DIGICERT_writeFile( "selfcert.der", pCertificate, certLength)))
        goto exit;
        */

        pPkcsCtx->requesterCertDescriptor.pCertificate = pCertificate;
        pPkcsCtx->requesterCertDescriptor.certLength = certLength;
        pPkcsCtx->requesterCertDescriptor.cookie = 0;

        /* parse the certificate, also cache selfcert for future use */
        MF_attach(&(pPkcsCtx->requesterCertMemFile), certLength, pPkcsCtx->requesterCertDescriptor.pCertificate);
        CS_AttachMemFile(&(pPkcsCtx->requesterCertStream), &(pPkcsCtx->requesterCertMemFile) );
        if (OK > (status = X509_parseCertificate( pPkcsCtx->requesterCertStream, &(pPkcsCtx->pRequesterCert))))
            goto exit;
    }

    *ppReqInfo = NULL;
exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SCEP, &hwAccelCtx);

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_releaseContext(scepContext **ppScepContext)
{
    return SCEP_CONTEXT_releaseContext(ppScepContext);
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_setRequestBodyCookie(void **ppCookie, ubyte* data, ubyte4 dataLen)
{
    MSTATUS status = OK;
    requestBodyCookie *bodyCookie = NULL;

    if (ppCookie == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppCookie = (requestBodyCookie*)MALLOC(sizeof(requestBodyCookie))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMSET(*ppCookie, 0x00, sizeof(requestBodyCookie))))
        goto exit;
    bodyCookie = (requestBodyCookie*)*ppCookie;
    if (NULL == (bodyCookie->data = MALLOC(dataLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(bodyCookie->data, data, dataLen)))
        goto exit;
    bodyCookie->dataLen = dataLen;
    bodyCookie->curPos = 0;
exit:
    if (OK > status)
    {
        if (bodyCookie && bodyCookie->data)
            FREE(bodyCookie->data);

        if (ppCookie && *ppCookie)
            FREE(*ppCookie);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_setPollingCookie(void **ppPollingCookie, ubyte* query, ubyte4 queryLen, void *pRequestBodyCookie)
{
    MSTATUS status = OK;
    pollingCookie *pollCookie=NULL;
    requestBodyCookie *bodyCookie;

    if (ppPollingCookie == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppPollingCookie = MALLOC(sizeof(pollingCookie))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET(*ppPollingCookie, 0x00, sizeof(pollingCookie))))
        goto exit;

    pollCookie = (pollingCookie*)*ppPollingCookie;

    if (NULL == (pollCookie->query = MALLOC(queryLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK  > (status = DIGI_MEMCPY(pollCookie->query, query, queryLen)))
        goto exit;
    pollCookie->queryLen = queryLen;


    /* if pCookie is not null, also cache that */
    if (pRequestBodyCookie)
    {
        bodyCookie = (requestBodyCookie*) pRequestBodyCookie;
        if (bodyCookie->data && bodyCookie->dataLen > 0)
        {
            if (OK > (status = SCEP_CLIENT_setRequestBodyCookie((void**)&(pollCookie->bodyCookie), bodyCookie->data, bodyCookie->dataLen)))
                goto exit;
        }
    }
exit:
    if (OK > status)
    {
        /* deallocate memory */
        SCEP_CLIENT_releasePollCookie(pollCookie);
    }
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_releaseCookie(void *pCookieToRelease)
{
    requestBodyCookie *cookie = pCookieToRelease;

    if (cookie)
    {
        if (cookie->data)
        {
            FREE(cookie->data);
        }
        FREE(cookie);
    }
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_releasePollCookie(void *pPollCookieToRelease)
{
    pollingCookie *pollCookie=pPollCookieToRelease;

    /* deallocate memory */
    if (pollCookie)
    {
        if (pollCookie->bodyCookie)
        {
            if (pollCookie->bodyCookie->data)
            {
                FREE(pollCookie->bodyCookie->data);
            }
            FREE(pollCookie->bodyCookie);
        }
        if (pollCookie->query)
        {
            FREE(pollCookie->query);
        }
        FREE(pollCookie);
        pollCookie = NULL;
    }
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_generateRequest(scepContext *pScepContext, ubyte **ppQuery, ubyte4 *pQueryLen)
{
    return SCEP_CLIENT_generateRequestEx(pScepContext, FALSE, ppQuery, pQueryLen, NULL, NULL);
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_generateRequestEx(scepContext *pScepContext, byteBoolean useHttpPOST, ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void** ppCookie)
{
    return SCEP_CLIENT_generateRequestWithCache(pScepContext, useHttpPOST, ppQuery, pQueryLen, pBodyLen, ppCookie, NULL);
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_generateRequestWithCache(scepContext *pScepContext, byteBoolean useHttpPOST, ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void** ppCookie, void **ppPollingCookie)
{
    MSTATUS          status;
    intBoolean       pkcsReqAllocated = FALSE;
    ubyte*           pPkcsReq = NULL;
    ubyte4           pkcsReqLen;
    ubyte*           pRetBuffer = NULL;
    ubyte4           retBufferLen = 0;
    ubyte*           queryPtr;
    ubyte4           escapedLen;
    sbyte*           queryPrefix1 = (sbyte*)"operation=";
    ubyte4           queryPrefix1Len = 10;
    sbyte*           queryPrefix2 = (sbyte*)"&message=";
    ubyte4           queryPrefix2Len = 9;
    intBoolean       useQueryPrefix2 = TRUE;
    SCEP_messageType messageType = pScepContext->pReqInfo->type;

    *ppQuery = NULL;
    *pQueryLen = 0;
    if (pBodyLen)
    {
        *pBodyLen = 0;
    }
    else if (useHttpPOST)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (ppCookie)
    {
        *ppCookie = NULL;
    }
    else if (useHttpPOST)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (ppPollingCookie)
    {
        *ppPollingCookie = NULL;
    }

    switch (messageType)
    {
    case scep_PKCSReq:
    case scep_GetCertInitial:
    case scep_GetCert:
    case scep_GetCRL:
    case scep_RevokeCert:
    case scep_PublishCRL:
    case scep_ApproveCertEnroll:
    case scep_RegisterEndEntity:
        if (OK > (status = SCEP_MESSAGE_generatePkiRequestMessage(pScepContext->pPkcsCtx, pScepContext, &pPkcsReq, &pkcsReqLen)))
           goto exit;
        if (useHttpPOST)
        {
            /* POST will send raw message in HTTP body. No Base64 encoding is needed */
            *pBodyLen = pkcsReqLen;
            if (OK > (status = SCEP_CLIENT_setRequestBodyCookie(ppCookie, pPkcsReq, pkcsReqLen)))
                goto exit;
        } else
        {
            /* base64 encode the request message */
            if (OK > (status = BASE64_encodeMessage(pPkcsReq, pkcsReqLen, &pRetBuffer, &retBufferLen)))
                goto exit;
        }
        pkcsReqAllocated = TRUE;
        break;
    case scep_GetCACert:
    case scep_GetNextCACert:
    case scep_GetCACertChain:
    case scep_GetCACaps:
#if defined(__ENABLE_DIGICERT_DIGICERT_PKCS7_ATTRS_ORDER__)
        /* Digicert does not like &message=ca query suffix for CA operations */
        useQueryPrefix2 = FALSE;
#endif
        useHttpPOST = FALSE; /* only PKCSOperation supports POST */
        /* these share the same message except the operation string */
        pPkcsReq = pScepContext->pReqInfo->value.caIdent.ident;
        pkcsReqLen = pScepContext->pReqInfo->value.caIdent.identLen;
        pRetBuffer = pPkcsReq;
        retBufferLen = pkcsReqLen;
        break;
    default:
        /* shouldn't happen */
        status = ERR_SCEP_NOT_SUPPORTED;
        goto exit;
    }
    /* record the choice of using Http POST; polling the server will use consistent choice */
    pScepContext->useHttpPOST = useHttpPOST;

    /*
    if ( OK > ( status = DIGICERT_writeFile( (const sbyte*)"c:\\ws\\src\\scep\\test\\reqmsg.der", pPkcsReq, pkcsReqLen)))
        goto exit;
    */

    /* construct the URL */
    if (useHttpPOST || FALSE == useQueryPrefix2)
    {
        *pQueryLen = queryPrefix1Len + mScepOperations[messageType-SCEP_operationsOffset].nameStr.nameLen;
    } else
    {
        /* for URLs, need to escape query part */
        if (OK > (status = URI_GetEscapedLength(QUERY, (sbyte *)pRetBuffer, retBufferLen, &escapedLen)))
            goto exit;
        *pQueryLen = queryPrefix1Len + mScepOperations[messageType-SCEP_operationsOffset].nameStr.nameLen +
            queryPrefix2Len + escapedLen;

    }
    if (NULL == (*ppQuery = (ubyte*)MALLOC(*pQueryLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    queryPtr = *ppQuery;
    if (OK > (status = DIGI_MEMCPY(queryPtr, queryPrefix1, queryPrefix1Len)))
        goto exit;
    queryPtr += queryPrefix1Len;
    if (OK > (status = DIGI_MEMCPY(queryPtr, mScepOperations[messageType-SCEP_operationsOffset].nameStr.name, mScepOperations[messageType-SCEP_operationsOffset].nameStr.nameLen)))
        goto exit;
    queryPtr += mScepOperations[messageType-SCEP_operationsOffset].nameStr.nameLen;
    if (!useHttpPOST && TRUE == useQueryPrefix2)
    {
        if (OK > (status = DIGI_MEMCPY(queryPtr, queryPrefix2, queryPrefix2Len)))
            goto exit;
        queryPtr += queryPrefix2Len;
        if (OK > (status = URI_Escape(QUERY, (sbyte *)pRetBuffer, retBufferLen,
            queryPtr, &escapedLen)))
            goto exit;
    }
    /* cache all request info, including requestBody if using POST; this is used for polling, i.e. GetCertInitial */
    /* OK if cannot cache */
    if (ppPollingCookie)
    {
        SCEP_CLIENT_setPollingCookie(ppPollingCookie, *ppQuery, *pQueryLen, ppCookie == NULL? NULL : *ppCookie);
    }
    /* change state to certReqPending */
    SCEP_CLIENT_STATE(pScepContext) = certReqPending;

exit:
    if (pkcsReqAllocated && pPkcsReq)
    {
        FREE(pPkcsReq);
    }
    if (pkcsReqAllocated && pRetBuffer)
    {
        FREE(pRetBuffer);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_recvResponse(scepContext *pScepContext, ubyte *contentType, ubyte4 contentTypeLen, ubyte *pHttpResp, ubyte4 httpRespLen)
{
    MSTATUS status = OK;
    sbyte4 result;
    ubyte4 i;
    sbyte4 type = -1;

    /* if ( OK > ( status = DIGICERT_writeFile( "c:\\ws\\src\\scep\\test\\httpresp.der", pHttpResp, httpRespLen)))
    goto exit;
    */
    for (i = 0; i < NUM_SCEP_RESPONSETYPES; i++)
    {
        if (mScepResponseTypes[i].nameLen == contentTypeLen)
        {
            if (OK > (status = DIGI_MEMCMP(contentType, mScepResponseTypes[i].name, mScepResponseTypes[i].nameLen, &result)))
                goto exit;
            if (result == 0)
            {
                type = i;
                break;
            }
        }
    }

    switch (type)
    {
    case x_pki_message:
    case xml:
    case x_x509_ca_ra_cert:
    case x_x509_ca_ra_cert_chain:
        if (OK > (status = SCEP_MESSAGE_parsePkcsResponse(pScepContext->pPkcsCtx, pScepContext, type, pHttpResp, httpRespLen)))
        {
            if (status != ERR_SCEP_NO_KNOWN_SIGNERS)
            {
                goto exit;
            }
        }
        break;
    case x_x509_ca_cert:
        /* content is DER encode X509 cert */
    default:
        /* any other type, we would use raw content */
        if (httpRespLen > 0)
        {
            pScepContext->pReceivedData = (ubyte*)MALLOC(httpRespLen);
            if (!pScepContext->pReceivedData)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            if (OK > (status = DIGI_MEMCPY(pScepContext->pReceivedData, pHttpResp, httpRespLen)))
                goto exit;
            pScepContext->receivedDataLength = httpRespLen;
        }
        else
        {
            pScepContext->pReceivedData = NULL;
            pScepContext->receivedDataLength = 0;
        }
        break;
    }

    SCEP_CLIENT_STATE(pScepContext) = finishedState;
exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_CLIENT_cloneRequestBodyCookie(requestBodyCookie *pCookie, void **ppClonedCookie, ubyte4 *pLen)
{
    MSTATUS status = OK;
    requestBodyCookie *pClone;
    if (!pCookie)
    {
        *ppClonedCookie = NULL;
        *pLen = 0;
        goto exit;
    }
    if (NULL == (*ppClonedCookie = MALLOC(sizeof(requestBodyCookie))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pClone = (requestBodyCookie *)*ppClonedCookie;
    if (NULL == (pClone->data = MALLOC(pCookie->dataLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMCPY(pClone->data, pCookie->data, pCookie->dataLen);
    pClone->dataLen = pCookie->dataLen;
    pClone->curPos = 0;
    *pLen = pCookie->dataLen;
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_generatePollServerRequest(scepContext *pScepContext,
                       ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void **ppCookie, void **ppPollingCookie)
{
    MSTATUS     status = OK;
    requestInfo *pReqInfo=NULL;
    pkcsCtxInternal *pPkcsCtx = NULL;

    if (!pScepContext || !pScepContext->pTransAttrs || !pBodyLen || !ppCookie)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppQuery = NULL;
    *pQueryLen = 0;
    if (pBodyLen)
    {
        *pBodyLen = 0;
    }
    if (ppCookie)
    {
        *ppCookie = NULL;
    }

    SCEP_CONTEXT_resetContextEx(pScepContext, TRUE);

    if (ppPollingCookie && (*ppPollingCookie))
    {
        /* short cut polling -- no regeneration of the pkimessage */

        pollingCookie *pollCookie = (pollingCookie*) *ppPollingCookie;

        if (NULL == (*ppQuery = MALLOC(pollCookie->queryLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(*ppQuery, pollCookie->query, pollCookie->queryLen);
        *pQueryLen = pollCookie->queryLen;
        /* if Http request method is not POST, requestBodyCookie is NULL.
         * Because all info is located in the URI */
        /* reset requestBodyCookie's curPos */
        /* *ppCookie = NULL; no need to do this since we have already resetted the values
        *pBodyLen = 0;*/
        if (pollCookie->bodyCookie)
        {
            /* ywang: need to clone bodyCookie */
            SCEP_CLIENT_cloneRequestBodyCookie(pollCookie->bodyCookie, ppCookie, pBodyLen);
        }

        /* change state to certReqPending */
        SCEP_CLIENT_STATE(pScepContext) = certReqPending;
    }
    else
    {
        pPkcsCtx = pScepContext->pPkcsCtx;
        if (NULL == (pScepContext->pReqInfo = MALLOC(sizeof(requestInfo))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        pReqInfo = pScepContext->pReqInfo;
        pReqInfo->type = scep_GetCertInitial;

        /* issuer is CA subject name */
        if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pReqInfo->value.issuerAndSubject.pIssuer)))
            goto exit;

        if (OK > (status = X509_extractDistinguishedNames(ASN1_FIRST_CHILD(pPkcsCtx->pCACertificate),
                                                          pPkcsCtx->CACertStream,
                                                          FALSE, pReqInfo->value.issuerAndSubject.pIssuer)))
        {
            goto exit;
        }

        if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pReqInfo->value.issuerAndSubject.pSubject)))
            goto exit;

        if (OK > (status = X509_extractDistinguishedNames(ASN1_FIRST_CHILD(pPkcsCtx->pRequesterCert),
                                                          pPkcsCtx->requesterCertStream,
                                                          FALSE, pReqInfo->value.issuerAndSubject.pSubject)))
        {
            goto exit;
        }
        /* selfcert should be cached */

        /* cache the request in pReceivedData */
        if (OK > (status = SCEP_CLIENT_generateRequestWithCache(pScepContext, pScepContext->useHttpPOST, ppQuery, pQueryLen, pBodyLen, ppCookie, ppPollingCookie)))
            goto exit;
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern SCEP_pkiStatus
SCEP_CLIENT_getStatus(scepContext *pScepContext)
{
    if (pScepContext->pTransAttrs)
        return pScepContext->pTransAttrs->pkiStatus;
    else
        return scep_SUCCESS;
}

/*------------------------------------------------------------------*/

extern intBoolean
SCEP_CLIENT_isDoneReceivingResponse(scepContext *pScepContext)
{
    return SCEP_CLIENT_STATE(pScepContext) == finishedState;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_getResponseContent(scepContext *pScepContext, ubyte** ppRespContent, ubyte4* pRespContentLen)
{
    MSTATUS status = OK;
    if (!SCEP_CLIENT_isDoneReceivingResponse(pScepContext))
    {
        goto exit;
    }
    *ppRespContent = pScepContext->pReceivedData;
    *pRespContentLen = pScepContext->receivedDataLength;

    pScepContext->pReceivedData = NULL;
    pScepContext->receivedDataLength = 0;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_getMessageType(scepContext *pScepContext, SCEP_messageType *pMessageType)
{
    MSTATUS status = OK;

    if (!pScepContext || !(pScepContext->pReqInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pMessageType = pScepContext->pReqInfo->type;

exit:
    return status;
}

/*------------------------------------------------------------------*/

extern ubyte4
SCEP_CLIENT_getHTTPStatusCode(scepContext *pScepContext)
{
    MOC_UNUSED(pScepContext);
    return 0; /* pScepContext->pHttpContext->httpStatusResponse; */
}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_CLIENT_getFailInfo(scepContext *pScepContext, SCEP_failInfo *pFailInfo)
{
    MSTATUS status = OK;

    if (!pScepContext || !(pScepContext->pTransAttrs))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pFailInfo = pScepContext->pTransAttrs->failinfo;

exit:
    return status;
}

/*
 * obtains the unique value for a message in a context
 */
MOC_EXTERN MSTATUS
SCEP_CLIENT_getTransactionId(scepContext *pScepContext, sbyte **ppTransactionId, ubyte4 *pTransactionIdLen, SCEP_messageType scepMsgType)
{
    MSTATUS status = OK;
    sbyte*  pTransactionId = NULL;
    ubyte4  transactionIdLen = 0;

    if ((!pScepContext) || !(ppTransactionId) || !(pTransactionIdLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppTransactionId = NULL;
    *pTransactionIdLen = 0;

    switch(scepMsgType)
    {
        case scep_PKCSReq:
        {
            if (!(pScepContext->pTransAttrs) || !(pScepContext->pTransAttrs->transactionID))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            pTransactionId = pScepContext->pTransAttrs->transactionID;
            transactionIdLen = pScepContext->pTransAttrs->transactionIDLen;
            break;
        }
        case scep_GetCACaps:
        {
            if (!(pScepContext->pReqInfo) || !(pScepContext->pReqInfo->value.caIdent.ident))
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
            pTransactionId = (sbyte *)pScepContext->pReqInfo->value.caIdent.ident;
            transactionIdLen = pScepContext->pReqInfo->value.caIdent.identLen;
            break;
        }
        default:
           status = ERR_SCEP;
    }

    if (NULL == (*ppTransactionId = MALLOC(transactionIdLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY((void *)(*ppTransactionId), (const void *)pTransactionId, transactionIdLen);
    *pTransactionIdLen = transactionIdLen;

exit:
    return status;
}

extern MSTATUS
getCustomCertExtension(ASN1_ITEM* pExtensionsSeq, CStream s, const ubyte* whichOID,
                 intBoolean* critical, ASN1_ITEM** ppExtension)
{
    ASN1_ITEM*  pOID;
    MSTATUS     status;

    if ((NULL == pExtensionsSeq) || (NULL == whichOID) ||
    (NULL == critical) || (NULL == ppExtension))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *critical = 0;
    *ppExtension = 0;

    status = ASN1_GetChildWithOID( pExtensionsSeq, s, whichOID, &pOID);
    if (OK > status )
        goto exit;

    if (pOID)
    {
        /* Extension ::= SEQUENCE {
                extnId     EXTENSION.&id({ExtensionSet}),
                critical   BOOLEAN DEFAULT FALSE,
                extnValue  OCTET STRING }  */
        ASN1_ITEM* pSibling = ASN1_NEXT_SIBLING( pOID);

        status = ERR_CERT_INVALID_STRUCT;

        if (NULL == pSibling || UNIVERSAL != (pSibling->id & CLASS_MASK ))
            goto exit;

        if ( BOOLEAN == pSibling->tag)
        {
            *critical = pSibling->data.m_boolVal;
            pSibling = ASN1_NEXT_SIBLING(pSibling);
            if ( NULL == pSibling || UNIVERSAL != (pSibling->id & CLASS_MASK ))
                goto exit;
        }

        if (OCTETSTRING != pSibling->tag)
            goto exit;

        *ppExtension = pSibling;

        if ( 0 == *ppExtension)
            goto exit;
    }

    status = OK;

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
SCEP_CLIENT_getUserPrivilegeExt(ubyte *pCertDer, ubyte4 certLen, ubyte **ppExt, ubyte4 *pExtLen)
{
    MSTATUS                     status = OK;
    ASN1_ITEMPTR                pExtensions = NULL;
    ASN1_ITEMPTR                pCert = NULL;
    ASN1_ITEMPTR                pSingleExtension    = NULL;
    MemFile                     memFile;
    CStream                     cs;
    intBoolean                  critical;
    ubyte *                     pData = NULL;

    if (!pCertDer || !certLen || !ppExt || !pExtLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppExt = NULL;
    *pExtLen = 0;

    MF_attach(&memFile, certLen, pCertDer);
    CS_AttachMemFile(&cs, &memFile);

    if (OK > (status = X509_parseCertificate(cs, &pCert)))
        goto exit;

    if (OK > (status = X509_getCertificateExtensions(ASN1_FIRST_CHILD(pCert), &pExtensions)))
        goto exit;

    if (!pExtensions)
        goto exit;

    if (OK > (status = getCustomCertExtension(pExtensions, cs,
                                             mocana_cert_extension_OID,
                                             &critical, &pSingleExtension)) || !pSingleExtension)
        goto exit;

    *ppExt = MALLOC(pSingleExtension->length);
    if (!*ppExt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pData   = (ubyte*)CS_memaccess(cs, pSingleExtension->dataOffset, pSingleExtension->length);
    DIGI_MEMCPY(*ppExt, pData, pSingleExtension->length);

    *pExtLen = pSingleExtension->length;

exit:
    if (pCert)
    {
        TREE_DeleteTreeItem((TreeItem*)pCert);
    }

    if (pData)
        CS_stopaccess(cs, pData);

    return status;
}

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */
