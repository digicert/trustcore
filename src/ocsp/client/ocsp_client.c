/*
 * ocsp_client.c
 *
 * OCSP Client Developer API
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

/**
@file       ocsp_client.c
@brief      NanoCert OCSP Client API.
@details    This file contains NanoCert OCSP Client API functions.

@since 4.2
@version 5.3 and later

@flags
To enable any of this file's functions, the following flag must be defined in
moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@filedoc    ocsp_client.c
*/

#include "../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

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
#include "../../crypto/crypto.h"
#include "../../crypto/rsa.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/pubcrypto.h"
#include "../../asn1/oiddefs.h"
#include "../../asn1/parseasn1.h"
#include "../../crypto/ca_mgmt.h"
#include "../../asn1/parsecert.h"
#include "../../asn1/derencoder.h"
#include "../../crypto/pkcs_common.h"
#include "../../common/base64.h"
#include "../../crypto/cert_chain.h"
#include "../../asn1/ASN1TreeWalker.h"
#include "../../crypto/asn1cert.h"
#include "../../common/uri.h"
#include "../../common/mtcp.h"
#include "../../common/mudp.h"
#include "../../common/debug_console.h"
#include "../../http/http_context.h"
#include "../../http/http.h"
#include "../../http/http_common.h"
#include "../../http/client/http_request.h"
#include "../../ocsp/ocsp.h"
#include "../../ocsp/ocsp_context.h"
#include "../../ocsp/ocsp_http.h"
#include "../../ocsp/ocsp_message.h"
#include "../../ocsp/client/ocsp_client.h"
#include "../../harness/harness.h"


/*------------------------------------------------------------------*/

/**
@brief      Creates an OCSP Client context.
@details    This function initializes OCSP CLIENT internal structures. The
            application should call this function before using other API
            functions.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param ppOcspContext    On return, pointer to ocspContext, which contains
                        information to configure the %client operation.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ocsp_client.c
*/

extern MSTATUS
OCSP_CLIENT_createContext(ocspContext **ppOcspContext)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if (!ppOcspContext)
        goto exit;

    if (OK > (status = OCSP_CONTEXT_createContext(ppOcspContext, OCSP_CLIENT)))
        goto exit;

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning++;
#endif

exit:
    return status;

} /* OCSP_CLIENT_createContext */

/*------------------------------------------------------------------*/

/**
@brief      Creates an OCSP Client context with local OCSP settings.
@details    This function initializes OCSP CLIENT internal structures. The
            application should call this function before using other API
            functions. This API will allocate the OCSP settings and the settings
            must be set per each OCSP context. Call
            OCSP_CLIENT_releaseContextLocal to free the context.

@ingroup    ocsp_client_functions

@since 6.5
@version 6.5 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param ppOcspContext    On return, pointer to ocspContext, which contains
                        information to configure the %client operation.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ocsp_client.c
*/

extern MSTATUS
OCSP_CLIENT_createContextLocal(ocspContext **ppOcspContext)
{
    return OCSP_CONTEXT_createContextLocal(ppOcspContext, OCSP_CLIENT);
} /* OCSP_CLIENT_createContextLocal */

/*------------------------------------------------------------------*/

/**
@brief      Generates the DER encoded OCSP request.

@details    This function generates the OCSP request based on the configuration
            and the specified inputs.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext     Context returned from OCSP_CLIENT_createContext().
@param pExts            Pointer to custom %extensions to send in the request.
@param extCount         Pointer to number of custom %extensions (\p pExts).
@param ppRetRequest     On return, pointer to well-formed OCSP request.
@param pRetRequestLen   On return, number of bytes in the well-formed OCSP
                          request.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ocsp_client.c
*/

extern MSTATUS
OCSP_CLIENT_generateRequest(ocspContext *pOcspContext,
                            extensions *pExts, ubyte4 extCount,
                            ubyte **ppRetRequest, ubyte4 *pRetRequestLen)
{
    OCSP_singleRequest**    pRequest  = NULL;
    OCSP_certID**           pCertID   = NULL;
    ubyte                   count, i;
    MSTATUS                 status    = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (0 == pOcspContext->pOcspSettings->certCount))
        goto exit;

    if (NULL == (pRequest = MALLOC(sizeof(OCSP_singleRequest *) * pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pRequest, 0x00, sizeof(OCSP_singleRequest *) * pOcspContext->pOcspSettings->certCount);

    if (NULL == (pCertID = MALLOC(sizeof(OCSP_certID *) * pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pCertID, 0x00, sizeof(OCSP_certID *) * pOcspContext->pOcspSettings->certCount);

    for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
    {
        /* Check for certificates availability */
        if ((NULL == pOcspContext->pOcspSettings->pCertInfo[count].pCert) ||
            (NULL == pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath) ||
            (0    >= pOcspContext->pOcspSettings->pCertInfo[count].certLen) ||
            (0    >= pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen))
        {
            goto exit;
        }
    }

    /* Generate single requests for each cert in question */
    for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
    {
        if (NULL == ((pRequest[count]) = MALLOC(sizeof(OCSP_singleRequest))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > (status = DIGI_MEMSET((ubyte *)pRequest[count], 0x00, sizeof(OCSP_singleRequest))))
            goto exit;

        /* Set the proper issuer for the certifcate in question */
        pOcspContext->pOcspSettings->pIssuerCert   = pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath;
        pOcspContext->pOcspSettings->issuerCertLen = pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen;

        if (OK > (status = OCSP_MESSAGE_generateSingleRequest(pOcspContext,
                                                              &pOcspContext->pOcspSettings->pCertInfo[count],
                                                              pRequest[count])))
        {
            goto exit;
        }

        /* Clean up as issuers are different */
        pOcspContext->pOcspSettings->pIssuerCert   = NULL;
        pOcspContext->pOcspSettings->issuerCertLen = 0;

        /* Cache the certId for validating response */
        if (NULL == ((pCertID[count]) = MALLOC(sizeof(OCSP_certID))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > DIGI_MEMCPY(pCertID[count], &(pRequest[count]->certId), sizeof(OCSP_certID)))
            goto exit;

    }

    /* Generate the complete request message in ASN1 format */
    if (OK > (status = OCSP_MESSAGE_generateRequestInternal(pOcspContext, pRequest,
                                                            pOcspContext->pOcspSettings->certCount,
                                                            pExts, extCount, ppRetRequest,
                                                            pRetRequestLen)))
    {
        goto exit;
    }

    /* Cache the certId of all the certs in requests to match the response */
    pOcspContext->ocspProcess.client.cachedCertId = pCertID;
    pCertID = NULL;

exit:
    /* Free up */
    if (pRequest)
    {
        for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
        {
            if (pRequest[count])
            {
                if ((*pRequest[count]).singleRequestExtensions)
                {
                    for (i = 0; i < (*pRequest[count]).extNumber; i++)
                    {
                        if ((*pRequest[count]).singleRequestExtensions[i].value)
                            FREE((*pRequest[count]).singleRequestExtensions[i].value);
                    }

                    FREE((*pRequest[count]).singleRequestExtensions);
                }

                FREE(pRequest[count]);
            }
        }

        FREE (pRequest);
    }

    if (pCertID)
    {
        for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
        {
            if (pCertID[count])
            {
                if ((*pCertID[count]).serialNumber)
                    FREE((*pCertID[count]).serialNumber);

                if ((*pCertID[count]).nameHash)
                    FREE((*pCertID[count]).nameHash);

                if ((*pCertID[count]).keyHash)
                    FREE((*pCertID[count]).keyHash);

                FREE(pCertID[count]);
            }
        }

        FREE (pCertID);
    }

    /* Free some more here as they are not needed in future processing */
    if (pOcspContext)
    {
        if (pOcspContext->ocspProcess.client.pIssuerInfo)
            CA_MGMT_freeCertDistinguishedName(&pOcspContext->ocspProcess.client.pIssuerInfo);

        if (pOcspContext->ocspProcess.client.issuerNameHash)
            FREE(pOcspContext->ocspProcess.client.issuerNameHash);

        if (pOcspContext->ocspProcess.client.issuerPubKeyHash)
            FREE(pOcspContext->ocspProcess.client.issuerPubKeyHash);
    }

    return status;
} /* OCSP_CLIENT_generateRequest */


/*------------------------------------------------------------------*/
/**
@brief      Generates the DER encoded OCSP request.

@details    This function generates the OCSP request based on the configuration
            and the inputs specified. Unlike the OCSP_CLIENT_generateRequest
            function, this function does not require the entire certificate
            to be passed to it. Instead, you can supply just the serial
            number information (through the \p pCertSerialNo and \p serialNoLen
            parameters).

@ingroup    ocsp_client_functions

@since 5.3
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext     Context returned from OCSP_CLIENT_createContext().
@param pExts            Pointer to custom %extensions to send in the request.
@param extCount         Pointer to number of custom %extensions (\p pExts).
@param pCertSerialNo    Pointer to certificate's serial number.
@param serialNoLen      Number of bytes in the serial number (\p pCertSerialNo).
@param ppRetRequest     On return, pointer to well-formed OCSP request.
@param pRetRequestLen   On return, number of bytes in the well-formed OCSP
                          request.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_generateRequestEx(ocspContext *pOcspContext,
                            extensions *pExts, ubyte4 extCount,
                            ubyte* pCertSerialNo, ubyte4 serialNoLen,
                            ubyte **ppRetRequest, ubyte4 *pRetRequestLen)
{
    OCSP_singleRequest**    pRequest  = NULL;
    OCSP_certID**           pCertID   = NULL;
    ubyte                   count, i;
    MSTATUS                 status    = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (0 == pOcspContext->pOcspSettings->certCount) ||
        (NULL == pCertSerialNo) || (0 == serialNoLen))
        goto exit;

    if (NULL == (pRequest = MALLOC(sizeof(OCSP_singleRequest *) * pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pRequest, 0x00, sizeof(OCSP_singleRequest *) * pOcspContext->pOcspSettings->certCount);

    if (NULL == (pCertID = MALLOC(sizeof(OCSP_certID *) * pOcspContext->pOcspSettings->certCount)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pCertID, 0x00, sizeof(OCSP_certID *) * pOcspContext->pOcspSettings->certCount);

    /* Generate single requests for each cert in question */
    for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
    {
        if (NULL == ((pRequest[count]) = MALLOC(sizeof(OCSP_singleRequest))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pOcspContext->pOcspSettings->pIssuerCert   = pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath;
        pOcspContext->pOcspSettings->issuerCertLen = pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen;

        if (OK > (status = OCSP_MESSAGE_generateSingleRequestEx(pOcspContext,
                                                                pCertSerialNo, serialNoLen,
                                                                &pOcspContext->pOcspSettings->pCertInfo[count],
                                                                pRequest[count])))
        {
            goto exit;
        }

        /* Cache the certId for validating response */
        if (NULL == ((pCertID[count]) = MALLOC(sizeof(OCSP_certID))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > DIGI_MEMCPY(pCertID[count], &(pRequest[count]->certId), sizeof(OCSP_certID)))
            goto exit;

    }

    /* Generate the complete request message in ASN1 format */
    if (OK > (status = OCSP_MESSAGE_generateRequestInternal(pOcspContext, pRequest,
                                                            pOcspContext->pOcspSettings->certCount,
                                                            pExts, extCount, ppRetRequest,
                                                            pRetRequestLen)))
    {
        goto exit;
    }

    /* Cache the certId of all the certs in requests to match the response */
    pOcspContext->ocspProcess.client.cachedCertId = pCertID;
    pCertID = NULL;

exit:
    /* Free up */
    if (pRequest)
    {
        for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
        {
            if (pRequest[count])
            {
                if ((*pRequest[count]).singleRequestExtensions)
                {
                    for (i = 0; i < (*pRequest[count]).extNumber; i++)
                    {
                        if ((*pRequest[count]).singleRequestExtensions[i].value)
                            FREE((*pRequest[count]).singleRequestExtensions[i].value);
                    }

                    FREE((*pRequest[count]).singleRequestExtensions);
                }

                FREE(pRequest[count]);
            }
        }

        FREE (pRequest);
    }

    if (pCertID)
    {
        for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
        {
            if (pCertID[count])
            {
                if ((*pCertID[count]).serialNumber)
                    FREE((*pCertID[count]).serialNumber);

                if ((*pCertID[count]).nameHash)
                    FREE((*pCertID[count]).nameHash);

                if ((*pCertID[count]).keyHash)
                    FREE((*pCertID[count]).keyHash);

                FREE(pCertID[count]);
            }
        }

        FREE (pCertID);
    }

    /* Free some more here as they are not needed in future processing */
    if (pOcspContext)
    {
        if (pOcspContext->ocspProcess.client.pIssuerInfo)
            CA_MGMT_freeCertDistinguishedName(&pOcspContext->ocspProcess.client.pIssuerInfo);

        if (pOcspContext->ocspProcess.client.issuerNameHash)
            FREE(pOcspContext->ocspProcess.client.issuerNameHash);

        if (pOcspContext->ocspProcess.client.issuerPubKeyHash)
            FREE(pOcspContext->ocspProcess.client.issuerPubKeyHash);
    }

    return status;
} /* OCSP_CLIENT_generateRequestEx */

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
OCSP_CLIENT_getResponderIdfromCertExtension(ASN1_ITEM *pExtension, CStream cs, ubyte **uriStr)
{
    ubyte*       buf;
    ubyte*       pUri      = NULL;
    ASN1_ITEMPTR pTemp     = NULL;
    ASN1_ITEMPTR pChild    = NULL;
    MSTATUS      status    = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pExtension) || (NULL == uriStr))
        goto exit;

    /* AccessDescription */
    if (NULL == (pTemp = ASN1_FIRST_CHILD(pExtension)))
        goto exit;

    while (pTemp)
    {
        /* accessMethod */
        if (NULL == (pChild = ASN1_FIRST_CHILD(pTemp)))
            goto exit;

        if (OK == (status = ASN1_VerifyOID(pChild, cs, id_ad_ocsp)))
            break;

        pTemp = ASN1_NEXT_SIBLING(pTemp);
    }

    if (OK > status)
    {
        /* the AIA does not contain info regarding OCSP responders */
        status = ERR_OCSP_BAD_AIA;
        goto exit;
    }

    if (NULL == (pChild = ASN1_NEXT_SIBLING(pChild)))
        goto exit;

    if (NULL == (pUri  = MALLOC(pChild->length + 1))) /* Add NULL character */
        goto exit;

    buf = (ubyte*)CS_memaccess(cs, pChild->dataOffset, pChild->length);

    if (OK > (status = DIGI_MEMCPY(pUri, buf, pChild->length)))
        goto exit;

    *(pUri + pChild->length) = 0;

    *uriStr = pUri;
    pUri = NULL;

    if (buf)
    {
        CS_stopaccess(cs, buf);
    }

exit:
    if (pUri)
        FREE(pUri);

    return status;

} /* OCSP_CLIENT_getResponderIdfromCertExtension */

/**
@brief      Retrieves the responder URI info from a certificate.

@details    This function strips out the responder location from a
            certificate's AIA (authority information access) structure,
            leaving the responder URI.

@ingroup    ocsp_client_functions

@since 4.2
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pCert        Pointer to certificate.
@param certLen      Number of bytes in the certificate (\p pCert).
@param uriStr       On return, pointer to responder URI.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     Typically this function is used when responders are not locally
            configured.

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getResponderIdfromCert(ubyte *pCert, ubyte4 certLen, ubyte **uriStr)
{
    MemFile      mf;
    CStream      cs;
    ASN1_ITEMPTR pCertRoot = NULL;
    ASN1_ITEMPTR pChild    = NULL;
    ASN1_ITEMPTR pExtensions    = NULL;
    MSTATUS      status    = ERR_OCSP_INVALID_INPUT;
    intBoolean   critical = FALSE;

    if ((NULL == pCert) || (0 >= certLen) || (NULL == uriStr))
        goto exit;

    /* Initialize uriStr to Null */
    *uriStr = NULL;

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getCertificateExtensions(ASN1_FIRST_CHILD(pCertRoot),
                                                     &pExtensions)) || !pExtensions)
    {
        goto exit;
    }

    if (OK > (status = X509_getCertExtension(pExtensions, cs, id_pe_authorityInfoAcess_OID, &critical, &pChild)) ||
        !pChild)
    {
        status = ERR_OCSP_BAD_AIA;
        goto exit;
    }

    status = OCSP_CLIENT_getResponderIdfromCertExtension(pChild, cs, uriStr);

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *)pCertRoot);

    return status;

} /* OCSP_CLIENT_getResponderIdfromCert */


/*------------------------------------------------------------------*/
/**
@brief      Parse the raw OCSP response.

@details    This function parses the raw OCSP response received by an
            application.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@todo_version (post-6.4 revision; commit  [ca5eb79], March 30, 2016.)

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param pResponses   Pointer to raw OCSP response received.
@param responsesLen Number of bytes in the raw OCSP response (\p pResponses).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_parseResponse(ocspContext *pOcspContext,
                           ubyte* pResponses, ubyte4 responsesLen)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == pResponses) || (0 == responsesLen))
        goto exit;
    
    /* write out the OCSP response
    if ( OK > ( status = DIGICERT_writeFile( "ocsp_resp.der", pResponses, responsesLen)))
        goto exit;
    */
    
    if (OK > (status = OCSP_MESSAGE_parseResponse(pOcspContext, pResponses, responsesLen)))
        goto exit;
  
    

    
exit:
    return status;

} /* OCSP_CLIENT_parseResponse */


/*------------------------------------------------------------------*/
/**
@brief      Retrieve OCSP response %status.

@details    This function retrieves the response %status of a parsed raw OCSP
            response resulting from a call to OCSP_CLIENT_parseResponse().

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param pStatus      On return, pointer to %status of parsed response.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getResponseStatus(ocspContext *pOcspContext, OCSP_responseStatus *pStatus)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == pStatus))
        goto exit;

    if (pOcspContext->ocspProcess.client.state < ocspResponseParsed)
    {
        status = ERR_OCSP_ILLEGAL_STATE;
        goto exit;
    }

    *pStatus = pOcspContext->ocspProcess.client.status;

    status = OK;

exit:
    return status;

} /* OCSP_CLIENT_getResponseStatus */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve a response's $ProducedAt$ data.

@details    This function retrieves a responses' \c ProducedAt data&mdash;the
            time at which the response was signed by the responder.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param pTime        On return, pointer to the \c producedAt time.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getProducedAt(ocspContext *pOcspContext, TimeDate *pTime)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == pTime))
        goto exit;

    if (pOcspContext->ocspProcess.client.state < ocspResponseParsed)
    {
        status = ERR_OCSP_ILLEGAL_STATE;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getProducedAt(pOcspContext, pTime)))
        goto exit;

exit:
    return status;
} /*OCSP_CLIENT_getProducedAt */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve a certificate's status.

@details    This function retrieves a certificate's status description from
            an OCSP response.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param ppStatus     On return, pointer to certificate's %status.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should only be called after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getCurrentCertStatus(ocspContext *pOcspContext, OCSP_certStatus **ppStatus)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == ppStatus))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentCertStatus(pOcspContext,ppStatus)))
        goto exit;

exit:
    return status;

} /* OCSP_CLIENT_getCurrentCertStatus */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve a response's certificate Id (CertId).

@details    This function extracts the certificate Id (CertId field) from an
            OCSP response for a single certificate pointed to by the
            response's internal data structures.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param ppCertId     On return, pointer to the OCSP_certID.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getCurrentCertId(ocspContext *pOcspContext, OCSP_certID **ppCertId)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == ppCertId))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentCertId(pOcspContext, ppCertId)))
        goto exit;

exit:
    return status;

} /* OCSP_CLIENT_getCurrentCertId */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve a certificate's refresh tiem (thisUpdate field).

@details    This function retrieves a certificate's \c thisUpdate
            field&mdash;the time at which the responder last refreshed the
            CRL list for the certificate in question).

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext Context returned from OCSP_CLIENT_createContext().
@param pTime        On return, pointer to the \c thisUpdate time.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_getCurrentThisUpdate(ocspContext *pOcspContext, TimeDate *pTime)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == pTime))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentThisUpdate(pOcspContext, pTime)))
        goto exit;

exit:
    return status;

} /* OCSP_CLIENT_getCurrentThisUpdate */


/*------------------------------------------------------------------*/

/**
@brief      Retrieve the nextUpdate field.

@details    This function retrieves a certificate's \c nextUpdate
            field&mdash;the time when the responder will refresh the CRL
            for the certificate in question.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext     Context returned from OCSP_CLIENT_createContext().
@param pTime            On return, pointer to the \c nextUpdate time.
@param pIsNextUpdate    On return, pointer to \c TRUE if the field is present;
                          otherwise pointer to \c FALSE.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
              OCSP_CLIENT_parseResponse().
@remark     The \c NextUpdate field is optional. Therefore the
              \p pIsNextUpdate %status should be examined before using the returned \p pTime.

@funcdoc    ocsp_client.c
*/

extern MSTATUS
OCSP_CLIENT_getCurrentNextUpdate(ocspContext *pOcspContext, TimeDate *pTime, byteBoolean *pIsNextUpdate)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext) || (NULL == pTime) || (NULL == pIsNextUpdate))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentNextUpdate(pOcspContext, pTime, pIsNextUpdate)))
        goto exit;

exit:
    return status;

} /* OCSP_CLIENT_getCurrentNextUpdate */


/*------------------------------------------------------------------*/

/**
@brief      Get the next certificate response to a request for multiple
            certificates.
            
@details    This function gets the next certificate response to a request
            for multiple certificates.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param pOcspContext     Context returned from OCSP_CLIENT_createContext().

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This method should be called only after a successful call to
            OCSP_CLIENT_parseResponse().

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_goToNextResponse(ocspContext *pOcspContext)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if ((NULL == pOcspContext))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_goToNextResponse(pOcspContext)))
        goto exit;

exit:
    return status;

} /* OCSP_CLIENT_goToNextResponse */


/*------------------------------------------------------------------*/

/**
@brief      Release (free) an ocspContext and its resources.

@details    This function releases OCSP CLIENT internal structures. The
            application should call this function to shut down the OCSP client
            module after OCSP operations.

@ingroup    ocsp_client_functions

@since 4.2
@version 4.2 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param ppOcspContext    Pointer to OCSP context to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This fuction purges all OCSP %client internal data, and should
            not be called until the OCSP client shutdown sequence.

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_releaseContext(ocspContext **ppOcspContext)
{
    MSTATUS status = ERR_OCSP_INVALID_INPUT;

    if (!ppOcspContext)
        goto exit;

    if (OK > (status = OCSP_CONTEXT_releaseContext(ppOcspContext)))
        goto exit;

#ifndef __DISABLE_DIGICERT_INIT__
        gMocanaAppsRunning--;
#endif

exit:
    return status;
} /* OCSP_CLIENT_releaseContext */

/*------------------------------------------------------------------*/

/**
@brief      Release (free) an ocspContext and its resources.

@details    This function releases OCSP CLIENT internal structures. The
            application should call this function to shut down the OCSP client
            module after OCSP operations. This will also release the OCSP
            settings in the context. Only call this function if the OCSP context
            was created using OCSP_CLIENT_createContextLocal.

@ingroup    ocsp_client_functions

@since 6.5
@version 6.5 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_OCSP_CLIENT__

@inc_file ocsp_client.h

@param ppOcspContext    Pointer to OCSP context to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an 
            English text error identifier corresponding to the function's 
            returned error status, use the \c DISPLAY_ERROR macro.

@remark     This fuction purges all OCSP %client internal data, and should
            not be called until the OCSP client shutdown sequence.

@funcdoc    ocsp_client.c
*/
extern MSTATUS
OCSP_CLIENT_releaseContextLocal(ocspContext **ppOcspContext)
{
    return OCSP_CONTEXT_releaseContextLocal(ppOcspContext);
} /* OCSP_CLIENT_releaseContextLocal */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_OCSP_CERT_VERIFY__))
static MSTATUS
OCSP_CLIENT_cloneCertInfo(ocspSettings *pOcspSettings, 
                    certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen)
{
    MSTATUS status = OK;
    sbyte4 i;
    ubyte *pParentCert, *pCertificate ;
    ubyte4 parentCertLen, certLength  ;
    ubyte4 certCount  ;

    CERTCHAIN_numberOfCertificates(pCertChain, &certCount);
    if(!pAnchorCert) 
        certCount-- ;

    /* The memory allocated in this function will be freed in the caller 
       as part of OCSP_Context_releaseContext */
    if (OK > (status = DIGI_CALLOC((void **)&(pOcspSettings->pCertInfo), certCount, 
             sizeof(OCSP_singleRequestInfo))))
    {
        goto exit;
    }

    if (OK > (status = DIGI_CALLOC((void **)&(pOcspSettings->pIssuerCertInfo), certCount,
              sizeof(OCSP_certInfo) )))
    {
        goto exit;
    }

    pOcspSettings->certCount = certCount;

    pParentCert = NULL ;
    parentCertLen = 0 ;
    for (i = 0; i < (sbyte4) certCount; i++)
    {
        CERTCHAIN_getCertificate(pCertChain, i, (const ubyte**)&pCertificate, &certLength);
        /* store the certificate in question*/
        if (OK > (status = DIGI_CALLOC((void **)&(pOcspSettings->pCertInfo[i].pCert), 1, certLength)))
        {
            goto exit;
        }
        DIGI_MEMCPY(pOcspSettings->pCertInfo[i].pCert,
                   pCertificate, certLength);
        pOcspSettings->pCertInfo[i].certLen = certLength;

        if((i == (sbyte4) certCount - 1 ) && pAnchorCert) 
            break ;
        CERTCHAIN_getCertificate(pCertChain, i+1, (const ubyte**)&pParentCert, &parentCertLen);
        /* store the issuer certificate of certificate in question*/
        if(parentCertLen > 0) {
            if (OK > (status = DIGI_CALLOC((void **)&(pOcspSettings->pIssuerCertInfo[i].pCertPath), 1, parentCertLen)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(pOcspSettings->pIssuerCertInfo[i].pCertPath, pParentCert, parentCertLen);
        }
        pOcspSettings->pIssuerCertInfo[i].certLen = parentCertLen;
    }
    if(pAnchorCert && anchorCertLen) 
    {
        if (OK > (status = DIGI_CALLOC((void **)&(pOcspSettings->pIssuerCertInfo[i].pCertPath), 1, anchorCertLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pOcspSettings->pIssuerCertInfo[i].pCertPath, pAnchorCert, anchorCertLen);
        pOcspSettings->pIssuerCertInfo[i].certLen = anchorCertLen;
    }
exit:
    return status;

}


extern MSTATUS
OCSP_CLIENT_getCertStatus(sbyte *pOcspCAUrl, ubyte *pCertificate, ubyte4 certLen,
                         certChainPtr pCertChain, const ubyte *pAnchorCert, ubyte4 anchorCertLen)
{
    MSTATUS status = OK;
    ocspContext*        pOcspContext  = NULL;
    httpContext*        pHttpContext  = NULL;
    ocspSettings*       pOcspSettings = NULL ;
    ubyte*              pRequest      = NULL;
    ubyte4              requestLen    = 0;
    ubyte*              pUriStr         = NULL;
    ubyte*              pResponse       = NULL;
    ubyte4              responseLen;
    intBoolean          isDone          = FALSE;
    OCSP_responseStatus respStatus;
    OCSP_certStatus*    pCertStatus     = NULL;
    ubyte4 i;

    /* Create a Client Context */
    if (OK > (status = OCSP_CLIENT_createContext(&pOcspContext)))
        goto exit;

    pOcspSettings = pOcspContext->pOcspSettings ;
    if (OK > (status = DIGI_MEMSET((ubyte *)pOcspSettings, 0x00, sizeof(ocspSettings))))
        goto exit;

    pOcspSettings->hashAlgo        = sha1_OID;
    pOcspSettings->signingAlgo     = sha1withRSAEncryption_OID;
    pOcspSettings->timeSkewAllowed = 360;

    if (OK > (status = OCSP_CLIENT_cloneCertInfo(pOcspSettings, pCertChain, 
              pAnchorCert, anchorCertLen)))
        goto exit;

    /* check if responder URL is passed */
    if (!pOcspCAUrl)
    {
        /* if not, get AIA (i.e. OCSP URI) from the leaf cert */
        if ((OK > (status = OCSP_CLIENT_getResponderIdfromCert(
                           pCertificate,  certLen,
                           &pUriStr))) || (NULL == pUriStr))
        {
            status = ERR_OCSP_BAD_AIA;
            goto exit;
        }
        pOcspSettings->pResponderUrl = (sbyte *)pUriStr;
    }
    else 
    {
        pOcspSettings->pResponderUrl = (sbyte *)pOcspCAUrl;
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
            goto exit;
        }
    } while (!isDone);

    /* API to parse the response */
    if (OK > (status = OCSP_CLIENT_parseResponse(pOcspContext, pResponse, responseLen)))
        goto exit;

    /* API to check the OCSP response status */
    if (OK > (status = OCSP_CLIENT_getResponseStatus(pOcspContext,  &respStatus)))
        goto exit;
    if (respStatus == ocsp_successful)
    {
        /* Get the cert status for all the certs in question inside a successful response */
        for (i = 0; i < pOcspSettings->certCount; i++)
        {
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
                     status = OK ;
                     break;

                case ocsp_revoked:
                     status = ERR_CERT_REVOKED ;
                     goto exit;

                case ocsp_unknown:
                     status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS ;
                     goto exit;
            }
            if (OK > (status = OCSP_CLIENT_goToNextResponse(pOcspContext)))
                goto exit;

            if (pCertStatus)
            {
                FREE(pCertStatus);
                pCertStatus = NULL;
            }

        }


    }
    else 
    {
        status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS ;
    }

exit:

    OCSP_CLIENT_httpUninit(&pHttpContext);

    if (pRequest) FREE(pRequest);
    if (pResponse) FREE(pResponse);
    if (pCertStatus)
         FREE(pCertStatus);

    if(pOcspSettings)
    {
        for ( i = 0; i < pOcspSettings->certCount; i++)
        {
            if (pOcspSettings->pCertInfo[i].pCert)
                DIGI_FREE((void **)&(pOcspSettings->pCertInfo[i].pCert));

            if (pOcspSettings->pIssuerCertInfo[i].pCertPath)
                DIGI_FREE((void **)&(pOcspSettings->pIssuerCertInfo[i].pCertPath));
        }
    }
    OCSP_CLIENT_releaseContext(&pOcspContext);


    if (pUriStr) FREE(pUriStr);
    return status ;
    
}

#endif /* __ENABLE_DIGICERT_OCSP_CERT_VERIFY__ */



#endif /* #ifdef __ENABLE_DIGICERT_OCSP_CLIENT__ */
