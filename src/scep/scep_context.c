/**
 * @file  scep_context.c
 * @brief SCEP context definition
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

/**
@file       scep_context.c
@brief      NanoCert SCEP Client API.
@details    This file contains NanoCert SCEP Client API functions.

@since 2.02
@version 3.06 and later

@flags
Whether the following flags are defined determine which additional header files
are included:

+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@filedoc    scep_context.c
*/

#include "../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

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
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/pkcs7.h"
#include "../crypto/pkcs10.h"
#include "../http/http_context.h"
#include "../common/dynarray.h"
#include "../crypto/pki_client_common.h"
#include "../scep/scep.h"
#include "../scep/scep_context.h"

/*------------------------------------------------------------------*/

/**
@brief      Create and initialize a scepContext.

@details    This function creates and initializes a scepContext.

@ingroup    func_scep_context_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_context.h

@param ppNewContext     On return, pointer to created scepContext.
@param roleType         Type of role; \c SCEP_CLIENT is the only supported role.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_context.c
*/
extern MSTATUS SCEP_CONTEXT_createContext(scepContext **ppNewContext, sbyte4 roleType)
{
    MSTATUS status = OK;

    if (!ppNewContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppNewContext = NULL;

    if (roleType != SCEP_CLIENT)
    {
        status = ERR_SCEP_INVALID_ROLETYPE;
        goto exit;
    }

    if (NULL == (*ppNewContext = (scepContext*) MALLOC(sizeof(scepContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize */
    if (OK > (status = DIGI_MEMSET((ubyte*)(*ppNewContext), 0x00, sizeof(scepContext))))
        goto exit;

    /* no need to create this for non-pkcs operation.
     * But since the context can be reused for different scep requests, we will create this anyway. */
#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__
    if (NULL == ((*ppNewContext)->pPkcsCtx = (pkcsCtxInternal*) MALLOC(sizeof(pkcsCtxInternal))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    /* initialize */
    if (OK > (status = DIGI_MEMSET((ubyte*)(*ppNewContext)->pPkcsCtx, 0x00, sizeof(pkcsCtxInternal))))
        goto exit;
#endif

    (*ppNewContext)->roleType = roleType;
exit:

    if (OK > status)
    {
        /* release memory in case of failure */
        if (ppNewContext && *ppNewContext)
        {
            if ((*ppNewContext)->pTransAttrs)
            {
                FREE((*ppNewContext)->pTransAttrs);
            }
#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__
            if ((*ppNewContext)->pPkcsCtx)
            {
                FREE((*ppNewContext)->pPkcsCtx);
            }
#endif
            FREE(*ppNewContext);
            *ppNewContext = NULL;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Reset (clear) scepContext for later reuse

@details    This function resets (clears) the specified scepContext so it can
            be reused for subsequent SCEP operations.

@ingroup    func_scep_context_mgmt

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_context.h

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@param pScepContext Pointer to SCEP context to reset (clear)

@funcdoc    scep_context.c
*/
extern MSTATUS SCEP_CONTEXT_resetContext(scepContext *pScepContext)
{
    return SCEP_CONTEXT_resetContextEx(pScepContext, FALSE);
}

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS
SCEP_CONTEXT_releaseRequestInfo(requestInfo *pReqInfo)
{
    if (NULL == pReqInfo)
        return OK;

    switch (pReqInfo->type)
    {
        case scep_PKCSReq:
            CRYPTO_uninitAsymmetricKey(&pReqInfo->value.certInfoAndReqAttrs.pubKey, NULL);

            if (pReqInfo->value.certInfoAndReqAttrs.pSubject)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.certInfoAndReqAttrs.pSubject);
            }
            if (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs)
            {
                if (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd)
                {
                    FREE(pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pChallengePwd);
                }
                if (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions)
                {
                    ubyte4 i = 0;
                    ubyte4 count = 0;
                    extensions *pOtherExts;

                    pOtherExts = pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions->otherExts;
                    count = pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions->otherExtCount;
                    if (NULL != pOtherExts && count > 0)
                    {
                        for (i = 0; i < count;  i++)
                        {
                            extensions *pExt = pOtherExts+i;
                            if (pExt->valueLen > 0)
                            {
                                FREE(pExt->value);
                            }
                        }
                        FREE (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions->otherExts);
                    }
                    FREE (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs->pExtensions);
                }
                FREE (pReqInfo->value.certInfoAndReqAttrs.pReqAttrs);
            }
            break;

        case scep_GetCertInitial:
            if (pReqInfo->value.issuerAndSubject.pIssuer)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.issuerAndSubject.pIssuer);
            }

            if (pReqInfo->value.issuerAndSubject.pSubject)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.issuerAndSubject.pSubject);
            }
            break;
        case scep_GetCert:
            if (pReqInfo->value.issuerAndSerialNo.pIssuer)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.issuerAndSerialNo.pIssuer);
            }
            if (pReqInfo->value.issuerAndSerialNo.serialNo)
            {
                FREE(pReqInfo->value.issuerAndSerialNo.serialNo);
            }
            break;
        case scep_GetCRL:
            if (pReqInfo->value.issuerSerialNoAndDistPts.pIssuer)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.issuerSerialNoAndDistPts.pIssuer);
            }
            if (pReqInfo->value.issuerSerialNoAndDistPts.serialNo)
            {
                FREE(pReqInfo->value.issuerSerialNoAndDistPts.serialNo);
            }
            if (pReqInfo->value.issuerSerialNoAndDistPts.distPts)
            {
                FREE(pReqInfo->value.issuerSerialNoAndDistPts.distPts);
            }

            break;
        case scep_GetCACert:
        case scep_GetCACertChain:
        case scep_GetNextCACert:
        case scep_GetCACaps:
        case scep_PublishCRL:
            if (pReqInfo->value.caIdent.ident)
            {
                FREE(pReqInfo->value.caIdent.ident);
            }
            break;
        case scep_RevokeCert:
            if (pReqInfo->value.revokeCert.serialNo)
            {
                FREE(pReqInfo->value.revokeCert.serialNo);
            }
            break;
        case scep_RegisterEndEntity:
            if (pReqInfo->value.endEntityInfo.pSubject)
            {
                CA_MGMT_freeCertDistinguishedName(&pReqInfo->value.endEntityInfo.pSubject);
            }
            if (pReqInfo->value.endEntityInfo.password)
            {
                FREE(pReqInfo->value.endEntityInfo.password);
            }
        default:
            break;
    }
    FREE(pReqInfo);
    return OK;
}

/*------------------------------------------------------------------*/

/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
extern MSTATUS SCEP_CONTEXT_resetContextEx(scepContext *pScepContext, intBoolean resetForContinue)
{
    MSTATUS status = OK;

    if (!pScepContext)

    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

    pScepContext->useHttpPOST = FALSE;

#endif

    if (pScepContext->pTransAttrs)
    {
        /* reset transaction attributes, except transactionId, which may be needed for polling */
        pScepContext->pTransAttrs->failinfo = 0;
        pScepContext->pTransAttrs->messageType = 0;
        pScepContext->pTransAttrs->pkiStatus = 0;

        /* do not reset useHttpPOST or transactionID if we will continue, as in polling */
        if (!resetForContinue)
        {
            if (pScepContext->pTransAttrs->transactionID)
            {
                FREE(pScepContext->pTransAttrs->transactionID);
                pScepContext->pTransAttrs->transactionID = NULL;
                pScepContext->pTransAttrs->transactionIDLen = 0;
            }
        }

        if (pScepContext->pTransAttrs->senderNonce)
        {
            FREE(pScepContext->pTransAttrs->senderNonce);
            pScepContext->pTransAttrs->senderNonce = NULL;
            pScepContext->pTransAttrs->senderNonceLen = 0;
        }

        if (pScepContext->pTransAttrs->recipientNonce)
        {
            FREE(pScepContext->pTransAttrs->recipientNonce);
            pScepContext->pTransAttrs->recipientNonce = NULL;
            pScepContext->pTransAttrs->recipientNonceLen = 0;
        }

        if (!resetForContinue)
        {
            FREE(pScepContext->pTransAttrs);
            pScepContext->pTransAttrs = NULL;
        }
    }
    if (pScepContext->pReceivedData)
    {
        FREE(pScepContext->pReceivedData);
        pScepContext->pReceivedData = NULL;
        pScepContext->receivedDataLength = 0;
    }

    if (pScepContext->pSendingData)
    {
        FREE(pScepContext->pSendingData);
        pScepContext->pSendingData = NULL;
        pScepContext->sendingDataLength = 0;
    }

    /* reset requestInfo */
    if (pScepContext->pReqInfo)
    {
        SCEP_CONTEXT_releaseRequestInfo(pScepContext->pReqInfo);
        pScepContext->pReqInfo = NULL;
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

/**
@brief      Release (free) a scepContext and its resources.

@details    This function releases (frees) the specified scepContext and its
            resources.

@ingroup    func_scep_context_mgmt

@since 2.02
@version 3.06 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_context.h

@param ppReleaseContext Pointer to SCEP context to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_context.c
*/
extern MSTATUS SCEP_CONTEXT_releaseContext(scepContext **ppReleaseContext)
{
    MSTATUS status = OK;

    if ((NULL == ppReleaseContext) || (NULL == (*ppReleaseContext)))
        goto exit;

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__
    if ((*ppReleaseContext)->pPkcsCtx)
    {
        status = CRYPTO_uninitAsymmetricKey(&((*ppReleaseContext)->pPkcsCtx->key), NULL);
        status = CRYPTO_uninitAsymmetricKey(&((*ppReleaseContext)->pPkcsCtx->signKey), NULL);

        if (SCEP_scepSettings()->funcPtrCertificateStoreRelease &&
            (*ppReleaseContext)->pPkcsCtx->CACertDescriptor.pCertificate != (*ppReleaseContext)->pPkcsCtx->RACertDescriptor.pCertificate)
        {
            SCEP_scepSettings()->funcPtrCertificateStoreRelease(0, &(*ppReleaseContext)->pPkcsCtx->CACertDescriptor);
        }
        if (SCEP_scepSettings()->funcPtrCertificateStoreRelease)
        {
            SCEP_scepSettings()->funcPtrCertificateStoreRelease(0, &(*ppReleaseContext)->pPkcsCtx->RACertDescriptor);
        }
        if ((*ppReleaseContext)->pPkcsCtx->pRACertificate)
        {
            if ((*ppReleaseContext)->pPkcsCtx->pCACertificate != (*ppReleaseContext)->pPkcsCtx->pRACertificate)
            {
                TREE_DeleteTreeItem((TreeItem*)(*ppReleaseContext)->pPkcsCtx->pCACertificate);
            }
            TREE_DeleteTreeItem((TreeItem*)(*ppReleaseContext)->pPkcsCtx->pRACertificate);
        }
        if ((*ppReleaseContext)->pPkcsCtx->requesterCertDescriptor.pCertificate)
        {
            if (0 == (*ppReleaseContext)->pPkcsCtx->requesterCertDescriptor.cookie)
            {
                FREE((*ppReleaseContext)->pPkcsCtx->requesterCertDescriptor.pCertificate);
            } else
            {
                if (SCEP_scepSettings()->funcPtrCertificateStoreRelease)
                {
                    SCEP_scepSettings()->funcPtrCertificateStoreRelease(0, &(*ppReleaseContext)->pPkcsCtx->requesterCertDescriptor);
                }
            }
        }
        if ((*ppReleaseContext)->pPkcsCtx->pRequesterCert)
        {
            TREE_DeleteTreeItem((TreeItem*)(*ppReleaseContext)->pPkcsCtx->pRequesterCert);
        }
        FREE((*ppReleaseContext)->pPkcsCtx);
    }
#endif

    if ((*ppReleaseContext)->pReqInfo)
    {
        SCEP_CONTEXT_releaseRequestInfo((*ppReleaseContext)->pReqInfo);
    }

    if ((*ppReleaseContext)->pTransAttrs)
    {
        if ((*ppReleaseContext)->pTransAttrs->transactionID)
        {
            FREE((*ppReleaseContext)->pTransAttrs->transactionID);
        }
        if ((*ppReleaseContext)->pTransAttrs->senderNonce)
        {
            FREE((*ppReleaseContext)->pTransAttrs->senderNonce);
        }
        if ((*ppReleaseContext)->pTransAttrs->recipientNonce)
        {
            FREE((*ppReleaseContext)->pTransAttrs->recipientNonce);
        }
        FREE((*ppReleaseContext)->pTransAttrs);
    }
    if ((*ppReleaseContext)->pReceivedData)
        FREE((*ppReleaseContext)->pReceivedData);

    FREE(*ppReleaseContext);
    *ppReleaseContext = NULL;

exit:
    return status;

}

/*------------------------------------------------------------------*/

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */
