/*
 * ocsp_context.c
 *
 * OCSP Context handling methods
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_OCSP_CLIENT__))

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

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
#include "../crypto/ca_mgmt.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/ca_mgmt.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/pkcs_common.h"
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_CONTEXT_createContext(ocspContext **ppNewContext, sbyte4 roleType)
{
    ocspContext*    pTempContext = NULL;
    MSTATUS         status       = OK;

    if ((NULL == ppNewContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppNewContext = NULL;

    /* check for roleType */
    if(OCSP_CLIENT != roleType && OCSP_SERVER != roleType)
    {
        status = ERR_OCSP_INIT_FAIL;
        goto exit;
    }

    if (NULL == (pTempContext = (ocspContext *)MALLOC(sizeof(ocspContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* initialize it */
    if (OK > (status = DIGI_MEMSET((ubyte*)pTempContext, 0x00, sizeof(ocspContext))))
        goto exit;

    /* initialize crypto acceleration context */
    if (OK > (status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_OCSP, &(pTempContext->hwAccelCtx))))
        goto exit;

    pTempContext->roleType      = roleType;
    pTempContext->pOcspSettings = OCSP_ocspSettings();

    /* Initialize it to NULL; to ensure weeding out of garbage value during processing */
    if (OK > (DIGI_MEMSET((ubyte *)pTempContext->pOcspSettings, 0x00, sizeof(ocspSettings))))
        goto exit;

    *ppNewContext = pTempContext;
    pTempContext  = NULL;

exit:
    if (NULL != pTempContext)
        FREE(pTempContext);

    return status;

} /* OCSP_CONTEXT_createContext */

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_CONTEXT_createContextLocal(ocspContext **ppNewContext, sbyte4 roleType)
{
    MSTATUS status;
    ocspSettings *pSettings = NULL;

    status = DIGI_CALLOC((void **) &pSettings, 1, sizeof(ocspSettings));
    if (OK != status)
    {
        goto exit;
    }

    status = OCSP_CONTEXT_createContext(ppNewContext, roleType);
    if (OK != status)
    {
        goto exit;
    }

    (*ppNewContext)->pOcspSettings = pSettings;
    pSettings = NULL;

exit:

    if (NULL != pSettings)
    {
        DIGI_FREE((void **) &pSettings);
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_CONTEXT_releaseContext(ocspContext **ppReleaseContext)
{
    ubyte   i      = 0;
    MSTATUS status = OK;

    if ((NULL == ppReleaseContext) || (NULL == (*ppReleaseContext)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OCSP_CLIENT == (*ppReleaseContext)->roleType)
    {
        /* Handle complexity regarding pResponderCert */
        if ((*ppReleaseContext)->ocspProcess.client.pResponderCert)
        {
            /* 1. pResponderCert == pIssuerRoot           */
            if ((*ppReleaseContext)->ocspProcess.client.pResponderCert == (*ppReleaseContext)->ocspProcess.client.pIssuerRoot)
            {
                TREE_DeleteTreeItem((TreeItem *)(*ppReleaseContext)->ocspProcess.client.pResponderCert);

                /* Make both NULL */
                (*ppReleaseContext)->ocspProcess.client.pResponderCert = NULL;
                (*ppReleaseContext)->ocspProcess.client.pIssuerRoot    = NULL;

            }
            /* 2. pResponderCert is the root */
            else if (NULL == ASN1_PARENT((*ppReleaseContext)->ocspProcess.client.pResponderCert))
            {
                TREE_DeleteTreeItem((TreeItem *)((*ppReleaseContext)->ocspProcess.client.pResponderCert));
            }
            else /* 3. pResponderCert is child of pResponseRoot */
            {
                /* Make it null; would be auto freed when pResponseRoot is deleted */
                (*ppReleaseContext)->ocspProcess.client.pResponderCert = NULL;
            }
        }

        if ((*ppReleaseContext)->ocspProcess.client.pResponseRoot)
            TREE_DeleteTreeItem((TreeItem*)((*ppReleaseContext)->ocspProcess.client.pResponseRoot));

        if ((*ppReleaseContext)->ocspProcess.client.pIssuerRoot)
            TREE_DeleteTreeItem((TreeItem*)((*ppReleaseContext)->ocspProcess.client.pIssuerRoot));

        if ((*ppReleaseContext)->pReceivedData)
            FREE((*ppReleaseContext)->pReceivedData);

        if ((*ppReleaseContext)->ocspProcess.client.pIssuerInfo)
            CA_MGMT_freeCertDistinguishedName(&((*ppReleaseContext)->ocspProcess.client.pIssuerInfo));

        if ((*ppReleaseContext)->ocspProcess.client.nonce)
            FREE((*ppReleaseContext)->ocspProcess.client.nonce);

        if ((*ppReleaseContext)->pOcspSettings)
        {
            for ( i = 0; i < (*ppReleaseContext)->pOcspSettings->certCount; i++)
            {
    #if (!defined(__ENABLE_DIGICERT_SSH_CLIENT__) && !defined(__ENABLE_DIGICERT_SSH_SERVER__) && \
        !defined(__ENABLE_DIGICERT_SSL_SERVER__) && !defined(__ENABLE_DIGICERT_SSL_ASYNC_SERVER_API__)) \
    || (defined(__ENABLE_DIGICERT_IKE_SERVER__) && defined(__ENABLE_IKE_OCSP_EXT__))
                if ((*ppReleaseContext)->pOcspSettings->pCertInfo[i].pCert)
                    DIGICERT_freeReadFile(&(*ppReleaseContext)->pOcspSettings->pCertInfo[i].pCert);

                if ((*ppReleaseContext)->pOcspSettings->pIssuerCertInfo[i].pCertPath)
                    DIGICERT_freeReadFile(&(*ppReleaseContext)->pOcspSettings->pIssuerCertInfo[i].pCertPath);
    #endif
                if ((*ppReleaseContext)->ocspProcess.client.cachedCertId)
                {
                    if ((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])
                    {
                        if (((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->serialNumber)
                            FREE(((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->serialNumber);

                        if (((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->nameHash)
                            FREE(((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->nameHash);

                        if (((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->keyHash)
                            FREE(((*ppReleaseContext)->ocspProcess.client.cachedCertId[i])->keyHash);

                        FREE((*ppReleaseContext)->ocspProcess.client.cachedCertId[i]);
                    }
                }
            }

            if ((*ppReleaseContext)->pOcspSettings->pCertInfo)
            {
                FREE(((*ppReleaseContext)->pOcspSettings->pCertInfo));
                (*ppReleaseContext)->pOcspSettings->pCertInfo = NULL;   
            }

            if ((*ppReleaseContext)->pOcspSettings->pIssuerCertInfo)
            {
                FREE(((*ppReleaseContext)->pOcspSettings->pIssuerCertInfo));
                (*ppReleaseContext)->pOcspSettings->pIssuerCertInfo = NULL;   
            }

            if ((*ppReleaseContext)->pOcspSettings->pSignerCert)
                DIGICERT_freeReadFile(&(*ppReleaseContext)->pOcspSettings->pSignerCert);

            if ((*ppReleaseContext)->pOcspSettings->pPrivKey)
                DIGICERT_freeReadFile(&(*ppReleaseContext)->pOcspSettings->pPrivKey);

            if ((*ppReleaseContext)->pOcspSettings->pTrustedResponders)
            {
                for ( i = 0; i < (*ppReleaseContext)->pOcspSettings->trustedResponderCount; i++)
                {
                    if ((*ppReleaseContext)->pOcspSettings->pTrustedResponders[i].pCertPath)
                        DIGICERT_freeReadFile(&(*ppReleaseContext)->pOcspSettings->pTrustedResponders[i].pCertPath);
                }
                FREE(((*ppReleaseContext)->pOcspSettings->pTrustedResponders));
            }
        }

        if ((*ppReleaseContext)->ocspProcess.client.cachedCertId)
            FREE ((*ppReleaseContext)->ocspProcess.client.cachedCertId);

    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_OCSP, &((*ppReleaseContext)->hwAccelCtx));

    FREE(*ppReleaseContext);
    *ppReleaseContext = NULL;

exit:
    return status;

} /* OCSP_CONTEXT_releaseContext */

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_CONTEXT_releaseContextLocal(ocspContext **ppReleaseContext)
{
    MSTATUS status;
    ocspSettings *pSettings = NULL;

    if ( (NULL == ppReleaseContext) || (NULL == *ppReleaseContext) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pSettings = (*ppReleaseContext)->pOcspSettings;

    status = OCSP_CONTEXT_releaseContext(ppReleaseContext);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_FREE((void **) &pSettings);

exit:

    return status;

} /* OCSP_CONTEXT_releaseContextLocal */

#endif /* #ifdef __ENABLE_DIGICERT_OCSP_CLIENT__ */
