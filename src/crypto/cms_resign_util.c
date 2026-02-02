/*
 * cms_resign_util.c
 *
 * CMS utility functions when resigning CMS data (see 'umresigner')
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

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/hw_accel.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"

#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/cert_chain.h"
#include "../crypto/cert_store.h"
#include "../crypto/cms.h"
#include "../crypto/moccms.h"
#include "../crypto/pkcs7.h"

#include "../crypto/cms_resign_util.h"
#include "../crypto/cms_resign_priv.h"

static ubyte  *pNULLHashType_OIDs[NUM_ALGOS] = {0};

/*---------------------------------------------------------------------------*/


extern MSTATUS
CMS_RESIGN_AcquireContext(CMS_ResignData_CTX *pCtx)
{
    MSTATUS status = OK;
    CMS_ResignData_I_CTX *pICtx = NULL;

    /* Check parameter validity */
    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Allocate context */
    status = DIGI_MALLOC((void**)&pICtx, sizeof(CMS_ResignData_I_CTX));
    if (OK != status)
        goto exit;

    /* Init context */
    status = DIGI_MEMSET((ubyte*)pICtx, 0, sizeof(CMS_ResignData_I_CTX));
    if (OK != status)
        goto exit;

    /* Success */
    *pCtx = (CMS_ResignData_CTX)pICtx;
    pICtx = NULL;

exit:
    /* Error cleanup */
    if (NULL != pICtx)
    {
        DIGI_FREE((void**)&pICtx);
    }
    return status;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_ReleaseContext(CMS_ResignData_CTX *pCtx)
{
    CMS_ResignData_I_CTX *pICtx = NULL;
    ubyte4               idx;

    /* If already cleared, just return */
    if ((NULL == pCtx) ||
        (NULL == *pCtx))
    {
        goto exit;
    }

    /* Free memory inside context */
    pICtx = (CMS_ResignData_I_CTX*)*pCtx;

    DIGI_FREE ((void**)&(pICtx->psignatureBlock));
    pICtx->signatureBlockLen = 0;
    pICtx->signatureBlockAvail = 0;

    DIGI_FREE ((void**)&(pICtx->pextractedData));
    pICtx->extractedDataLen = 0;

    DIGI_FREE ((void**)&(pICtx->pextractedCerts));
    pICtx->extractedCertsLen = 0;

    CERT_STORE_releaseStore (&(pICtx->pTrustStore));

    for (idx = 0; idx < pICtx->numSignRaw; ++idx)
    {
        DIGI_FREE ((void**)&(pICtx->pSignRawArray[idx]->pData));
        DIGI_FREE ((void**)&(pICtx->pSignRawArray[idx]));
    }
    DIGI_FREE ((void**)&(pICtx->pSignRawArray));

    /* Don't need to free the OID array since ptrs to const strings (not allocated) */
    /* Zero out everything */
    DIGI_MEMSET ((ubyte*)pICtx, 0, sizeof(CMS_ResignData_I_CTX));

    /* Free the context */
    DIGI_FREE ((void**)&pICtx);
    *pCtx = NULL;

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern MSTATUS
CMS_RESIGN_setExtractedData(CMS_ResignData_CTX ctx,
                            const ubyte        *pData,
                            ubyte4             dataLen)
{
    MSTATUS status = OK;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == pICtx) || (NULL == pData) || (0 == dataLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (NULL != pICtx->pextractedData)
    {
        DIGI_FREE ((void **)&(pICtx->pextractedData));
        pICtx->extractedDataLen = 0;
    }

    status = DIGI_MALLOC ((void**)&(pICtx->pextractedData), dataLen);
    if (OK != status)
        goto exit;

    pICtx->extractedDataLen = dataLen;
    DIGI_MEMCPY (pICtx->pextractedData, pData, dataLen);

exit:
    return status;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_getExtractedData(CMS_ResignData_CTX ctx,
                            ubyte              **ppData,
                            ubyte4             *pDataLen)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == ppData) || (NULL == pDataLen))
    {
        goto exit;
    }

    if (pICtx == NULL)
    {
        *pDataLen = 0;
        *ppData = NULL;
        goto exit;
    }

    *pDataLen = pICtx->extractedDataLen;
    *ppData = pICtx->pextractedData;

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern MSTATUS
CMS_RESIGN_setExtractedCertificates(CMS_ResignData_CTX ctx,
                                    const ubyte        *pData,
                                    ubyte4             dataLen)
{
    MSTATUS status = OK;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == pICtx) || (NULL == pData) || (0 == dataLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (NULL != pICtx->pextractedCerts)
    {
        DIGI_FREE ((void **)&(pICtx->pextractedCerts));
        pICtx->extractedCertsLen = 0;
    }

    status = DIGI_MALLOC ((void**)&(pICtx->pextractedCerts), dataLen);
    if (OK != status)
        goto exit;

    pICtx->extractedCertsLen = dataLen;
    DIGI_MEMCPY (pICtx->pextractedCerts, pData, dataLen);

exit:
    return status;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_getExtractedCertificates(CMS_ResignData_CTX ctx,
                                    ubyte              **ppData,
                                    ubyte4             *pDataLen)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == ppData) || (NULL == pDataLen))
    {
        goto exit;
    }

    if (NULL == pICtx)
    {
        *pDataLen = 0;
        *ppData = NULL;
        goto exit;
    }

    *pDataLen = pICtx->extractedCertsLen;
    *ppData = pICtx->pextractedCerts;

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern MSTATUS
CMS_RESIGN_setExtractedSignature(CMS_ResignData_CTX ctx,
                                 const ubyte        *pData,
                                 ubyte4             dataLen)
{
    MSTATUS status = OK;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == pICtx) || (NULL == pData) || (0 == dataLen))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (NULL != pICtx->psignatureBlock)
    {
        DIGI_FREE ((void **)&(pICtx->psignatureBlock));
        pICtx->signatureBlockLen = 0;
    }

    status = DIGI_MALLOC ((void**)&(pICtx->psignatureBlock), dataLen);
    if (OK != status)
        goto exit;

    pICtx->signatureBlockLen = dataLen;
    DIGI_MEMCPY (pICtx->psignatureBlock, pData, dataLen);
    /* Mark it as available */
    pICtx->signatureBlockAvail = 1;


exit:
    return status;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_getExtractedSignature(CMS_ResignData_CTX ctx,
                                 ubyte              **ppData,
                                 ubyte4             *pDataLen)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == ppData) || (NULL == pDataLen))
    {
        goto exit;
    }

    if (NULL == pICtx)
    {
        *pDataLen = 0;
        *ppData = NULL;
        goto exit;
    }

    if (0 == pICtx->signatureBlockAvail)
    {
        /* Already retrieved and not available (cleared). Return nothing. */
        *pDataLen = 0;
        *ppData = NULL;
        goto exit;
    }

    *pDataLen = pICtx->signatureBlockLen;
    *ppData = pICtx->psignatureBlock;

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_clearExtractedSignature(CMS_ResignData_CTX ctx)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if (NULL != pICtx)
    {
        /* Mark it to not be returned again */
        pICtx->signatureBlockAvail = 0;
    }
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_addRawSignature(CMS_ResignData_CTX ctx,
                           const ubyte        *pData,
                           ubyte4             dataLen)
{
    MSTATUS status;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;
    CMS_RESIGN_Array *pRaw = NULL;
    CMS_RESIGN_Array **ppAllRaw = NULL;

    if ((NULL == pICtx) || (NULL == pData) || (0 == dataLen))
    {
        goto exit;
    }

    /* Allocate memory */
    status = DIGI_MALLOC ((void**)&pRaw, sizeof(CMS_RESIGN_Array));
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&ppAllRaw, sizeof(CMS_RESIGN_Array*) * (pICtx->numSignRaw + 1));
    if (OK != status)
        goto exit;

    if (0 < pICtx->numSignRaw)
    {
        /* Copy older content */
        status = DIGI_MEMCPY ((ubyte*)ppAllRaw, pICtx->pSignRawArray,
                             sizeof(CMS_RESIGN_Array*) * pICtx->numSignRaw);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pICtx->pSignRawArray));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pRaw->pData), dataLen, (void*)pData, dataLen);
    if (OK != status)
        goto exit;
    pRaw->dataLen = dataLen;

    ppAllRaw[pICtx->numSignRaw] = pRaw;
    pICtx->pSignRawArray = ppAllRaw;
    pICtx->numSignRaw++;

    /* Success */
    pRaw = NULL;
    ppAllRaw = NULL;

exit:
    /* Error clean up */
    if (NULL != pRaw)
    {
        DIGI_FREE ((void**)&pRaw);
        DIGI_FREE ((void**)&ppAllRaw);
    }
    return;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_getRawSignatures(CMS_ResignData_CTX ctx,
                            void               *pCMSCtx)
{
    MSTATUS status;
    sbyte4  idx;
    MOC_CMS_context pCMS = (MOC_CMS_context)pCMSCtx;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if (NULL == pICtx)
    {
        goto exit;
    }

    for (idx = 0; idx < (sbyte4)pICtx->numSignRaw; ++idx)
    {
        status = DIGI_CMS_addSignatureRaw (pCMS,
                                          pICtx->pSignRawArray[idx]->pData,
                                          pICtx->pSignRawArray[idx]->dataLen);
        if (OK != status)
            goto exit;
    }

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern MSTATUS
CMS_RESIGN_setExtractedSignatureHashType(CMS_ResignData_CTX ctx,
                                         ubyte4             hashType)
{
    MSTATUS status = OK;
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if (NULL == pICtx)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    switch (hashType)
    {
        case 4:  /* md5 */
            if (0 == pICtx->psignatureHashType_OID[0])
                pICtx->psignatureHashType_OID[0] = (ubyte *)md5_OID;
            break;
        case 5:  /* sha1 */
            if (0 == pICtx->psignatureHashType_OID[1])
                pICtx->psignatureHashType_OID[1] = (ubyte *)sha1_OID;
            break;
        case 11: /* sha256 */
            if (0 == pICtx->psignatureHashType_OID[2])
                pICtx->psignatureHashType_OID[2] = (ubyte *)sha256_OID;
            break;
        case 12: /* sha384 */
            if (0 == pICtx->psignatureHashType_OID[3])
                pICtx->psignatureHashType_OID[3] = (ubyte *)sha384_OID;
            break;
        case 13: /* sha512 */
            if (0 == pICtx->psignatureHashType_OID[4])
                pICtx->psignatureHashType_OID[4] = (ubyte *)sha512_OID;
            break;
        case 14: /* sha224 */
            if (0 == pICtx->psignatureHashType_OID[5])
                pICtx->psignatureHashType_OID[5] = (ubyte *)sha224_OID;
            break;
        default:
            status = ERR_UMP_INVALID_SIGNATURE;
    }

exit:
    return status;

}

/*---------------------------------------------------------------------------*/


extern int
CMS_RESIGN_getNumSigningAlgos(void)
{
    return NUM_ALGOS;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_getExtractedSignature_OIDs(CMS_ResignData_CTX ctx,
                                      ubyte              ***ppOids)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == ppOids))
    {
        goto exit;
    }

    if (NULL == pICtx)
    {
        *ppOids = pNULLHashType_OIDs; /* Safety for the caller who assumes this is good data*/
        goto exit;
    }

    *ppOids = (ubyte **)pICtx->psignatureHashType_OID;

exit:
    return;
}

/*---------------------------------------------------------------------------*/


extern void
CMS_RESIGN_clearExtractedSignature_OID(CMS_ResignData_CTX ctx,
                                       ubyte4             index)
{
    CMS_ResignData_I_CTX *pICtx = (CMS_ResignData_I_CTX *)ctx;

    if ((NULL == pICtx) || (NUM_ALGOS <= index))
    {
        goto exit;
    }
    pICtx->psignatureHashType_OID[index] = 0;

exit:
    return;
}
