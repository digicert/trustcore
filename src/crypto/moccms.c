/*
 * moccms.c
 *
 * CMS API
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
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/debug_console.h"

#include "../asn1/mocasn1.h"
#include "../asn1/oiddefs.h"

#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../crypto/pkcs_common.h"
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/dsa2.h"
#include "../crypto/three_des.h"
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#include "../crypto/crypto.h"
#include "../crypto/ansix9_63_kdf.h"
#include "../crypto/aes_keywrap.h"

#include "../harness/harness.h"

#include "../crypto/moccms_priv.h"
#include "../crypto/moccms.h"
#include "../crypto/moccms_util.h"
#include "../crypto/moccms_asn.h"

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
#include "../crypto/cms_resign_util.h"
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

#include "../crypto/moccms_decode.h"
#include "../crypto/moccms_encode.h"

#if defined(__ENABLE_DIGICERT_CMS__)

/* Add more output to debug console when set to '(1)' */
#define VERBOSE_DEBUG (0)

/* OID: 1.2.840.113549.1.7.2 */
static ubyte CMS_OUTER_SIGNED_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
static ubyte4 CMS_OUTER_SIGNED_DATA_LEN = 11;

/* OID: 1.2.840.113549.1.7.3 */
static ubyte CMS_OUTER_ENVELOPE_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 };
static ubyte4 CMS_OUTER_ENVELOPE_DATA_LEN = 11;


/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_DECODER__))

extern MSTATUS
DIGI_CMS_newContext(MOC_HW(hwAccelDescr hwAccelCtx)
                   MOC_CMS_context         *pNewContext,
                   const void              *callbackArg,
                   const MOC_CMS_Callbacks *pCallbacks)
{
    MSTATUS       status = OK;
    MOC_CMS_CTX*  pNewCtx = NULL;
    hwAccelDescr tmp = (hwAccelDescr)0;

    /* ContentInfo sequence [rfc5652 - Section 3, page 6] */
    MAsn1TypeAndCount defEnv[3] =
    {
     {  MASN1_TYPE_SEQUENCE, 2},
       /* contentType:           ContentType */
       {  MASN1_TYPE_OID, 0},
       /* content [0] EXPLICIT:  ANY DEFINED BY contentType */
       {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT, 0},
    };


    if ((NULL == pNewContext) ||
        (NULL == pCallbacks))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC ((void **)&pNewCtx, 1, sizeof (MOC_CMS_CTX));
    if (OK != status)
        goto exit;

    /* Create the outer envelope 'reader' */
    status = MAsn1CreateElementArray (defEnv, 3,
                                      MASN1_FNCT_DECODE, &MAsn1OfIndefFunction,
                                      &(pNewCtx->pRootEnv));
    if (OK != status)
        goto exit;

    /* Point to the sections within the ASN.1 template */
    pNewCtx->idxEnvOID = 1;
    pNewCtx->idxEnvContent = 2;

    status = DIGI_CMS_A_createCollectData (&(pNewCtx->pOidData),
                                          pNewCtx->pRootEnv,
                                          pNewCtx->pRootEnv + pNewCtx->idxEnvOID);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC ((void**)&pNewCtx->cb, sizeof (MOC_CMS_Callbacks));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY ((void*)pNewCtx->cb, pCallbacks, sizeof (MOC_CMS_Callbacks));
    if (OK != status)
        goto exit;

    /* Success */
    pNewCtx->cbArg = callbackArg;
    pNewCtx->mag = 'I';
    {
        pNewCtx->hwAccelCtx = MOC_HW(hwAccelCtx) tmp;
    }
    *pNewContext = pNewCtx;

    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_CMS_deleteContext ((void**) &pNewCtx);
    }
    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_DECODER__ */


/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_ENCODER__))

extern MSTATUS
DIGI_CMS_newContextOut (MOC_HW(hwAccelDescr hwAccelCtx)
                       MOC_CMS_context     *pNewContext,
                       MOC_CMS_ContentType type,
                       RNGFun              rngFun,
                       void                *rngFunArg,
                       intBoolean          isStreaming,
                       const void          *callbackArg,
                       MOC_CMS_UpdateData  dataUpdateFun)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pNewCtx = NULL;
    hwAccelDescr tmp = (hwAccelDescr)0;

    if ((NULL == pNewContext) ||
        (NULL == dataUpdateFun))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = DIGI_CALLOC ((void **)&pNewCtx, 1, sizeof (MOC_CMS_OUT_CTX));
    if (OK != status)
        goto exit;

    /* Save stream attributes */
    pNewCtx->contentType = type;
    pNewCtx->streamType = (isStreaming)?
                            E_MOC_CMS_st_streaming:E_MOC_CMS_st_definite;

    /* Set type specific data */
    switch(type)
    {
    case E_MOC_CMS_ct_signedData:
        status = DIGI_CMS_createSignContextOut (pNewCtx);
        break;

    case E_MOC_CMS_ct_envelopedData:
        status = DIGI_CMS_createEnvelopContextOut (pNewCtx);
        break;

    default:
        status = ERR_INVALID_INPUT;
    }
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_createAsn1MemoryCache (&(pNewCtx->pAsn1Mem));
    if (OK != status)
        goto exit;

    /* Success */
    pNewCtx->cb = dataUpdateFun;
    pNewCtx->cbArg = callbackArg;
    pNewCtx->mag = 'O';
    pNewCtx->rngFun = rngFun;
    pNewCtx->rngArg = rngFunArg;
    {
        pNewCtx->hwAccelCtx = MOC_HW(hwAccelCtx) tmp;
    }
    *pNewContext = pNewCtx;

    pNewCtx = NULL;

exit:
    if (NULL != pNewCtx)
    {
        DIGI_CMS_deleteContext ((void**)&pNewCtx);
    }
    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_ENCODER__ */

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_deleteContext (MOC_CMS_context *pContext)
{
    MSTATUS         status = OK;
    MOC_CMS_CTX     *pICtx = NULL;
    MOC_CMS_OUT_CTX *pOCtx = NULL;

    /* Already deleted? */
    if (NULL == pContext || NULL == *pContext)
    {
        goto exit;
    }

    /* Check magic */
    pICtx = (MOC_CMS_CTX*) *pContext;

    switch (pICtx->mag)
    {
#if (!defined(__DISABLE_DIGICERT_CMS_DECODER__))
    case 'I':
        DIGI_CMS_deleteContextIn (pICtx);
        break;
#endif
#if (!defined(__DISABLE_DIGICERT_CMS_ENCODER__))
    case 'O':
        pOCtx = (MOC_CMS_OUT_CTX*) *pContext;
        DIGI_CMS_deleteContextOut (pOCtx);
        break;
#endif
    }

    /* Done */
    *pContext = NULL;

exit:
    return status;
}


/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_DECODER__))

extern MSTATUS
DIGI_CMS_updateContext(MOC_CMS_context context,
                      const ubyte           *input,
                      ubyte4          inputLen,
                      intBoolean      *pFinished)
{
    MSTATUS       status = OK;
    MOC_CMS_CTX*  pCtx = NULL;

    ubyte4 bytesRead;
    MOC_CMS_DataInfo info1 = { NULL, NULL, NULL, 0, 0, 1, 0 };

    if (NULL == context)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Update root level ASN.1 parser */
    status = MAsn1DecodeIndefiniteUpdate (input, inputLen,
                                          pCtx->pRootEnv,
                                          &DIGI_CMS_A_decodeSeqDataReturn,
                                          &info1,
                                          &bytesRead,
                                          pFinished);
    if (OK != status)
    {
        if (E_MOC_CMS_ct_undetermined == pCtx->contentType)
        {
            pCtx->contentType = E_MOC_CMS_ct_invalid;

            /* Probably NOT a CMS payload */
            status = ERR_PAYLOAD;
        }
        goto exit;
    }

    /* Detect if outer-most sequence uses 'indefinite' length. This
     * indicates the 'streaming' variant of the CMS ASN1 encoding.
     */
    if (E_MOC_CMS_st_undetermined == pCtx->streamType)
    {
        if (MASN1_STATE_DECODE_PARTIAL <= pCtx->pRootEnv[0].state)
        {
            /* Check INDEF flag bit */
            if (0 != (MASN1_STATE_DECODE_INDEF & pCtx->pRootEnv[0].state))
            {
                pCtx->streamType = E_MOC_CMS_st_streaming;
            }
            else
            {
                pCtx->streamType = E_MOC_CMS_st_definite;
            }
        }
    }

    if (FALSE == pCtx->pOidData->keepDone)
    {
        /* Collect encoded OID */
        status = DIGI_CMS_A_collectOid (pCtx->pOidData);
        if (OK != status)
            goto exit;
    }

    /* Time to check the OID? */
    if ((E_MOC_CMS_ct_undetermined == pCtx->contentType) &&
        (TRUE == pCtx->pOidData->keepDone))
    {
        sbyte4 cmpResult = 1;
        /* Try OID match with 'signed' CMS */
        status = ASN1_compareOID (CMS_OUTER_SIGNED_DATA,
                                  CMS_OUTER_SIGNED_DATA_LEN,
                                  pCtx->pOidData->pKeepData,
                                  pCtx->pOidData->keepDataLen,
                                  NULL, &cmpResult);
        if (OK != status)
            goto exit;
        if (0 == cmpResult)
        {
            pCtx->contentType = E_MOC_CMS_ct_signedData;
        }
        else
        {
            /* Try OID match with 'envelop' CMS */
            status = ASN1_compareOID (CMS_OUTER_ENVELOPE_DATA,
                                      CMS_OUTER_ENVELOPE_DATA_LEN,
                                      pCtx->pOidData->pKeepData,
                                      pCtx->pOidData->keepDataLen,
                                      NULL, &cmpResult);
            if (OK != status)
                goto exit;
            if (0 == cmpResult)
            {
                pCtx->contentType = E_MOC_CMS_ct_envelopedData;
            }
            else
            {
                /* Not a supported OID */
                pCtx->contentType = E_MOC_CMS_ct_invalid;
            }
        }
    }

    switch (pCtx->contentType)
    {
    case E_MOC_CMS_ct_undetermined:
        /* Wait for more input */
        break;

    case E_MOC_CMS_ct_signedData:
        /* Parse signed data */
        status = DIGI_CMS_parseSigned (pCtx,
                                      input, inputLen,
                                      &info1, *pFinished);
        break;

    case E_MOC_CMS_ct_envelopedData:
        /* Parse enveloped data */
        status = DIGI_CMS_parseEnveloped (pCtx,
                                         input, inputLen,
                                         &info1, *pFinished);
        break;

    case E_MOC_CMS_ct_invalid:
        status = ERR_PAYLOAD;
        break;

    default:
        status = ERR_NOT_IMPLEMENTED;
        break;
    }

exit:
    DIGI_CMS_A_freeDataInfo(&info1);
    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_DECODER__ */


/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_ENCODER__))

extern MSTATUS
DIGI_CMS_updateContextOut (MOC_CMS_context context,
                          const ubyte     *output,
                          ubyte4          outputLen,
                          intBoolean      last)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;

    if (NULL == context)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    switch (pCtx->contentType)
    {
    case E_MOC_CMS_ct_signedData:
        /* Write signed data */
        status = DIGI_CMS_writeSigned (pCtx,
                                      output, outputLen,
                                      last);
        break;

    case E_MOC_CMS_ct_envelopedData:
        /* Write envelop data */
        status = DIGI_CMS_writeEnvelop (pCtx,
                                       output, outputLen,
                                       last);
        break;

    case E_MOC_CMS_ct_invalid:
        status = ERR_PAYLOAD;
        break;

    default:
        status = ERR_NOT_IMPLEMENTED;
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_finalizeContextOut (MOC_CMS_context context)
{
    MSTATUS     status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;

    if (NULL == context)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    switch (pCtx->contentType)
    {
    case E_MOC_CMS_ct_signedData:
        /* Write signed data */
        status = DIGI_CMS_finalizeSigned (pCtx);
        break;

    case E_MOC_CMS_ct_envelopedData:
        /* Write envelop data */
        status = DIGI_CMS_finalizeEnvelop (pCtx);
        break;

    case E_MOC_CMS_ct_invalid:
        status = ERR_PAYLOAD;
        break;

    default:
        status = ERR_NOT_IMPLEMENTED;
        break;
    }

exit:

    if (NULL != pCtx)
    {
        DIGI_CMS_U_cleanAsn1MemoryCache (pCtx->pAsn1Mem);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_ENCODER__ */

/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_DECODER__))

extern MSTATUS
DIGI_CMS_getContentType(MOC_CMS_context     context,
                       MOC_CMS_ContentType *cmsContentType)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == cmsContentType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *cmsContentType = pCtx->contentType;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getCallbacks (MOC_CMS_context   context,
                      MOC_CMS_Callbacks *pCB)
{
    MSTATUS     status;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == pCB))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = DIGI_MEMCPY (pCB, pCtx->cb, sizeof (MOC_CMS_Callbacks));

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getNumRecipients (MOC_CMS_context context,
                          sbyte4          *pNumRecipients)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == pNumRecipients))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumRecipients = -1;
    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumRecipients = pCtx->pUn->env.numRecipients;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getRecipientId (MOC_CMS_context     context,
                        sbyte4              idxRecipient,
                        MOC_CMS_RecipientId *pRecipient)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == pRecipient))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Ensure idxRecipient value is in valid range */
    if ((0 > idxRecipient) || (idxRecipient >= pCtx->pUn->env.numRecipients))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Copy type fields */
    status = DIGI_MEMCPY (pRecipient,
                         pCtx->pUn->env.pRecipients[idxRecipient],
                         sizeof(MOC_CMS_RecipientId));
    if (OK != status)
        goto exit;

    /* Copy deeper, which depends on the ID type */
    switch (pCtx->pUn->env.pRecipients[idxRecipient]->type)
    {
    case NO_TAG:
        status = DIGI_CMS_cloneKTRid (&(pRecipient->ri.ktrid),
                                     &(pCtx->pUn->env.pRecipients[idxRecipient]->ri.ktrid));
        break;

    case 1:
        status = DIGI_CMS_cloneKARid (&(pRecipient->ri.karid),
                                     &(pCtx->pUn->env.pRecipients[idxRecipient]->ri.karid));
        break;

    default:
        status = ERR_INVALID_INPUT;
        goto exit;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_deleteRecipientId(MOC_CMS_RecipientId *pRecipient)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (NULL == pRecipient)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Free memory, which depends on the ID type */
    switch (pRecipient->type)
    {
    case NO_TAG:
        status = DIGI_CMS_freeKTRid (&(pRecipient->ri.ktrid));
        break;

    case 1:
        status = DIGI_CMS_freeKARid (&(pRecipient->ri.karid));
        break;

    default:
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getNumSigners(MOC_CMS_context context,
                      sbyte4          *pNumSigners)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == pNumSigners))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumSigners = -1;
    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumSigners = pCtx->pUn->sign.numValidSigs;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getSignerInfo (MOC_CMS_context     context,
                       sbyte4              idxSigner,
                       MOC_CMS_MsgSignInfo *pSigner)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == pSigner))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Ensure idxSigner value is in valid range */
    if ((0 > idxSigner) || (idxSigner >= (sbyte4)pCtx->pUn->sign.numSigners))
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    status = DIGI_MEMCPY (pSigner,
                         &(pCtx->pUn->sign.pSigners[idxSigner]),
                         sizeof (MOC_CMS_MsgSignInfo));
    if (OK != status)
        goto exit;

    /* This makes a deep copy */
    status = DIGI_CMS_cloneSigner(pSigner,
                                 &(pCtx->pUn->sign.pSigners[idxSigner]));

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getNumSignatures (MOC_CMS_context context,
                          sbyte4          *pNumSigs)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx;

    if ((NULL == context) ||
        (NULL == pNumSigs))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pNumSigs = -1;
    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumSigs = pCtx->pUn->sign.numSigners;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_deleteSignerInfo (MOC_CMS_MsgSignInfo *pSigner)
{
    MSTATUS status = OK;

    if (NULL == pSigner)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pSigner->pASN1)
    {
        DIGI_FREE ((void**)&(pSigner->pASN1));
    }
    if (NULL != pSigner->pMsgSigDigest)
    {
        DIGI_FREE ((void**)&(pSigner->pMsgSigDigest));
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getCertificates (MOC_CMS_context context,
                         const ubyte     **ppCerts,
                         ubyte4          *pCertLen)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == ppCerts) ||
        (NULL == pCertLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Assume no data */
    *ppCerts = NULL;
    *pCertLen = 0;

    /* Check if anything is there */
    if (TRUE == pCtx->pUn->sign.pCerts->keepDone)
    {
        *ppCerts = pCtx->pUn->sign.pCerts->pKeepData;
        *pCertLen = pCtx->pUn->sign.pCerts->keepDataLen;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getCRLs (MOC_CMS_context context,
                 const ubyte     **ppCRLs,
                 ubyte4          *pCRLsLen)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == ppCRLs)  ||
        (NULL == pCRLsLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Assume no data */
    *ppCRLs = NULL;
    *pCRLsLen = 0;

    /* Check if anything is there */
    if (TRUE == pCtx->pUn->sign.pCRLs->keepDone)
    {
        *ppCRLs = pCtx->pUn->sign.pCRLs->pKeepData;
        *pCRLsLen = pCtx->pUn->sign.pCRLs->keepDataLen;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getNumDigests (MOC_CMS_context context,
                       ubyte4          *pNumDigests)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == pNumDigests))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (FALSE == pCtx->pUn->sign.hashesDone)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    *pNumDigests = pCtx->pUn->sign.numAlgos;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_getDigestID (MOC_CMS_context context,
                     ubyte4          idx,
                     const ubyte     **pDigestAlgoOID)
{
    MSTATUS     status = OK;
    MOC_CMS_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == pDigestAlgoOID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx = (MOC_CMS_CTX*)context;
    if ('I' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (FALSE == pCtx->pUn->sign.hashesDone)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (idx >= pCtx->pUn->sign.numAlgos)
    {
        status = ERR_INDEX_OOB;
        goto exit;
    }

    *pDigestAlgoOID = pCtx->pUn->sign.pHashes[idx].algoOID;

exit:
    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_DECODER__ */


/*----------------------------------------------------------------------*/
#if (!defined(__DISABLE_DIGICERT_CMS_ENCODER__))

extern MSTATUS
DIGI_CMS_setPayloadLength (MOC_CMS_context context,
                          ubyte4          len)
{
    MSTATUS           status = OK;
    MOC_CMS_OUT_CTX   *pCtx = NULL;

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Only valid when in 'definite' stream mode */
    if (E_MOC_CMS_st_definite != pCtx->streamType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pCtx->payloadLen = len;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addSigner (MOC_CMS_context     context,
                   ubyte               *pCert,
                   ubyte4              certLen,
                   const AsymmetricKey *pKey,
                   const ubyte         *pDigestAlgoOID,
                   ubyte4              digestAlgoOIDLen,
                   MOC_CMS_action      action,
                   MOC_CMS_signerID    *pSignID)
{
    MSTATUS           status = OK;
    MOC_CMS_OUT_CTX   *pCtx = NULL;
    MOC_CMS_SignerCtx *pSigner = NULL;
    MOC_CMS_SignerCtx **ppAllSigners = NULL;
    MAsn1Element      *pOID= NULL;

    MAsn1TypeAndCount defOID[1] = {
      {  MASN1_TYPE_OID, 0}
    };

    if ((NULL == context) ||
        (NULL == pCert) ||
        (NULL == pKey) ||
        (NULL == pDigestAlgoOID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->sign.hashesDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make OID encoder */
    status = MAsn1CreateElementArray (defOID, 1,
                                      MASN1_FNCT_ENCODE, NULL, &pOID);
    if (OK != status)
        goto exit;

    /* Make memory */
    status = DIGI_CALLOC((void**)&pSigner, 1, sizeof(MOC_CMS_SignerCtx));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllSigners, sizeof(MOC_CMS_SignerCtx*) * (pCtx->pUn->sign.numSigners + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->sign.numSigners)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllSigners, (ubyte*)pCtx->pUn->sign.pSigners,
                            sizeof(MOC_CMS_SignerCtx*) * pCtx->pUn->sign.numSigners);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->sign.pSigners));
    }

    /* Encode OID data */
    status = MAsn1SetValue (pOID, pDigestAlgoOID, digestAlgoOIDLen);
    if (OK != status)
        goto exit;

    status = MAsn1EncodeAlloc (pOID, &(pSigner->digestAlgoOID), &(pSigner->digestAlgoOIDLen));
    if (OK != status)
        goto exit;

    /* Set new data */
    status = DIGI_MALLOC_MEMCPY ((void**)&(pSigner->cert), certLen, pCert, certLen);
    if (OK != status)
        goto exit;
    pSigner->certLen = certLen;

    pSigner->pKey = pKey;
    pSigner->flags = action;
    pSigner->hwAccelCtx = pCtx->hwAccelCtx;

    /* Save index as ID value if requested */
    if (NULL != pSignID)
    {
        *pSignID = pCtx->pUn->sign.numSigners;
    }

    /* Add to array */
    ppAllSigners[pCtx->pUn->sign.numSigners] = pSigner;
    pCtx->pUn->sign.pSigners = ppAllSigners;
    ++pCtx->pUn->sign.numSigners;

    /* Success */
    pSigner = NULL;
    ppAllSigners = NULL;

exit:
    /* Error cleanup */
    if (NULL != pSigner)
    {
        DIGI_FREE ((void**)&pCert);
        DIGI_FREE ((void**)&pSigner);
        DIGI_FREE ((void**)&ppAllSigners);
    }

    MAsn1FreeElementArray (&pOID);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addSignerAttribute (MOC_CMS_context  context,
                            MOC_CMS_signerID signId,
                            const ubyte      *idOID,
                            ubyte4           oidLen,
                            ubyte4           typeID,
                            const ubyte      *value,
                            ubyte4           valueLen,
                            intBoolean       authenticated)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == idOID) ||
        (NULL == value))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->sign.hashesDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    if (MOC_CMS_signerID_ALL == signId)
    {
        sbyte4 idx;

        /* Add to all signers */
        for (idx = 0; idx < pCtx->pUn->sign.numSigners; ++idx)
        {
            MOC_CMS_SignerCtx *pSign = pCtx->pUn->sign.pSigners[idx];

            status = DIGI_CMS_addAttribute (pSign,
                                           authenticated,
                                           idOID, oidLen,
                                           typeID,
                                           value, valueLen);
        }
    }
    else
    {
        /* Valid index? */
        if (signId >= pCtx->pUn->sign.numSigners)
        {
            status = ERR_INDEX_OOB;
            goto exit;
        }

        /* Add to this signer */
        MOC_CMS_SignerCtx *pSign = pCtx->pUn->sign.pSigners[signId];

        status = DIGI_CMS_addAttribute (pSign,
                                       authenticated,
                                       idOID, oidLen,
                                       typeID,
                                       value, valueLen);
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addCertificate (MOC_CMS_context context,
                        ubyte           *pCert,
                        ubyte4          certLen)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;
    MOC_CMS_Array   *pData = NULL;
    MOC_CMS_Array   **ppAllData = NULL;

    if ((NULL == context) ||
        (NULL == pCert))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->lastDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make memory */
    status = DIGI_MALLOC((void**)&pData, sizeof(MOC_CMS_Array));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllData, sizeof(MOC_CMS_Array*) * (pCtx->pUn->sign.numAddedCerts + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->sign.numAddedCerts)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllData, (ubyte*)pCtx->pUn->sign.pAddedCerts,
                            sizeof(MOC_CMS_Array*) * pCtx->pUn->sign.numAddedCerts);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->sign.pAddedCerts));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pData->pData), certLen, pCert, certLen);
    if (OK != status)
        goto exit;
    pData->dataLen = certLen;

    /* Add to array */
    ppAllData[pCtx->pUn->sign.numAddedCerts] = pData;
    pCtx->pUn->sign.pAddedCerts = ppAllData;
    ++pCtx->pUn->sign.numAddedCerts;

    /* Success */
    pData = NULL;
    ppAllData = NULL;

exit:
    /* Error cleanup */
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
        DIGI_FREE ((void**)&ppAllData);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addCRL (MOC_CMS_context context,
                ubyte           *pCRL,
                ubyte4          CRLLen)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;
    MOC_CMS_Array   *pCRLData = NULL;
    MOC_CMS_Array   **ppAllData = NULL;

    if ((NULL == context) ||
        (NULL == pCRL))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->lastDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make memory */
    status = DIGI_MALLOC((void**)&pCRLData, sizeof(MOC_CMS_Array));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllData, sizeof(MOC_CMS_Array*) * (pCtx->pUn->sign.numCRLs + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->sign.numCRLs)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllData, (ubyte*)pCtx->pUn->sign.pCRLs,
                            sizeof(MOC_CMS_Array*) * pCtx->pUn->sign.numCRLs);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->sign.pCRLs));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pCRLData->pData), CRLLen, pCRL, CRLLen);
    if (OK != status)
        goto exit;
    pCRLData->dataLen = CRLLen;

    /* Add to array */
    ppAllData[pCtx->pUn->sign.numCRLs] = pCRLData;
    pCtx->pUn->sign.pCRLs = ppAllData;
    ++pCtx->pUn->sign.numCRLs;

    /* Success */
    pCRLData = NULL;
    ppAllData = NULL;

exit:
    /* Error cleanup */
    if (NULL != pCRLData)
    {
        DIGI_FREE ((void**)&pCRLData);
        DIGI_FREE ((void**)&ppAllData);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addSignatureRaw (MOC_CMS_context context,
                         const ubyte     *pSig,
                         ubyte4          sigLen)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;
    MOC_CMS_Array   *pRawData = NULL;
    MOC_CMS_Array   **ppAllRawData = NULL;

    if ((NULL == context) ||
        (NULL == pSig))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->lastDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make memory */
    status = DIGI_MALLOC((void**)&pRawData, sizeof(MOC_CMS_Array));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllRawData, sizeof(MOC_CMS_Array*) * (pCtx->pUn->sign.numAddedRawSigs + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->sign.numAddedRawSigs)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllRawData, (ubyte*)pCtx->pUn->sign.pAddedRawSigs,
                            sizeof(MOC_CMS_Array*) * pCtx->pUn->sign.numAddedRawSigs);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->sign.pAddedRawSigs));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pRawData->pData), sigLen, (ubyte *)pSig, sigLen);
    if (OK != status)
        goto exit;
    pRawData->dataLen = sigLen;

    /* Add to array */
    ppAllRawData[pCtx->pUn->sign.numAddedRawSigs] = pRawData;
    pCtx->pUn->sign.pAddedRawSigs = ppAllRawData;
    ++pCtx->pUn->sign.numAddedRawSigs;

    /* Success */
    pRawData = NULL;
    ppAllRawData = NULL;

exit:
    /* Error cleanup */
    if (NULL != pRawData)
    {
        DIGI_FREE ((void**)&(pRawData->pData));
        DIGI_FREE ((void**)&pRawData);
        DIGI_FREE ((void**)&ppAllRawData);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addDigest (MOC_CMS_context context,
                   const ubyte     *digestAlgoOID,
                   ubyte4          digestAlgoOIDLen)
{
    MSTATUS         status = OK;

    MOC_CMS_OUT_CTX *pCtx = NULL;
    MOC_CMS_Array   *pDigest = NULL;
    MOC_CMS_Array   **pAllDigs = NULL;
    MAsn1Element      *pOID= NULL;

    MAsn1TypeAndCount defOID[1] = {
      {  MASN1_TYPE_OID, 0}
    };

    if ((NULL == context) ||
        (NULL == digestAlgoOID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->sign.hashesDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make OID encoder */
    status = MAsn1CreateElementArray (defOID, 1,
                                      MASN1_FNCT_ENCODE, NULL, &pOID);
    if (OK != status)
        goto exit;

    /* Make memory */
    status = DIGI_MALLOC((void**)&pDigest, sizeof(MOC_CMS_Array));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&pAllDigs, sizeof(MOC_CMS_Array*) * (pCtx->pUn->sign.numAddedDigests + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->sign.numAddedDigests)
    {
        status = DIGI_MEMCPY((ubyte*)pAllDigs, (ubyte*)pCtx->pUn->sign.pAddedDigests,
                            sizeof(MOC_CMS_Array*) * pCtx->pUn->sign.numAddedDigests);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->sign.pAddedDigests));
    }

    /* Encode OID data */
    status = MAsn1SetValue (pOID, digestAlgoOID, digestAlgoOIDLen);
    if (OK != status)
        goto exit;

    status = MAsn1EncodeAlloc (pOID, &(pDigest->pData), &(pDigest->dataLen));
    if (OK != status)
        goto exit;

    /* Add to array */
    pAllDigs[pCtx->pUn->sign.numAddedDigests] = pDigest;
    pCtx->pUn->sign.pAddedDigests = pAllDigs;
    ++pCtx->pUn->sign.numAddedDigests;

    /* Success */
    pDigest = NULL;
    pAllDigs = NULL;

exit:
    /* Error cleanup */
    if (NULL != pDigest)
    {
        DIGI_FREE ((void**)&(pDigest->pData));
        DIGI_FREE ((void**)&pDigest);
    }
    if (NULL != pAllDigs)
    {
        DIGI_FREE ((void**)&pAllDigs);
    }
    MAsn1FreeElementArray (&pOID);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_setEncryption (MOC_CMS_context context,
                       const ubyte     *encryptAlgoOID,
                       ubyte4          encryptAlgoOIDLen,
                       RNGFun          rngFun,
                       void            *rngFunArg)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;

    if ((NULL == context) ||
        (NULL == encryptAlgoOID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->env.firstDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Store RNG reference */
    pCtx->pUn->env.encrRngFun = rngFun;
    pCtx->pUn->env.encrRngArg = rngFunArg;

    /* Create the bulk encryption algorithm */
    status = DIGI_CMS_createBulkAlgo (MOC_SYM(pCtx->hwAccelCtx)
                                     (ubyte *)encryptAlgoOID,
                                     encryptAlgoOIDLen,
                                     pCtx->pAsn1Mem,
                                     &(pCtx->pUn->env));
    if (OK != status)
        goto exit;

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addRecipient (MOC_CMS_context context,
                      const ubyte     *pCert,
                      ubyte4          certLen)
{
    MSTATUS         status = OK;
    MOC_CMS_OUT_CTX *pCtx = NULL;
    MOC_CMS_Array   *pRecipient = NULL;
    MOC_CMS_Array   **ppAllRecips = NULL;

    if ((NULL == context) ||
        (NULL == pCert))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->env.firstDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make memory */
    status = DIGI_MALLOC((void**)&pRecipient, sizeof(MOC_CMS_Array));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllRecips, sizeof(MOC_CMS_Array*) * (pCtx->pUn->env.numRecipients + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->env.numRecipients)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllRecips, (ubyte*)pCtx->pUn->env.pRecipients,
                            sizeof(MOC_CMS_Array*) * pCtx->pUn->env.numRecipients);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->env.pRecipients));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pRecipient->pData), certLen, (ubyte *)pCert, certLen);
    if (OK != status)
        goto exit;
    pRecipient->dataLen = certLen;

    /* Add to array */
    ppAllRecips[pCtx->pUn->env.numRecipients] = pRecipient;
    pCtx->pUn->env.pRecipients = ppAllRecips;
    ++pCtx->pUn->env.numRecipients;

    /* Success */
    pRecipient = NULL;
    ppAllRecips = NULL;

exit:
    /* Error cleanup */
    if (NULL != pRecipient)
    {
        DIGI_FREE ((void**)&pRecipient);
        DIGI_FREE ((void**)&ppAllRecips);
    }
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addUnprotectedAttribute (MOC_CMS_context context,
                                 const ubyte     *idOID,
                                 ubyte4          oidLen,
                                 ubyte4          typeID,
                                 const ubyte     *value,
                                 ubyte4          valueLen)
{
    MSTATUS           status = OK;
    MOC_CMS_OUT_CTX   *pCtx = NULL;
    MOC_CMS_Attribute *pAttr = NULL;
    MOC_CMS_Attribute **ppAllAttr = NULL;

    if ((NULL == context) ||
        (NULL == idOID) ||
        (NULL == value))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cast to correct context */
    pCtx = (MOC_CMS_OUT_CTX*)context;
    if ('O' != pCtx->mag)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }
    if (TRUE == pCtx->pUn->env.firstDone)
    {
        status = ERR_PKCS7_CONTEXT_COMPLETED;
        goto exit;
    }

    /* Make memory */
    status = DIGI_MALLOC((void**)&pAttr, sizeof(MOC_CMS_Attribute));
    if (OK != status)
        goto exit;

    /* Add to pointer array */
    status = DIGI_MALLOC((void**)&ppAllAttr, sizeof(MOC_CMS_Attribute*) * (pCtx->pUn->env.numAttributes + 1) );
    if (OK != status)
        goto exit;

    if (0 < pCtx->pUn->env.numAttributes)
    {
        status = DIGI_MEMCPY((ubyte*)ppAllAttr, (ubyte*)pCtx->pUn->env.pRecipients,
                            sizeof(MOC_CMS_Attribute*) * pCtx->pUn->env.numAttributes);
        if (OK != status)
            goto exit;

        DIGI_FREE ((void**)&(pCtx->pUn->env.pUnauthAttributes));
    }

    status = DIGI_MALLOC_MEMCPY ((void**)&(pAttr->pOID), oidLen,
                                (ubyte *)idOID, oidLen);
    if (OK != status)
        goto exit;

    pAttr->oidLen = oidLen;

    /* Create the ASN1 encoded data */
    status = DIGI_CMS_makeASN1FromAttribute (typeID, value, valueLen, pAttr);
    if (OK != status)
        goto exit;

    /* Add to array */
    ppAllAttr[pCtx->pUn->env.numAttributes] = pAttr;
    pCtx->pUn->env.pUnauthAttributes = ppAllAttr;
    ++pCtx->pUn->env.numAttributes;

    /* Success */
    pAttr = NULL;
    ppAllAttr = NULL;

exit:
    /* Error cleanup */
    if (NULL != pAttr)
    {
        DIGI_FREE ((void**)&(pAttr->pOID));
        DIGI_FREE ((void**)&pAttr);
        DIGI_FREE ((void**)&ppAllAttr);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_CMS_ENCODER__ */

#endif  /* defined(__ENABLE_DIGICERT_CMS__) */
