/*
 * moccms_decode.c
 *
 * Mocana CMS API Implementation for Decoding
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

#if (defined(__ENABLE_DIGICERT_CMS__) && !defined(__DISABLE_DIGICERT_CMS_DECODER__))

/* Add more output to debug console when set to '(1)' */
#define VERBOSE_DEBUG (0)

/************************************************************************/

/* OID: 1.2.840.113549.1.7.1 */
static ubyte CMS_OUTER_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static ubyte4 CMS_OUTER_DATA_LEN = 11;

/************************************************************************/

/* Memory Management Helper Functions */

/** Function to 'clone' a 'MOC_CMS_IssuerSerialNumber' instance, making a 'deep copy'.
 *
 *  @param pOut The pointer to the output instance.
 *  @param pIn  The pointer to the input instance.
 */
static MSTATUS
DIGI_CMS_cloneIssuer(MOC_CMS_IssuerSerialNumber *pOut,
                    const MOC_CMS_IssuerSerialNumber *pIn);

/** Function to 'clone' a 'MOC_CMS_SubjectKeyIdentifier' instance, making a 'deep copy'.
 *
 *  @param pOut The pointer to the output instance.
 *  @param pIn  The pointer to the input instance.
 */
static MSTATUS
DIGI_CMS_cloneSubjectKey(MOC_CMS_SubjectKeyIdentifier *pOut,
                        const MOC_CMS_SubjectKeyIdentifier *pIn);

/** Function to 'clone' a 'MOC_CMS_OriginatorPublicKey' instance, making a 'deep copy'.
 *
 *  @param pOut The pointer to the output instance.
 *  @param pIn  The pointer to the input instance.
 */
static MSTATUS
DIGI_CMS_cloneOriginatorKey(MOC_CMS_OriginatorPublicKey *pOut,
                           const MOC_CMS_OriginatorPublicKey *pIn);

/** Function to 'free' a 'MOC_CMS_IssuerSerialNumber' instance, releasing all held memory.
 *
 *  @param pData The pointer to the instance to be freed.
 */
static MSTATUS
DIGI_CMS_freeIssuer(MOC_CMS_IssuerSerialNumber *pData);

/** Function to 'free' a 'MOC_CMS_SubjectKeyIdentifier' instance, releasing all held memory.
 *
 *  @param pData The pointer to the instance to be freed.
 */
static MSTATUS
DIGI_CMS_freeSubjectKey(MOC_CMS_SubjectKeyIdentifier *pData);

/** Function to 'free' a 'MOC_CMS_OriginatorPublicKey' instance, releasing all held memory.
 *
 *  @param pData The pointer to the instance to be freed.
 */
static MSTATUS
DIGI_CMS_freeOriginatorKey(MOC_CMS_OriginatorPublicKey *pData);

/* CMS Context Helper Functions */

/** Function to create a specific context for 'signed' CMS data.
 *  <p>The new context is stored in the given 'MOC_CMS_CTX' instance.
 *  <p>The 'pUn' pointer in that context must be accessed as a 'MOC_CMS_SignedCtx*' after
 *     this function is finished.
 *
 *  @param pCtx  The pointer to a 'MOC_CMS_CTX' instance.
 */
static MSTATUS
DIGI_CMS_createSignContext(MOC_CMS_CTX *pCtx);

/** Function to delete a 'MOC_CMS_SignedCtx' instance.
 *  <p>All memory held by this instance will be 'freed'.
 *
 *  @param pCtx A pointer to a 'MOC_CMS_SignedCtx' instance, which will be freed and
 *              the pointer will be set to NULL.
 */
static MSTATUS
DIGI_CMS_deleteSignContext(MOC_CMS_SignedCtx *pCtx);

/** Function to create a specific context for 'envelop' CMS data.
 *  <p>The new context is stored in the given 'MOC_CMS_CTX' instance.
 *  <p>The 'pUn' pointer in that context must be accessed as a 'MOC_CMS_EnvelopCtx*' after
 *     this function is finished.
 *
 *  @param pCtx  The pointer to a 'MOC_CMS_CTX' instance.
 */
static MSTATUS
DIGI_CMS_createEnvelopContext(MOC_CMS_CTX *pCtx);

/** Function to delete a 'MOC_CMS_EnvelopCtx' instance.
 *  <p>All memory held by this instance will be 'freed'.
 *
 *  @param pCtx A pointer to a 'MOC_CMS_EnvelopCtx' instance, which will be freed and
 *              the pointer will be set to NULL.
 */
static MSTATUS
DIGI_CMS_deleteEnvelopContext(MOC_CMS_EnvelopCtx *pCtx);

/* Cryptographic Helper Functions */

/** Function to decrypt a 'chunk' of data.
 *  <p>The data 'chunk' will be internally adjusted to match the block size of the
 *     crypto algorithm.
 *  <p>Any data not fitting into the block size will be saved in the context for the
 *     next call to this function.
 *  <p>The decrypted data is stored in an allocated array. The caller must free that array.
 *  <p>The 'update' input indicates whether this is the 'final' data chunk. If that is the
 *     case, the final decryption step is performed and (if used) any padding is removed.
 *
 *  @param type
 *  @param encryptedInfo
 *  @param encryptedInfoLen
 *  @param pCtx
 *  @param update
 *  @param decryptedInfo
 *  @param decryptedInfoLen
 */
static MSTATUS
DIGI_CMS_decryptChunked(MOC_SYM(hwAccelDescr hwAccelCtx)
                       encryptedContentType type,
                       ubyte *encryptedInfo,
                       ubyte4 encryptedInfoLen,
                       MOC_CMS_CTX *pCtx,
                       MOC_CMS_UpdateType update,
                       ubyte **decryptedInfo,
                       sbyte4 *decryptedInfoLen);

/** Function to parse the 'DigestAlgorithmIdentifiers' CMS data and create all needed
 *  hash instances.
 *  <p>The passed in ASN1 data will be parsed as formatted according to RFC-5652 (CMS).
 *  <p>This function will call 'DIGI_CMS_U_constructHashes' to construct each needed hash.
 *  <p>The hash instances are stored in the given context.
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_CTX' instance to be used.
 *  @param pData   The pointer to the ASN1 string, containing the 'DigestAlgorithmIdentifiers'
 *                 data
 *  @param dataLen The length of the ASN string.
 *
 */
static MSTATUS
DIGI_CMS_Sig_getHashAlgos(MOC_CMS_CTX *pCtx,
                         ubyte *pData,
                         ubyte4 dataLen);

/** Pass new data to the hash algorithm(s) in the given context.
 *  <p>If this data chunk is the last one, you MUST use 'DIGI_CMS_Sig_hashDataFinal', instead!
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_CTX' instance to be used.
 *  @param pData   A pointer to the (next) payload data.
 *  @param dataLen The length of the data.
 *
 */
static MSTATUS
DIGI_CMS_Sig_hashDataChunked(MOC_CMS_CTX *pCtx,
                            ubyte *pData,
                            ubyte4 dataLen);

/** Pass final data to the hash algorithm(s) in the given context.
 *  <p>If this data chunk is NOT the last one, you MUST use 'DIGI_CMS_Sig_hashDataChunked',
 *     instead!
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_CTX' instance to be used.
 *  @param pData   A pointer to the final payload data.
 *  @param dataLen The length of the data.
 *
 */
static MSTATUS
DIGI_CMS_Sig_hashDataFinal(MOC_CMS_CTX *pCtx,
                          ubyte *pData,
                          ubyte4 dataLen);

/** Function to perform the verification of 'signature' data using the final
 *  hash data for the payload and certificate data provided by the user code.
 *  <p>The successful verification of the signature is reflected in both, the return
 *     code and the 'MOC_CMS_MsgSignInfo' data.
 *
 *  @param pSigData        The ASN1 encoded signature (digest) data from CMS.
 *  @param sigDataLen      The length of the ASN1 signature data.
 *  @param numHashes       The number of 'MOC_CMS_SignedDataHash' instances used while
 *                         hashing the payload data.
 *  @param pSignedDataHash The array of 'MOC_CMS_SignedDataHash' instances, containing the
 *                         hash data.
 *  @param callbackArg     The generic argument passed to all callback functions.
 *  @param cb              Pointer to the callback structure containing callback functions.
 *  @param pNumSigners     Pointer to the variable, where the number of 'MOC_CMS_MsgSignInfo'
 *                         instances in the created array should be stored.
 *  @param ppSigInfos      Pointer to the array variable, where the memory pointer to the
 *                         'MOC_CMS_MsgSignInfo' array should be stored.
 *
 */
static MSTATUS
DIGI_CMS_verifySignatures(MOC_CMS_CTX *pCtx,
                         ubyte *pSigData,
                         ubyte4 sigDataLen,
                         ubyte4 numHashes,
                         MOC_CMS_SignedDataHash *pSignedDataHash,
                         const void *callbackArg,
                         const MOC_CMS_Callbacks *cb,
                         ubyte4 *pNumSigners,
                         ubyte4 *pNumValidSigs,
                         MOC_CMS_MsgSignInfo **ppSigInfos);

/** Function to decode the 'identity' of a signer from ASN encoded CMS data, and
 *  to call the callback function to obtain the certificate data for that identity
 *  as an ASN1 encoded string.
 *  <p>The 'cmsVersion' determines, what type of identity is used:
 *  <ul>
 *  <li>1: The 'IssuerAndSerialNumber' type.
 *  </ul>
 *  <p>The certificate data is placed in newly allocated memory, which MUST be
 *     freed by the caller.
 *
 *  @param cmsVersion       The CMS signer version.
 *  @param pSigner          The ASN1 root element with the CMS 'signer' data per RFC-5652
 *  @param callbackArg      The generic argument passed to all callback functions.
 *  @param cb               Pointer to the callback structure containing callback functions.
 *  @param ppExternalCert   Pointer to the data array pointer, which should be set when the
 *                          certificate was located successfully.
 *  @param pExternalCertLen Pointer to the variable, where the length of the certificate
 *                          data array should be stored.
 *
 */
static MSTATUS
DIGI_CMS_getSignerCert(ubyte cmsVersion,
                      MAsn1Element *pSigner,
                      const void *callbackArg,
                      const MOC_CMS_Callbacks *cb,
                      ubyte **ppExternalCert,
                      ubyte4 *pExternalCertLen);

/** Function to process the 'recipient' data in an 'envelop' CMS message. It will
 *  parse the data to create the 'crypto' algorithms as described by the CMS.
 *  <p>The created algorithm instances are stored in the given context.
 *  <p>This function uses 'DIGI_CMS_U_getBulkAlgo' to create the algorithm instances.
 *  <p>The 'RecipientInfos' data is a set of 'recipient' specifications, so multiple
 *     crypto algorithms may be created.
 *
 *  @param pCtx          The pointer to the context to be used.
 *  @param pCryptoData   The ASN1 encoded string containing the 'RecipientInfos' data from
 *                       the CMS message.
 *  @param cryptoDataLen The length of the ASN1 string from CMS.
 */
static MSTATUS
DIGI_CMS_processEnvelopAlgo(MOC_CMS_CTX *pCtx,
                           ubyte *pCrytpoData,
                           ubyte4 cryptoDataLen);

/** This function parses the 'identity' of a single 'recipient' and then calls
 *  into 'user' code to obtain the private key data for decrypting the symmetric
 *  decrypt key for the applied crypto algorithm.
 *  <p>There are two callback functions, that have different 'identity' types to locate
 *     the correct private key.
 *
 *  @param pData              The ASN1 data string containing the 'RecipientInfos' CMS
 *                            data.
 *  @param dataLen            The length of the ASN1 string.
 *  @param callbackArg        The user provided callback argument, passed to all calls.
 *  @param getPrivateKeyFun   The callback function, taking an 'issuer name' and a 'serial
 *                            number' as identifier.
 *  @param getPrivateKeyFunEx The callback function, taking a 'MOC_CMS_RecipientId' as an
 *                            identifier.
 *  @param ppSymmetricKey     A pointer to a 'ubyte*' variable, where the obtained symmetric
 *                            key data is to be stored.
 *  @param pSymmetricKeyLen   A pointer to a 'ubyte4' variable, where the length of the
 *                            symmetric key array is to be stored.
 *  @param ppRec              The pointer to a variable pointing to the memory where an array
 *                            of 'MOC_CMS_RecipientId*' instances should be stored. Can be set
 *                            to NULL to not save the 'MOC_CMS_RecipientId' data.
 *  @param recipientIndex     A pointer to the variable containing the 'offset' into the above
 *                            array, where the new instance are stored. In return, it will
 *                            contain the new offset (= current length) into that array.
 *
 */
static MSTATUS
DIGI_CMS_processRecipientInfos(MOC_HW(hwAccelDescr hwAccelCtx) ubyte *pData,
                              ubyte4 dataLen,
                              const void *callbackArg,
                              MOC_CMS_GetPrivateKey getPrivateKeyFun,
                              MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                              ubyte **ppSymmetricKey,
                              ubyte4 *pSymmetricKeyLen,
                              MOC_CMS_RecipientId ***ppRec,
                              sbyte4 *recipientIndex);

/** Function to validate a certificate.
 *  <p>The certificate data is an ASN1 encoded string.
 *  <p>The 'user' callback is used to perform the validation of the data
 *     inside the certificate.
 *
 * @param pCert       The root ASN1 element containing the certificate data.
 * @param pSigInfo    The signer information containing information about the
 *                    signature data.
 * @param callbackArg The generic argument passed to all callback functions.
 * @param valCertFun  The function provided by the 'user' code for certificate
 *                    validation.
 *
 */
static MSTATUS
DIGI_CMS_validateCertificate(MAsn1Element* pCert,
                            MOC_CMS_MsgSignInfo *pSigInfo,
                            const void* callbackArg,
                            MOC_CMS_ValidateRootCertificate valCertFun);


/*----------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_RE_SIGNER__

/**
 * Install an instance of 'CMS_ResignData_CTX' into the CMS_context
 * This function adds a pointer to an object in which MOC_CMS will save extracted
 * CMS info to be used when Re-signing CMS messages.
 * Note: This is only needed by ump.c & ummaker.c when re-signing, so we are not
 * including it in header files.
 */
MOC_EXTERN void DIGI_CMS_setResignCtx(MOC_CMS_context pContext, CMS_ResignData_CTX ctx);

MOC_EXTERN CMS_ResignData_CTX DIGI_CMS_getResignCtx(MOC_CMS_context pContext);

/*----------------------------------------------------------------------*/

extern void
DIGI_CMS_setResignCtx(MOC_CMS_context pContext, CMS_ResignData_CTX ctx)
{
    MOC_CMS_CTX*  pMCCtx = NULL;
    if (NULL == pContext)
    {
        return;
    }

    pMCCtx = (MOC_CMS_CTX*) pContext;
    if ('I' != pMCCtx->mag)
    {
        return;
    }

    pMCCtx->pResData = (void*)ctx;
}

/*----------------------------------------------------------------------*/

extern CMS_ResignData_CTX
DIGI_CMS_getResignCtx(MOC_CMS_context pContext)
{
    MOC_CMS_CTX*  pMCCtx = NULL;
    if (NULL == pContext)
    {
        return NULL;
    }

    pMCCtx = (MOC_CMS_CTX*) pContext;
    if ('I' != pMCCtx->mag)
    {
        return NULL;
    }

    return (CMS_ResignData_CTX)pMCCtx->pResData;

}
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

/*----------------------------------------------------------------------*/

extern void
DIGI_CMS_deleteContextIn(MOC_CMS_CTX* pCtx)
{
    switch (pCtx->contentType)
    {
    case E_MOC_CMS_ct_signedData:
        DIGI_CMS_deleteSignContext (&(pCtx->pUn->sign));
        break;
    case E_MOC_CMS_ct_envelopedData:
        DIGI_CMS_deleteEnvelopContext (&(pCtx->pUn->env));
        break;
    default:
        /* do nothing */
        break;
    }
    DIGI_CMS_A_freeCollectData (&(pCtx->pOidData));
    MAsn1FreeElementArray (&(pCtx->pRootEnv));
    if (NULL != pCtx->cb)
    {
        DIGI_FREE ((void**) &(pCtx->cb));
    }
    DIGI_FREE ((void**) &pCtx);
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_cloneSigner(MOC_CMS_MsgSignInfo* pOut,
                    const MOC_CMS_MsgSignInfo* pIn)
{
    MSTATUS             status = OK;
    MOC_CMS_MsgSignInfo si = { 0 };

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Copy simple values */
    si.verifies = pIn->verifies;

    /* Clone ASN1 string, if set */
    if (NULL != pIn->pASN1)
    {
        si.ASN1Len = pIn->ASN1Len;
        status = DIGI_MALLOC ((void**)&(si.pASN1), si.ASN1Len);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (si.pASN1, pIn->pASN1, si.ASN1Len);
        if (OK != status)
            goto exit;
    }

    /* Clone message digest array, if set */
    if (NULL != pIn->pMsgSigDigest)
    {
        si.msgSigDigestLen = pIn->msgSigDigestLen;
        status = DIGI_MALLOC ((void**)&(si.pMsgSigDigest), si.msgSigDigestLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (si.pMsgSigDigest, pIn->pMsgSigDigest, si.msgSigDigestLen);
        if (OK != status)
            goto exit;
    }

    /* If success, copy from intermediate store to output */
    status = DIGI_MEMCPY (pOut, &si, sizeof (MOC_CMS_MsgSignInfo));
    if (OK != status)
        goto exit;

    /* Success */
    si.pASN1 = NULL;
    si.pMsgSigDigest = NULL;

exit:
    if (NULL != si.pASN1)
    {
        DIGI_FREE ((void**)&(si.pASN1));
    }
    if (NULL != si.pMsgSigDigest)
    {
        DIGI_FREE ((void**)&(si.pMsgSigDigest));
    }
    return status;
}

/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_cloneKTRid(MOC_CMS_KeyTransRecipientId* pOut,
                   const MOC_CMS_KeyTransRecipientId* pIn)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cloning depends on id type */
    switch (pIn->type)
    {
    case NO_TAG:
        status = DIGI_CMS_cloneIssuer (&(pOut->u.issuerAndSerialNumber),
                                      &(pIn->u.issuerAndSerialNumber));
        break;
    case 0:
        status = DIGI_CMS_cloneSubjectKey (&(pOut->u.subjectKeyIdentifier),
                                          &(pIn->u.subjectKeyIdentifier));
        break;
    default:
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_cloneKARid(MOC_CMS_KeyAgreeRecipientId* pOut,
                   const MOC_CMS_KeyAgreeRecipientId* pIn)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Cloning depends on id type */
    switch (pIn->type)
    {
    case NO_TAG:
        status = DIGI_CMS_cloneIssuer (&(pOut->u.issuerAndSerialNumber),
                                      &(pIn->u.issuerAndSerialNumber));
        break;
    case 0:
        status = DIGI_CMS_cloneSubjectKey (&(pOut->u.subjectKeyIdentifier),
                                          &(pIn->u.subjectKeyIdentifier));
        break;
    case 1:
        status = DIGI_CMS_cloneOriginatorKey (&(pOut->u.originatorKey),
                                             &(pIn->u.originatorKey));
        break;

    default:
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_freeKTRid(MOC_CMS_KeyTransRecipientId* pData)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Freeing memory depends on id type */
    switch (pData->type)
    {
    case NO_TAG:
        status = DIGI_CMS_freeIssuer (&(pData->u.issuerAndSerialNumber));
        break;

    case 0:
        status = DIGI_CMS_freeSubjectKey (&(pData->u.subjectKeyIdentifier));
        break;

    default:
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_freeKARid(MOC_CMS_KeyAgreeRecipientId* pData)
{
    MSTATUS status = ERR_INVALID_INPUT;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Freeing memory depends on id type */
    switch (pData->type)
    {
    case NO_TAG:
        status = DIGI_CMS_freeIssuer (&(pData->u.issuerAndSerialNumber));
        break;

    case 0:
        status = DIGI_CMS_freeSubjectKey (&(pData->u.subjectKeyIdentifier));
        break;

    case 1:
        status = DIGI_CMS_freeOriginatorKey (&(pData->u.originatorKey));
        break;

    default:
        break;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_parseSigned(MOC_CMS_CTX *pCtx,
                    const ubyte *pData,
                    ubyte4 dataLen,
                    MOC_CMS_DataInfo *pInfo,
                    intBoolean last)
{
    MSTATUS    status = OK;
    ubyte4     bytesRead;
    ubyte2     envSignIdx;
    ubyte2     encapContentOIDidx;
    intBoolean finished = FALSE;

    MOC_CMS_DataInfo info2 = { NULL, NULL, NULL, 0, 0, 2, 0 };
    MOC_CMS_DataInfo info3 = { NULL, NULL, NULL, 0, 0, 3, 0 };

    /* Does the content type value match expectation? */
    if (E_MOC_CMS_ct_signedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Create specific context, if it is not yet made */
    if (NULL == pCtx->pUn)
    {
        status = DIGI_CMS_createSignContext(pCtx);
        if (OK != status)
            goto exit;
    }

    envSignIdx = pCtx->pUn->sign.idxEnv;
    encapContentOIDidx = pCtx->pUn->sign.idxDataOid;

    /* Not yet streaming actual content? */
    if (0 == pCtx->pUn->sign.streaming)
    {
        /* Parse the Signer Info */
        if ((0 < pCtx->pRootEnv[envSignIdx].valueLen) &&
            (NULL != pCtx->pRootEnv[envSignIdx].value.pValue))
        {
            /* Data is stored in root ASN1 */
            status = MAsn1DecodeIndefiniteUpdate (pCtx->pRootEnv[envSignIdx].value.pValue,
                                                  pCtx->pRootEnv[envSignIdx].valueLen,
                                                  pCtx->pUn->sign.asnSign,
                                                  &DIGI_CMS_A_decodeSeqDataReturn,
                                                  &info2,
                                                  &bytesRead,
                                                  &finished);
        }
        else if (0 < pInfo->len)
        {
            /* Data is stored in 'indefinite' encoded sequence */
            status = MAsn1DecodeIndefiniteUpdate (pInfo->pData,
                                                  pInfo->len,
                                                  pCtx->pUn->sign.asnSign,
                                                  &DIGI_CMS_A_decodeSeqDataReturn,
                                                  &info2,
                                                  &bytesRead,
                                                  &finished);
        }
        if (OK != status)
            goto exit;

        /* Still need to collect data? */
        if (FALSE == pCtx->pUn->sign.pCrypto->keepDone)
        {
            status = DIGI_CMS_A_collectEncoded (pCtx->pUn->sign.pCrypto);
            if (OK != status)
                goto exit;
        }

        if (TRUE == pCtx->pUn->sign.pCrypto->keepDone)
        {
            if (FALSE == pCtx->pUn->sign.pPkgOid->keepDone)
            {
                status = DIGI_CMS_A_collectOid (pCtx->pUn->sign.pPkgOid);
                if (OK != status)
                    goto exit;
            }

            if (TRUE == pCtx->pUn->sign.pPkgOid->keepDone)
            {
                MAsn1Element* nxtAsn = pCtx->pUn->sign.asnSign + (encapContentOIDidx + 1);

                /* Indicate stream of signed data area */
                pCtx->pUn->sign.streaming = 1;
                pCtx->pUn->sign.stream_data = nxtAsn->encoding.pEncoding;

                /* Did the data arrived as INDEF? */
                if ((0 != (MASN1_STATE_DECODE_INDEF & nxtAsn->state)) ||
                    (0 != (MASN1_STATE_DECODE_INDEF_ENCODED & nxtAsn->state)))
                {
                    /*MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN_LEN*/
                    if ((nxtAsn->state > MASN1_STATE_DECODE_INDEF_ENCODED_SUB_LEN) ||
                        (nxtAsn->state == MASN1_STATE_DECODE_COMPLETE_INDEF))
                    {
                        /* The length of the data represents the partial/full data */
                        pCtx->pUn->sign.stream_data_len = nxtAsn->encodingLen;
                    }
                    else if (0 < info2.len)
                    {
                        /* Add back SEQ start (A0 80) length */
                        pCtx->pUn->sign.stream_data_len = info2.len + 2;
                    }
                    else
                    {
                        /* The length of the data represents the TAG/LEN parts */
                        pCtx->pUn->sign.stream_data_len = nxtAsn->encodingLen;
                    }
                }
                else
                {
                    /* Pass on data after OID as raw 'package' */
                    if (nxtAsn->state < MASN1_STATE_DECODE_LEN)
                    {
                        /* The length of the data represents the TAG/LEN parts */
                        pCtx->pUn->sign.stream_data_len = nxtAsn->encodingLen;
                    }
                    else
                    {
                        /* The length of the data represents the partial/full data */
                        pCtx->pUn->sign.stream_data_len = nxtAsn->encodingLen
                                - nxtAsn->buffer.remaining;
                    }
                }
            }
        }
    }
    else
    {
        /* Was the data inside an 'indefinite' encoded sequence or not? */
        if (0 < pInfo->len)
        {
            /* This is the raw 'package' data */
            pCtx->pUn->sign.stream_data_len = pInfo->len;
            pCtx->pUn->sign.stream_data = pInfo->pData;
        }
        else
        {
            /* This is the raw 'package' data */
            pCtx->pUn->sign.stream_data_len = dataLen;
            pCtx->pUn->sign.stream_data = (ubyte *)pData;
        }

        status = MAsn1DecodeIndefiniteUpdate (pCtx->pUn->sign.stream_data,
                                              pCtx->pUn->sign.stream_data_len,
                                              pCtx->pUn->sign.asnSign,
                                              &DIGI_CMS_A_decodeSeqDataReturn,
                                              &info2,
                                              &bytesRead,
                                              &finished);

        if (OK != status)
            goto exit;
    }

    if (1 == pCtx->pUn->sign.streaming)
    {
        /* Create and check hash data if we have found any algorithm */
        if (NULL == pCtx->pUn->sign.pHashes)
        {
            sbyte4 cmpResult;
            /* Found the raw data OID? */
            status = ASN1_compareOID (CMS_OUTER_DATA,
                                      CMS_OUTER_DATA_LEN,
                                      pCtx->pUn->sign.pPkgOid->pKeepData,
                                      pCtx->pUn->sign.pPkgOid->keepDataLen,
                                      NULL,
                                      &cmpResult);
            if (OK != status)
                goto exit;

            if (cmpResult != 0)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            /* Set Hash algorithm for this context */
            status = DIGI_CMS_Sig_getHashAlgos (pCtx,
                                               pCtx->pUn->sign.pCrypto->pKeepData,
                                               pCtx->pUn->sign.pCrypto->keepDataLen);
            if (OK != status)
                goto exit;
        }

        /* Should we process any data, now? */
        if ((FALSE == pCtx->lastDone) &&
            (NULL != pCtx->pUn->sign.pHashes))
        {
            if (NULL != pCtx->pUn->sign.stream_data)
            {
                if (E_MOC_CMS_st_streaming == pCtx->streamType)
                {
                    /* Raw data is in OCTET */
                    intBoolean dummy;
                    MAsn1Element* rawAsn = pCtx->pUn->sign.asnRawIndef;

                    /* We should be ready to create the digest */
                    status = MAsn1DecodeIndefiniteUpdate(pCtx->pUn->sign.stream_data,
                                                         pCtx->pUn->sign.stream_data_len,
                                                         rawAsn,
                                                         &DIGI_CMS_A_decodeSeqDataReturn,
                                                         &info3,
                                                         &bytesRead,
                                                         &dummy);
                    if (OK != status)
                        goto exit;

                    /* Data arrives in 'info3' */
                    if ((NULL != info3.pData) &&
                        (0 < info3.len))
                    {
                         if (MASN1_STATE_DECODE_COMPLETE_INDEF == rawAsn->state)
                         {
                             status = DIGI_CMS_Sig_hashDataFinal (pCtx,
                                                                 info3.pData,
                                                                 info3.len);
                             if (OK != status)
                                 goto exit;

                             if ((NULL != pCtx->cb->dataUpdateFun) &&
                                 (0 != rawAsn->valueLen))
                             {
                                 status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                                   (void*)pCtx,
                                                                   E_MOC_CMS_ut_final,
                                                                   info3.pData,
                                                                   info3.len);
                                 if (OK != status)
                                     goto exit;
                             }

                             pCtx->lastDone = TRUE;
                         }
                         else
                         {
                             status = DIGI_CMS_Sig_hashDataChunked (pCtx,
                                                                  info3.pData,
                                                                  info3.len);
                             if (OK != status)
                                 goto exit;

                             if ((NULL != pCtx->cb->dataUpdateFun) &&
                                 (0 != rawAsn->valueLen))
                             {
                                 status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                                   (void*)pCtx,
                                                                   E_MOC_CMS_ut_update,
                                                                   info3.pData,
                                                                   info3.len);
                             }
                         }
                    }
                    else
                    {
                        if (MASN1_STATE_DECODE_COMPLETE_INDEF == rawAsn->state)
                        {
                            status = DIGI_CMS_Sig_hashDataFinal (pCtx,
                                                                info3.pData,
                                                                info3.len);
                            if (OK != status)
                                goto exit;

                            if ((NULL != pCtx->cb->dataUpdateFun) &&
                                (0 != rawAsn->valueLen))
                            {
                                status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                                  (void*)pCtx,
                                                                  E_MOC_CMS_ut_final,
                                                                  info3.pData,
                                                                  info3.len);
                                if (OK != status)
                                    goto exit;
                            }

                            pCtx->lastDone = TRUE;
                        }
                    }
                }
                else if (E_MOC_CMS_st_definite == pCtx->streamType)
                {
                    intBoolean   dummy;
                    MAsn1Element *rawAsn = pCtx->pUn->sign.asnRawDef;
                    MAsn1Element *pRaw = NULL;
                    ubyte4       section = 0;

                    /* We should be ready to create the digest */
                    status = MAsn1DecodeIndefiniteUpdate (pCtx->pUn->sign.stream_data,
                                                          pCtx->pUn->sign.stream_data_len,
                                                          rawAsn,
                                                          &DIGI_CMS_A_decodeSeqDataReturn,
                                                          &info3,
                                                          &bytesRead,
                                                          &dummy);
                    if (OK != status)
                        goto exit;

                    /* Look at all SETOF elements (OCTET) */
                    do
                    {
                        MAsn1GetOfElementAtIndex (rawAsn,
                                                  section,
                                                  &pRaw);
                        if (NULL == pRaw)
                            break;
                        if (MASN1_STATE_NONE == pRaw[0].state)
                            break;

                        /* Actual octet bytes in this raw entry? */
                        if ((NULL != pRaw[0].value.pValue) &&
                            (0 < pRaw[0].valueLen))
                        {
                            if (MASN1_STATE_DECODE_COMPLETE == rawAsn->state)
                            {
                                status = DIGI_CMS_Sig_hashDataFinal (pCtx,
                                                                    pRaw[0].value.pValue,
                                                                    pRaw[0].valueLen);
                                if (OK != status)
                                    goto exit;

                                if ((NULL != pCtx->cb->dataUpdateFun) &&
                                    (0 != rawAsn->valueLen))
                                {
                                    status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                                      (void*)pCtx,
                                                                      E_MOC_CMS_ut_final,
                                                                      pRaw[0].value.pValue,
                                                                      pRaw[0].valueLen);
                                    if (OK != status)
                                        goto exit;
                                }

                                pCtx->lastDone = TRUE;
                            }
                            else
                            {
                                status = DIGI_CMS_Sig_hashDataChunked (pCtx,
                                                                      pRaw[0].value.pValue,
                                                                      pRaw[0].valueLen);
                                if (OK != status)
                                    goto exit;

                                if ((NULL != pCtx->cb->dataUpdateFun) &&
                                    (0 != rawAsn->valueLen))
                                {
                                    status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                                      (void*)pCtx,
                                                                      E_MOC_CMS_ut_update,
                                                                      pRaw[0].value.pValue,
                                                                      pRaw[0].valueLen);
                                }
                            }
                        }

                        /* Never read this again, if complete */
                        if (MASN1_STATE_DECODE_COMPLETE == pRaw[0].state)
                        {
                            pRaw[0].value.pValue = NULL;
                        }

                        /* Attempt to read the next section */
                        ++section;
                    } while(1);
                }  /* if (pCtx->streamType) */
                else
                {
                    status = ERR_INVALID_INPUT;
                    goto exit;
                }
            }
        }

        if (TRUE == pCtx->lastDone)
        {
            status = DIGI_CMS_A_collectSetOF (pCtx->pUn->sign.pCerts);
            if (OK != status)
                goto exit;

            status = DIGI_CMS_A_collectSetOF (pCtx->pUn->sign.pCRLs);
            if (OK != status)
                goto exit;

            status = DIGI_CMS_A_collectEncoded (pCtx->pUn->sign.pDigest);
            if (OK != status)
                goto exit;

            if (TRUE == pCtx->pUn->sign.pDigest->keepDone)
            {
                pCtx->pUn->sign.finished = TRUE;
            }
        }
    }

    /* Check if all data have been digested */
    if ((TRUE == pCtx->pUn->sign.finished) && (TRUE == last))
    {
        if (FALSE == pCtx->pUn->sign.signFinished)
        {
            /* Mark end, even if some trailing bytes may arrive */
            pCtx->pUn->sign.signFinished = TRUE;

            status = DIGI_CMS_verifySignatures (pCtx,
                                               pCtx->pUn->sign.pDigest->pKeepData,
                                               pCtx->pUn->sign.pDigest->keepDataLen,
                                               pCtx->pUn->sign.numAlgos,
                                               pCtx->pUn->sign.pHashes,
                                               pCtx->cbArg,
                                               pCtx->cb,
                                               &(pCtx->pUn->sign.numSigners),
                                               &(pCtx->pUn->sign.numValidSigs),
                                               &(pCtx->pUn->sign.pSigners));

            if (NULL != pCtx->cb->dataUpdateFun)
            {
                MSTATUS status2;
                status2 = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                   (void*)pCtx,
                                                   E_MOC_CMS_ut_result,
                                                   NULL,
                                                   0);
                /* Did the final update report an error from the 'user'? */
                if ((OK == status) && (OK != status2))
                {
                    status = status2;
                }
            }

            if (OK != status)
                goto exit;
        }
    }

exit:
    DIGI_CMS_A_freeDataInfo(&info2);
    DIGI_CMS_A_freeDataInfo(&info3);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_parseEnveloped(MOC_CMS_CTX *pCtx,
                       const ubyte *pData,
                       ubyte4 dataLen,
                       MOC_CMS_DataInfo *pInfo,
                       intBoolean last)
{
    MSTATUS    status = OK;
    ubyte4     bytesRead;
    ubyte2     envEnvIdx;
    intBoolean done = FALSE;

    encryptedContentType type = NORMAL;

    MOC_CMS_DataInfo info2 = { NULL, NULL, NULL, 0, 0, 2, 0 };
    MOC_CMS_DataInfo info3 = { NULL, NULL, NULL, 0, 0, 3, 0 };

    if (E_MOC_CMS_ct_envelopedData != pCtx->contentType)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Create specific context, if it is not yet made */
    if (NULL == pCtx->pUn)
    {
        status = DIGI_CMS_createEnvelopContext (pCtx);
        if (OK != status)
            goto exit;
    }

    envEnvIdx = pCtx->pUn->env.idxEnv;

    /* Not yet streaming actual content? */
    if (0 == pCtx->pUn->env.streaming)
    {
        if (0 < pInfo->len)
        {
            /* Decode EnvelopedData from collected data */
            status = MAsn1DecodeIndefiniteUpdate (pInfo->pData,
                                                  pInfo->len,
                                                  pCtx->pUn->env.asnCrypto,
                                                  &DIGI_CMS_A_decodeSeqDataReturn, &info2,
                                                  &bytesRead, &done);
        }
        else if (NULL != pCtx->pRootEnv[envEnvIdx].value.pValue)
        {
            if (0 < pCtx->pRootEnv[envEnvIdx].valueLen)
            {
                /* Decode EnvelopedData from data */
                status = MAsn1DecodeIndefiniteUpdate (pCtx->pRootEnv[envEnvIdx].value.pValue,
                                                      pCtx->pRootEnv[envEnvIdx].valueLen,
                                                      pCtx->pUn->env.asnCrypto,
                                                      &DIGI_CMS_A_decodeSeqDataReturn, &info2,
                                                      &bytesRead, &done);
            }
        }
        if (OK != status)
            goto exit;

        /* Keep various elements for processing */
        if (FALSE == pCtx->pUn->env.pRecipient->keepDone)
        {
            status = DIGI_CMS_A_collectEncoded (pCtx->pUn->env.pRecipient);
            if (OK != status)
                goto exit;
        }

        if (TRUE == pCtx->pUn->env.pRecipient->keepDone)
        {
            if (FALSE == pCtx->pUn->env.pPkgOid->keepDone)
            {
                status = DIGI_CMS_A_collectOid (pCtx->pUn->env.pPkgOid);
                if (OK != status)
                    goto exit;
            }

            if (TRUE == pCtx->pUn->env.pPkgOid->keepDone)
            {
                if (FALSE == pCtx->pUn->env.pCryptoA->keepDone)
                {
                    status = DIGI_CMS_A_collectOid (pCtx->pUn->env.pCryptoA);
                    if (OK != status)
                        goto exit;
                }

                if (TRUE == pCtx->pUn->env.pCryptoA->keepDone)
                {
                    if (FALSE == pCtx->pUn->env.pCryptoI->keepDone)
                    {
                        status = DIGI_CMS_A_collectEncoded (pCtx->pUn->env.pCryptoI);
                        if (OK != status)
                            goto exit;
                    }

                    /* Reached the raw 'package' data */
                    if (TRUE == pCtx->pUn->env.pCryptoI->keepDone)
                    {
                        pCtx->pUn->env.streaming = 1;
                    }
                }
            }
        }
    }
    else
    {
        if (0 < pInfo->len)
        {
            /* This is the raw 'package' data */
            pCtx->pUn->env.stream_data_len = pInfo->len;
            pCtx->pUn->env.stream_data = pInfo->pData;
        }
        else
        {
            /* This is the raw 'package' data */
            pCtx->pUn->env.stream_data_len = dataLen;
            pCtx->pUn->env.stream_data = (ubyte *)pData;
        }

        status = MAsn1DecodeIndefiniteUpdate (pCtx->pUn->env.stream_data,
                                              pCtx->pUn->env.stream_data_len,
                                              pCtx->pUn->env.asnCrypto,
                                              &DIGI_CMS_A_decodeSeqDataReturn,
                                              &info2,
                                              &bytesRead,
                                              &done);
        if (OK != status)
            goto exit;
    }

    if (1 == pCtx->pUn->env.streaming)
    {
        ubyte2       idxContent = pCtx->pUn->env.idxCrypRaw;
        ubyte4       section = 0;
        MAsn1Element *pRaw = NULL;
        intBoolean   foundAny = FALSE;

        /* Do we have the crypto algorithm set? */
        if (NULL == pCtx->pUn->env.pBulkAlgo)
        {
            sbyte4 cmpResult;
            /* Found the correct OID? */
            status = ASN1_compareOID (CMS_OUTER_DATA,
                                      CMS_OUTER_DATA_LEN,
                                      pCtx->pUn->env.pPkgOid->pKeepData,
                                      pCtx->pUn->env.pPkgOid->keepDataLen,
                                      NULL, &cmpResult);
            if (OK != status)
                goto exit;

            if (cmpResult != 0)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            status = DIGI_CMS_processEnvelopAlgo (pCtx,
                                                 pCtx->pUn->env.pRecipient->pKeepData,
                                                 pCtx->pUn->env.pRecipient->keepDataLen);
            if (OK != status)
                goto exit;
        }

        if (E_MOC_CMS_st_streaming == pCtx->streamType)
        {
            if ((0 != info2.len) &&
                (NULL != info2.pData))
            {
                /* SETOF OCTET strings in '[0]' - IMPLICIT */
                status = MAsn1DecodeIndefiniteUpdate (info2.pData,
                                                      info2.len,
                                                      pCtx->pUn->env.asnRawImpl,
                                                      &DIGI_CMS_A_decodeSeqDataReturn,
                                                      &info3,
                                                      &bytesRead,
                                                      &done);
                if (OK != status)
                    goto exit;

                if ((0 < info3.len) &&
                    (NULL != info3.pData))
                {
                    /* Read data in 'info3' */
                    ubyte* decryptedInfo = NULL;
                    sbyte4 decryptedInfoLen = 0;

                    if (NULL != pCtx->pUn->env.held_data)
                    {
                        pCtx->pUn->env.last_done = FALSE;
                        status = DIGI_CMS_decryptChunked (MOC_SYM(pCtx->hwAccelCtx) type,
                                                         pCtx->pUn->env.held_data,
                                                         pCtx->pUn->env.held_data_len,
                                                         pCtx,
                                                         E_MOC_CMS_ut_update,
                                                         &decryptedInfo,
                                                         &decryptedInfoLen);
                        if (OK != status)
                           goto exit;

                        DIGI_FREE ((void**)&(pCtx->pUn->env.held_data));
                        pCtx->pUn->env.held_data_len = 0;
                    }

                    /* Good data? */
                    if ((NULL != decryptedInfo) && (0 != decryptedInfoLen))
                    {
                        if (NULL != pCtx->cb->dataUpdateFun)
                        {
                            status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                              (void*)pCtx,
                                                              E_MOC_CMS_ut_update,
                                                              decryptedInfo,
                                                              decryptedInfoLen);
                            if (OK != status)
                               goto exit;
                        }
                    }

                    /* Clean up */
                    if (NULL != decryptedInfo)
                    {
                        DIGI_FREE ((void**)&decryptedInfo);
                    }

                    foundAny = TRUE;
                    status = DIGI_MALLOC ((void**)&(pCtx->pUn->env.held_data),
                                         info3.len);
                    if (OK != status)
                        goto exit;
                    
                    DIGI_MEMCPY (pCtx->pUn->env.held_data,
                                info3.pData,
                                info3.len);
                    pCtx->pUn->env.held_data_len = info3.len;
                }
                else
                {
                    /* Do nothing */
                }
            }
        }
        else if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            MAsn1Element *pIn = pCtx->pUn->env.asnCrypto + idxContent;

            if ((0 != pIn->valueLen) &&
                (NULL != pIn->value.pValue))
            {
                pRaw = pCtx->pUn->env.asnRawImpl;
                ubyte4 decodeFlag = MASN1_DECODE_UPDATE;

                /* Is this the last? */
                if (MASN1_STATE_DECODE_COMPLETE == pIn->state)
                {
                    decodeFlag = MASN1_DECODE_LAST_CALL;
                }

                /* Single encoded OCTET string in '[0]' - IMPLICIT */
                status = MAsn1DecodeUpdateFlag (pIn[0].value.pValue,
                                                pIn[0].valueLen,
                                                decodeFlag,
                                                pRaw,
                                                &bytesRead,
                                                &done);
                if (OK != status)
                    goto exit;

                /* Actual octet bytes in this raw entry? */
                if ((NULL != pRaw[0].value.pValue) &&
                    (0 < pRaw[0].valueLen))
                {
                    ubyte* decryptedInfo = NULL;
                    sbyte4 decryptedInfoLen = 0;

                    if (NULL != pCtx->pUn->env.held_data)
                    {
                        pCtx->pUn->env.last_done = FALSE;
                        status = DIGI_CMS_decryptChunked (MOC_SYM(pCtx->hwAccelCtx) type,
                                                         pCtx->pUn->env.held_data,
                                                         pCtx->pUn->env.held_data_len,
                                                         pCtx,
                                                         E_MOC_CMS_ut_update,
                                                         &decryptedInfo,
                                                         &decryptedInfoLen);
                        if (OK != status)
                           goto exit;

                        DIGI_FREE ((void**)&(pCtx->pUn->env.held_data));
                        pCtx->pUn->env.held_data_len = 0;
                    }

                    /* Good data? */
                    if ((NULL != decryptedInfo) && (0 != decryptedInfoLen))
                    {
                        if (NULL != pCtx->cb->dataUpdateFun)
                        {
                            status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                              (void*)pCtx,
                                                              E_MOC_CMS_ut_update,
                                                              decryptedInfo,
                                                              decryptedInfoLen);
                            if (OK != status)
                               goto exit;
                        }
                    }

                    /* Clean up */
                    if (NULL != decryptedInfo)
                    {
                        DIGI_FREE ((void**)&decryptedInfo);
                    }

                    foundAny = TRUE;
                    status = DIGI_MALLOC ((void**)&(pCtx->pUn->env.held_data),
                                         pRaw[0].valueLen);
                    if (OK != status)
                        goto exit;
                    
                    DIGI_MEMCPY (pCtx->pUn->env.held_data,
                                pRaw[0].value.pValue,
                                pRaw[0].valueLen);
                    pCtx->pUn->env.held_data_len = pRaw[0].valueLen;
                }
            }

        }  /* if (pCtx->streamType) */
        else
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* Parser indicated we finished, so flush held data if any is set */
        if ((TRUE == done) &&
            (TRUE == foundAny))
        {
            if (E_MOC_CMS_st_streaming == pCtx->streamType)
            {
                section = 0;
                foundAny = FALSE;

                do
                {
                    MAsn1GetOfElementAtIndex (pCtx->pUn->env.asnRaw,
                                              section,
                                              &pRaw);
                    if (NULL == pRaw)
                        break;

                    if (NULL != pRaw[0].value.pValue)
                    {
                        foundAny = TRUE;
                        break;
                    }
                    ++section;
                } while(1);
            }
            else if (E_MOC_CMS_st_definite == pCtx->streamType)
            {
                /* Never happens in 'definite' format */
                foundAny = FALSE;
            }
        }

        /* When no more data is found, we're done */
        if ( (TRUE == done) &&
             (FALSE == foundAny) &&
             (NULL != pCtx->pUn->env.held_data) &&
             (MASN1_STATE_DECODE_COMPLETE <= pCtx->pUn->env.asnCrypto[idxContent].state) )
        {
            ubyte  *decryptedInfo = NULL;
            sbyte4 decryptedInfoLen = 0;

            pCtx->pUn->env.last_done = TRUE;
            status = DIGI_CMS_decryptChunked (MOC_SYM(pCtx->hwAccelCtx) type,
                                             pCtx->pUn->env.held_data,
                                             pCtx->pUn->env.held_data_len,
                                             pCtx,
                                             E_MOC_CMS_ut_final,
                                             &decryptedInfo,
                                             &decryptedInfoLen);

            DIGI_FREE ((void**)&(pCtx->pUn->env.held_data));
            pCtx->pUn->env.held_data_len = 0;

            if (OK != status)
                goto exit;

            /* Good data? */
            if ((NULL != decryptedInfo) && (0 != decryptedInfoLen))
            {
                if (NULL != pCtx->cb->dataUpdateFun)
                {
                    status = pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                                      (void*)pCtx,
                                                      E_MOC_CMS_ut_final,
                                                      decryptedInfo,
                                                      decryptedInfoLen);
                }
            }

            /* Clean up */
            if (NULL != decryptedInfo)
            {
                DIGI_FREE ((void**)&decryptedInfo);
            }
        }
    }

    /* Result call */
    if (TRUE == pCtx->pUn->env.last_done)
    {
        if (NULL != pCtx->cb->dataUpdateFun)
        {
            pCtx->cb->dataUpdateFun (pCtx->cbArg,
                                     (void*)pCtx,
                                     E_MOC_CMS_ut_result,
                                     NULL,
                                     0);
        }
    }

exit:
    DIGI_CMS_A_freeDataInfo(&info2);
    DIGI_CMS_A_freeDataInfo(&info3);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_cloneIssuer(MOC_CMS_IssuerSerialNumber* pOut,
                    const MOC_CMS_IssuerSerialNumber* pIn)
{
    MSTATUS                    status = OK;
    MOC_CMS_IssuerSerialNumber sn = { 0 };

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pIn->pIssuer)
    {
        sn.issuerLen = pIn->issuerLen;
        status = DIGI_MALLOC ((void**)&(sn.pIssuer), sn.issuerLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (sn.pIssuer, pIn->pIssuer, sn.issuerLen);
        if (OK != status)
            goto exit;
    }

    if (NULL != pIn->pSerialNumber)
    {
        sn.serialNumberLen = pIn->serialNumberLen;
        status = DIGI_MALLOC ((void**)&(sn.pSerialNumber), sn.serialNumberLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (sn.pSerialNumber, pIn->pSerialNumber, sn.serialNumberLen);
        if (OK != status)
            goto exit;
    }

    /* If success, copy from intermediate store to output */
    status = DIGI_MEMCPY (pOut, &sn, sizeof (MOC_CMS_IssuerSerialNumber));
    if (OK != status)
        goto exit;

    /* Success */
    sn.pIssuer = NULL;
    sn.pSerialNumber = NULL;

exit:
    if (NULL != sn.pIssuer)
    {
        DIGI_FREE ((void**)&(sn.pIssuer));
    }
    if (NULL != sn.pSerialNumber)
    {
        DIGI_FREE ((void**)&(sn.pSerialNumber));
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_cloneSubjectKey(MOC_CMS_SubjectKeyIdentifier* pOut,
                        const MOC_CMS_SubjectKeyIdentifier* pIn)
{
    MSTATUS                      status = OK;
    MOC_CMS_SubjectKeyIdentifier sk = { 0 };

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pIn->pIdentifier)
    {
        sk.identifierLen = pIn->identifierLen;
        status = DIGI_MALLOC ((void**)&(sk.pIdentifier), sk.identifierLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (sk.pIdentifier, pIn->pIdentifier, sk.identifierLen);
        if (OK != status)
            goto exit;
    }

    /* If success, copy from intermediate store to output */
    status = DIGI_MEMCPY (pOut, &sk, sizeof (MOC_CMS_SubjectKeyIdentifier));
    if (OK != status)
        goto exit;

    /* Success */
    sk.pIdentifier = NULL;

exit:
    if (NULL != sk.pIdentifier)
    {
        DIGI_FREE ((void**)&(sk.pIdentifier));
    }
    return status;
}

/*----------------------------------------------------------------------*/


static MSTATUS
DIGI_CMS_cloneOriginatorKey(MOC_CMS_OriginatorPublicKey* pOut,
                           const MOC_CMS_OriginatorPublicKey* pIn)
{
    MSTATUS                     status = OK;
    MOC_CMS_OriginatorPublicKey opk = { 0 };

    if ((NULL == pOut) ||
        (NULL == pIn))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pIn->pAlgoOID)
    {
        opk.algoOIDLen = pIn->algoOIDLen;
        status = DIGI_MALLOC ((void**)&(opk.pAlgoOID), opk.algoOIDLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (opk.pAlgoOID, pIn->pAlgoOID, opk.algoOIDLen);
        if (OK != status)
            goto exit;
    }

    if (NULL != pIn->pAlgoParameters)
    {
        opk.algoParametersLen = pIn->algoParametersLen;
        status = DIGI_MALLOC ((void**)&(opk.pAlgoParameters), opk.algoParametersLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (opk.pAlgoParameters, pIn->pAlgoParameters, opk.algoParametersLen);
        if (OK != status)
            goto exit;
    }

    if (NULL != pIn->pPublicKey)
    {
        opk.publicKeyLen = pIn->publicKeyLen;
        status = DIGI_MALLOC ((void**)&(opk.pPublicKey), opk.publicKeyLen);
        if (OK != status)
            goto exit;
        status = DIGI_MEMCPY (opk.pPublicKey, pIn->pPublicKey, opk.publicKeyLen);
        if (OK != status)
            goto exit;
    }

    /* If success, copy from intermediate store to output */
    status = DIGI_MEMCPY (pOut, &opk, sizeof (MOC_CMS_OriginatorPublicKey));
    if (OK != status)
        goto exit;

    /* Success */
    opk.pAlgoOID = NULL;
    opk.pAlgoParameters = NULL;
    opk.pPublicKey = NULL;

exit:
    if (NULL != opk.pAlgoOID)
    {
        DIGI_FREE ((void**)&(opk.pAlgoOID));
    }
    if (NULL != opk.pAlgoParameters)
    {
        DIGI_FREE ((void**)&(opk.pAlgoParameters));
    }
    if (NULL != opk.pPublicKey)
    {
        DIGI_FREE ((void**)&(opk.pPublicKey));
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_freeIssuer(MOC_CMS_IssuerSerialNumber* pData)
{
    MSTATUS status = OK;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pData->pIssuer)
    {
        DIGI_FREE ((void**)&(pData->pIssuer));
    }
    if (NULL != pData->pSerialNumber)
    {
        DIGI_FREE ((void**)&(pData->pSerialNumber));
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_freeSubjectKey(MOC_CMS_SubjectKeyIdentifier* pData)
{
    MSTATUS status = OK;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pData->pIdentifier)
    {
        DIGI_FREE ((void**)&(pData->pIdentifier));
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_freeOriginatorKey(MOC_CMS_OriginatorPublicKey* pData)
{
    MSTATUS status = OK;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pData->pAlgoOID)
    {
        DIGI_FREE ((void**)&(pData->pAlgoOID));
    }
    if (NULL != pData->pAlgoParameters)
    {
        DIGI_FREE ((void**)&(pData->pAlgoParameters));
    }
    if (NULL != pData->pPublicKey)
    {
        DIGI_FREE ((void**)&(pData->pPublicKey));
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_createSignContext(MOC_CMS_CTX *pCtx)
{
    MSTATUS           status = OK;
    MOC_CMS_SignedCtx *pCtxS = NULL;

    /* ContentType OID */
    /* id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 } */

    /* Sequence with SIGNED data [rfc5652 - Section 5.1, page 9] */
    MAsn1TypeAndCount defSigned[11] =
    {
     {  MASN1_TYPE_SEQUENCE, 6},
       /* version:          CMSVersion */
       {  MASN1_TYPE_INTEGER, 0},
       /* digestAlgorithms: DigestAlgorithmIdentifiers */
       {  MASN1_TYPE_ENCODED, 0},
       /* encapContentInfo: EncapsulatedContentInfo */
       {  MASN1_TYPE_SEQUENCE, 2},
         {  MASN1_TYPE_OID, 0},
         {  MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_OPTIONAL, 0},
       /* certificates [0] IMPLICIT: CertificateSet OPTIONAL */
       {  MASN1_TYPE_SET_OF | MASN1_IMPLICIT | MASN1_OPTIONAL, 1},
         {  MASN1_TYPE_ENCODED, 0},
       /* crls [1] IMPLICIT: RevocationInfoChoices OPTIONAL */
       {  MASN1_TYPE_SET_OF | MASN1_IMPLICIT | MASN1_OPTIONAL | 1, 1},
         {  MASN1_TYPE_ENCODED, 0},
       /* signerInfos:       SignerInfos */
       {  MASN1_TYPE_ENCODED, 0},
    };

    /* Simple TLV with definite Raw data [rfc5652 - Section 5.2, page 11] */
    MAsn1TypeAndCount defRawDef[2] =
    {
        { MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT, 1 },
            {  MASN1_TYPE_OCTET_STRING, 0},
    };

    /* Simple OCTET with indefinite Raw data [rfc5652 - Section 5.2, page 11] */
    MAsn1TypeAndCount defRawIndef[2] =
    {
        { MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT, 1 },
            {  MASN1_TYPE_OCTET_STRING, 0},
    };

    status = DIGI_CALLOC ((void **)&pCtxS, 1, sizeof (MOC_CMS_SignedCtx));
    if (OK != status)
        goto exit;

    /* Create the 'array' asnSign */
    status = MAsn1CreateElementArray (defSigned, 11, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction,
                                      &(pCtxS->asnSign));
    if (OK != status)
        goto exit;

    /* Create the simple 'array' asnRawDef */
    status = MAsn1CreateElementArray (defRawDef, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction,
                                      &(pCtxS->asnRawDef));
    if (OK != status)
        goto exit;

    /* Create the simple 'array' asnRawIndef */
    status = MAsn1CreateElementArray (defRawIndef, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction,
                                      &(pCtxS->asnRawIndef));
    if (OK != status)
        goto exit;

    /* Point to the sections within the ASN.1 template.
     * This allows us to change the template and contain all needed adjustments
     * to this function. */
    pCtxS->idxEnv = 2;
    pCtxS->idxAlgo = 2;
    pCtxS->idxDataOid = 4;
    pCtxS->idxCerts = 6;
    pCtxS->idxCRLs = 8;
    pCtxS->idxDigest = 10;
    pCtxS->idxRaw = 1;

    /* Create collection of streaming data */
    status = DIGI_CMS_A_createCollectData (&(pCtxS->pCrypto),
                                          pCtxS->asnSign,
                                          pCtxS->asnSign + pCtxS->idxAlgo);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxS->pPkgOid),
                                          pCtxS->asnSign,
                                          pCtxS->asnSign + pCtxS->idxDataOid);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxS->pCerts),
                                          pCtxS->asnSign + pCtxS->idxCerts,
                                          pCtxS->asnSign + pCtxS->idxCerts + 1);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxS->pCRLs),
                                          pCtxS->asnSign + pCtxS->idxCRLs,
                                          pCtxS->asnSign + pCtxS->idxCRLs + 1);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxS->pDigest),
                                          pCtxS->asnSign,
                                          pCtxS->asnSign + pCtxS->idxDigest);
    if (OK != status)
        goto exit;

    pCtx->pUn = (MOC_CMS_TypeCtx*)pCtxS;
    pCtxS = NULL;

exit:
    if (NULL != pCtxS)
    {
        /* Clean up after error */
        DIGI_CMS_deleteSignContext (pCtxS);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_deleteSignContext(MOC_CMS_SignedCtx *pCtx)
{
    MSTATUS status = OK;

    if (NULL == pCtx)
    {
        goto exit;
    }

    if (NULL != pCtx->pSigners)
    {
        int i;
        for (i = 0; i < (int)pCtx->numSigners; i++)
        {
            if (NULL != pCtx->pSigners[i].pASN1)
            {
                DIGI_FREE ((void**)&(pCtx->pSigners[i].pASN1));
            }
            if (NULL != pCtx->pSigners[i].pMsgSigDigest)
            {
                DIGI_FREE ((void**)&(pCtx->pSigners[i].pMsgSigDigest));
            }
            if (NULL != pCtx->pSigners[i].pSigningTime)
            {
                DIGI_FREE ((void**)&(pCtx->pSigners[i].pSigningTime));
            }
        }
        DIGI_FREE ((void**)&(pCtx->pSigners));
    }
    if (NULL != pCtx->pHashes)
    {
        DIGI_CMS_U_destructHashes (MOC_HASH(pCtx->hwAccelCtx) pCtx->numAlgos,
                                  &(pCtx->pHashes));
    }

    DIGI_CMS_A_freeCollectData (&(pCtx->pDigest));
    DIGI_CMS_A_freeCollectData (&(pCtx->pCRLs));
    DIGI_CMS_A_freeCollectData (&(pCtx->pCerts));
    DIGI_CMS_A_freeCollectData (&(pCtx->pPkgOid));
    DIGI_CMS_A_freeCollectData (&(pCtx->pCrypto));
    MAsn1FreeElementArray (&(pCtx->asnRawDef));
    MAsn1FreeElementArray (&(pCtx->asnRawIndef));
    MAsn1FreeElementArray (&(pCtx->asnSign));

    /* Final free */
    status = DIGI_FREE ((void **)&pCtx);

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_createEnvelopContext(MOC_CMS_CTX *pCtx)
{
    MSTATUS            status = OK;
    MOC_CMS_EnvelopCtx *pCtxE = NULL;

    /* ContentType OID */
    /* id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 } */

    /* EnvelopedData sequence [rfc5652 - Section 6.1, page 18] */
    MAsn1TypeAndCount defCrypto[13] =
    {
     {  MASN1_TYPE_SEQUENCE, 5},
       /* version:               CMSVersion */
       {  MASN1_TYPE_INTEGER, 0},
       /* originatorInfo [0] IMPLICIT: OriginatorInfo OPTIONAL */
       {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | MASN1_OPTIONAL, 1},
         {  MASN1_TYPE_ENCODED, 0},
       /* recipientInfos:        RecipientInfos */
       { MASN1_TYPE_ENCODED, 0 },
       /* encryptedContentInfo:  EncryptedContentInfo */
       {  MASN1_TYPE_SEQUENCE, 3},
         /* contentType:                ContentType */
         {  MASN1_TYPE_OID, 0},
         /* contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier */
         {  MASN1_TYPE_SEQUENCE, 2},
           {  MASN1_TYPE_OID, 0},     /* ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier */
           {  MASN1_TYPE_OCTET_STRING, 0},
         /* encryptedContent: [0] IMPLICIT EncryptedContent OPTIONAL */
         {  MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0},
       /* unprotectedAttrs [1] IMPLICIT: UnprotectedAttributes OPTIONAL */
       {  MASN1_TYPE_SEQUENCE | MASN1_IMPLICIT | MASN1_OPTIONAL | 1 , 1},
         {  MASN1_TYPE_ENCODED, 0},
    };

    /* TLV with Raw data [rfc5652 - Section 6.1, page 18] */
    MAsn1TypeAndCount defRaw[2] =
    {
       {  MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT , 1},
          {  MASN1_TYPE_OCTET_STRING, 0},
    };

    /* TLV with Raw data (IMPLICIT) [rfc5652 - Section 6.1, page 18] */
    MAsn1TypeAndCount defRawImpl[1] =
    {
       {  MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT, 0},
    };

    status = DIGI_CALLOC ((void **)&pCtxE, 1, sizeof (MOC_CMS_EnvelopCtx));
    if (OK != status)
        goto exit;

    /* Create the 'array' crypto */
    status = MAsn1CreateElementArray (defCrypto, 13, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction, &(pCtxE->asnCrypto));
    if (OK != status)
        goto exit;

    /* Create the 'array' raw */
    status = MAsn1CreateElementArray (defRaw, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction, &(pCtxE->asnRaw));
    if (OK != status)
        goto exit;

    /* Create the 'array' raw */
    status = MAsn1CreateElementArray (defRawImpl, 1, MASN1_FNCT_DECODE,
                                      &MAsn1OfIndefFunction, &(pCtxE->asnRawImpl));
    if (OK != status)
        goto exit;

    /* Point to the sections within the ASN.1 template.
     * This allows us to change the template and contain all needed adjustments
     * to this function. */
    pCtxE->idxEnv = 2;
    pCtxE->idxCrypRecipient = 4;
    pCtxE->idxCrypDataOID = 6;
    pCtxE->idxCrypAlgo = 8;
    pCtxE->idxCrypIV   = 9;
    pCtxE->idxCrypRaw  = 10;

    /* Create collection of streaming data */
    status = DIGI_CMS_A_createCollectData (&(pCtxE->pRecipient),
                                          pCtxE->asnCrypto,
                                          pCtxE->asnCrypto + pCtxE->idxCrypRecipient);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxE->pPkgOid),
                                          pCtxE->asnCrypto,
                                          pCtxE->asnCrypto + pCtxE->idxCrypDataOID);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxE->pCryptoA),
                                          pCtxE->asnCrypto,
                                          pCtxE->asnCrypto + pCtxE->idxCrypAlgo);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_A_createCollectData (&(pCtxE->pCryptoI),
                                          pCtxE->asnCrypto,
                                          pCtxE->asnCrypto + pCtxE->idxCrypIV);
    if (OK != status)
        goto exit;

    pCtx->pUn = (MOC_CMS_TypeCtx*)pCtxE;
    pCtxE = NULL;

exit:
    if (NULL != pCtxE)
    {
        /* Clean up after error */
        DIGI_CMS_deleteEnvelopContext (pCtxE);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_deleteEnvelopContext(MOC_CMS_EnvelopCtx *pCtx)
{
    MSTATUS status = OK;

    if (NULL == pCtx)
    {
        goto exit;
    }

    if (NULL != pCtx->pRecipients)
    {
        sbyte4 idx;
        for (idx = 0; idx < pCtx->numRecipients; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pRecipients[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pRecipients));
    }
    if ((NULL != pCtx->pBulkCtx) && (NULL != pCtx->pBulkAlgo))
    {
        pCtx->pBulkAlgo->deleteFunc (MOC_SYM(pCtx->hwAccelCtx) &pCtx->pBulkCtx);
    }

    if (NULL != pCtx->held_data)
    {
        DIGI_FREE ((void**)&(pCtx->held_data));
    }

    DIGI_CMS_A_freeCollectData (&(pCtx->pCryptoI));
    DIGI_CMS_A_freeCollectData (&(pCtx->pCryptoA));
    DIGI_CMS_A_freeCollectData (&(pCtx->pPkgOid));
    DIGI_CMS_A_freeCollectData (&(pCtx->pRecipient));
    MAsn1FreeElementArray (&(pCtx->asnRaw));
    MAsn1FreeElementArray (&(pCtx->asnRawImpl));
    MAsn1FreeElementArray (&(pCtx->asnCrypto));

    /* Final free */
    status = DIGI_FREE ((void **)&pCtx);

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_decryptChunked(MOC_SYM(hwAccelDescr hwAccelCtx)
      encryptedContentType type,
      ubyte* encryptedInfo,
      ubyte4 encryptedInfoLen,
      MOC_CMS_CTX *pCtx,
      MOC_CMS_UpdateType update,
      ubyte** decryptedInfo,
      sbyte4* decryptedInfoLen)
{
    MSTATUS status = OK;

    ubyte* decryptedData = NULL;
    ubyte4 total, remain, toDecrypt = 0;
    ubyte lastByte;

    if ((NULL == encryptedInfo) || (0 == encryptedInfoLen))
    {
        goto exit; /* nothing to do */
    }

    /* Decrypt as much data as possible: The store data and the new
     * data that was passed in. */
    total = pCtx->pUn->env.last_size + encryptedInfoLen;

    if (pCtx->pUn->env.pBulkAlgo->blockSize)
    {
        /* The block size may change the total number we can decrypt at once */
        remain = total % pCtx->pUn->env.pBulkAlgo->blockSize;
        toDecrypt = total - remain;
    }
    else
    {
        remain = 0;
        toDecrypt = total;
    }

    /* Check if there is any data to decrypt */
    if (0 != toDecrypt)
    {
        status = DIGI_MALLOC ((void**)&decryptedData, toDecrypt);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (decryptedData,
                             pCtx->pUn->env.last,
                             pCtx->pUn->env.last_size);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY (decryptedData + pCtx->pUn->env.last_size,
                             encryptedInfo,
                             toDecrypt - pCtx->pUn->env.last_size);
        if (OK != status)
            goto exit;

        /* Adjust the length and pointer to what the 'last size' was,
         * which is the number of bytes we just prepended to the new data.
         */
        encryptedInfo += toDecrypt - pCtx->pUn->env.last_size;
        encryptedInfoLen -= toDecrypt - pCtx->pUn->env.last_size;
        /* Clear old size */
        pCtx->pUn->env.last_size = 0;

        status = pCtx->pUn->env.pBulkAlgo->cipherFunc (MOC_SYM(hwAccelCtx)
                                                       pCtx->pUn->env.pBulkCtx,
                                                       decryptedData,
                                                       toDecrypt, 0,
                                                       pCtx->pUn->env.iv);
        if (OK != status)
            goto exit;

        if ((TRUE == pCtx->pUn->env.last_done) &&
            (0 != pCtx->pUn->env.pBulkAlgo->blockSize))
        {
            /* Look at last byte for padding value */
            lastByte = decryptedData[total - 1];
            /* Is the value in a sane range? */
            if ((1 > lastByte) ||
                (lastByte > pCtx->pUn->env.pBulkAlgo->blockSize))
            {
                status = ERR_CRYPTO_BAD_PAD;
                goto exit;
            }
        }
        else
        {
            /* Always no padding */
            lastByte = 0;
        }

        /* Copy decrypted data buffer, dropping the 'last' bytes */
        *decryptedInfoLen = toDecrypt - lastByte;
        *decryptedInfo = decryptedData;
        decryptedData = NULL;
    }

    if (0 != remain)
    {
        status = DIGI_MEMCPY (pCtx->pUn->env.last + pCtx->pUn->env.last_size,
                             encryptedInfo,
                             encryptedInfoLen);
        if (OK != status)
            goto exit;
    }

    /* Set buffer length and clear unused bytes */
    pCtx->pUn->env.last_size = remain;
    DIGI_MEMSET (pCtx->pUn->env.last + pCtx->pUn->env.last_size, 0,
                pCtx->pUn->env.pBulkAlgo->blockSize - pCtx->pUn->env.last_size);

exit:
    
    if (NULL != decryptedData)
    {
        (void) DIGI_MEMSET_FREE(&decryptedData, toDecrypt);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_Sig_getHashAlgos(MOC_CMS_CTX *pCtx,
                         ubyte* pData,
                         ubyte4 dataLen)
{
    MSTATUS status = OK;

    /* DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier */
    /* DigestAlgorithmIdentifier ::= AlgorithmIdentifier */
    /* AlgorithmIdentifier sequence [rfc5280 - Section 4.1.1.2, page 17] */
    MAsn1TypeAndCount def[4] =
    {
      {   MASN1_TYPE_SET_OF, 1},
        {   MASN1_TYPE_SEQUENCE, 2},
        /* algorithm:               OBJECT IDENTIFIER */
        {   MASN1_TYPE_OID, 0},
        /* parameters:              ANY DEFINED BY algorithm OPTIONAL */
        {   MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0},
    };

    MAsn1Element *pRootHash = NULL;
    ubyte4       bytesRead;
    ubyte4       hashes = 0;

    MAsn1Element *pElement = NULL;
    ubyte4       numHash = 0;

    status = MAsn1CreateElementArray (def, 4,
                                      MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootHash);
    if (OK != status)
        goto exit;

    /* Decode SET from memory array */
    status = MAsn1Decode (pData,
                          dataLen,
                          pRootHash, &bytesRead);
    if (OK != status)
        goto exit;

    /* Read hash OID */
    /* Access 'SET_OF' element at index 0, if it exists */
    status = MAsn1GetOfElementAtIndex (pRootHash,
                                       numHash,
                                       &pElement);
    if (OK != status)
        goto exit;

    while (NULL != pElement)
    {
        /* Read OID and add 'bit' to 'hashes', if recognized */
        status = DIGI_CMS_U_getDigestAlgorithmHash (pElement + 1,
                                                   &hashes);
        if (OK != status)
            goto exit;
#ifdef __ENABLE_DIGICERT_RE_SIGNER__
        /* Save the hashType here so that we may add it back in when re-signing */
        ubyte4  hashType = 0;
        CMS_ResignData_CTX RSCtx = DIGI_CMS_getResignCtx(pCtx);

        if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
        {
            status = DIGI_CMS_U_getHashAlgoIdFromHashAlgoOID(pElement + 1,
                                                            &hashType);
            if (OK == status)
            {
                CMS_RESIGN_setExtractedSignatureHashType(RSCtx, hashType);
            }
        }

#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

        /* Access 'SET_OF' element at next index, if it exists */
        ++numHash;
        status = MAsn1GetOfElementAtIndex (pRootHash,
                                           numHash,
                                           &pElement);
        if (OK != status)
            goto exit;
    }

    /* Use full bit set to create actual digest hash array */
    status = DIGI_CMS_U_constructHashes (MOC_HASH(pCtx->hwAccelCtx) hashes,
                                        &(pCtx->pUn->sign.numAlgos),
                                        &(pCtx->pUn->sign.pHashes));

exit:
    MAsn1FreeElementArray (&pRootHash);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_Sig_hashDataChunked(MOC_CMS_CTX *pCtx,
                            ubyte* data,
                            ubyte4 dataLen)
{
    MSTATUS status = OK;
    ubyte4  i;

    if (TRUE == pCtx->pUn->sign.hashesDone)
    {
        goto exit;
    }

    if (0 != dataLen)
    {
        /* feed the data to all the hashes */
        for (i = 0; i < pCtx->pUn->sign.numAlgos; ++i)
        {
            MOC_CMS_SignedDataHash* pHash = (pCtx->pUn->sign.pHashes) + i;
            status = pHash->hashAlgo->updateFunc (MOC_HASH(pCtx->hwAccelCtx)
                                                  pHash->bulkCtx,
                                                  data, dataLen);
            if (OK != status)
                goto exit;
        }
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_Sig_hashDataFinal(MOC_CMS_CTX *pCtx,
                           ubyte* data,
                           ubyte4 dataLen)
{
    ubyte4  i;

    if (TRUE == pCtx->pUn->sign.hashesDone)
    {
        goto exit;
    }

    /* Feed the data to all the hashes */
    for (i = 0; i < pCtx->pUn->sign.numAlgos; ++i)
    {
        MOC_CMS_SignedDataHash* pHash = (pCtx->pUn->sign.pHashes) + i;
        if (0 < dataLen)
        {
            pHash->hashAlgo->updateFunc (MOC_HASH(pCtx->hwAccelCtx)
                                         pHash->bulkCtx,
                                         data, dataLen);
        }

        pHash->hashAlgo->finalFunc (MOC_HASH(pCtx->hwAccelCtx)
                                    pHash->bulkCtx,
                                    pHash->hashData);
    }

    pCtx->pUn->sign.hashesDone = TRUE;

exit:
    return OK;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_verifySignatures(MOC_CMS_CTX *pCtx,
                         ubyte* pSigData, ubyte4 sigDataLen,
                         ubyte4 numHashes,
                         MOC_CMS_SignedDataHash* pSignedDataHash,
                         const void* callbackArg,
                         const MOC_CMS_Callbacks *cb,
                         ubyte4* pNumSigners,
                         ubyte4* pNumValidSigs,
                         MOC_CMS_MsgSignInfo **ppSigInfos)
{
    MSTATUS status = OK;

    ubyte4       numValidSigners = 0;
    ubyte4       totalSignatures;
    MAsn1Element *pSignerInfoCertificate = NULL;
    ubyte        *pExternalCert = NULL;
    ubyte4       externalCertLen = 0;
    ubyte4       bytesRead;

    MAsn1TypeAndCount defSet[2] =
    {
      /* SignerInfos: SET OF SignerInfo with 0 or more elements [rfc5652 - Section 5.1, page 8] */
      {   MASN1_TYPE_SET_OF, 1},
        {   MASN1_TYPE_ENCODED, 0},
    };

    /* Sequence with Signer Info [rfc5652 - Section 5.3, page 13] */
    MAsn1TypeAndCount defSign[10] =
    {
      {   MASN1_TYPE_SEQUENCE, 7},
        /* version:          CMSVersion */
        {   MASN1_TYPE_INTEGER, 0},
        /* sid:              SignerIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* digestAlgorithm:  DigestAlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signedAttrs [0] IMPLICIT: SignedAttributes OPTIONAL */
        {   MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT | MASN1_OPTIONAL, 1},
          {   MASN1_TYPE_ENCODED, 0},
        /* signatureAlgorithm: SignatureAlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signature:     SignatureValue */
        {   MASN1_TYPE_OCTET_STRING, 0},
        /* unsignedAttrs [1] IMPLICIT: UnsignedAttributes OPTIONAL */
        {   MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT | MASN1_OPTIONAL | 1, 1},
          {   MASN1_TYPE_ENCODED, 0},
    };

    /* Generic structure expected from external X509 cert data [rfc5280 - Section 4.1, page 16] */
    MAsn1TypeAndCount defCert[4] =
    {
      {   MASN1_TYPE_SEQUENCE, 3},
        /* tbsCertificate:       TBSCertificate */
        {   MASN1_TYPE_ENCODED, 0},
        /* signatureAlgorithm:   AlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signatureValue:       BIT STRING */
        {   MASN1_TYPE_ENCODED, 0},
    };

    MAsn1Element *pRootSet = NULL;
    MAsn1Element *pRootSign = NULL;
    MAsn1Element *pElement = NULL;

    MOC_CMS_MsgSignInfo *pSigInfos = NULL;
    ubyte4              numSigners = 0;

    status = MAsn1CreateElementArray (defSet, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootSet);
    if (OK != status)
        goto exit;

    /* Decode 1st SET from memory array */
    status = MAsn1Decode (pSigData, sigDataLen,
                          pRootSet, &bytesRead);
    if (OK != status)
        goto exit;

    /* Access 'SET_OF' element at index 0, if it exists */
    status = MAsn1GetOfElementAtIndex (pRootSet, numSigners,
                                       &pElement);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    /* When we are re-signing, add the saved signature block to the output
     * and then clear it after use so that we only add it once.            */
    ubyte *pSignature = NULL;
    ubyte *pSigPrev = NULL;
    ubyte4 sigLen = 0;
    CMS_ResignData_CTX RSCtx = DIGI_CMS_getResignCtx (pCtx);
#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

    while (NULL != pElement)
    {
        status = MAsn1CreateElementArray (defSign, 10, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pRootSign);
        if (OK != status)
            goto exit;

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
        if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
        {
            pSigPrev = pSignature;
            status = DIGI_MALLOC((void**)&pSignature,
                                    pElement[0].valueLen+sigLen); /* Poss Grow */
            if (OK != status)
                goto exit;

            if ((pSigPrev != NULL) && (sigLen != 0))
            {
                status = DIGI_MEMCPY (pSignature, pSigPrev, sigLen); /* Copy old one */
                if (OK != status)
                    goto exit;
                DIGI_FREE((void**)&pSigPrev);

            }
            status = DIGI_MEMCPY (pSignature+sigLen,
                                 pElement[0].value.pValue,
                                 pElement[0].valueLen); /* Copy new one */
            sigLen += pElement[0].valueLen;
            if (OK != status)
                goto exit;

            /* For the new CMS encoder */
            CMS_RESIGN_addRawSignature (RSCtx, pElement[0].value.pValue, pElement[0].valueLen);
        }
#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

        status = MAsn1Decode (pElement[0].value.pValue, pElement[0].valueLen,
                              pRootSign, &bytesRead);
        if (OK != status)
            goto exit;

        /* Count signer entry */
        ++numSigners;

        /* Access 'SET_OF' element at next index, if it exists */
        status = MAsn1GetOfElementAtIndex (pRootSet, numSigners,
                                           &pElement);
        if (OK != status)
            goto exit;

        MAsn1FreeElementArray(&pRootSign);
    }

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
    {
        const ubyte* pCerts = NULL;
        ubyte4 certsLen;

        status = DIGI_CMS_getCertificates (pCtx, &pCerts, &certsLen);
        if (OK != status)
            goto exit;

        if ((NULL != pCerts) &&
            (0 < certsLen))
        {
            /* Transfer certificate(s) to resigner context */
            status = CMS_RESIGN_setExtractedCertificates (RSCtx, pCerts, certsLen);
            if (OK != status)
                goto exit;
        }

        if ((pSignature != NULL) && (sigLen != 0))
        {
            status = CMS_RESIGN_setExtractedSignature (RSCtx, pSignature, sigLen);
            if (OK > status)
            {
                DIGI_FREE ((void**)&pSignature);
                goto exit;
            }

            DIGI_FREE ((void**)&pSignature);
            sigLen = 0;
        }
    }
#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

    if (NULL != ppSigInfos)
    {
        status = DIGI_CALLOC((void**)&pSigInfos, numSigners, sizeof(MOC_CMS_MsgSignInfo));
        if (OK != status)
            goto exit;
    }

    for (totalSignatures = 0; totalSignatures < numSigners; ++totalSignatures)
    {
        MAsn1Element *pSignerIdentifier = NULL;
        MAsn1Element *pSignature = NULL;
        ubyte        cmsVersion = 0;

        /* Access 'SET_OF' element at index */
        status = MAsn1GetOfElementAtIndex (pRootSet, totalSignatures,
                                           &pElement);
        if (OK != status)
            goto exit;

        status = MAsn1CreateElementArray (defSign, 10, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pRootSign);
        if (OK != status)
            goto exit;
        status = MAsn1Decode (pElement[0].value.pValue,
                              pElement[0].valueLen,
                              pRootSign,
                              &bytesRead);
        if (OK != status)
            goto exit;

        pSignerIdentifier = pRootSign + 2;
        pSignature = pRootSign + 7;

        /* Read version 1 -> Issuer and Serial Number
         *              3 -> Subject key identifier
         *              [rfc-5652 - Section 5.3, page 14] */
        cmsVersion = pRootSign[1].value.pValue[0];

        /* Access to certificate via callback */
        status = DIGI_CMS_getSignerCert (cmsVersion, pSignerIdentifier,
                                        callbackArg, cb,
                                        &pExternalCert, &externalCertLen);
        if (OK != status)
            goto exit;

        /* Decode outer structure of X509 certificate data */
        status = MAsn1CreateElementArray (defCert, 4, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pSignerInfoCertificate);
        if (OK != status)
            goto exit;

        if ((NULL != pExternalCert) &&
            (0 != externalCertLen))
        {
            ubyte4 bytesRead2;
            status = MAsn1Decode (pExternalCert, externalCertLen,
                                  pSignerInfoCertificate, &bytesRead2);
            if (OK != status)
                goto exit;

            /* Verify signer data */
            status = DIGI_CMS_U_processSignerInfoWithCert (MOC_ASYM(pCtx->hwAccelCtx) pRootSign, pSignerInfoCertificate,
                                                          pSignature,
                                                          numHashes, pSignedDataHash,
                                                          (pSigInfos) ? pSigInfos + numValidSigners : NULL);
            if (OK != status)
                goto exit;

            /* Validate Certificate */
            status = DIGI_CMS_validateCertificate (pSignerInfoCertificate,
                                                  (pSigInfos) ? pSigInfos + numValidSigners : NULL,
                                                  callbackArg, cb->valCertFun);
            if (OK != status)
            {
                status = ERR_PKCS7_UNKNOWN_CERTIFICATE_AUTHORITY;
            }
        }
        else
        {
            status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
        }

        if (OK == status)
        {
            ++numValidSigners;
        }
        else
        {
            /* Clean up returned data */
            if (NULL != pSigInfos)
            {
                if (NULL != pSigInfos[numValidSigners].pASN1)
                {
                    DIGI_FREE ((void**)&(pSigInfos[numValidSigners].pASN1));
                }
                if (NULL != pSigInfos[numValidSigners].pMsgSigDigest)
                {
                    DIGI_FREE ((void**)&(pSigInfos[numValidSigners].pMsgSigDigest));
                }
                if (NULL != pSigInfos[numValidSigners].pSigningTime)
                {
                    DIGI_FREE ((void**)&(pSigInfos[numValidSigners].pSigningTime));
                }
            }
            
            if ((ERR_PKCS7_UNKNOWN_CERTIFICATE_AUTHORITY != status) &&
                (ERR_PKCS7_INVALID_SIGNATURE != status))
            {
                break; /* fatal error */
            }
        }

        DIGI_FREE ((void**)&pExternalCert);
        MAsn1FreeElementArray (&pSignerInfoCertificate);
        MAsn1FreeElementArray (&pRootSign);
    }

    if ((0 == numValidSigners) &&
        (OK == status))
    {
        status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
    }

    /* Success, copy results */
    *pNumSigners = numSigners;
    *pNumValidSigs = numValidSigners;
    if (NULL != ppSigInfos)
    {
        *ppSigInfos = pSigInfos;
    }
    pSigInfos = NULL;

exit:
    if (NULL != pSigInfos)
    {
        DIGI_FREE ((void**)&pSigInfos);
    }
    if (NULL != pExternalCert)
    {
        DIGI_FREE ((void**)&pExternalCert);
    }
    MAsn1FreeElementArray (&pSignerInfoCertificate);
    MAsn1FreeElementArray (&pRootSign);
    MAsn1FreeElementArray (&pRootSet);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_getSignerCert(ubyte cmsVersion,
                      MAsn1Element* pSigner,
                      const void* callbackArg,
                      const MOC_CMS_Callbacks *cb,
                      ubyte** ppExternalCert,
                      ubyte4* pExternalCertLen)
{
    MSTATUS      status = OK;
    MAsn1Element *pRootSig = NULL;
    ubyte4       bytesRead;

    if (1 == cmsVersion)
    {
        /* IssuerAndSerialNumber structure [rfc5652 - Section 10.2.4, page 38] */
        MAsn1TypeAndCount sigSet[3] =
        {
          { MASN1_TYPE_SEQUENCE, 2},
             /* issuer:       Name */
             {  MASN1_TYPE_ENCODED, 0},
             /* serialNumber: CertificateSerialNumber */
             {  MASN1_TYPE_INTEGER, 0},
        };

        status = MAsn1CreateElementArray (sigSet, 3, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pRootSig);
        if (OK != status)
            goto exit;

        /* Decode IssuerAndSerialNumber from memory array */
        status = MAsn1Decode (pSigner[0].value.pValue, pSigner[0].valueLen,
                              pRootSig, &bytesRead);
        if (OK != status)
            goto exit;

        /* Did we find valid data? */
        if ((NULL == pRootSig[1].value.pValue) ||
            (NULL == pRootSig[2].value.pValue))
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }

        if (NULL != cb && NULL != cb->getCertFun)
        {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
            if (VERBOSE_DEBUG)
            {
                DEBUG_CONSOLE_printf("MOC_CMS_GetSignerCert: Calling 'getCertFun'\n");
            }
#endif
            status = cb->getCertFun(callbackArg,
                                    pRootSig[2].value.pValue,
                                    pRootSig[2].valueLen,
                                    pRootSig[1].value.pValue,
                                    pRootSig[1].valueLen,
                                    ppExternalCert,
                                    pExternalCertLen);
            if (OK != status)
                goto exit;
        }
    }
    else if (3 == cmsVersion)
    {
        /* SubjectKeyIdentifier structure */
        MAsn1TypeAndCount ski[1] =
        {
          { MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT, 0},
        };

        status = MAsn1CreateElementArray (ski, 1, MASN1_FNCT_DECODE,
                                          &MAsn1OfFunction, &pRootSig);
        if (OK != status)
            goto exit;

        /* Decode IssuerAndSerialNumber from memory array */
        status = MAsn1Decode (pSigner[0].value.pValue, pSigner[0].valueLen,
                              pRootSig, &bytesRead);
        if (OK != status)
            goto exit;

        /* Did we find valid data? */
        if (NULL == pRootSig[0].value.pValue)
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }

        if (NULL != cb && NULL != cb->getCertFunV3)
        {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
            if (VERBOSE_DEBUG)
            {
                DEBUG_CONSOLE_printf("MOC_CMS_GetSignerCert: Calling 'getCertFunV3'\n");
            }
#endif
            status = cb->getCertFunV3(callbackArg,
                                      pRootSig[0].value.pValue,
                                      pRootSig[0].valueLen,
                                      ppExternalCert,
                                      pExternalCertLen);
            if (OK != status)
                goto exit;
        }
    }
    else /* only 1 and 3 are supported */
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

exit:
    MAsn1FreeElementArray (&pRootSig);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_validateCertificate(MAsn1Element* pCert,
                            MOC_CMS_MsgSignInfo *pSigInfo,
                            const void* callbackArg,
                            MOC_CMS_ValidateRootCertificate valCertFun)
{
    MSTATUS      status = OK;
    MAsn1Element *pCurrentCertificate = pCert;

    if (NULL == valCertFun)
    {
        status = ERR_PKCS7_NO_CERT_VALIDATION_CALLBACK;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (VERBOSE_DEBUG)
    {
        DEBUG_CONSOLE_printf("MOC_CMS_ValidateCertificate: Calling 'valCertFun'\n");
    }
#endif

    status = valCertFun (callbackArg,
                         pCurrentCertificate->encoding.pEncoding,
                         pCurrentCertificate->encodingLen,
                         pSigInfo);
exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_processEnvelopAlgo(MOC_CMS_CTX *pCtx,
                           ubyte* pCryptoData,
                           ubyte4 cryptoDataLen)
{
    MSTATUS status = OK;

    ubyte  *pSymmetricKey = NULL;
    ubyte4 symmetricKeyLen = 0;

    /* Decrypt symmetric key data */
    status = DIGI_CMS_processRecipientInfos (MOC_HW(pCtx->hwAccelCtx) pCryptoData,
                                            cryptoDataLen,
                                            pCtx->cbArg,
                                            pCtx->cb->getPrivKeyFun,
                                            pCtx->cb->getPrivKeyFunEx,
                                            &pSymmetricKey,
                                            &symmetricKeyLen,
                                            &pCtx->pUn->env.pRecipients,
                                            &pCtx->pUn->env.numRecipients);
    if (OK != status)
       goto exit;

    if ((NULL == pSymmetricKey) ||
        (0 >= symmetricKeyLen))
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("MOC_CMS_ProcessEnvelopAlgo - NO_RECIPIENT: (1)\n");
        }
#endif
        status = ERR_PKCS7_NO_RECIPIENT_KEY_MATCH;
        goto exit;
    }

    status = DIGI_CMS_U_getBulkAlgo (MOC_SYM(pCtx->hwAccelCtx) pCtx->pUn->env.pCryptoA->pKeepData,
                                    pCtx->pUn->env.pCryptoA->keepDataLen,
                                    pCtx->pUn->env.pCryptoI->pKeepData,
                                    pCtx->pUn->env.pCryptoI->keepDataLen,
                                    pSymmetricKey, symmetricKeyLen,
                                    pCtx->pUn->env.iv,
                                    &(pCtx->pUn->env.pBulkCtx),
                                    &(pCtx->pUn->env.pBulkAlgo));
    if (OK != status)
       goto exit;

#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (VERBOSE_DEBUG)
    {
        DEBUG_CONSOLE_printf("MOC_CMS_ProcessEnvelopAlgo - RECIPIENT\n");
    }
#endif

exit:
    if (NULL != pSymmetricKey)
    {
        DIGI_FREE ((void**)&pSymmetricKey);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_processRecipientInfos(MOC_HW(hwAccelDescr hwAccelCtx) ubyte* pData,
                              ubyte4 dataLen,
                              const void* callbackArg,
                              MOC_CMS_GetPrivateKey getPrivateKeyFun,
                              MOC_CMS_GetPrivateKeyEx getPrivateKeyFunEx,
                              ubyte** ppSymmetricKey,
                              ubyte4* pSymmetricKeyLen,
                              MOC_CMS_RecipientId*** ppRec,
                              sbyte4* recipientIndex)
{
    MSTATUS status = OK;

    ubyte4       bytesRead;
    MAsn1Element *pElement = NULL;
    ubyte4       counter = 0;

    MOC_CMS_RecipientId* pRec;

    MAsn1Element *pRootInfo = NULL;
    MAsn1Element *pRootTransKey = NULL;
    MAsn1Element *pRootAgreeKey = NULL;

    /* SET SIZE (1..MAX) OF RecipientInfo [rfc5652 - Section 6.1, page 18]*/
    MAsn1TypeAndCount defList[2] =
    {
      {   MASN1_TYPE_SET_OF, 1},
        {   MASN1_TYPE_ENCODED , 0},
    };

    /* RecipientInfo choice [rfc5652 - Section 6.2, page 20] */
    /*       RecipientInfo ::= CHOICE {
    **          ktri      KeyTransRecipientInfo,
    **          kari  [1] KeyAgreeRecipientInfo,
    **          kekri [2] KEKRecipientInfo,
    **          pwri  [3] PasswordRecipientinfo,
    **          ori   [4] OtherRecipientInfo }
     */

    /* Choice 'NO_TAG': KeyTransRecipientInfo sequence */
    MAsn1TypeAndCount defTransInfo[1] =
    {
        {   MASN1_TYPE_ENCODED , 0},
    };

    /* Choice 1: KeyAgreeRecipientInfo sequence */
    MAsn1TypeAndCount defAgreeInfo[1] =
    {
        {   MASN1_TYPE_ENCODED | MASN1_EXPLICIT | 1, 0},
    };

    status = MAsn1CreateElementArray (defList, 2, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootInfo);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defTransInfo, 1, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootTransKey);
    if (OK != status)
        goto exit;

    status = MAsn1CreateElementArray (defAgreeInfo, 1, MASN1_FNCT_DECODE,
                                      &MAsn1OfFunction, &pRootAgreeKey);
    if (OK != status)
        goto exit;

    status = MAsn1Decode (pData,
                          dataLen,
                          pRootInfo,
                          &bytesRead);
    if (OK != status)
        goto exit;

    /* Start loop over elements */
    status = MAsn1GetOfElementAtIndex (pRootInfo,
                                       counter,
                                       &pElement);
    if (OK != status)
        goto exit;

    /* Check what is inside the SET */
    while (NULL != pElement)
    {
        pRec = NULL;

        /* Try CHOICE [1], first */
        status = MAsn1Decode (pElement[0].encoding.pEncoding,
                              pElement[0].encodingLen,
                              pRootAgreeKey,
                              &bytesRead);
        if (OK != status)
        {
            /* Try CHOICE SEQ, last */
            status = MAsn1Decode (pElement[0].encoding.pEncoding,
                                  pElement[0].encodingLen,
                                  pRootTransKey,
                                  &bytesRead);
            if (OK != status)
            {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
                if (VERBOSE_DEBUG)
                {
                    DEBUG_CONSOLE_printf("MOC_CMS_ProcessRecipientInfos - ASN1 no match\n");
                }
#endif
                goto exit;
            }

            /* Decode 'Trans' content encryption key */
            status = DIGI_CMS_U_processKeyTransRecipientInfo(MOC_HW(hwAccelCtx) pElement,
                                                            callbackArg,
                                                            getPrivateKeyFun,
                                                            getPrivateKeyFunEx,
                                                            ppSymmetricKey,
                                                            pSymmetricKeyLen,
                                                            &pRec);
            /* Found a match? */
            if (OK == status)
                goto finish;
        }
        else
        {
            /* Decode 'Agree' content encryption key */
            status = DIGI_CMS_U_processKeyAgreeRecipientInfo(MOC_HW(hwAccelCtx) pElement,
                                                            callbackArg,
                                                            getPrivateKeyFun,
                                                            getPrivateKeyFunEx,
                                                            ppSymmetricKey,
                                                            pSymmetricKeyLen,
                                                            &pRec);
            /* Found a match? */
            if (OK == status)
                goto finish;
        }

        /* Next entry in SETOF */
        ++counter;
        status = MAsn1GetOfElementAtIndex(pRootInfo,
                                          counter,
                                          &pElement);
        if (OK != status)
            goto exit;
    }

    /* No match found */
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
    if (VERBOSE_DEBUG)
    {
        DEBUG_CONSOLE_printf("MOC_CMS_ProcessRecipientInfos - NO_RECIPIENT: (2)\n");
    }
#endif
    status = ERR_PKCS7_NO_RECIPIENT_KEY_MATCH;
    goto exit;

    /* Found a recipient, when status is OK */
finish:
    if (OK == status)
    {
#ifdef __ENABLE_DIGICERT_DEBUG_CONSOLE__
        if (VERBOSE_DEBUG)
        {
            DEBUG_CONSOLE_printf("MOC_CMS_ProcessRecipientInfos - RECIPIENT\n");
        }
#endif
        /* Add returned recipient info to list, if requested */
        if (NULL != ppRec)
        {
            MOC_CMS_RecipientId** tmpOld = *ppRec;
            ubyte4 lenOld = *recipientIndex;
            MOC_CMS_RecipientId** array = NULL;

            status = DIGI_MALLOC ((void**)&array,
                                 (lenOld + 1)*sizeof (MOC_CMS_RecipientId*));
            if (OK != status)
                goto exit;

            if (NULL != tmpOld)
            {
                status = DIGI_MEMCPY (array, tmpOld,
                                     lenOld*sizeof (MOC_CMS_RecipientId*));
                DIGI_FREE ((void**)&tmpOld);

                if (OK != status)
                {
                    DIGI_FREE((void**) &array);
                    goto exit;
                }
            }
            array[lenOld] = pRec;
            *ppRec = array;
        }

        *recipientIndex = *recipientIndex + 1;
    }

exit:
    MAsn1FreeElementArray(&pRootAgreeKey);
    MAsn1FreeElementArray(&pRootTransKey);
    MAsn1FreeElementArray(&pRootInfo);
    return status;
}

#endif  /* (defined(__ENABLE_DIGICERT_CMS__) && !defined(__DISABLE_DIGICERT_CMS_DECODER__)) */
