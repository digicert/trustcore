/*
 * moccms_encode.c
 *
 * CMS API Implementation for Encoding
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

#include "../crypto/moccms_encode.h"

#if (defined(__ENABLE_DIGICERT_CMS__) && !defined(__DISABLE_DIGICERT_CMS_ENCODER__))

/* Add more output to debug console when set to '(1)' */
#define VERBOSE_DEBUG (0)

/************************************************************************/

/* OID: 1.2.840.113549.1.7.1 */
static ubyte CMS_OUTER_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
static ubyte4 CMS_OUTER_DATA_LEN = 11;

/* OID: 1.2.840.113549.1.7.2 */
static ubyte CMS_OUTER_SIGNED_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02 };
static ubyte4 CMS_OUTER_SIGNED_DATA_LEN = 11;

/* OID: 1.2.840.113549.1.7.3 */
static ubyte CMS_OUTER_ENVELOPE_DATA[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 };
static ubyte4 CMS_OUTER_ENVELOPE_DATA_LEN = 11;

/* OID: 1.2.840.113549.1.9.3 */
static ubyte PKCS9_CONTENT_TYPE[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03 };
static ubyte4 PKCS9_CONTENT_TYPE_LEN = 11;

/* OID: 1.2.840.113549.1.9.4 */
static ubyte PKCS9_MESSAGE_DIGEST[] =
{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04 };
static ubyte4 PKCS9_MESSAGE_DIGEST_LEN = 11;

/************************************************************************/

/* Internal Writing Helper Functions */

/** Create the ASN1 data for a CMS structure that contains certificates for the given context,
 *  which represents a 'signed' CMS message.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 *  @param pMem       A pointer to the CMS memory cache, which is used to keep the ASN1 memory
 *                    reference until the CMS data is finalized.
 *  @param pCtx       A pointer to the context instance to be used.
 *  @param pOut       A pointer to an \c MAsn1Element that will reference the ASN1 data as encoded
 *                    by this function. It can be part of a larger ASN1 'template'.
 *  @param pSet       A pointer to an \c intBoolean. It will be set to \c TRUE, when there is any data
 *                    encoded into the ASN1, and it will be set to \c FALSE, when there are no
 *                    certificates stored in the ASN1.
 */
static MSTATUS
DIGI_CMS_writeCerts(MOC_CMS_ASN1_Memory   *pMem,
                   MOC_CMS_OUT_SignedCtx *pCtx,
                   MAsn1Element          *pOut,
                   intBoolean            *pSet);

/** Create the ASN1 data for a CMS structure that contains CRLs for the given context,
 *  which represents a 'signed' CMS message.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 *  @param pMem       A pointer to the CMS memory cache, which is used to keep the ASN1 memory
 *                    reference until the CMS data is finalized.
 *  @param pCtx       A pointer to the context instance to be used.
 *  @param pOut       A pointer to an \c MAsn1Element that will reference the ASN1 data as encoded
 *                    by this function. It can be part of a larger ASN1 'template'.
 *  @param pSet       A pointer to an \c intBoolean. It will be set to \c TRUE, when there is any data
 *                    encoded into the ASN1, and it will be set to \c FALSE, when there are no
 *                    CRLs stored in the ASN1.
 */
static MSTATUS
DIGI_CMS_writeCRLs(MOC_CMS_ASN1_Memory   *pMem,
                  MOC_CMS_OUT_SignedCtx *pCtx,
                  MAsn1Element          *pOut,
                  intBoolean            *pSet);

/** Stream more CMS data for the given context to a buffer and return it to
 *  the caller.
 *
 *  @param pCtx        A pointer to the context instance to be used.
 *  @param ppData      The ASN1 data buffer with (more) CMS data.
 *  @param pDataLen    The length of the CMS data in bytes.
 *  @param pIsComplete Signals that this is the last CMS data being streamed, when set
 *                     to \c TRUE.
 */
static MSTATUS
DIGI_CMS_updateEncoder(MOC_CMS_OUT_CTX *pCtx,
                      ubyte           **ppData,
                      ubyte4          *pDataLen,
                      intBoolean      *pIsComplete);

/** Create the digest value authenticating the attributes in a \c MOC_CMS_SignerCtx. It is
 *  returned as a \c ubyte array, and the size of the array is determined by the algorithm
 *  specified in the \c MOC_CMS_SignedDataHash instance.
 *
 *  @param pMem      A pointer to the CMS memory cache, which is used to keep the ASN1 memory
 *                   reference until the CMS data is finalized.
 *  @param pCtx      A pointer to the \c MOC_CMS_SignerCtx instance.
 *  @param pHash     A pointer to the \c MOC_CMS_SignedDataHash instance.
 *  @param pAttr     A pointer to the \c MAsn1Element that will contain the 'attribute' set
 *                   encoded as ASN1.
 *  @param ppHashOut A pointer to an array variable. It will be set to point to memory containing
 *                   The hash digest value for all attributes.
 */
static MSTATUS
DIGI_CMS_signAttributes(MOC_HASH(hwAccelDescr hwAccelCtx)
                       MOC_CMS_ASN1_Memory    *pMem,
                       MOC_CMS_SignerCtx      *pCtx,
                       MOC_CMS_SignedDataHash *pHash,
                       MAsn1Element           *pAttr,
                       ubyte                  **ppHashOut);

/** Create ASN1 data representing CMS 'SignerInfo' items for the given context,
 *  which represents a 'signed' CMS message. The data will be stored in the ASN1
 *  template instance held by the context.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 *  @param pCtx       A pointer to the context instance to be used.
 */
static MSTATUS
DIGI_CMS_writeSignerInfos(MOC_CMS_OUT_CTX *pCtx);

/** Create ASN1 data representing a single CMS 'SignerInfo' for the given
 *  data. The values to be encoded will be stored in the ASN1 template instances
 *  passed to this function.
 *  <p>This function will fail, if the context does not process a 'signed' CMS.
 *
 *  @param pSigner     Pointer to the 'MOC_CMS_SignerCtx' instance to be read.
 *  @param pHash       Pointer to the 'MOC_CMS_SignedDataHash' instance to be read.
 *  @param pSID        Pointer to the ASN1 element in which to store the 'signer id' data.
 *  @param pDigestAlgo Pointer to the ASN1 element in which to store the 'digest algorithm id' data.
 *  @param pSigAlgo    Pointer to the ASN1 element in which to store the 'SignatureAlgorithmIdentifier'.
 *  @param pSig        Pointer to the ASN1 element in which to store the 'Signature Value' (OCTET).
 */
static MSTATUS
DIGI_CMS_writeSignerInfo(MOC_CMS_ASN1_Memory *pMem,
                        RNGFun rngFun, void* rngArg,
                        MOC_CMS_SignerCtx   *pSigner,
                        MOC_CMS_SignedDataHash *pHash,
                        ubyte        *pExternHash,
                        MAsn1Element *pSID,
                        MAsn1Element *pDigestAlgo,
                        MAsn1Element *pSigAlgo,
                        MAsn1Element *pSig);

static MSTATUS
DIGI_CMS_writeRecipientInfos(MOC_HW(hwAccelDescr hwAccelCtx)
                            MOC_CMS_ASN1_Memory    *pMem,
                            MOC_CMS_OUT_EnvelopCtx *pEnv,
                            MAsn1Element           *pRec,
                            MAsn1Element           *pCur);

/* Cryptographic Helper Functions */

static MSTATUS
DIGI_CMS_encryptChunked(MOC_SYM(hwAccelDescr hwAccelCtx)
                       const ubyte   *data,
                       ubyte4  dataLen,
                       MOC_CMS_OUT_CTX *pCtx,
                       ubyte   **encryptedInfo,
                       sbyte4  *encryptedInfoLen);

static MSTATUS
DIGI_CMS_encryptFinal(MOC_SYM(hwAccelDescr hwAccelCtx)
                     MOC_CMS_OUT_CTX *pCtx,
                     ubyte   **encryptedInfo,
                     sbyte4  *encryptedInfoLen);

/** Function to read all 'MOC_CMS_SignerCtx' instances and create the needed
 *  hash digest instances.
 *  <p>The context contains the array 'pSigners' that represents all signers;
 *  <p>This function will call 'DIGI_CMS_U_constructHashes' to construct each needed hash.
 *  <p>The hash instances are stored in the given context.
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_OUT_CTX' instance to be used.
 */
static MSTATUS
DIGI_CMS_OUT_Sig_getHashAlgos(MOC_CMS_OUT_CTX *pCtx);

/** Pass new data to the hash algorithm(s) in the given context.
 *  <p>If this data chunk is the last one, you MUST use 'MOC_CMS_Sig_hashDataFinal', instead!
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_OUT_CTX' instance to be used.
 *  @param pData   A pointer to the (next) payload data.
 *  @param dataLen The length of the data.
 *
 */
static MSTATUS
DIGI_CMS_OUT_Sig_hashDataChunked(MOC_CMS_OUT_CTX *pCtx,
                                const ubyte* data,
                                ubyte4 dataLen);

/** Pass final data to the hash algorithm(s) in the given context.
 *  <p>If this data chunk is NOT the last one, you MUST use 'MOC_CMS_Sig_hashDataChunked',
 *     instead!
 *
 *  @param pCtx    A pointer to the 'MOC_CMS_OUT_CTX' instance to be used.
 *  @param pData   A pointer to the final payload data.
 *  @param dataLen The length of the data.
 *
 */
static MSTATUS
DIGI_CMS_OUT_Sig_hashDataFinal(MOC_CMS_OUT_CTX *pCtx,
                              const ubyte *pData,
                              ubyte4 dataLen);

/*----------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_RE_SIGNER__

/**
 * Install an instance of 'CMS_ResignData_CTX' into the CMS_context
 * This function adds a pointer to an object in which MOC_CMS will save extracted
 * CMS info to be used when Re-signing CMS messages.
 * Note: This is only needed by ump.c & ummaker.c when re-signing, so we are not
 * including it in header files.
 */
MOC_EXTERN void DIGI_CMS_OUT_setResignCtx(MOC_CMS_context pContext, CMS_ResignData_CTX ctx);

MOC_EXTERN CMS_ResignData_CTX DIGI_CMS_OUT_getResignCtx(MOC_CMS_context pContext);

/*----------------------------------------------------------------------*/

extern void
DIGI_CMS_OUT_setResignCtx(MOC_CMS_context pContext, CMS_ResignData_CTX ctx)
{
    MOC_CMS_OUT_CTX *pMCCtx = NULL;
    if (NULL == pContext)
    {
        return;
    }

    pMCCtx = (MOC_CMS_OUT_CTX*) pContext;
    if ('O' != pMCCtx->mag)
    {
        return;
    }

    pMCCtx->pResData = (void*)ctx;
}

/*----------------------------------------------------------------------*/


extern CMS_ResignData_CTX
DIGI_CMS_OUT_getResignCtx(MOC_CMS_context pContext)
{
    MOC_CMS_OUT_CTX*  pMCCtx = NULL;
    if (NULL == pContext)
    {
        return NULL;
    }

    pMCCtx = (MOC_CMS_OUT_CTX*) pContext;
    if ('O' != pMCCtx->mag)
    {
        return NULL;
    }

    return (CMS_ResignData_CTX)pMCCtx->pResData;

}
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

/*----------------------------------------------------------------------*/

extern void
DIGI_CMS_deleteContextOut(MOC_CMS_OUT_CTX* pCtx)
{
    switch (pCtx->contentType)
    {
    case E_MOC_CMS_ct_signedData:
        DIGI_CMS_deleteSignContextOut (&(pCtx->pUn->sign));
        DIGI_FREE ((void**)&pCtx->pUn);
        break;
    case E_MOC_CMS_ct_envelopedData:
        DIGI_CMS_deleteEnvelopContextOut (&(pCtx->pUn->env));
        DIGI_FREE ((void**)&pCtx->pUn);
        break;
    default:
        /* do nothing */
        break;
    }
    DIGI_CMS_U_deleteAsn1MemoryCache (&(pCtx->pAsn1Mem));
    DIGI_FREE ((void**) &pCtx);
}

/*----------------------------------------------------------------------*/


extern MSTATUS
DIGI_CMS_createSignContextOut(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS               status = OK;
    MOC_CMS_OUT_SignedCtx *pCtxS = NULL;
    sbyte4                version;

    /* ContentInfo sequence [rfc5652 - Section 3, page 6] */
    MAsn1TypeAndCount defRoot[11] =
    {
     {  MASN1_TYPE_SEQUENCE, 2},
       /* contentType:           ContentType [OID] */
       {  MASN1_TYPE_OID, 0},
       /* content [0] EXPLICIT:  ANY DEFINED BY contentType */
       /* SignedData  [rfc5652 - Section 5.1, page 8] */
       { MASN1_TYPE_SEQUENCE | MASN1_EXPLICIT | 0, 6 },
          /* version:          CMSVersion */
          {  MASN1_TYPE_INTEGER, 0},
          /* digestAlgorithms DigestAlgorithmIdentifier */
          {  MASN1_TYPE_ENCODED, 0},
          /* encapContentInfo: EncapsulatedContentInfo */
          {  MASN1_TYPE_SEQUENCE, 2},
             /* eContentType ContentType */
            {  MASN1_TYPE_OID, 0},
             /* eContent */
            {  MASN1_TYPE_OCTET_STRING | MASN1_EXPLICIT | 0, 0},
          /* certificates [0] IMPLICIT: CertificateSet OPTIONAL */
          {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
          /* crls [1] IMPLICIT: RevocationInfoChoices OPTIONAL */
          {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
           /* signerInfos:       SignerInfos */
          {  MASN1_TYPE_ENCODED, 0},
    };

    status = DIGI_CALLOC((void**)&pCtxS, 1, sizeof(MOC_CMS_OUT_SignedCtx));
    if (OK != status)
        goto exit;

    /* Set index to each field to help locate it, in case above template changes */
    pCtxS->idxOID = 1;
    pCtxS->idxVersion = 3;
    pCtxS->idxDigest = 4;
    pCtxS->idxPkgOID = 6;
    pCtxS->idxPkgData = 7;
    pCtxS->idxCerts = 8;
    pCtxS->idxCRLs = 9;
    pCtxS->idxSigners = 10;
    pCtxS->hwAccelCtx = pCtx->hwAccelCtx;

    /* Create the 'signed' data root */
    status = MAsn1CreateElementArray (defRoot, 11, MASN1_FNCT_ENCODE, NULL, &(pCtxS->pRoot));
    if (OK != status)
        goto exit;

    if (E_MOC_CMS_st_streaming == pCtx->streamType)
    {
        /* Set state */
        status = MAsn1SetValueLenSpecial (pCtxS->pRoot + pCtxS->idxCerts, MASN1_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;

        status = MAsn1SetValueLenSpecial (pCtxS->pRoot + pCtxS->idxCRLs, MASN1_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;
    }

    /* Set OID for outer CMS data (only value bytes) */
    status = MAsn1SetValue (pCtxS->pRoot + pCtxS->idxOID,
                            CMS_OUTER_SIGNED_DATA + 2,
                            CMS_OUTER_SIGNED_DATA_LEN - 2);
    if (OK != status)
        goto exit;

    /* version number: RFC-5652, Sec 5.1, for now set to version 1,
       and if any signerInfo is versio 3 we will change it later */
    version = 1;
    status = MAsn1SetInteger (pCtxS->pRoot + pCtxS->idxVersion,
                              NULL,
                              0, TRUE, version);
    if (OK != status)
        goto exit;

    /* Success */
    pCtx->pUn = (MOC_CMS_OUT_TypeCtx*)pCtxS;
    pCtxS = NULL;

exit:
    if (NULL != pCtxS)
    {
        /* Error cleanup */
        MAsn1FreeElementArray (&(pCtxS->pRoot));
        DIGI_FREE ((void**)&pCtxS);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_deleteSignContextOut(MOC_CMS_OUT_SignedCtx *pCtx)
{
    MSTATUS status = OK;
    sbyte4  idx, cnt;

    /* NULL is already deleted */
    if (NULL == pCtx)
        goto exit;

    if (NULL != pCtx->pAddedCerts)
    {
        cnt = pCtx->numAddedCerts;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pAddedCerts[idx]->pData));
            DIGI_FREE ((void**)&(pCtx->pAddedCerts[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pAddedCerts));
    }
    if (NULL != pCtx->pAddedDigests)
    {
        cnt = pCtx->numAddedDigests;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pAddedDigests[idx]->pData));
            DIGI_FREE ((void**)&(pCtx->pAddedDigests[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pAddedDigests));
    }
    if (NULL != pCtx->pAddedRawSigs)
    {
        cnt = pCtx->numAddedRawSigs;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pAddedRawSigs[idx]->pData));
            DIGI_FREE ((void**)&(pCtx->pAddedRawSigs[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pAddedRawSigs));
    }
    if (NULL != pCtx->pCRLs)
    {
        cnt = pCtx->numCRLs;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pCRLs[idx]->pData));
            DIGI_FREE ((void**)&(pCtx->pCRLs[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pCRLs));
    }
    if (NULL != pCtx->pSigners)
    {
        cnt = pCtx->numSigners;
        for (idx = 0; idx < cnt; ++idx)
        {
            int k;

            if (NULL != pCtx->pSigners[idx]->pAuthAttr)
            {
                for (k = 0; k < (int)pCtx->pSigners[idx]->numAuthAttr; ++k)
                {
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pAuthAttr[k]->pASN1));
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pAuthAttr[k]->pOID));
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pAuthAttr[k]));
                }
                DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pAuthAttr));
            }

            if (NULL != pCtx->pSigners[idx]->pUnauthAttr)
            {
                for (k = 0; k < (int)pCtx->pSigners[idx]->numUnauthAttr; ++k)
                {
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pUnauthAttr[k]->pASN1));
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pUnauthAttr[k]->pOID));
                    DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pUnauthAttr[k]));
                }
                DIGI_FREE ((void**)&(pCtx->pSigners[idx]->pUnauthAttr));
            }

            DIGI_FREE ((void**)&(pCtx->pSigners[idx]->digestAlgoOID));
            DIGI_FREE ((void**)&(pCtx->pSigners[idx]->cert));
            DIGI_FREE ((void**)&(pCtx->pSigners[idx]));
        }
        DIGI_FREE((void**)&(pCtx->pSigners));
    }

    if (NULL != pCtx->pHashes)
    {
        DIGI_CMS_U_destructHashes (MOC_HASH(0) pCtx->numAlgos,
                                  &(pCtx->pHashes));
    }

    MAsn1FreeElementArray (&(pCtx->pRoot));

exit:
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_createEnvelopContextOut(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS               status = OK;
    MOC_CMS_OUT_EnvelopCtx *pCtxE = NULL;

    /* ContentInfo sequence [rfc5652 - Section 3, page 6] */
    MAsn1TypeAndCount defRoot[12] =
    {
     {  MASN1_TYPE_SEQUENCE, 2},
       /* contentType:           ContentType [OID] */
       {  MASN1_TYPE_OID, 0},
       /* content [0] EXPLICIT:  ANY DEFINED BY contentType */
       /* EnvelopedData  [rfc5652 - Section 6.1, page 19] */
       {  MASN1_TYPE_SEQUENCE | MASN1_EXPLICIT | 0, 5 },
          /* version:          CMSVersion */
          {  MASN1_TYPE_INTEGER, 0},
          /* originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL */
          {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
          /* recipientInfos RecipientInfos */
          {  MASN1_TYPE_SET_OF, 1},
             /* RecipientInfo */
            {  MASN1_TYPE_ENCODED, 0},
          /* encryptedContentInfo EncryptedContentInfo */
          {  MASN1_TYPE_SEQUENCE, 3},
             /* contentType ContentType */
            {  MASN1_TYPE_OID, 0},
            /* contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier */
            {  MASN1_TYPE_ENCODED, 0},
             /* encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL */
            {  MASN1_TYPE_OCTET_STRING | MASN1_IMPLICIT | 0, 0},
          /* unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL */
          {  MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
    };

    status = DIGI_CALLOC((void**)&pCtxE, 1, sizeof(MOC_CMS_OUT_EnvelopCtx));
    if (OK != status)
        goto exit;

    /* Set index to each field to help locate it, in case above template changes */
    pCtxE->idxOID = 1;
    pCtxE->idxVersion = 3;
    pCtxE->idxOrigin = 4;
    pCtxE->idxRecipients = 5;
    pCtxE->idxPkgOID = 8;
    pCtxE->idxAlgo = 9;
    pCtxE->idxPkg = 10;
    pCtxE->idxAttr = 11;
    pCtxE->hwAccelCtx = pCtx->hwAccelCtx;

    /* Create the 'envelop' data root */
    status = MAsn1CreateElementArray (defRoot, 12, MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &(pCtxE->pRoot));
    if (OK != status)
        goto exit;

    /* NOTE: Originator based recipients are NOT supported */
    if (E_MOC_CMS_st_streaming == pCtx->streamType)
    {
        /* Set state */
        status = MAsn1SetValueLenSpecial (pCtxE->pRoot + pCtxE->idxOrigin, MASN1_NO_VALUE);
        if (OK != status)
            goto exit;

        status = MAsn1SetValueLenSpecial (pCtxE->pRoot + pCtxE->idxAttr, MASN1_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;
    }
    else if (E_MOC_CMS_st_definite == pCtx->streamType)
    {
        /* Set state */
        status = MAsn1SetValue (pCtxE->pRoot + pCtxE->idxOrigin, NULL, 0);
        if (OK != status)
            goto exit;
    }

    /* Set OID for outer CMS data (only value bytes) */
    status = MAsn1SetValue (pCtxE->pRoot + pCtxE->idxOID,
                            CMS_OUTER_ENVELOPE_DATA + 2,
                            CMS_OUTER_ENVELOPE_DATA_LEN - 2);
    if (OK != status)
        goto exit;

    /* version number: the choice is either 0 or 2 depending on
     * whether we have any unauthenticated attributes and any recipient info
     * version is not 0 - so we cannot completely decide until we looked at
     * all the recipients in detail:
     *
     *  [rfc5652 - Section 6.1, page 19]
     *          IF (originatorInfo is absent) AND
     *             (unprotectedAttrs is absent) AND
     *             (all RecipientInfo structures are version 0)
     *          THEN version is 0
     *          ELSE version is 2
     */
    pCtxE->version = 0;

    /* Success */
    pCtx->pUn = (MOC_CMS_OUT_TypeCtx*)pCtxE;
    pCtxE = NULL;

exit:
    if (NULL != pCtxE)
    {
        /* Error cleanup */
        MAsn1FreeElementArray (&(pCtxE->pRoot));
        DIGI_FREE ((void**)&pCtxE);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_deleteEnvelopContextOut(MOC_CMS_OUT_EnvelopCtx *pCtx)
{
    MSTATUS status = OK;
    sbyte4  idx, cnt;

    /* NULL is already deleted */
    if (NULL == pCtx)
        goto exit;

    if (NULL != pCtx->pUnauthAttributes)
    {
        cnt = pCtx->numAttributes;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pUnauthAttributes[idx]->pASN1));
            DIGI_FREE ((void**)&(pCtx->pUnauthAttributes[idx]->pOID));
            DIGI_FREE ((void**)&(pCtx->pUnauthAttributes[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pUnauthAttributes));
    }

    if (NULL != pCtx->pRecipients)
    {
        cnt = pCtx->numRecipients;
        for (idx = 0; idx < cnt; ++idx)
        {
            DIGI_FREE ((void**)&(pCtx->pRecipients[idx]->pData));
            DIGI_FREE ((void**)&(pCtx->pRecipients[idx]));
        }
        DIGI_FREE ((void**)&(pCtx->pRecipients));
    }

    if ((NULL != pCtx->pBulkCtx) && (NULL != pCtx->pBulkAlgo))
    {
        pCtx->pBulkAlgo->deleteFunc (MOC_SYM(pCtx->hwAccelCtx) &pCtx->pBulkCtx);
    }

    MAsn1FreeElementArray (&(pCtx->pRoot));
exit:
    return status;
}

/*----------------------------------------------------------------------*/


extern MSTATUS
DIGI_CMS_writeSigned(MOC_CMS_OUT_CTX *pCtx,
                    const ubyte *pData,
                    ubyte4 dataLen,
                    intBoolean last)
{
    MSTATUS      status = OK;
    MAsn1Element *pRootHash = NULL;
    ubyte        *pHashEnc = NULL;
    ubyte        *pFirst = NULL;
    ubyte4       hashEncSize, firstSize;
    intBoolean   isComplete = FALSE;

    /* Check first, if the Hash Digest Algorithm list has been made.
     * If not, create it and write out the SET of OID values
     */
    if (NULL == pCtx->pUn->sign.pHashes)
    {
        sbyte4       idx;
        MAsn1Element *pElement = NULL;

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

        status = DIGI_CMS_OUT_Sig_getHashAlgos (pCtx);
        if (OK != status)
            goto exit;

        status = MAsn1CreateElementArray (def, 4,
                                          MASN1_FNCT_ENCODE,
                                          &MAsn1OfFunction, &pRootHash);
        if (OK != status)
            goto exit;

        /* Start element */
        pElement = pRootHash + 1;

        /* Loop over all found algos */
        for (idx = 0; idx < (sbyte4)pCtx->pUn->sign.numAlgos; ++idx)
        {
            /* Output fields */
            MAsn1Element *pOID;
            MAsn1Element *pPar;
            ubyte4       lenDER;

            /* The first element already exists, do not add. */
            if (idx > 0)
            {
                /* Next SETOF Element */
                status = MAsn1CopyAddOfEntry (pRootHash + 0, &pElement);
                if (OK != status)
                    goto exit;
            }

            pOID = pElement + 1;
            pPar = pElement + 2;

            /* This assumes that OID values are less than 127 bytes in length (see also
             * \c CRYPTO_getRSAHashAlgoOID() ) */
            lenDER = pCtx->pUn->sign.pHashes[idx].algoOID[0];
            status = MAsn1SetValue (pOID,
                                    pCtx->pUn->sign.pHashes[idx].algoOID + 1,
                                    lenDER);
            if (OK != status)
                goto exit;

            /* Set parameters to NULL */
            status = DIGI_CMS_U_setEncodedNIL (pPar);
            if (OK != status)
                goto exit;
        }
#ifdef __ENABLE_DIGICERT_RE_SIGNER__
        if (NULL != pCtx->pResData) /* NULL is OK, and means not saving Resign data.*/
        {
            ubyte4             maxAlgos, i, j;
            ubyte              **original_OID;
            CMS_ResignData_CTX RSCtx = (CMS_ResignData_CTX*)pCtx->pResData;

            /* Restore any unique OIDs from previous signature blocks */
            maxAlgos = CMS_RESIGN_getNumSigningAlgos();

            CMS_RESIGN_getExtractedSignature_OIDs(RSCtx, &original_OID);

            /* Eliminate duplicates from the saved list */
            for(i = 0; i < pCtx->pUn->sign.numAlgos; i++)
            {
                for(j = 0; j < maxAlgos; j++)
                {
                    if ((original_OID != NULL) && (original_OID[j] == pCtx->pUn->sign.pHashes[i].algoOID))
                    {
                        CMS_RESIGN_clearExtractedSignature_OID(RSCtx, j);
                    }
                }
            }

            /* Add algorithm entries from previous signers */
            for(i = 0; i < maxAlgos; i++)
            {
                if ((original_OID != NULL) && (original_OID[i]))
                {
                    /* Output fields */
                    MAsn1Element *pOID;
                    MAsn1Element *pPar;
                    ubyte4       lenDER;

                    if (0 < idx)
                    {
                        /* Next SETOF Element */
                        status = MAsn1CopyAddOfEntry (pRootHash + 0, &pElement);
                        if (OK != status)
                            goto exit;
                    }
                    pOID = pElement + 1;
                    pPar = pElement + 2;

                    /* This assumes that OID values are less than 127 bytes in length (see also
                     * \c CRYPTO_getRSAHashAlgoOID() ) */
                    lenDER = original_OID[i][0];
                    status = MAsn1SetValue (pOID,
                                            original_OID[i] + 1,
                                            lenDER);
                    if (OK != status)
                        goto exit;

                    /* Set parameters to NULL */
                    status = DIGI_CMS_U_setEncodedNIL (pPar);
                    if (OK != status)
                        goto exit;
                }
            }
        }
#endif  /*__ENABLE_DIGICERT_RE_SIGNER__*/
        if (idx > 0)
        {
            /* Create output in ASN1 */
            status = MAsn1EncodeAlloc (pRootHash, &pHashEnc, &hashEncSize);
            if (OK != status)
                goto exit;

            /* And set for streaming CMS */
            status = MAsn1SetEncoded (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxDigest,
                                      pHashEnc, hashEncSize);
            if (OK != status)
                goto exit;

            status = DIGI_CMS_U_addToAsn1MemoryCache (pCtx->pAsn1Mem,
                                                     (void*)pHashEnc);
            if (OK != status)
                goto exit;

            /* Success */
            pHashEnc = NULL;
        }
        else
        {
            /* No digests. Empty? */
            status = MAsn1SetEncoded (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxDigest,
                                      NULL, 0);
            if (OK != status)
                goto exit;
        }

        /* Set OID for inner Package data (only value bytes) */
        status = MAsn1SetValue (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgOID,
                                CMS_OUTER_DATA + 2,
                                CMS_OUTER_DATA_LEN - 2);
        if (OK != status)
            goto exit;

        if (E_MOC_CMS_st_streaming == pCtx->streamType)
        {
            /* Write first data to callback */
            status = DIGI_CMS_updateEncoder (pCtx, &pFirst, &firstSize, &isComplete);
            if (OK != status)
                goto exit;

            /* Update callback */
            if (NULL != pCtx->cb)
            {
                status = pCtx->cb (pCtx->cbArg,
                                   (void*)pCtx,
                                   E_MOC_CMS_ut_update,
                                   pFirst,
                                   firstSize);
            }
            /* Success? */
            DIGI_FREE ((void**)&pFirst);
            if (OK != status)
                goto exit;
        }
        else if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            /* Was the length provided? */
            if (0 < pCtx->payloadLen)
            {
                /* Set payload length for ASN1 */
                status = MAsn1SetValueLen (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                           pCtx->payloadLen);
                if (OK != status)
                    goto exit;
            }
        }
    }

    /* Now write the data and hash it */
    if (FALSE == last)
    {
        if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        status = DIGI_CMS_OUT_Sig_hashDataChunked (pCtx,
                                                  pData,
                                                  dataLen);
        if (OK != status)
            goto exit;

        if (0 < dataLen)
        {
            /* Update template */
            status = MAsn1AddIndefiniteData (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                             pData, dataLen, last);
            if (OK != status)
                goto exit;
        }

        /* Write more payload data to callback */
        status = DIGI_CMS_updateEncoder (pCtx, &pFirst, &firstSize, &isComplete);
        /* Success? */
        if (OK != status)
            goto exit;

        /* Update callback */
        if (NULL != pCtx->cb)
        {
            status = pCtx->cb (pCtx->cbArg,
                               (void*)pCtx,
                               E_MOC_CMS_ut_update,
                               pFirst,
                               firstSize);
        }
    }
    else
    {
        if (E_MOC_CMS_st_streaming == pCtx->streamType)
        {
            status = MAsn1AddIndefiniteData (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                             pData, dataLen, MASN1_BUF_FLAG_ENCODE_INDEF);

        }
        else if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            /* Was the length provided? */
            if (0 < pCtx->payloadLen)
            {
                status = MAsn1AddData (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                       pData, dataLen);
            }
            else
            {
                status = MAsn1SetValue (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                        pData, dataLen);
            }
        }
        else
        {
            status = ERR_INVALID_INPUT;
        }
        if (OK != status)
            goto exit;

        status = DIGI_CMS_OUT_Sig_hashDataFinal (pCtx,
                                                pData,
                                                dataLen);
        if (OK != status)
            goto exit;
    }


exit:
    DIGI_FREE ((void**)&pFirst);
    DIGI_FREE ((void**)&pHashEnc);
    MAsn1FreeElementArray (&pRootHash);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_finalizeSigned(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS      status = OK;
    ubyte        *pLast = NULL;
    ubyte4       lastSize;
    intBoolean   isComplete = FALSE;
    intBoolean   isSet = FALSE;

    if (TRUE == pCtx->lastDone)
    {
        /* Already finished */
        goto exit;
    }

    /* Did the data correctly end with 'last' set to true when calling 'DIGI_CMS_writeSigned()',
     * or do we need to close out the stream and finalize the hash? */
    if (FALSE == pCtx->pUn->sign.hashesDone)
    {
        /* Finalize the streamed data */
        if (E_MOC_CMS_st_streaming == pCtx->streamType)
        {
            status = MAsn1AddIndefiniteData (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxPkgData,
                                             NULL, 0, MASN1_BUF_FLAG_ENCODE_INDEF);
        }
        else if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            /* Nothing else to do */
        }
        else
        {
            status = ERR_INVALID_INPUT;
        }
        if (OK != status)
            goto exit;

        /* Get the complete hash */
        status = DIGI_CMS_OUT_Sig_hashDataFinal (pCtx,
                                                NULL, 0);
        if (OK != status)
            goto exit;
    }

    /* Store added certificate data in OPTIONAL sequence, if there are any */
    status = DIGI_CMS_writeCerts (pCtx->pAsn1Mem,
                                 &(pCtx->pUn->sign),
                                 pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCerts,
                                 &isSet);
    if (OK != status)
        goto exit;

    if (FALSE == isSet)
    {
        status = ERR_INTERNAL_ERROR;

        switch (pCtx->streamType)
        {
        case E_MOC_CMS_st_streaming:
            /* Set to empty */
            status = MAsn1SetValueLenSpecial (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCerts,
                                              MASN1_NO_VALUE);
            break;
        case E_MOC_CMS_st_definite:
            /* Set to empty */
            status = MAsn1SetValue (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCerts,
                                    NULL, 0);
            break;
        default:
            break;
        }

        if (OK != status)
            goto exit;
    }

    /* Store added CRL in OPTIONAL sequence, if there are any */
    isSet = FALSE;
    status = DIGI_CMS_writeCRLs (pCtx->pAsn1Mem,
                                &(pCtx->pUn->sign),
                                pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCRLs,
                                &isSet);
    if (OK != status)
        goto exit;

    if (FALSE == isSet)
    {
        status = ERR_INTERNAL_ERROR;

        switch (pCtx->streamType)
        {
        case E_MOC_CMS_st_streaming:
            /* Set to empty */
            status = MAsn1SetValueLenSpecial (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCRLs,
                                              MASN1_NO_VALUE);
            break;
        case E_MOC_CMS_st_definite:
            /* Set to empty */
            status = MAsn1SetValue (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCRLs,
                                    NULL, 0);
            break;
        default:
            break;
        }
        if (OK != status)
            goto exit;
    }

    if (E_MOC_CMS_st_streaming == pCtx->streamType)
    {
        /* Clear UNKNOWN flag */
        status = MAsn1SetValueLenSpecial (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCerts,
                                          MASN1_CLEAR_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;

        status = MAsn1SetValueLenSpecial (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxCRLs,
                                          MASN1_CLEAR_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;
    }

    /* Create signature data */
    status = DIGI_CMS_writeSignerInfos (pCtx);
    if (OK != status)
        goto exit;

    /* Write more payload data to callback. It should now signal completeness */
    status = DIGI_CMS_updateEncoder (pCtx, &pLast, &lastSize, &isComplete);
    if (OK != status)
        goto exit;

    /* Check for consistent state of ASN1 encoder */
    if (FALSE == isComplete)
    {
        status = ERR_PKCS7_CONTEXT_NOT_COMPLETED;
        goto exit;
    }

    pCtx->lastDone = TRUE;

    /* Update callback */
    if (NULL != pCtx->cb)
    {
        status = pCtx->cb (pCtx->cbArg,
                           (void*)pCtx,
                           E_MOC_CMS_ut_final,
                           pLast,
                           lastSize);
    }

exit:
    DIGI_FREE ((void**)&pLast);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_writeEnvelop(MOC_CMS_OUT_CTX *pCtx,
                     const ubyte *pData,
                     ubyte4 dataLen,
                     intBoolean last)
{
    MSTATUS    status = OK;
    ubyte      *pFirst = NULL;
    ubyte4     firstSize;
    intBoolean isComplete = FALSE;

    ubyte      *encryptedInfo = NULL, *finalInfo = NULL, *combInfo = NULL;
    ubyte4     encryptedInfoLen, finalInfoLen;

    if (FALSE == pCtx->pUn->env.firstDone)
    {
        /* Mark CMS stream as started */
        pCtx->pUn->env.firstDone = TRUE;

        /* Write all recipient info */
        status = DIGI_CMS_writeRecipientInfos (MOC_HW(pCtx->hwAccelCtx)
                                              pCtx->pAsn1Mem,
                                              &(pCtx->pUn->env),
                                              pCtx->pUn->env.pRoot + pCtx->pUn->env.idxRecipients,
                                              pCtx->pUn->env.pRoot + pCtx->pUn->env.idxRecipients + 1);
        if (OK != status)
            goto exit;

        /* Select version number */
        if (0 == pCtx->pUn->env.version)
        {
            pCtx->pUn->env.version = (NULL != pCtx->pUn->env.pUnauthAttributes) ? 2 : 0;
        }

        status = MAsn1SetInteger (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxVersion,
                                  NULL, 0, TRUE,
                                  pCtx->pUn->env.version);
        if (OK != status)
            goto exit;

        /* Set OID for inner Package data (only value bytes) */
        status = MAsn1SetValue (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkgOID,
                                CMS_OUTER_DATA + 2,
                                CMS_OUTER_DATA_LEN - 2);
        if (OK != status)
            goto exit;

        if (E_MOC_CMS_st_streaming == pCtx->streamType)
        {
            /* Write first data to callback */
            status = DIGI_CMS_updateEncoder (pCtx, &pFirst, &firstSize, &isComplete);
            if (OK != status)
                goto exit;

            /* Update callback */
            if (NULL != pCtx->cb)
            {
                status = pCtx->cb (pCtx->cbArg,
                                   (void*)pCtx,
                                   E_MOC_CMS_ut_update,
                                   pFirst,
                                   firstSize);
            }
            /* Success? */
            DIGI_FREE ((void**)&pFirst);
            if (OK != status)
                goto exit;
        }
        else if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            /* Was the length provided? */
            if (0 < pCtx->payloadLen)
            {
                /* Set payload length for ASN1 */
                status = MAsn1SetValueLen (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkg,
                                           pCtx->payloadLen);
                if (OK != status)
                    goto exit;
            }
        }
    }

    if (FALSE == last)
    {
        if (E_MOC_CMS_st_definite == pCtx->streamType)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        status = DIGI_CMS_encryptChunked (MOC_SYM(pCtx->hwAccelCtx)
                                         pData, dataLen,
                                         pCtx,
                                         &encryptedInfo,
                                         (sbyte4 *) &encryptedInfoLen);
        if (OK != status)
            goto exit;

        if (0 < encryptedInfoLen)
        {
            /* Update template */
            status = MAsn1AddIndefiniteData (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkg,
                                             encryptedInfo, encryptedInfoLen, last);
            if (OK != status)
                goto exit;

            /* Write next encrypted data block to callback */
            status = DIGI_CMS_updateEncoder (pCtx, &pFirst, &firstSize, &isComplete);
            if (OK != status)
                goto exit;

            /* Update callback */
            if (NULL != pCtx->cb)
            {
                status = pCtx->cb (pCtx->cbArg,
                                   (void*)pCtx,
                                   E_MOC_CMS_ut_update,
                                   pFirst,
                                   firstSize);
            }
            /* Clean up */
            DIGI_FREE ((void**)&pFirst);
            DIGI_FREE ((void**)&encryptedInfo);
            /* Success? */
            if (OK != status)
                goto exit;
        }
    }
    else
    {
        status = DIGI_CMS_encryptChunked (MOC_SYM(pCtx->hwAccelCtx)
                                         pData, dataLen,
                                         pCtx,
                                         &encryptedInfo,
                                         (sbyte4 *) &encryptedInfoLen);
        if (OK != status)
            goto exit;

        status = DIGI_CMS_encryptFinal (MOC_SYM(pCtx->hwAccelCtx)
                                       pCtx,
                                       &finalInfo,
                                       (sbyte4 *) &finalInfoLen);
        if (OK != status)
            goto exit;

        /* Combine final encrypted data */
        if (0 < finalInfoLen)
        {
            status = DIGI_MALLOC ((void**)&combInfo, encryptedInfoLen + finalInfoLen);
            if (OK != status)
                goto exit;

            /* Might be empty */
            if (NULL != encryptedInfo)
            {
                status = DIGI_MEMCPY (combInfo, encryptedInfo, encryptedInfoLen);
                if (OK != status)
                    goto exit;
            }

            status = DIGI_MEMCPY (combInfo + encryptedInfoLen, finalInfo, finalInfoLen);
            if (OK != status)
                goto exit;

            DIGI_FREE ((void**)&encryptedInfo);
            encryptedInfo = combInfo;
            encryptedInfoLen = encryptedInfoLen + finalInfoLen;

            combInfo = NULL;
        }

        if (0 < encryptedInfoLen)
        {
            /* Update template */
            if (E_MOC_CMS_st_streaming == pCtx->streamType)
            {
                status = MAsn1AddIndefiniteData (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkg,
                                                 encryptedInfo, encryptedInfoLen, MASN1_BUF_FLAG_ENCODE_INDEF);

            }
            else if (E_MOC_CMS_st_definite == pCtx->streamType)
            {
                /* Was the length provided? */
                if (0 < pCtx->payloadLen)
                {
                    status = MAsn1AddData (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkg,
                                           encryptedInfo, encryptedInfoLen);
                }
                else
                {
                    status = MAsn1SetValue (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxPkg,
                                            encryptedInfo, encryptedInfoLen);
                }
            }
            else
            {
                status = ERR_INVALID_INPUT;
            }
            if (OK != status)
                goto exit;

            status = DIGI_CMS_U_addToAsn1MemoryCache(pCtx->pAsn1Mem, encryptedInfo);
            if (OK != status)
                goto exit;
            
            encryptedInfo = NULL;
        }
    }

exit:
    /* Error clean up */
    DIGI_FREE ((void**)&combInfo);
    DIGI_FREE ((void**)&encryptedInfo);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_finalizeEnvelop(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS      status = OK;
    ubyte        *pLast = NULL;
    ubyte4       lastSize;
    intBoolean   isComplete = FALSE;

    if (NULL == pCtx->pUn->env.pUnauthAttributes)
    {
        /* DO not use attributes */
        status = MAsn1SetValue (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxAttr,
                                NULL, 0);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DIGI_CMS_U_setAttributesImpl (pCtx->pAsn1Mem,
                                              pCtx->pUn->env.pUnauthAttributes,
                                              pCtx->pUn->env.numAttributes,
                                              1,
                                              pCtx->pUn->env.pRoot + pCtx->pUn->env.idxAttr);
        if (OK != status)
            goto exit;
    }

    if (E_MOC_CMS_st_streaming == pCtx->streamType)
    {
        status = MAsn1SetValueLenSpecial (pCtx->pUn->env.pRoot + pCtx->pUn->env.idxAttr,
                                          MASN1_CLEAR_UNKNOWN_VALUE);
        if (OK != status)
            goto exit;
    }

    /* Write more payload data to callback. It should now signal completeness */
    status = DIGI_CMS_updateEncoder (pCtx, &pLast, &lastSize, &isComplete);
    if (OK != status)
        goto exit;

    if (FALSE == isComplete)
    {
        status = ERR_PKCS7_CONTEXT_NOT_COMPLETED;
        goto exit;
    }

    pCtx->lastDone = TRUE;

    /* Update callback */
    if (NULL != pCtx->cb)
    {
        status = pCtx->cb (pCtx->cbArg,
                           (void*)pCtx,
                           E_MOC_CMS_ut_final,
                           pLast,
                           lastSize);
    }

exit:
    DIGI_FREE ((void**)&pLast);
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_addAttribute(MOC_CMS_SignerCtx *pSigner,
                     intBoolean        authenticated,
                     const ubyte       *pOID,
                     ubyte4            oidLen,
                     ubyte4            typeId,
                     const ubyte       *pVal,
                     ubyte4            valLen)
{
    MSTATUS status;

    MOC_CMS_Attribute *pAttr = NULL;

    MOC_CMS_Attribute **pAllAttr = NULL;
    sbyte4            next = 0;

    /* Make entry */
    status = DIGI_MALLOC ((void**)&pAttr, sizeof(MOC_CMS_Attribute));
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC_MEMCPY ((void**)&(pAttr->pOID), oidLen, (ubyte *)pOID, oidLen);
    if (OK != status)
        goto exit;

    pAttr->oidLen = oidLen;

    /* Create the ASN1 encoded data */
    status = DIGI_CMS_makeASN1FromAttribute (typeId, pVal, valLen, pAttr);
    if (OK != status)
        goto exit;

    /* Add to list */
    if (TRUE == authenticated)
    {
        status = DIGI_MALLOC((void**)&pAllAttr, sizeof(MOC_CMS_Attribute *) * (pSigner->numAuthAttr + 1));
        if (OK != status)
            goto exit;

        if (0 < pSigner->numAuthAttr)
        {
            status = DIGI_MEMCPY ((ubyte*)pAllAttr, pSigner->pAuthAttr,
                                 sizeof(MOC_CMS_Attribute *) * pSigner->numAuthAttr);
            if (OK != status)
                goto exit;

            DIGI_FREE((void**)&(pSigner->pAuthAttr));
        }
        next = pSigner->numAuthAttr;

        pSigner->numAuthAttr++;
        pSigner->pAuthAttr = pAllAttr;
    }
    else
    {
        status = DIGI_MALLOC((void**)&pAllAttr, sizeof(MOC_CMS_Attribute *) * (pSigner->numUnauthAttr + 1));
        if (OK != status)
            goto exit;

        if (0 < pSigner->numUnauthAttr)
        {
            status = DIGI_MEMCPY ((ubyte*)pAllAttr, pSigner->pUnauthAttr,
                                 sizeof(MOC_CMS_Attribute *) * pSigner->numUnauthAttr);
            if (OK != status)
                goto exit;

            DIGI_FREE((void**)&(pSigner->pUnauthAttr));
        }

        next = pSigner->numUnauthAttr;

        pSigner->numUnauthAttr++;
        pSigner->pUnauthAttr = pAllAttr;
    }

    pAllAttr[next] = pAttr;

    /* Success */
    pAllAttr = NULL;
    pAttr = NULL;

exit:
    /* Error clean up */
    if (NULL != pAttr)
    {
        DIGI_FREE ((void**)&(pAttr->pOID));
        DIGI_FREE ((void**)&(pAttr->pASN1));
        DIGI_FREE ((void**)&pAttr);
        DIGI_FREE ((void**)&pAllAttr);
    }
    return status;
}


/*----------------------------------------------------------------------*/

extern MSTATUS
DIGI_CMS_makeASN1FromAttribute(ubyte4 typeID,
                              const ubyte* value,
                              ubyte4 valueLen,
                              MOC_CMS_Attribute* pAttr)
{
    MSTATUS status = OK;
    MAsn1Element *pItem = NULL;

    /* Create the ASN1 encoded data */
    if (MASN1_TYPE_ENCODED == typeID)
    {
        /* Copy raw ASN1 */
        status = DIGI_MALLOC_MEMCPY ((void**)&(pAttr->pASN1), valueLen, (ubyte *)value, valueLen);
        if (OK != status)
        goto exit;

        pAttr->asn1Len = valueLen;
    }
    else
    {
        /* Create the ASN1 per type */
        switch (typeID)
        {
            case MASN1_TYPE_BOOLEAN:
            {
                intBoolean val = value[0];
                MAsn1TypeAndCount def[1] =
                {
                    {   MASN1_TYPE_BOOLEAN, 0}
                };
                status = MAsn1CreateElementArray (def, 1, MASN1_FNCT_ENCODE, NULL, &pItem);
                if (OK != status)
                    goto exit;

                status = MAsn1SetBoolean (pItem, val);
                if (OK != status)
                    goto exit;

                status = MAsn1EncodeAlloc (pItem, &(pAttr->pASN1), &(pAttr->asn1Len));
                if (OK != status)
                    goto exit;
            }
            break;

            case MASN1_TYPE_OID:
            {
                MAsn1TypeAndCount def[1] =
                {
                    {   MASN1_TYPE_OID, 0}
                };
                status = MAsn1CreateElementArray (def, 1, MASN1_FNCT_ENCODE, NULL, &pItem);
                if (OK != status)
                    goto exit;

                status = MAsn1SetValue (pItem, value, valueLen);
                if (OK != status)
                    goto exit;

                status = MAsn1EncodeAlloc (pItem, &(pAttr->pASN1), &(pAttr->asn1Len));
                if (OK != status)
                    goto exit;
            }
            break;

            case MASN1_TYPE_INTEGER:
            {
                MAsn1TypeAndCount def[1] =
                {
                    {   MASN1_TYPE_INTEGER, 0}
                };
                status = MAsn1CreateElementArray (def, 1, MASN1_FNCT_ENCODE, NULL, &pItem);
                if (OK != status)
                    goto exit;

                status = MAsn1SetInteger (pItem, (ubyte *)value, valueLen, TRUE, 0);
                if (OK != status)
                    goto exit;

                status = MAsn1EncodeAlloc (pItem, &(pAttr->pASN1), &(pAttr->asn1Len));
                if (OK != status)
                    goto exit;
            }
            break;

            case MASN1_TYPE_OCTET_STRING:
            {
                MAsn1TypeAndCount def[1] =
                {
                    {   MASN1_TYPE_OCTET_STRING, 0}
                };
                status = MAsn1CreateElementArray (def, 1, MASN1_FNCT_ENCODE, NULL, &pItem);
                if (OK != status)
                    goto exit;

                status = MAsn1SetValue (pItem, value, valueLen);
                if (OK != status)
                    goto exit;

                status = MAsn1EncodeAlloc (pItem, &(pAttr->pASN1), &(pAttr->asn1Len));
                if (OK != status)
                    goto exit;
            }
            break;

            case MASN1_TYPE_UTC_TIME:
            {
                struct TimeDate* val = (struct TimeDate*)value;
                MAsn1TypeAndCount def[1] =
                {
                    {   MASN1_TYPE_UTC_TIME, 0}
                };
                status = MAsn1CreateElementArray (def, 1, MASN1_FNCT_ENCODE, NULL, &pItem);
                if (OK != status)
                    goto exit;

                status = MAsn1SetTime (pItem, val);
                if (OK != status)
                    goto exit;

                status = MAsn1EncodeAlloc (pItem, &(pAttr->pASN1), &(pAttr->asn1Len));
                if (OK != status)
                    goto exit;
            }
            break;

            default:
                status = ERR_INVALID_ARG;
                goto exit;
        }
    }

exit:
    MAsn1FreeElementArray (&pItem);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_writeCerts(MOC_CMS_ASN1_Memory   *pMem,
                   MOC_CMS_OUT_SignedCtx *pCtx,
                   MAsn1Element          *pOut,
                   intBoolean            *pSet)
{
    MSTATUS status = OK;
    sbyte4  idx;

    ubyte   *pAllCerts = NULL;
    ubyte4  allCertsLen;
    ubyte4  count = 0;

    MAsn1Element      *pCerts = NULL;
    MAsn1Element      *pCur;
    MAsn1TypeAndCount defCerts[2] =
    {
       {  MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT | 0 , 1},
          {  MASN1_TYPE_ENCODED, 0},
    };

    status = MAsn1CreateElementArray (defCerts, 2,
                                      MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pCerts);
    if (OK != status)
        goto exit;

    pCur = pCerts + 1;

    /* Add all 'additional' certificates */
    for (idx = 0; idx < pCtx->numAddedCerts; ++idx)
    {
        if (count > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pCerts, &pCur);
            if (OK != status)
                goto exit;
        }

        status = MAsn1SetValue (pCur,
                                pCtx->pAddedCerts[idx]->pData,
                                pCtx->pAddedCerts[idx]->dataLen);
        if (OK != status)
            goto exit;

        ++count;
    }

    /* Add all signer certificates with the action flag 'ADD' */
    for (idx = 0; idx < pCtx->numSigners; ++idx)
    {
        MOC_CMS_SignerCtx *pCtxS = pCtx->pSigners[idx];

        if (0 != (E_MOC_CMS_sa_addCert & pCtxS->flags))
        {
            if (count > 0)
            {
                /* Next SETOF Element */
                status = MAsn1CopyAddOfEntry (pCerts, &pCur);
                if (OK != status)
                    goto exit;
            }

            status = MAsn1SetValue (pCur, pCtxS->cert, pCtxS->certLen);
            if (OK != status)
                goto exit;

            ++count;
        }
    }

    if (0 == count)
    {
        *pSet = FALSE;
        /* No data for OPTIONAL */
        goto exit;
    }

    /* Make full ASN1 */
    status = MAsn1EncodeAlloc (pCerts, &pAllCerts, &allCertsLen);
    if (OK != status)
        goto exit;

    /* Set the returned element */
    status = MAsn1SetValue (pOut, pAllCerts, allCertsLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem, (void*)pAllCerts);
    if (OK != status)
        goto exit;

    /* Memory is owned by MAsn1Element */
    pAllCerts = NULL;
    *pSet = TRUE;

exit:
    /* Error clean up */
    if (NULL != pAllCerts)
    {
        DIGI_FREE ((void**)&pAllCerts);
    }
    MAsn1FreeElementArray (&pCerts);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_writeCRLs(MOC_CMS_ASN1_Memory   *pMem,
                  MOC_CMS_OUT_SignedCtx *pCtx,
                  MAsn1Element          *pOut,
                  intBoolean            *pSet)
{
    MSTATUS status = OK;
    sbyte4  idx;

    ubyte   *pAllCRLs = NULL;
    ubyte4  allCRLsLen;
    ubyte4  count = 0;

    MAsn1Element      *pCRLs = NULL;
    MAsn1Element      *pCur;
    MAsn1TypeAndCount defCerts[2] =
    {
       {  MASN1_TYPE_SEQUENCE_OF | MASN1_IMPLICIT | 1 , 1},
          {  MASN1_TYPE_ENCODED, 0},
    };

    status = MAsn1CreateElementArray (defCerts, 2,
                                      MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pCRLs);
    if (OK != status)
        goto exit;

    pCur = pCRLs + 1;

    /* Add all CRL data */
    for (idx = 0; idx < pCtx->numCRLs; ++idx)
    {
        if (count > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pCRLs, &pCur);
            if (OK != status)
                goto exit;
        }

        status = MAsn1SetValue (pCur,
                                pCtx->pCRLs[idx]->pData,
                                pCtx->pCRLs[idx]->dataLen);
        if (OK != status)
            goto exit;

        ++count;
    }

    if (0 == count)
    {
        *pSet = FALSE;
        /* No data for OPTIONAL */
        goto exit;
    }

    /* Make full ASN1 */
    status = MAsn1EncodeAlloc (pCRLs, &pAllCRLs, &allCRLsLen);
    if (OK != status)
        goto exit;

    /* Set the returned element */
    status = MAsn1SetValue (pOut, pAllCRLs, allCRLsLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem, (void*)pAllCRLs);
    if (OK != status)
        goto exit;

    /* Memory is owned by MAsn1Element */
    pAllCRLs = NULL;
    *pSet = TRUE;

exit:
    /* Error clean up */
    if (NULL != pAllCRLs)
    {
        DIGI_FREE ((void**)&pAllCRLs);
    }
    MAsn1FreeElementArray (&pCRLs);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_updateEncoder(MOC_CMS_OUT_CTX *pCtx,
                      ubyte           **ppData,
                      ubyte4          *pDataLen,
                      intBoolean      *pIsComplete)
{
    MSTATUS status = OK;
    ubyte4  usedLen;

    ubyte   *pOut = NULL;
    ubyte4  outLen = 0;

    /* Write first data to callback */
    switch (pCtx->streamType)
    {
    case E_MOC_CMS_st_definite:
        status = MAsn1EncodeUpdate (pCtx->pUn->sign.pRoot,
                                    NULL, 0,
                                    &usedLen, pIsComplete);
        if (ERR_BUFFER_TOO_SMALL != status)
            goto exit;
        status = DIGI_MALLOC ((void**)&pOut, usedLen);
        if (OK != status)
            goto exit;
        status = MAsn1EncodeUpdate (pCtx->pUn->sign.pRoot,
                                    pOut, usedLen,
                                    &outLen, pIsComplete);
        break;

    case E_MOC_CMS_st_streaming:
        status = MAsn1EncodeIndefiniteUpdate (pCtx->pUn->sign.pRoot,
                                              NULL, 0,
                                              &usedLen, pIsComplete);
        if (ERR_BUFFER_TOO_SMALL != status)
            goto exit;
        status = DIGI_MALLOC ((void**)&pOut, usedLen);
        if (OK != status)
            goto exit;
        status = MAsn1EncodeIndefiniteUpdate (pCtx->pUn->sign.pRoot,
                                              pOut, usedLen,
                                              &outLen, pIsComplete);
        break;
            
    default:
        break; /* legacy, no change, consider error status in future */
    }

    /* Success */
    *ppData = pOut;
    *pDataLen = outLen;
    pOut = NULL;

exit:
    /* Error cleanup */
    if (NULL != pOut)
    {
        DIGI_FREE ((void**)pOut);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_signAttributes(MOC_HASH(hwAccelDescr hwAccelCtx)
                       MOC_CMS_ASN1_Memory    *pMem,
                       MOC_CMS_SignerCtx      *pCtx,
                       MOC_CMS_SignedDataHash *pHash,
                       MAsn1Element           *pAttr,
                       ubyte                  **ppHashOut)
{
    MSTATUS status = OK;
    ubyte   *pData = NULL;
    ubyte4  dataLen;

    BulkCtx bulkCtx = NULL;

    /* Make a copy of the ASN1/DER data with all attributes */
    status = DIGI_MALLOC ((void**)&pData, pAttr->valueLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pData, pAttr->value.pValue, pAttr->valueLen);
    if (OK != status)
        goto exit;

    dataLen = pAttr->valueLen;

    /* We use the SETOF DER encoding (not the TAG '[0]') for the digest.
     * [RFC-5652, Section 5.4, page 16]
     */
    pData[0] = 0x31;

    /* Create hash algo instance and create digest value of all attributes */
    pHash->hashAlgo->allocFunc (MOC_HASH(hwAccelCtx)
                                &bulkCtx);
    pHash->hashAlgo->initFunc (MOC_HASH(hwAccelCtx)
                               bulkCtx);
    pHash->hashAlgo->updateFunc (MOC_HASH(hwAccelCtx)
                                 bulkCtx,
                                 pData, dataLen);

    /* Create final data and overwrite digest of payload used as
     * SignerInfo data.
     */
    pHash->hashAlgo->finalFunc (MOC_HASH(hwAccelCtx)
                                bulkCtx,
                                pHash->hashData);

    /* Free context */
    pHash->hashAlgo->freeFunc (MOC_HASH(hwAccelCtx)
                               &bulkCtx);
exit:
    DIGI_FREE ((void**)&pData);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_writeSignerInfos(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS      status;
    MAsn1Element *pSigners = NULL;
    MAsn1Element *pSign = NULL;
    MAsn1Element *pElement;
    sbyte4       idx, i;
    ubyte        *pData = NULL;
    ubyte4       dataLen;
    ubyte        *pAttrHash = NULL;
    ubyte4       version = 1;

    /* Sequence with Signer Info [rfc5652 - Section 5.3, page 13] */
    MAsn1TypeAndCount defSet[2] =
    {
      /* SignerInfos: SET OF SignerInfo with 0 or more elements [rfc5652 - Section 5.1, page 8] */
      {  MASN1_TYPE_SET_OF, 1},
        {  MASN1_TYPE_ENCODED, 0},
    };

    /* Sequence with Signer Info [rfc5652 - Section 5.3, page 13] */
    MAsn1TypeAndCount defSign[8] =
    {
      /* SignerInfo [rfc5652 - Section 5.1, page 8] */
      {   MASN1_TYPE_SEQUENCE, 7},
        /* version:          CMSVersion */
        {   MASN1_TYPE_INTEGER, 0},
        /* sid:              SignerIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* digestAlgorithm:  DigestAlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signedAttrs [0] IMPLICIT: SignedAttributes OPTIONAL */
        {   MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL, 0},
        /* signatureAlgorithm: SignatureAlgorithmIdentifier */
        {   MASN1_TYPE_ENCODED, 0},
        /* signature:     SignatureValue */
        {   MASN1_TYPE_ENCODED, 0},
        /* unsignedAttrs [1] IMPLICIT: UnsignedAttributes OPTIONAL */
        {   MASN1_TYPE_ENCODED | MASN1_TYPE_INDEF_ALLOWED | MASN1_OPTIONAL , 0},
    };

    status = MAsn1CreateElementArray (defSet, 2,
                                      MASN1_FNCT_ENCODE,
                                      &MAsn1OfFunction, &pSigners);
    if (OK != status)
        goto exit;

    /* Start element */
    pElement = pSigners + 1;

    /* Loop over all found algos */
    for (idx = 0; idx < pCtx->pUn->sign.numSigners; ++idx)
    {
        intBoolean             isMatch = FALSE;
        sbyte4                 cmpRes = -1;
        MOC_CMS_SignedDataHash *pHash = NULL;
        MOC_CMS_SignerCtx      *pCtxS = pCtx->pUn->sign.pSigners[idx];

        status = MAsn1CreateElementArray (defSign, 8,
                                          MASN1_FNCT_ENCODE,
                                          &MAsn1OfFunction, &pSign);
        if (OK != status)
            goto exit;

        /* The first element already exists, do not add. */
        if (idx > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pSigners, &pElement);
            if (OK != status)
                goto exit;
        }

        /* Locate matching hash */
        for (i = 0; i < (sbyte4)pCtx->pUn->sign.numAlgos; ++i)
        {
            pHash = pCtx->pUn->sign.pHashes + i;
            status = DIGI_MEMCMP (pHash->algoOID, pCtxS->digestAlgoOID + 1,
                                 pCtxS->digestAlgoOIDLen - 1, &cmpRes);
            if (OK != status)
                goto exit;

            /* Found? */
            if (0 == cmpRes)
            {
                isMatch = TRUE;
                break;
            }
        }

        /* Got one in 'pHash'? */
        if (FALSE == isMatch)
        {
            /* Should never happen */
            status = ERR_INTERNAL_ERROR;
            goto exit;
        }

        /* Write authenticated attributes, IMPLICIT TAG = 0 */
        pAttrHash = NULL;
        if (0 < pCtxS->numAuthAttr)
        {
            ubyte* pContentOID = NULL;
            ubyte4 contentOIDLen;

            if (E_MOC_CMS_ct_signedData == pCtx->contentType)
            {
                /* This encoder always uses the 'raw' data OID */
                pContentOID = CMS_OUTER_DATA + 2;
                contentOIDLen = CMS_OUTER_DATA_LEN - 2;
            }
            else
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            /* Add required content type attribute [RFC-5652, Section 11.1, page 40] */
            status = DIGI_CMS_addAttribute (pCtxS, TRUE,
                                           PKCS9_CONTENT_TYPE + 2,
                                           PKCS9_CONTENT_TYPE_LEN -2,
                                           MASN1_TYPE_OID,
                                           pContentOID, contentOIDLen);
            if (OK != status)
                goto exit;

            /* Add required digest attribute [RFC-5652, Section 11.2, page 40] */
            status = DIGI_CMS_addAttribute (pCtxS, TRUE,
                                           PKCS9_MESSAGE_DIGEST + 2,
                                           PKCS9_MESSAGE_DIGEST_LEN -2,
                                           MASN1_TYPE_OCTET_STRING,
                                           pHash->hashData, pHash->hashDataLen);
            if (OK != status)
                goto exit;

            /* Add all attributes that are signed to the ASN1 */
            status = DIGI_CMS_U_setAttributesImpl (pCtx->pAsn1Mem,
                                                  pCtxS->pAuthAttr,
                                                  pCtxS->numAuthAttr,
                                                  0,
                                                  pSign + 4);
            if (OK != status)
                goto exit;

            /* Create digest over signed attributes and store as CMS signature
             * in 'pAttrHash' [RFC-5652, Section 5.4, page 16] */
            status = DIGI_CMS_signAttributes (MOC_HASH(pCtx->hwAccelCtx)
                                             pCtx->pAsn1Mem,
                                             pCtxS, pHash,
                                             pSign + 4,
                                             &pAttrHash);
            if (OK != status)
                goto exit;
        }

        /* Write the data to the encoding elements */
        status = DIGI_CMS_writeSignerInfo (pCtx->pAsn1Mem,
                                          pCtx->rngFun, pCtx->rngArg,
                                          pCtxS, pHash,
                                          pAttrHash,
                                          pSign + 2, /*sid*/
                                          pSign + 3, /*digestAlgorithm*/
                                          pSign + 5, /*signatureAlgorithm*/
                                          pSign + 6);/*signature*/
        if (OK != status)
            goto exit;

        /* Version number: */
        if (pCtxS->flags & E_MOC_CMS_sa_version3)
        {
            version = 3;

            /* once we have a single SignerInfo of version 3,
               change the version within the MOC_CMS_OUT_SignedCtx ASN1 to version 3 */
            MOC_CMS_OUT_SignedCtx * pSignedCtx = (MOC_CMS_OUT_SignedCtx *) pCtx->pUn;
            status = MAsn1SetInteger (pSignedCtx->pRoot + pSignedCtx->idxVersion, NULL, 0, TRUE, version);
            if (OK != status)
                goto exit;
        }

        status = MAsn1SetInteger (pSign + 1,
                                  NULL, 0, TRUE,
                                  version);
        if (OK != status)
            goto exit;

        /* Write unauthenticated attributes, IMPLICIT TAG = 1 */
        if (0 < pCtxS->numUnauthAttr)
        {
            status = DIGI_CMS_U_setAttributesImpl (pCtx->pAsn1Mem,
                                                  pCtxS->pUnauthAttr,
                                                  pCtxS->numUnauthAttr,
                                                  1,
                                                  pSign + 7);
            if (OK != status)
                goto exit;
        }

        /* Encode to memory */
        status = MAsn1EncodeAlloc (pSign, &pData, &dataLen);
        if (OK != status)
            goto exit;

        /* Write to element */
        status = MAsn1SetEncoded (pElement,
                                  pData, dataLen);
        if (OK != status)
            goto exit;

        status = DIGI_CMS_U_addToAsn1MemoryCache (pCtx->pAsn1Mem,
                                                 (void*)pData);
        if (OK != status)
            goto exit;

        /* Release */
        pData = NULL;
        MAsn1FreeElementArray (&pSign);
    }

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    /* When we are re-signing, add the saved signatures in raw form to the
     * output */
    CMS_ResignData_CTX RSCtx = pCtx->pResData;
    if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
    {
        CMS_RESIGN_getRawSignatures (RSCtx, (void*)pCtx);
    }
#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

    /* Add any extra 'raw' signatures, while keeping 'idx' counting up */
    for (i = 0; i < pCtx->pUn->sign.numAddedRawSigs; ++i)
    {
        /* The first element already exists, do not add. */
        if (idx > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pSigners, &pElement);
            if (OK != status)
                goto exit;
        }

        /* Set Raw data as ASN1 */
        status = MAsn1SetEncoded (pElement,
                                  pCtx->pUn->sign.pAddedRawSigs[i]->pData,
                                  pCtx->pUn->sign.pAddedRawSigs[i]->dataLen);
        if (OK != status)
            goto exit;

        ++idx;
    }

    /* Encode to memory */
    status = MAsn1EncodeAlloc (pSigners, &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* Write to element */
    status = MAsn1SetEncoded (pCtx->pUn->sign.pRoot + pCtx->pUn->sign.idxSigners,
                              pData, dataLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pCtx->pAsn1Mem,
                                             (void*)pData);
    if (OK != status)
        goto exit;

    /* Memory is owned by MAsn1Element */
    pData = NULL;

exit:
    /* Error clean up */
    if (NULL != pData)
    {
        DIGI_FREE ((void**)&pData);
    }
    DIGI_FREE ((void**)&pAttrHash);
    MAsn1FreeElementArray (&pSign);
    MAsn1FreeElementArray (&pSigners);
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_writeSignerInfo(MOC_CMS_ASN1_Memory *pMem,
                        RNGFun rngFun, void* rngArg,
                        MOC_CMS_SignerCtx   *pSigner,
                        MOC_CMS_SignedDataHash *pHash,
                        ubyte        *pExternHash,
                        MAsn1Element *pSID,
                        MAsn1Element *pDigestAlgo,
                        MAsn1Element *pSigAlgo,
                        MAsn1Element *pSig)
{
    MSTATUS status = OK;
    ubyte4  lenDER, hashType;

    MOC_CMS_IssuerSerialNumber ISN;
    ubyte *pSKI = NULL; /* subject key identifier */
    ubyte4 skiLen = 0;

    /* Create SID data */
    if (pSigner->flags & E_MOC_CMS_sa_version3) /* version3 uses subjectKeyIdentifier */
    {
        status = DIGI_CMS_U_parseX509CertForSubjectKeyIdentifier (pSigner->cert, pSigner->certLen, &pSKI, &skiLen);
        if (OK != status)
            goto exit;

        status = DIGI_CMS_U_setSubjectKeyIdentifier(pMem, pSKI, skiLen, pSID);
        if (OK != status)
            goto exit; 
    }
    else /* get serial number and issuer */
    {
        status = DIGI_CMS_U_parseX509CertForSerialNumber (pSigner->cert, pSigner->certLen,
                                                        &(ISN.pSerialNumber), &(ISN.serialNumberLen));
        if (OK != status)
            goto exit;

        status = DIGI_CMS_U_parseX509CertForIssuerName (pSigner->cert, pSigner->certLen,
                                                    &(ISN.pIssuer), &(ISN.issuerLen));
        if (OK != status)
            goto exit;

        /* Store in ASN1 */
        status = DIGI_CMS_U_setIssuerSerialNumber (pMem, &ISN, pSID);
        if (OK != status)
            goto exit;
    }
    /* This assumes that OID values are less than 127 bytes in length (see also
     * \c CRYPTO_getRSAHashAlgoOID() ) */
    lenDER = pHash->algoOID[0];
    /* Set Digest OID */
    status = DIGI_CMS_U_setDigestAlgorithmHash (pMem,
                                               pHash->algoOID + 1,
                                               lenDER,
                                               pDigestAlgo);
    if (OK != status)
        goto exit;

    /* Get internal type id for hash */
    status = DIGI_CMS_U_getSignerAlgorithmHashType (pHash->algoOID + 1,
                                                   lenDER,
                                                   &hashType);
    if (OK != status)
        goto exit;

    /* Set OID of crypto algorithm */
    status = DIGI_CMS_U_setSignerSignatureAlgoKey(pMem,
                                                 (AsymmetricKey *) pSigner->pKey,
                                                 hashType,
                                                 pSigAlgo);
    if (OK != status)
        goto exit;

    /* Create signature value and store in ASN1.
     * If an external hash value was provided (e.g. authenticated attributes)
     * use that value instead of the content hash.
     */
    status = DIGI_CMS_U_setSignatureValue (MOC_ASYM(pSigner->hwAccelCtx) pMem,
                                          rngFun,
                                          rngArg,
                                          pSigner->pKey,
                                          (NULL == pExternHash)?pHash->hashData:pExternHash,
                                          pHash->hashDataLen,
                                          hashType,
                                          pSig);
exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_writeRecipientInfos(MOC_HW(hwAccelDescr hwAccelCtx)
                            MOC_CMS_ASN1_Memory    *pMem,
                            MOC_CMS_OUT_EnvelopCtx *pEnv,
                            MAsn1Element           *pRec,
                            MAsn1Element           *pCur)
{
    MSTATUS      status = OK;
    sbyte4       idx;

    for (idx = 0; idx < pEnv->numRecipients; ++idx)
    {
        /* A new SET entry? */
        if (idx > 0)
        {
            /* Next SETOF Element */
            status = MAsn1CopyAddOfEntry (pRec, &pCur);
            if (OK != status)
                goto exit;
        }

        status = DIGI_CMS_U_writeRecipientID (MOC_HW(hwAccelCtx)
                                             pMem,
                                             pEnv->encrRngFun, pEnv->encrRngArg,
                                             pEnv->pBulkAlgo,
                                             pEnv->encryptKey, pEnv->encrKeyLen,
                                             pEnv->pRecipients[idx]->pData,
                                             pEnv->pRecipients[idx]->dataLen,
                                             pCur,
                                             &(pEnv->version));
        if (OK != status)
            goto exit;
    }

exit:
    return status;
}

/*----------------------------------------------------------------------*/


static MSTATUS
DIGI_CMS_encryptChunked(MOC_SYM(hwAccelDescr hwAccelCtx)
                       const ubyte   *data,
                       ubyte4  dataLen,
                       MOC_CMS_OUT_CTX *pCtx,
                       ubyte   **encryptedInfo,
                       sbyte4  *encryptedInfoLen)
{
    MSTATUS status = OK;
    ubyte   *encryptedData = NULL;
    ubyte4  total, remain, toEncrypt;

    if ((NULL == data) || (0 == dataLen))
    {
        goto exit; /* nothing to do */
    }

    /* Decrypt as much data as possible: The store data and the new
     * data that was passed in. */
    total = pCtx->pUn->env.last_size + dataLen;

    if (pCtx->pUn->env.pBulkAlgo->blockSize)
    {
        /* The block size may change the total number we can encrypt at once */
        remain = total % pCtx->pUn->env.pBulkAlgo->blockSize;
        toEncrypt = total - remain;
    }
    else
    {
        remain = 0;
        toEncrypt = total;
    }

    if (0 != toEncrypt)
    {
        status = DIGI_MALLOC ((void**)&encryptedData, toEncrypt);
        if (OK != status)
            goto exit;

        DIGI_MEMCPY (encryptedData, pCtx->pUn->env.last, pCtx->pUn->env.last_size);
        DIGI_MEMCPY (encryptedData + pCtx->pUn->env.last_size, data, toEncrypt - pCtx->pUn->env.last_size);

        /* Adjust the length and pointer to what the 'last size' was,
         * which is the number of bytes we just prepended to the new data.
         */
        data += toEncrypt - pCtx->pUn->env.last_size;
        dataLen -= toEncrypt - pCtx->pUn->env.last_size;

        /* Clear old size */
        pCtx->pUn->env.last_size = 0;

        /* Encrypt */
        status = pCtx->pUn->env.pBulkAlgo->cipherFunc (MOC_SYM(hwAccelCtx)
                                                       pCtx->pUn->env.pBulkCtx,
                                                       encryptedData,
                                                       toEncrypt, 1,
                                                       pCtx->pUn->env.iv);
        if (OK != status)
            goto exit;

    }

    if (0 != remain)
    {
        status = DIGI_MEMCPY (pCtx->pUn->env.last + pCtx->pUn->env.last_size,
                             data,
                             dataLen);
        if (OK != status)
            goto exit;
    }

    /* Set buffer length */
    pCtx->pUn->env.last_size = remain;

    /* Success */
    *encryptedInfo = encryptedData;
    *encryptedInfoLen = toEncrypt;

    encryptedData = NULL;

exit:
    if (NULL != encryptedData)
    {
        DIGI_FREE ((void**)&encryptedData);
    }
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_encryptFinal(MOC_SYM(hwAccelDescr hwAccelCtx)
                     MOC_CMS_OUT_CTX *pCtx,
                     ubyte   **encryptedInfo,
                     sbyte4  *encryptedInfoLen)
{
    MSTATUS status = OK;
    sbyte4  i;

    *encryptedInfo = NULL;
    *encryptedInfoLen = 0;

    if (0 < pCtx->pUn->env.pBulkAlgo->blockSize)
    {
        sbyte4 padSize = pCtx->pUn->env.pBulkAlgo->blockSize - pCtx->pUn->env.last_size;

        for (i = pCtx->pUn->env.last_size; i < (sbyte4)pCtx->pUn->env.pBulkAlgo->blockSize; ++i)
        {
            pCtx->pUn->env.last[i] = (ubyte) padSize;
        }

        status = pCtx->pUn->env.pBulkAlgo->cipherFunc (MOC_SYM(hwAccelCtx)
                                                       pCtx->pUn->env.pBulkCtx,
                                                       pCtx->pUn->env.last,
                                                       pCtx->pUn->env.pBulkAlgo->blockSize,
                                                       1, pCtx->pUn->env.iv);
        if (OK != status)
            goto exit;

        *encryptedInfo = pCtx->pUn->env.last;
        *encryptedInfoLen = pCtx->pUn->env.pBulkAlgo->blockSize;
    }

exit:
    return status;
}


/*----------------------------------------------------------------------*/

static MSTATUS
DIGI_CMS_OUT_Sig_getHashAlgos(MOC_CMS_OUT_CTX *pCtx)
{
    MSTATUS status = OK;
    sbyte4  idx;
    ubyte4  allHashes = 0;

    /* Assume empty list */
    pCtx->pUn->sign.numAlgos = 0;
    pCtx->pUn->sign.pHashes = NULL;

    /* Empty array? */
    if (NULL == pCtx->pUn->sign.pSigners)
    {
        goto exit;
    }

    for (idx = 0; idx < pCtx->pUn->sign.numSigners; ++idx)
    {
        const ubyte *pOID = pCtx->pUn->sign.pSigners[idx]->digestAlgoOID;
        ubyte4       OIDLen = pCtx->pUn->sign.pSigners[idx]->digestAlgoOIDLen;
        ubyte4       id;

        status = DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData (pOID, OIDLen,
                                                             &id);
        if (OK != status)
            goto exit;

        if (ht_none == id)
        {
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
        }

        /* Make an OR of all hashes */
        allHashes |= (1 << id);
    }

    /* Add any extra digests */
    for (idx = 0; idx < pCtx->pUn->sign.numAddedDigests; ++idx)
    {
        MOC_CMS_Array *pDigs = pCtx->pUn->sign.pAddedDigests[idx];
        ubyte4        id;

        status = DIGI_CMS_U_getHashAlgoIdFromHashAlgoOIDData (pDigs->pData, pDigs->dataLen,
                                                             &id);
        if (OK != status)
            goto exit;

        if (ht_none == id)
        {
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
        }

        /* Make an OR of all hashes */
        allHashes |= (1 << id);
    }

    /* Use full bit set to create actual digest hash array */
    status = DIGI_CMS_U_constructHashes (MOC_HASH(pCtx->hwAccelCtx) allHashes,
                                        &(pCtx->pUn->sign.numAlgos),
                                        &(pCtx->pUn->sign.pHashes));

exit:
    return status;
}

/*----------------------------------------------------------------------*/


static MSTATUS
DIGI_CMS_OUT_Sig_hashDataChunked(MOC_CMS_OUT_CTX *pCtx,
                                const ubyte* data,
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
DIGI_CMS_OUT_Sig_hashDataFinal(MOC_CMS_OUT_CTX *pCtx,
                              const ubyte* data,
                              ubyte4 dataLen)
{
    MSTATUS status = OK;
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
            status = pHash->hashAlgo->updateFunc (MOC_HASH(pCtx->hwAccelCtx)
                                                  pHash->bulkCtx,
                                                  data, dataLen);
            if (OK != status)
                goto exit;
        }

        status = pHash->hashAlgo->finalFunc (MOC_HASH(pCtx->hwAccelCtx)
                                             pHash->bulkCtx,
                                             pHash->hashData);
        if (OK != status)
            goto exit;
    }


    pCtx->pUn->sign.hashesDone = TRUE;

exit:
    return status;
}

/*----------------------------------------------------------------------*/


extern MSTATUS
DIGI_CMS_createBulkAlgo(MOC_SYM(hwAccelDescr hwAccelCtx)
                       ubyte  *pOID,
                       ubyte4 OIDLen,
                       MOC_CMS_ASN1_Memory    *pMem,
                       MOC_CMS_OUT_EnvelopCtx *pCtx)
{
    MSTATUS status = OK;
    sbyte4  keyLength = 0;

    ubyte   *algoParams = NULL;
    ubyte4  algoParamsLen;

    MAsn1Element *pAlgoIdRec = NULL;
    /* AlgorithmIdentifier  [rfc5280 - Section 4.1.1.2, page 17] */
    MAsn1TypeAndCount defAlgoId[3] =
    {
         {  MASN1_TYPE_SEQUENCE, 2},
            {  MASN1_TYPE_OID, 0}, /* OID */
            {  MASN1_TYPE_OCTET_STRING | MASN1_OPTIONAL, 0 },
    };

    status = MAsn1CreateElementArray (defAlgoId, 3, MASN1_FNCT_ENCODE,
                                      NULL, &pAlgoIdRec);
    if (OK != status)
        goto exit;

    /* Set up bulk encrypt algorithm and obtain IV size */
    status = DIGI_CMS_U_getCryptoAlgoParams (pOID, OIDLen,
                                            &(pCtx->pBulkAlgo),
                                            &keyLength);
    if (OK != status)
       goto exit;

    pCtx->encrKeyLen = keyLength;

    /* Valid OID, so set it in ASN1 */
    status = MAsn1SetValue (pAlgoIdRec + 1,
                            pOID, OIDLen);
    if (OK != status)
        goto exit;

    /* Create the encryption context and the IV */
    status = pCtx->encrRngFun (pCtx->encrRngArg,
                              (ubyte4) keyLength,
                              pCtx->encryptKey);
    if (OK != status)
       goto exit;

    if (0 < pCtx->pBulkAlgo->blockSize)
    {
        status = pCtx->encrRngFun (pCtx->encrRngArg,
                                   pCtx->pBulkAlgo->blockSize,
                                   pCtx->iv);
        if (OK != status)
            goto exit;

        status = MAsn1SetValue (pAlgoIdRec + 2,
                                pCtx->iv, pCtx->pBulkAlgo->blockSize);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = MAsn1SetValue (pAlgoIdRec + 2, NULL, 0);
        if (OK != status)
            goto exit;
    }

    /* Create context */
    pCtx->pBulkCtx = pCtx->pBulkAlgo->createFunc (MOC_SYM(hwAccelCtx)
                                                  pCtx->encryptKey, keyLength, 1);
    if (NULL == pCtx->pBulkCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Make full ASN1 */
    status = MAsn1EncodeAlloc (pAlgoIdRec, &algoParams, &algoParamsLen);
    if (OK != status)
        goto exit;

    /* Set the data for this algorithm */
    status = MAsn1SetValue (pCtx->pRoot + pCtx->idxAlgo,
                            algoParams, algoParamsLen);
    if (OK != status)
        goto exit;

    status = DIGI_CMS_U_addToAsn1MemoryCache (pMem, (void*)algoParams);
    if (OK != status)
        goto exit;

    /* Now owned by MAsn1Element */
    algoParams = NULL;

exit:
/* Error clean up */
    if (NULL != algoParams)
    {
        DIGI_FREE ((void**)&algoParams);
    }
    MAsn1FreeElementArray (&pAlgoIdRec);
    return status;
}
#endif  /* (defined(__ENABLE_DIGICERT_CMS__) && !defined(__DISABLE_DIGICERT_CMS_ENCODER__)) */
