/* Version: /Users/roubindersingh/Downloads/ */
/*
 * ocsp_message.c
 *
 * OCSP -- Online Certificate Status Protocol Messages
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
#include "../common/datetime.h"
#include "../asn1/oiddefs.h"
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
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/asn1cert.h"
#include "../http/http_context.h"
#include "../ocsp/ocsp.h"
#include "../ocsp/ocsp_context.h"
#include "../ocsp/ocsp_message.h"
#include "../harness/harness.h"
#include "../crypto_interface/cryptointerface.h"

#include "../common/memory_debug.h"


/*------------------------------------------------------------------*/

typedef enum CertificateChild
{
    cert_version               = 1,
    cert_serialNumber          = 2,
    cert_signature             = 3,
    cert_issuer                = 4,
    cert_validity              = 5,
    cert_subject               = 6,
    cert_subjectPublicKeyInfo  = 7

} CertificateChild;


/*------------------------------------------------------------------*/

/* General static methods */
static MSTATUS OCSP_MESSAGE_sanityCheck(ocspContext *pOcspContext);
static MSTATUS OCSP_MESSAGE_GetCertificatePart(ASN1_ITEM* rootItem, ASN1_ITEM** ppCertificate);
static MSTATUS OCSP_MESSAGE_getSignedCertificateChild(ASN1_ITEM* pCertificate, CertificateChild whichChild, ASN1_ITEM** ppChild);
static MSTATUS OCSP_MESSAGE_getCertificatePartChild(ASN1_ITEM* pCertificate, CertificateChild whichChild, ASN1_ITEM** ppChild);
static MSTATUS OCSP_MESSAGE_getCertificateChild(ASN1_ITEM* pCertificateRoot, CertificateChild whichChild, ASN1_ITEM** ppChild);
static MSTATUS OCSP_MESSAGE_getCertificateIssuerSerialNumber(ubyte* pCert, ubyte4 certLen, certDistinguishedName *pIssuerDN, ubyte **ppSerialNumber, ubyte4 *pLen);
extern MSTATUS OCSP_MESSAGE_getCertificateSignature(ASN1_ITEM* pCertificate, ASN1_ITEM** ppSignature);
static MSTATUS OCSP_MESSAGE_getHash(ocspContext *pOcspContext, ubyte* pData, ubyte4 dataLen, const ubyte* hashAlgo, ubyte* pHashBuf, ubyte4* pHashLen);
static MSTATUS OCSP_MESSAGE_certDistinguishedNameCompare(certDistinguishedName *pNameInfo1, certDistinguishedName *pNameInfo2, sbyte4 *pResult);
static MSTATUS OCSP_MESSAGE_checkCertificateIssuer(ubyte* pCert, ubyte4 certLen, ubyte* pIssuerCert, ubyte4 issuerCertLen);
#if 0
static MSTATUS GetCertOID(ASN1_ITEM* pAlgoId, CStream s, const ubyte* whichOID, ubyte* whichOIDSubType, ASN1_ITEM** ppOID);
#endif

/* Static methods used in request generation*/
static MSTATUS OCSP_MESSAGE_addRequest(DER_ITEMPTR requestList, OCSP_singleRequest *pRequest);
static MSTATUS OCSP_MESSAGE_addServiceLocator(OCSP_singleRequestInfo *pSingleRequestInfo, extensions **ppExt);
static MSTATUS OCSP_MESSAGE_sign(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead, ocspContext *pOcspContext, const ubyte* signAlgoOID);
static MSTATUS OCSP_MESSAGE_rsaSignAux(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey, DER_ITEMPTR pToSign, ubyte signAlgo, ubyte **ppSignature, sbyte4 *sigLen);

/* Static methods used during parsing of a response */
static MSTATUS OCSP_MESSAGE_verifySignature(ocspContext *pOcspContext, ASN1_ITEMPTR pResponseRoot, CStream cs);
static MSTATUS OCSP_MESSAGE_checkResponderId(ocspContext *pOcspContext);
static MSTATUS OCSP_MESSAGE_checkTime(ocspContext *pOcspContext);
static MSTATUS OCSP_MESSAGE_checkNonce(ocspContext *pOcspContext);
static MSTATUS OCSP_MESSAGE_checkOCSPSigning(ocspContext *pOcspContext, byteBoolean *isfound);
static MSTATUS OCSP_MESSAGE_validateCertInfo(ocspContext *pOcspContext,OCSP_certID *pCertId);

/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_GetCertificatePart(ASN1_ITEM* rootItem, ASN1_ITEM** ppCertificate)
{
    ASN1_ITEMPTR pItem  = NULL;
    MSTATUS      status = ERR_CERT_INVALID_STRUCT;

    if ((NULL == rootItem) || (NULL == ppCertificate))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* go to signed struct */
    if (NULL == (pItem = ASN1_FIRST_CHILD(rootItem)))
        goto exit;

    /* go to certificate object */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    *ppCertificate = pItem;
    status = OK;

exit:
    return status;

} /* OCSP_MESSAGE_GetCertificatePart */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_getSignedCertificateChild(ASN1_ITEM* pSignedCertificate,
                                       CertificateChild whichChild,
                                       ASN1_ITEM** ppChild)
{
    ASN1_ITEMPTR pCertificate   = NULL;
    MSTATUS      status         = OK;

    if ((NULL == pSignedCertificate) || (NULL == ppChild))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get to the certificate part */
    if (NULL == (pCertificate = ASN1_FIRST_CHILD(pSignedCertificate)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getCertificatePartChild(pCertificate, whichChild, ppChild)))
        goto exit;

exit:
    return status;

} /* OCSP_MESSAGE_getSignedCertificateChild */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_getCertificatePartChild(ASN1_ITEM* pCertificate,
                                     CertificateChild whichChild,
                                     ASN1_ITEM** ppChild)
{
    ASN1_ITEMPTR pVersion  = NULL;
    MSTATUS      status    = OK;

    if ((NULL == pCertificate) || (NULL == ppChild))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* need to see if there is the optional version (tag 0) */
    if (OK > (status = ASN1_GetChildWithTag(pCertificate, 0, &pVersion)))
        goto exit;

    if (ppChild)
    {
        if (OK > ASN1_GetNthChild(pCertificate, (pVersion) ? whichChild : whichChild - 1, ppChild))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
    }

exit:

    return status;

} /* OCSP_MESSAGE_getCertificatePartChild */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_getCertificateChild(ASN1_ITEM* pCertificateRoot,
                                 CertificateChild whichChild,
                                 ASN1_ITEM** ppChild)
{
    ASN1_ITEMPTR pCertificate = NULL;
    MSTATUS      status       = OK;

    if ((NULL == pCertificateRoot) || (NULL == ppChild))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_GetCertificatePart(pCertificateRoot, &pCertificate)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getCertificatePartChild(pCertificate, whichChild, ppChild)))
        goto exit;

exit:
    if (pCertificate)
        TREE_DeleteTreeItem((TreeItem *) pCertificate);

    return status;

} /* OCSP_MESSAGE_getCertificateChild */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_getCertificateIssuerSerialNumber(ubyte* pCert, ubyte4 certLen,
                                              certDistinguishedName *pIssuerDN,
                                              ubyte **ppSerialNumber, ubyte4 *pLen)
{
    MemFile      mf;
    CStream      cs;
    ASN1_ITEMPTR pCertRoot     = NULL;
    ASN1_ITEMPTR pIssuer       = NULL;
    ASN1_ITEMPTR pSerialNum    = NULL;
    ubyte*       pSerialNumber = NULL;
    MSTATUS      status    = OK;

    MF_attach(&mf, certLen, pCert);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pCertRoot), &pIssuer, &pSerialNum)))
        goto exit;

    if (pIssuerDN)
    {
        if (OK > (status = X509_extractDistinguishedNamesFromName(pIssuer, cs, pIssuerDN)))
            goto exit;
    }

    if (ppSerialNumber)
    {
        ubyte *buf = NULL;

        if (NULL == (pSerialNumber = MALLOC(pSerialNum->length)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *pLen = pSerialNum->length;
        buf   = (ubyte*)CS_memaccess(cs, pSerialNum->dataOffset, pSerialNum->length);

        if (OK > (status = DIGI_MEMCPY(pSerialNumber, buf, pSerialNum->length)))
        {
            goto exit;
        }

        if (buf)
        {
            CS_stopaccess(cs, buf);
        }

        *ppSerialNumber = pSerialNumber;
        pSerialNumber   = NULL;
    }

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem*)pCertRoot);

    if (pSerialNumber)
        FREE(pSerialNumber);

    return status;

} /* OCSP_MESSAGE_getCertificateIssuerSerialNumber */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCertificateSignature(ASN1_ITEM* pCertificate, ASN1_ITEM** ppSignature)
{
    MSTATUS status = OK;

    if ((NULL == pCertificate) || (NULL == ppSignature))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = ASN1_GetNthChild(pCertificate, 3, ppSignature)))
        goto exit;

exit:
    return status;

} /* OCSP_MESSAGE_getCertificateSignature */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_getHash(ocspContext *pOcspContext, ubyte* pData, ubyte4 dataLen,
                     const ubyte* hashAlgo, ubyte* pHashBuf, ubyte4* pHashLen)
{
    void*   pHash       = NULL;
    void*   pTempBuf    = NULL;
    ubyte4  digestSize  = 0;
    MSTATUS status      = OK;

    *pHashLen = 0;

    if (OK > (status = CRYPTO_ALLOC(pOcspContext->hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(pOcspContext->hwAccelCtx, dataLen, TRUE, &pTempBuf)))
        goto exit;

    DIGI_MEMCPY(pTempBuf, pData, dataLen);

    if (EqualOID(md5_OID, hashAlgo))
    {
        digestSize = MD5_RESULT_SIZE;
        status     = MD5_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
    else if (EqualOID(sha1_OID, hashAlgo))
    {
        digestSize = SHA1_RESULT_SIZE;
        status     = SHA1_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
#if (!defined(__DISABLE_DIGICERT_SHA224__))
    else if (EqualOID(sha224_OID, hashAlgo))
    {
        digestSize = SHA224_RESULT_SIZE;
        status     = SHA224_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
#endif
#if (!defined(__DISABLE_DIGICERT_SHA256__))
    else if (EqualOID(sha256_OID, hashAlgo))
    {
        digestSize = SHA256_RESULT_SIZE;
        status     = SHA256_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
#endif
#if (!defined(__DISABLE_DIGICERT_SHA384__))
    else if (EqualOID(sha384_OID, hashAlgo))
    {
        digestSize = SHA384_RESULT_SIZE;
        status     = SHA384_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
#endif
#if (!defined(__DISABLE_DIGICERT_SHA512__))
    else if (EqualOID(sha512_OID, hashAlgo))
    {
        digestSize = SHA512_RESULT_SIZE;
        status     = SHA512_completeDigest(MOC_HASH(pOcspContext->hwAccelCtx) pTempBuf, dataLen, pHash);
    }
#endif
    else
    {
        status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
    }

    if (OK > status)
        goto exit;

    DIGI_MEMCPY(pHashBuf, pHash, digestSize);
    *pHashLen = digestSize;

exit:

    if (pTempBuf)
        CRYPTO_FREE(pOcspContext->hwAccelCtx, TRUE, &pTempBuf);

    if (pHash)
        CRYPTO_FREE(pOcspContext->hwAccelCtx, TRUE, &pHash);

    return status;

} /* OCSP_MESSAGE_getHash */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_certDistinguishedNameCompare(certDistinguishedName *pNameInfo1,
                                          certDistinguishedName *pNameInfo2,
                                          sbyte4 *pResult)
{
    relativeDN* pRelativeDN1 = NULL;
    relativeDN* pRelativeDN2 = NULL;
    ubyte4      i;
    MSTATUS     status = OK;

    if (!pResult)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pResult = -1;

    if (!pNameInfo1 || !pNameInfo2)
        goto exit;

   if (pNameInfo1->dnCount != pNameInfo2->dnCount)
   {
       goto exit;
   }
   else
   {
       pRelativeDN1 = pNameInfo1->pDistinguishedName;
       pRelativeDN2 = pNameInfo2->pDistinguishedName;

       for (i = 0; i < pNameInfo1->dnCount; i++)
       {
            nameAttr *pAttr1;
            nameAttr *pAttr2;
            ubyte4 j;

            if ((pRelativeDN1+i)->nameAttrCount != (pRelativeDN2+i)->nameAttrCount)
                goto exit;

            pAttr1 = (pRelativeDN1+i)->pNameAttr;
            pAttr2 = (pRelativeDN2+i)->pNameAttr;

            for (j = 0; j < (pRelativeDN1+i)->nameAttrCount; j++)
            {
                sbyte4 result;

                if ((pAttr1+j)->oid != (pAttr2+j)->oid)
                    goto exit;

                if ((pAttr1+j)->type != (pAttr2+j)->type)
                    goto exit;

                if ((pAttr1+j)->valueLen != (pAttr2+j)->valueLen)
                    goto exit;

                if (OK > (status = DIGI_MEMCMP((pAttr1+j)->value, (pAttr2+j)->value, (pAttr1+j)->valueLen, &result)))
                    goto exit;

                if (result != 0)
                    goto exit;
            }
       }

       *pResult = 0;
   }

exit:
    return status;

} /* OCSP_MESSAGE_certDistinguishedNameCompare */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_rsaSignAux(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey,
                        DER_ITEMPTR pToSign, ubyte signAlgo,
                        ubyte **ppSignature, sbyte4 *pSigLen)
{
    ubyte4          dataLen;
    sbyte4          temp;
    void*           pHash               = NULL;
    void*           pTempBuf            = NULL;
    ubyte*          pBitString          = NULL;
    DER_ITEMPTR     pSequence           = NULL;
    ubyte*          pBuffer             = NULL;
    const ubyte*    hashAlgoOID         = NULL;
    ubyte4          digestSize          = 0;
    MSTATUS         status              = OK;

    /* Find the signature length */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelCtx)
        pRSAKey, &temp, akt_undefined);
    if (OK != status)
        goto exit;
#else
    if (OK > (status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, &temp)))
        goto exit;
#endif

    if (NULL == (pBitString = MALLOC(temp + 1))) /* Additional padding bit */
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pSigLen = temp;

    if (OK > (status = DER_GetLength(pToSign, &dataLen)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, dataLen, TRUE, &pTempBuf)))
        goto exit;

    if (OK > (status = DER_SerializeInto(pToSign, pTempBuf, &dataLen)))
        goto exit;

    switch (signAlgo)
    {
        case md5withRSAEncryption:
        {
            digestSize  = MD5_RESULT_SIZE;
            hashAlgoOID = md5_OID;
            status      = MD5_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }

        case sha1withRSAEncryption:
        {
            digestSize  = SHA1_RESULT_SIZE;
            hashAlgoOID = sha1_OID;
            status      = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }

#ifndef __DISABLE_DIGICERT_SHA224__
        case sha224withRSAEncryption:
        {
            digestSize  = SHA224_RESULT_SIZE;
            hashAlgoOID = sha224_OID;
            status      = SHA224_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case sha256withRSAEncryption:
        {
            digestSize  = SHA256_RESULT_SIZE;
            hashAlgoOID = sha256_OID;
            status      = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case sha384withRSAEncryption:
        {
            digestSize  = SHA384_RESULT_SIZE;
            hashAlgoOID = sha384_OID;
            status      = SHA384_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case sha512withRSAEncryption:
        {
            digestSize  = SHA512_RESULT_SIZE;
            hashAlgoOID = sha512_OID;
            status      = SHA512_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
        }
#endif

        default:
        {
            status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
            break;
        }
    }

    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    if (OK > status)
        goto exit;

    /* now construct a new ASN.1 DER encoding with this */
    if (OK > (status = DER_AddSequence(NULL, &pSequence)))
        goto exit;

    if (OK > (status = DER_StoreAlgoOID(pSequence, hashAlgoOID, TRUE)))
       goto exit;

    if (OK > (status = DER_AddItem(pSequence, OCTETSTRING, digestSize, pHash, NULL)))
       goto exit;

    if (OK > (status = DER_Serialize(pSequence, &pBuffer, &dataLen)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(hwAccelCtx)
        pRSAKey, pBuffer, dataLen, &pBitString[1], NULL, akt_undefined);
    if (OK != status)
        goto exit;
#else
    if (OK > (status = RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, pBuffer,
                                       dataLen, &pBitString[1], NULL)))
        goto exit;
#endif

    pBitString[0] = 0x00;
    *ppSignature  = pBitString;
    pBitString    = NULL;

exit:
    if (pSequence)
        TREE_DeleteTreeItem((TreeItem *) pSequence);

    if (pBuffer)
        FREE(pBuffer);

    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    if (pHash)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pHash);

    if (pBitString)
        FREE(pBitString);

    return status;

} /* OCSP_MESSAGE_rsaSignAux */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_sign(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
                  ocspContext *pOcspContext, const ubyte* signAlgoOID)

{
    sbyte4         signatureLen  = 0;
    sbyte4         cmpRes;
    AsymmetricKey  signKey;
    DER_ITEMPTR    pSignature    = NULL;
    ubyte          isKeyInit     = 0;
    ubyte*         pBitString    = NULL;
    certDescriptor privKeyDesc;
    MSTATUS        status        = OK;

    if ((NULL == pSignedHead) || (NULL == pOcspContext) || (NULL == signAlgoOID))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Initialize private key descriptor */
    privKeyDesc.pCertificate  = pOcspContext->pOcspSettings->pPrivKey;
    privKeyDesc.certLength    = pOcspContext->pOcspSettings->privKeyLen;
    privKeyDesc.pKeyBlob      = NULL;
    privKeyDesc.keyBlobLength = 0;

    /* Convert the private key certificate in DER format to internal */
    /* Digicert internal structure                                     */
    if (OK > (status = CA_MGMT_convertKeyDER(privKeyDesc.pCertificate,privKeyDesc.certLength,
                                             &privKeyDesc.pKeyBlob, &privKeyDesc.keyBlobLength)))
    {
        goto exit;
    }

    if ((0 >= privKeyDesc.keyBlobLength) || (NULL == privKeyDesc.pKeyBlob))
    {
        status = ERR_OCSP_MISSING_SIGNER_KEY;
        goto exit;
    }

    if (OK > (status = CRYPTO_initAsymmetricKey(&signKey)))
        goto exit;

    isKeyInit = 1;

    if (OK > (status = CA_MGMT_extractKeyBlobEx(privKeyDesc.pKeyBlob, privKeyDesc.keyBlobLength, &signKey)))
        goto exit;

    /* signature algo */
    if (OK > (status = DER_AddTag(pSignedHead, 0, &pSignature)))
        goto exit;

    if (OK > (status = DER_AddSequence(pSignature, &pSignature)))
        goto exit;

    /* verify this is a signAlgo we support */
    switch(signKey.type)
    {
        case akt_rsa:
        {
            if (PKCS1_OID_LEN+1 != signAlgoOID[0])
            {
                status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
                goto exit;
            }

            DIGI_MEMCMP(signAlgoOID + 1, pkcs1_OID + 1, PKCS1_OID_LEN, &cmpRes);

            if (0 != cmpRes)
            {
                status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
                goto exit;
            }

            if (OK > (status = DER_StoreAlgoOID(pSignature, signAlgoOID, TRUE)))
                goto exit;

            /* now generate the signature */
            if (OK > (status = OCSP_MESSAGE_rsaSignAux(MOC_RSA(hwAccelCtx) signKey.key.pRSA,
                                                       DER_FIRST_CHILD(pSignedHead),
                                                       signAlgoOID[ 1 + PKCS1_OID_LEN],
                                                       &pBitString, &signatureLen)))
            {
                goto exit;
            }

            break;
        }

        case akt_dsa:
        {
            /* We currently do not support request signing by DSA which is an
                            OPTIONAL requirement an error would be send as the code will
                            fall onto default without break */

            if (dsaWithSHA1_OID[0] != signAlgoOID[0])
            {
                status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
                goto exit;
            }

            DIGI_MEMCMP(signAlgoOID, dsaWithSHA1_OID, dsaWithSHA1_OID[0]+1, &cmpRes);
            if (0 != cmpRes)
            {
                status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
                goto exit;
            }

            if (OK > (status = DER_StoreAlgoOID(pSignature, signAlgoOID, TRUE)))
                goto exit;

            /* FALL_THROUGH */
        }

        default:
        {
            status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
            break;
        }
    }

    /* Add signature */
    if (OK > (status = DER_AddItemOwnData(pSignature, BITSTRING, signatureLen + 1, /* +1 unused bits octets */
                                          &pBitString, NULL)))
    {
        goto exit;
    }

    /* add requester cert if present */
    if (pOcspContext->pOcspSettings->signerCertLen > 0)
    {
        if (OK > (status = DER_AddTag(pSignature, 0, &pSignature)))
            goto exit;

        if (OK > (status = DER_AddItem(pSignature, SEQUENCE|CONSTRUCTED,
                                       pOcspContext->pOcspSettings->signerCertLen,
                                       pOcspContext->pOcspSettings->pSignerCert, NULL)))
        {
            goto exit;
        }
    }

exit:
    if (isKeyInit)
    {
        CRYPTO_uninitAsymmetricKey(&signKey, NULL);

        if (privKeyDesc.pKeyBlob)
            FREE(privKeyDesc.pKeyBlob);
    }

    if (pBitString)
        FREE(pBitString);

    return status;

} /* OCSP_MESSAGE_sign */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_addRequest(DER_ITEMPTR requestList, OCSP_singleRequest *pRequest)
{
    DER_ITEMPTR request = NULL;
    DER_ITEMPTR certID  = NULL;
    DER_ITEMPTR ext     = NULL;
    MSTATUS     status  = OK;

    if (OK > (status = DER_AddSequence(requestList, &request)))
        goto exit;

    /* add CertID */
    if (OK > (status = DER_AddSequence(request, &certID)))
        goto exit;

    if (OK > (status = DER_StoreAlgoOID(certID, pRequest->certId.hashAlgo, TRUE)))
        goto exit;

    if (OK > (status = DER_AddItem(certID, OCTETSTRING, pRequest->certId.hashLength, pRequest->certId.nameHash, NULL)))
        goto exit;

    if (OK > (status = DER_AddItem(certID, OCTETSTRING, pRequest->certId.hashLength, pRequest->certId.keyHash, NULL)))
        goto exit;

    if (OK > (status = DER_AddItem(certID, INTEGER, pRequest->certId.serialNumberLength, pRequest->certId.serialNumber, NULL)))
        goto exit;

    /* add any single request extensions if any */
    if ((0 < pRequest->extNumber) && (NULL != pRequest->singleRequestExtensions))
    {
        ubyte4      i;
        DER_ITEMPTR pTemp = NULL;

        if (OK > (status = DER_AddTag(request, 0, &ext)))
            goto exit;

        if (OK > (status = DER_AddSequence(ext, &ext)))
            goto exit;

        for (i = 0; i < pRequest->extNumber; i++)
        {
            extensions *pExt = &(pRequest->singleRequestExtensions[i]);

            if (OK > (status = DER_AddSequence(ext, &pTemp)))
                goto exit;

            if (OK > (status = DER_AddOID(pTemp, pExt->oid, NULL)))
                goto exit;

            if (pExt->isCritical)
            {
                ubyte copyData[MAX_DER_STORAGE];

                copyData[0] = 0xff;

                if (OK > (status = DER_AddItemCopyData(pTemp, BOOLEAN, 1, copyData, NULL)))
                    goto exit;
            }

            if (OK > (status = DER_AddItem(pTemp, OCTETSTRING, pExt->valueLen, pExt->value, NULL)))
                goto exit;

        }
    }

exit:

    return status;

} /* OCSP_MESSAGE_addRequest */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_addExtension(DER_ITEMPTR pRequestExt, extensions *pExt)
{
    ubyte       copyData[MAX_DER_STORAGE];
    DER_ITEMPTR pTempExt = NULL;
    MSTATUS     status    = OK;

    if (OK > (status = DER_AddSequence(pRequestExt, &pTempExt)))
        goto exit;

    if (OK > (status = DER_AddOID(pTempExt, pExt->oid, NULL)))
        goto exit;

    if (pExt->isCritical)
    {
        copyData[0] = 0xff;

        if (OK > (status = DER_AddItemCopyData(pTempExt, BOOLEAN, 1, copyData, NULL)))
            goto exit;
    }

    if (OK > (status = DER_AddItem(pTempExt, OCTETSTRING, pExt->valueLen, pExt->value, NULL)))
        goto exit;

exit:
    return status;

} /* OCSP_MESSAGE_addExtension */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_addServiceLocator(OCSP_singleRequestInfo *pSingleRequestInfo, extensions **ppExt)
{
    MemFile      memfile;
    CStream      cs;
    extensions*  pExt            = NULL;
    ASN1_ITEMPTR pCertRoot       = NULL;
    ASN1_ITEMPTR pIssuerName     = NULL;
    ASN1_ITEMPTR pAIA            = NULL;
    DER_ITEMPTR  pServiceLocator = NULL;
    MSTATUS      status          = OK;

    if ((NULL == pSingleRequestInfo->pCert) || (NULL == ppExt) || (0 >= pSingleRequestInfo->certLen))
        goto exit;

    *ppExt = NULL;

    if (NULL == (pExt = MALLOC(sizeof(extensions))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Create a DER root Item to fill serviceLocator content */
    if (OK > (status = DER_AddSequence(NULL, &pServiceLocator)))
        goto exit;

    MF_attach(&memfile, pSingleRequestInfo->certLen, pSingleRequestInfo->pCert);
    CS_AttachMemFile(&cs, &memfile);

    if (OK > (status = ASN1_Parse(cs, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get the issuerName field from the certificate */
    if (OK > (status = OCSP_MESSAGE_getSignedCertificateChild(ASN1_FIRST_CHILD(pCertRoot), cert_issuer, &pIssuerName)))
        goto exit;

    /* Copy issuer name data into DER root */
    if (OK > (status = DER_AddItem(pServiceLocator,SEQUENCE|CONSTRUCTED, pIssuerName->length,
                                   pSingleRequestInfo->pCert + pIssuerName->dataOffset,
                                   NULL)))
    {
        goto exit;
    }

    /* Now try to add AuthorityInfoAccess locator: optional field if not found no error */
    if (NULL == (pAIA = ASN1_FIRST_CHILD(pCertRoot)))
        goto genExt;

    if (NULL == (pAIA = ASN1_FIRST_CHILD(pAIA)))
        goto genExt;

    /* Goto Extensions */
    if (OK > (status = ASN1_GetChildWithTag(pAIA, 3, &pAIA)))
        goto exit;

    if (NULL == pAIA)
    {
        /* Not found; Not an Error */
        goto genExt;
    }

    status = ASN1_GetChildWithOID(pAIA, cs, id_pe_authorityInfoAcess_OID, &pAIA);
    if (OK != status || NULL == pAIA)
    {
        /* Not found; Not an Error */
        goto genExt;
    }

    /* Go to the next sibling's first child to simply copy the entire sequence */
    if (NULL == (pAIA = ASN1_NEXT_SIBLING(pAIA)))
        goto genExt;  /* Not found; Not an Error */

    if (NULL == (pAIA = ASN1_FIRST_CHILD(pAIA)))
        goto genExt;  /* Not found; Not an Error */

    /* Copy AIA data into DER root */
    if (OK > (status = DER_AddItem(pServiceLocator,SEQUENCE|CONSTRUCTED, pAIA->length,
                                   pSingleRequestInfo->pCert+pAIA->dataOffset,
                                   NULL)))
    {
        goto exit;
    }

genExt:
    /* This generates the extension even in the absence of optional AIA field */
    pExt->oid        = (ubyte *)id_pkix_ocsp_service_locator;
    pExt->isCritical = FALSE;

    /* Serialize it into DER format */
    if (OK > (status = DER_Serialize(pServiceLocator, &pExt->value, &pExt->valueLen)))
        goto exit;

    *ppExt = pExt;
    pExt   = NULL;

exit:
    if (pExt)
        FREE(pExt);

    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    if (pServiceLocator)
        TREE_DeleteTreeItem((TreeItem *)pServiceLocator);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_addNonce(ocspContext *pOcspContext,DER_ITEMPTR pRequestExt)
{
    ubyte4         nonceLen    = 16;
    ubyte*         nonce       = NULL;
    DER_ITEMPTR    pNonce      = NULL;
    DER_ITEMPTR    pNonceValue = NULL;
    ubyte*         nonceValue  = NULL;
    ubyte4         nonceValueLen;
    MSTATUS        status      = OK;

    if (NULL == (nonce = MALLOC(nonceLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = RANDOM_numberGenerator(g_pRandomContext, nonce, nonceLen)))
        goto exit;

    if (OK > (status = DER_AddSequence(pRequestExt, &pNonce)))
        goto exit;

    if (OK > (status = DER_AddOID(pNonce, id_pkix_ocsp_nonce_OID, NULL)))
        goto exit;

    if (OK > (status = DER_AddItem(NULL, OCTETSTRING, nonceLen, nonce, &pNonceValue)))
        goto exit;

    if (OK > (status = DER_Serialize(pNonceValue, &nonceValue, &nonceValueLen)))
        goto exit;

    if (OK > (status = DER_AddItemOwnData(pNonce, OCTETSTRING, nonceValueLen, &nonceValue, NULL)))
        goto exit;

    /* Cache the values to validate during parsing */
    pOcspContext->ocspProcess.client.nonce    = nonce;
    pOcspContext->ocspProcess.client.nonceLen = nonceLen;

    nonce = NULL;

exit:

    if (pNonceValue)
        TREE_DeleteTreeItem((TreeItem*)pNonceValue);
    if (nonce)
        FREE(nonce);

    return status;

} /* OCSP_MESSAGE_addNonce */

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_generateSingleRequestEx(ocspContext *pOcspContext,
                                     ubyte* pCertSerialNo, ubyte4 serialNoLen,
                                     OCSP_singleRequestInfo *pSingleRequestInfo,
                                     OCSP_singleRequest *pSingleRequest)
{
    certDistinguishedName* pIssuerInfo        = NULL;
    ubyte*                 pKeyHash           = NULL;
    ubyte*                 pNameHash          = NULL;
    ubyte*                 pData              = NULL;
    ASN1_ITEMPTR           pSubject           = NULL;
    ASN1_ITEMPTR           pPubKeyInfo        = NULL;
    ASN1_ITEMPTR           pPubKey            = NULL;
    ubyte4                 dataLen;
    ubyte4                 hashSize;
    MSTATUS                status             = OK;

    if ((NULL == pSingleRequest) || (NULL == pOcspContext) || (NULL == pCertSerialNo) || (NULL == pSingleRequestInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pSingleRequest,0x00, sizeof(OCSP_singleRequest))))
        goto exit;

    /* Fall back to default Algo sha1 in case not manually configured */
    pSingleRequest->certId.hashAlgo = ((NULL != pOcspContext->pOcspSettings->hashAlgo) ?
                                               (pOcspContext->pOcspSettings->hashAlgo) : (sha1_OID));

    if (NULL == (pNameHash = MALLOC(CERT_MAXDIGESTSIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (pKeyHash = MALLOC(CERT_MAXDIGESTSIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pOcspContext->ocspProcess.client.issuerCertBuf = pOcspContext->pOcspSettings->pIssuerCert;

    MF_attach(&pOcspContext->ocspProcess.client.issuerMemFile, pOcspContext->pOcspSettings->issuerCertLen, pOcspContext->pOcspSettings->pIssuerCert);
    CS_AttachMemFile(&pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.issuerMemFile);

    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.pIssuerRoot)))
        goto exit;

    if (NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subject, &pSubject)))
        goto exit;

    dataLen = pSubject->headerSize + pSubject->length;
    pData   = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.issuerCs, pSubject->dataOffset - pSubject->headerSize, dataLen);

    if (OK > (status = OCSP_MESSAGE_getHash(pOcspContext, pData, dataLen,
                                            pSingleRequest->certId.hashAlgo,
                                            pNameHash, &hashSize)))
    {
        goto exit;
    }

    if (pData)
    {
        CS_stopaccess(pOcspContext->ocspProcess.client.issuerCs, pData);
    }

    pSingleRequest->certId.hashLength = hashSize;

    /* Copy the name hash in the request */
    if (NULL == (pSingleRequest->certId.nameHash  = MALLOC(pSingleRequest->certId.hashLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pSingleRequest->certId.nameHash, pNameHash, pSingleRequest->certId.hashLength);

    if (NULL == (pOcspContext->ocspProcess.client.issuerNameHash = MALLOC(hashSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subjectPublicKeyInfo, &pPubKeyInfo)))
        goto exit;

    /* get to the key bits */
    if (OK > (status = ASN1_GetNthChild(pPubKeyInfo, 2, &pPubKey)))
        goto exit;

    pData   = (ubyte*) CS_memaccess(pOcspContext->ocspProcess.client.issuerCs, pPubKey->dataOffset, pPubKey->length);
    dataLen = pPubKey->length;

    if (OK > (status = OCSP_MESSAGE_getHash(pOcspContext, pData, dataLen, pSingleRequest->certId.hashAlgo,
        pKeyHash, &hashSize)))
    {
        goto exit;
    }

    if (pData)
    {
        CS_stopaccess(pOcspContext->ocspProcess.client.issuerCs, pData);
    }

    /* copy the keyHash into singlerequest */
    if (NULL == (pSingleRequest->certId.keyHash = MALLOC(pSingleRequest->certId.hashLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pSingleRequest->certId.keyHash, pKeyHash, pSingleRequest->certId.hashLength);

    if (NULL == (pOcspContext->ocspProcess.client.issuerPubKeyHash = MALLOC(hashSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Caching for multiple certs with same issuer */
    DIGI_MEMCPY(pOcspContext->ocspProcess.client.issuerNameHash, pNameHash, hashSize);
    DIGI_MEMCPY(pOcspContext->ocspProcess.client.issuerPubKeyHash, pKeyHash, hashSize);
    pOcspContext->ocspProcess.client.hashSize    = hashSize;
    pOcspContext->ocspProcess.client.pIssuerInfo = pIssuerInfo;

    /** RHS values will be uninitialized in case of same issuer **/
    pSingleRequest->certId.serialNumber       = pCertSerialNo;
    pSingleRequest->certId.serialNumberLength = serialNoLen;
    pSingleRequest->singleRequestExtensions   = pSingleRequestInfo->pSingleExts;
    pSingleRequest->extNumber                 = pSingleRequestInfo->extCount;

    /* Add Service Locator Extension; Optional */
    if (pOcspContext->pOcspSettings->shouldAddServiceLocator)
    {
        extensions* pServiceExt;

        if (OK < (status = OCSP_MESSAGE_addServiceLocator(pSingleRequestInfo, &pServiceExt)))
            goto exit;

        if (pServiceExt)
        {
            extensions* pExts = NULL;

            pSingleRequest->extNumber = pSingleRequest->extNumber + 1;

            if (NULL == (pExts = MALLOC(sizeof(extensions)*(pSingleRequest->extNumber))))
            {
                FREE(pServiceExt);
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMSET((ubyte *)pExts, 0x00, sizeof(extensions)*(pSingleRequest->extNumber));
            DIGI_MEMCPY(pExts, pSingleRequest->singleRequestExtensions,sizeof(extensions)*(pSingleRequest->extNumber-1));
            DIGI_MEMCPY((pExts+pSingleRequest->extNumber-1), pServiceExt, sizeof(extensions));

            /* Free the previous values */
            if (pSingleRequest->singleRequestExtensions)
                FREE(pSingleRequest->singleRequestExtensions);

            /* Assign the newly formed one */
            pSingleRequest->singleRequestExtensions = pExts;

            pExts = NULL;
        }

        if (pServiceExt)
            FREE(pServiceExt);
    }

exit:
    if (pNameHash)
        FREE(pNameHash);

    if (pKeyHash)
        FREE(pKeyHash);

    if (pPubKey)
        TREE_DeleteTreeItem((TreeItem *)pPubKey);

    if (pPubKeyInfo)
        TREE_DeleteTreeItem((TreeItem *)pPubKeyInfo);

    if (pSubject)
        TREE_DeleteTreeItem((TreeItem *)pSubject);

    return status;
} /* OCSP_MESSAGE_generateSingleRequest */

/*------------------------------------------------------------------*/

/* This is extern function called by OCSP_CLIENT_generateRequest */
extern MSTATUS
OCSP_MESSAGE_generateSingleRequest(ocspContext *pOcspContext,
                                   OCSP_singleRequestInfo *pSingleRequestInfo,
                                   OCSP_singleRequest *pSingleRequest)
{
    certDistinguishedName* pIssuerInfo          = NULL;
    ubyte*                 pKeyHash             = NULL;
    ubyte*                 pNameHash            = NULL;
    ubyte*                 pSerialNumber        = NULL;
    ubyte*                 pData                = NULL;
    ASN1_ITEMPTR           pSubject             = NULL;
    ASN1_ITEMPTR           pPubKeyInfo          = NULL;
    ASN1_ITEMPTR           pPubKey              = NULL;
    ubyte4                 serialNumberLen      = 0;
    ubyte4                 dataLen;
    ubyte4                 hashSize;
    sbyte4                 cmpResult;
    MSTATUS                status               = OK;

    if ((NULL == pSingleRequest) || (NULL == pOcspContext) || (NULL == pSingleRequestInfo))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pSingleRequest,0x00, sizeof(OCSP_singleRequest))))
        goto exit;

    /* Additional test to verify cert-issuer identity before forming the request; not an RFC requirement */
    if (OK > (status = OCSP_MESSAGE_checkCertificateIssuer(pSingleRequestInfo->pCert,
                                                           pSingleRequestInfo->certLen,
                                                           pOcspContext->pOcspSettings->pIssuerCert,
                                                           pOcspContext->pOcspSettings->issuerCertLen)))
    {
        goto exit;
    }

    /* Fall back to default Algo sha1 in case not manually configured */
    pSingleRequest->certId.hashAlgo = ((NULL != pOcspContext->pOcspSettings->hashAlgo) ?
                                               (pOcspContext->pOcspSettings->hashAlgo) : (sha1_OID));

    if (NULL == (pNameHash = MALLOC(CERT_MAXDIGESTSIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (pKeyHash = MALLOC(CERT_MAXDIGESTSIZE)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pIssuerInfo)))
        goto exit;

    if (OK > (status = DIGI_MEMSET((ubyte *)pIssuerInfo, 0x00, sizeof(certDistinguishedName))))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCertificateIssuerSerialNumber(pSingleRequestInfo->pCert,
                                                                     pSingleRequestInfo->certLen,
                                                                     pIssuerInfo, &pSerialNumber,
                                                                     &serialNumberLen)))
    {
        goto exit;
    }

    /* check whether the issuer is the same as the previous certId, if not, set singleIssuer to FALSE */
    if (OK > (status = OCSP_MESSAGE_certDistinguishedNameCompare(pOcspContext->ocspProcess.client.pIssuerInfo,
                                                                 pIssuerInfo, &cmpResult)))
    {
        goto exit;
    }

    if (cmpResult != 0)
    {
        if (!pOcspContext->ocspProcess.client.pIssuerInfo)
        {
            /* this is the first issuer we encounter */
            pOcspContext->ocspProcess.client.hasSingleIssuer = TRUE;
        }
        else
        {
            pOcspContext->ocspProcess.client.hasSingleIssuer = FALSE;

            /* release memory for previous issuer instances */
            CA_MGMT_freeCertDistinguishedName(&pOcspContext->ocspProcess.client.pIssuerInfo);

            if (pOcspContext->ocspProcess.client.pIssuerRoot)
            {
                TREE_DeleteTreeItem((TreeItem*)pOcspContext->ocspProcess.client.pIssuerRoot);
            }

            if (pOcspContext->ocspProcess.client.issuerNameHash)
            {
                FREE(pOcspContext->ocspProcess.client.issuerNameHash);
            }

            if (pOcspContext->ocspProcess.client.issuerPubKeyHash)
            {
                FREE(pOcspContext->ocspProcess.client.issuerPubKeyHash);
            }
        }

        if ((NULL == pOcspContext->pOcspSettings->pIssuerCert) ||
             (0   >= pOcspContext->pOcspSettings->issuerCertLen))
        {
            status = ERR_OCSP_MISSING_ISSUER_CERT;
            goto exit;
        }

        pOcspContext->ocspProcess.client.issuerCertBuf = pOcspContext->pOcspSettings->pIssuerCert;

        MF_attach(&pOcspContext->ocspProcess.client.issuerMemFile, pOcspContext->pOcspSettings->issuerCertLen, pOcspContext->pOcspSettings->pIssuerCert);
        CS_AttachMemFile(&pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.issuerMemFile);

        if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.pIssuerRoot)))
            goto exit;

        if (NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subject, &pSubject)))
            goto exit;

        dataLen = pSubject->headerSize + pSubject->length;
        pData   = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.issuerCs, pSubject->dataOffset - pSubject->headerSize, dataLen);

        if (OK > (status = OCSP_MESSAGE_getHash(pOcspContext, pData, dataLen,
                                                pSingleRequest->certId.hashAlgo,
                                                pNameHash, &hashSize)))
        {
            goto exit;
        }

        if (pData)
        {
            CS_stopaccess(pOcspContext->ocspProcess.client.issuerCs, pData);
        }

        pSingleRequest->certId.hashLength = hashSize;

        /* Copy the name hash in the request */
        if (NULL == (pSingleRequest->certId.nameHash  = MALLOC(pSingleRequest->certId.hashLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSingleRequest->certId.nameHash, pNameHash, pSingleRequest->certId.hashLength);

        if (NULL == (pOcspContext->ocspProcess.client.issuerNameHash = MALLOC(hashSize)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subjectPublicKeyInfo, &pPubKeyInfo)))
            goto exit;

        /* get to the key bits */
        if (OK > (status = ASN1_GetNthChild(pPubKeyInfo, 2, &pPubKey)))
            goto exit;

        pData   = (ubyte*) CS_memaccess(pOcspContext->ocspProcess.client.issuerCs, pPubKey->dataOffset, pPubKey->length);
        dataLen = pPubKey->length;

        if (OK > (status = OCSP_MESSAGE_getHash(pOcspContext, pData, dataLen, pSingleRequest->certId.hashAlgo,
            pKeyHash, &hashSize)))
        {
            goto exit;
        }

        if (pData)
        {
            CS_stopaccess(pOcspContext->ocspProcess.client.issuerCs, pData);
        }

        /* copy the keyHash into singlerequest */
        if (NULL == (pSingleRequest->certId.keyHash = MALLOC(pSingleRequest->certId.hashLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSingleRequest->certId.keyHash, pKeyHash, pSingleRequest->certId.hashLength);

        if (NULL == (pOcspContext->ocspProcess.client.issuerPubKeyHash = MALLOC(hashSize)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* Caching for multiple certs with same issuer */
        DIGI_MEMCPY(pOcspContext->ocspProcess.client.issuerNameHash, pNameHash, hashSize);
        DIGI_MEMCPY(pOcspContext->ocspProcess.client.issuerPubKeyHash, pKeyHash, hashSize);
        pOcspContext->ocspProcess.client.hashSize    = hashSize;
        pOcspContext->ocspProcess.client.pIssuerInfo = pIssuerInfo;
        pIssuerInfo = NULL;

    }
    else /* else same Issuer no need to retrieve issuer cert again */
    {
        /* Free pIssuerInfo created for this pass; as it is same as cached */
        if (pIssuerInfo)
            CA_MGMT_freeCertDistinguishedName(&pIssuerInfo);
        pIssuerInfo = NULL;

        /* Using cached data */
        pSingleRequest->certId.hashLength = pOcspContext->ocspProcess.client.hashSize;

        if (NULL == (pSingleRequest->certId.nameHash  = MALLOC(pSingleRequest->certId.hashLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSingleRequest->certId.nameHash, pOcspContext->ocspProcess.client.issuerNameHash, pSingleRequest->certId.hashLength);

        if (NULL == (pSingleRequest->certId.keyHash = MALLOC(pSingleRequest->certId.hashLength)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        DIGI_MEMCPY(pSingleRequest->certId.keyHash, pOcspContext->ocspProcess.client.issuerPubKeyHash, pSingleRequest->certId.hashLength);
    }

    /** RHS values will be uninitialized in case of same issuer **/
    pSingleRequest->certId.serialNumber       = pSerialNumber; pSerialNumber = NULL;
    pSingleRequest->certId.serialNumberLength = serialNumberLen;
    pSingleRequest->singleRequestExtensions   = pSingleRequestInfo->pSingleExts;
    pSingleRequest->extNumber                 = pSingleRequestInfo->extCount;

    /* Add Service Locator Extension; Optional */
    if (pOcspContext->pOcspSettings->shouldAddServiceLocator)
    {
        extensions* pServiceExt;

        if (OK < (status = OCSP_MESSAGE_addServiceLocator(pSingleRequestInfo, &pServiceExt)))
            goto exit;

        if (pServiceExt)
        {
            extensions* pExts = NULL;

            pSingleRequest->extNumber = pSingleRequest->extNumber + 1;

            if (NULL == (pExts = MALLOC(sizeof(extensions)*(pSingleRequest->extNumber))))
            {
                status = ERR_MEM_ALLOC_FAIL;
                FREE(pServiceExt);
                goto exit;
            }

            DIGI_MEMSET((ubyte *)pExts, 0x00, sizeof(extensions)*(pSingleRequest->extNumber));
            DIGI_MEMCPY(pExts, pSingleRequest->singleRequestExtensions,sizeof(extensions)*(pSingleRequest->extNumber-1));
            DIGI_MEMCPY((pExts+pSingleRequest->extNumber-1), pServiceExt, sizeof(extensions));

            /* Free the previous values */
            if (pSingleRequest->singleRequestExtensions)
                FREE(pSingleRequest->singleRequestExtensions);

            /* Assign the newly formed one */
            pSingleRequest->singleRequestExtensions = pExts;

            pExts = NULL;
        }

        if (pServiceExt)
            FREE(pServiceExt);
    }

exit:
    if (pNameHash)
        FREE(pNameHash);

    if (pKeyHash)
        FREE(pKeyHash);

    if (pSerialNumber)
        FREE(pSerialNumber);

    if (pPubKey)
        TREE_DeleteTreeItem((TreeItem *)pPubKey);

    if (pPubKeyInfo)
        TREE_DeleteTreeItem((TreeItem *)pPubKeyInfo);

    if (pSubject)
        TREE_DeleteTreeItem((TreeItem *)pSubject);
    if (pIssuerInfo)
        CA_MGMT_freeCertDistinguishedName(&pIssuerInfo);

    return status;

} /* OCSP_MESSAGE_generateSingleRequest */


/*------------------------------------------------------------------*/

/* Write the request in DER format to be send across */
/* This is extern function called by OCSP_CLIENT_generateRequest */
extern MSTATUS
OCSP_MESSAGE_generateRequestInternal(ocspContext *pOcspContext, OCSP_singleRequest** pRequests,
                                     ubyte4 requestCount, extensions *pExts, ubyte4 extCount,
                                     ubyte** ppRetRequest, ubyte4* pRetRequestLen)
{

    DER_ITEMPTR    pRequest       = NULL;
    DER_ITEMPTR    pTbsRequest    = NULL;
    DER_ITEMPTR    pRequestorName = NULL;
    DER_ITEMPTR    pRequestList   = NULL;
    DER_ITEMPTR    pRequestExt    = NULL;
    DER_ITEMPTR    pTemp          = NULL;
    ubyte          copyData[MAX_DER_STORAGE];
    ubyte4         count;
    MSTATUS        status         = OK;

    if (OK > (status = DER_AddSequence(NULL, &pRequest)))
        goto exit;

    if (OK > (status = DER_AddSequence(pRequest, &pTbsRequest)))
        goto exit;

    /* version = 0: Optional*/
    if (OK > (status = DER_AddTag(pTbsRequest, 0, &pTemp)))
        goto exit;

    copyData[0] = 0;

    if (OK > (status = DER_AddItemCopyData(pTemp, INTEGER, 1, copyData, NULL)))
        goto exit;

    if (pOcspContext->pOcspSettings->shouldSign)
    {
        /* 4.1.2 If the request is signed, the requestor SHALL specify its name */
        /*       in the requestorName field.*/

        ubyte4 subjectNameOffset;
        ubyte4 subjectNameLen;

        if ((NULL == pOcspContext->pOcspSettings->pSignerCert) ||
            (0    >= pOcspContext->pOcspSettings->signerCertLen))
        {
            status = ERR_OCSP_MISSING_SIGNER_CERT;
            goto exit;
        }

        if (OK > (status = CA_MGMT_extractCertASN1Name(pOcspContext->pOcspSettings->pSignerCert,
                                                       pOcspContext->pOcspSettings->signerCertLen,
                                                       TRUE, FALSE, &subjectNameOffset,
                                                       &subjectNameLen)))
        {
            goto exit;
        }

        if (OK > (status = DER_AddTag(pTbsRequest, 1, &pRequestorName)))
            goto exit;

        if (OK > (status = DER_AddTag(pRequestorName, 4, &pRequestorName)))
            goto exit;

        if (OK > (status = DER_AddItem(pRequestorName, SEQUENCE|CONSTRUCTED, subjectNameLen,
                                       pOcspContext->pOcspSettings->pSignerCert+subjectNameOffset,
                                       &pRequestorName)))
        {
            goto exit;
        }

    }

    /* requestList */
    if (OK > (status = DER_AddSequence(pTbsRequest, &pRequestList)))
        goto exit;

    /* Add single request(s) */
    for (count = 0; count < requestCount; count++)
    {
        if (OK > (status = OCSP_MESSAGE_addRequest(pRequestList, pRequests[count])))
            goto exit;
    }

    /* extensions; optional */
    if ((0 < extCount) || (pOcspContext->pOcspSettings->shouldAddNonce))
    {
        if (OK > (status = DER_AddTag(pTbsRequest, 2, &pRequestExt)))
            goto exit;

        if (OK > (status = DER_AddSequence(pRequestExt, &pRequestExt)))
            goto exit;

        for (count = 0; count < extCount; count++)
        {
            if (OK > (status = OCSP_MESSAGE_addExtension(pRequestExt, pExts+count)))
                goto exit;
        }

        if (pOcspContext->pOcspSettings->shouldAddNonce)
        {
            if (OK > (status = OCSP_MESSAGE_addNonce(pOcspContext, pRequestExt)))
                goto exit;
        }
    }

    /* Signature; optional */
    if (pOcspContext->pOcspSettings->shouldSign)
    {
        /* Basic tests to check the presence of Signer Cert and Private key       */
        if ((NULL == pOcspContext->pOcspSettings->pSignerCert) ||
            (0 >= pOcspContext->pOcspSettings->signerCertLen))
        {
            status = ERR_OCSP_MISSING_SIGNER_CERT;
            goto exit;
        }

        if ((NULL == pOcspContext->pOcspSettings->pPrivKey)||
            (0 >= pOcspContext->pOcspSettings->privKeyLen))
        {
            status = ERR_OCSP_MISSING_SIGNER_KEY;
            goto exit;
        }

        /* 4.1.2 The requestor MAY choose to sign the OCSP request. In that case,
                 the signature is computed over the tbsRequest structure.         */

        if (OK > (status = OCSP_MESSAGE_sign(MOC_ASYM(pOcspContext->hwAccelCtx) pRequest,pOcspContext,
                                             pOcspContext->pOcspSettings->signingAlgo)))
        {
            goto exit;
        }
    }

    if (OK > (status = DER_Serialize(pRequest, ppRetRequest, pRetRequestLen)))
        goto exit;

exit:
    if (pRequest)
        TREE_DeleteTreeItem((TreeItem *) pRequest);

    return status;

} /* OCSP_MESSAGE_generateRequestInternal */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_checkCertificateIssuer(ubyte * pCert, ubyte4 certLen,
                                    ubyte * pIssuerCert, ubyte4 issuerCertLen)
{
    MemFile         mfCert, mfIssuer;
    CStream         csCert, csIssuer;
    ASN1_ITEMPTR    pCertRoot    = NULL;
    ASN1_ITEMPTR    pIssuerRoot  = NULL;
    MSTATUS         status       = OK;

    MF_attach(&mfCert, certLen, pCert);
    CS_AttachMemFile(&csCert, &mfCert);

    if (OK > (status = ASN1_Parse(csCert, &pCertRoot)))
        goto exit;

    if (NULL == pCertRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    MF_attach(&mfIssuer, issuerCertLen, pIssuerCert);
    CS_AttachMemFile(&csIssuer, &mfIssuer);

    if (OK > (status = ASN1_Parse(csIssuer, &pIssuerRoot)))
        goto exit;

    if (NULL == pIssuerRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_checkCertificateIssuer(ASN1_FIRST_CHILD(pCertRoot), csCert,
                                                   ASN1_FIRST_CHILD(pIssuerRoot), csIssuer)))
    {
        goto exit;
    }

exit:
    if (pCertRoot)
        TREE_DeleteTreeItem((TreeItem *) pCertRoot);

    if (pIssuerRoot)
        TREE_DeleteTreeItem((TreeItem *) pIssuerRoot);

    return status;
}


/*------------------------------------------------------------------*/
#if 0
/* Method lifted as is from src/asn1 */
static MSTATUS
GetCertOID(ASN1_ITEM* pAlgoId, CStream s, const ubyte* whichOID,
           ubyte* whichOIDSubType, ASN1_ITEM** ppOID)
{

    ASN1_ITEM*  pOID = NULL;
    ubyte4      i;
    ubyte4      oidLen;
    ubyte       digit;
    MSTATUS     status;

    /* whichOIDSubType and ppOID can be null */
    if (NULL == whichOID)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    oidLen = *whichOID;
    status = ERR_CERT_INVALID_STRUCT;

    if ((NULL == pAlgoId) ||
        ((pAlgoId->id & CLASS_MASK) != UNIVERSAL) ||
        (pAlgoId->tag != SEQUENCE))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD(pAlgoId);
    if (NULL == pOID ||
        ((pOID->id & CLASS_MASK) != UNIVERSAL) ||
        (pOID->tag != OID))
    {
        goto exit;
    }

    if (pOID->length != oidLen + ((whichOIDSubType) ? 1 : 0))
    {
        /* not the expected OID...*/
        status = ERR_CERT_NOT_EXPECTED_OID;
        goto exit;
    }

    /* compare OID */
    CS_seek(s, pOID->dataOffset, MOCANA_SEEK_SET);
    for (i = 0; i < oidLen; ++i)
    {
        if (OK > (status = CS_getc(s, &digit)))
            goto exit;

        if (whichOID[i+1] != digit)
        {
            status = ERR_CERT_NOT_EXPECTED_OID;
            goto exit;
        }
    }

    if (whichOIDSubType)
    {
        if (OK > (status = CS_getc(s, whichOIDSubType)))
            goto exit;
    }

    if (ppOID)
    {
        *ppOID = pOID;
    }

    status = OK;

exit:
    return status;

} /* GetCertOID */
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getResponderId(ocspContext *pOcspContext, OCSP_responderId **ppResponderId)
{
    ASN1_ITEMPTR      pItem        = NULL;
    OCSP_responderId* pResponderId = NULL;
    MSTATUS           status       = OK;

    if ((NULL == pOcspContext) || (NULL == ppResponderId))
        goto exit;

    if (NULL == (pResponderId = MALLOC(sizeof(OCSP_responderId))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* unwrap root */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponseRoot)))
        goto exit;

    /* tbsResponse */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    /* version or responderId */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    /* has version? */
    if (0 == pItem->tag)
    {
        pItem = ASN1_NEXT_SIBLING(pItem);
    }

    /* by name */
    if (1 == pItem->tag)
    {
        pResponderId->type = ocsp_byName;
        pItem              = ASN1_FIRST_CHILD(pItem);

        if (OK > (status = CA_MGMT_allocCertDistinguishedName(&(pResponderId->value.pName))))
            goto exit;

        if (OK > (status = X509_extractDistinguishedNamesFromName(pItem, pOcspContext->ocspProcess.client.cs,
                                                                  pResponderId->value.pName)))
        {
            goto exit;
        }
    }

    /* if byKeyHash, check whether responder == issuer, otherwise can't find cert */
    if (2 == pItem->tag)
    {
        pResponderId->type = ocsp_byKeyHash;
        pItem              = ASN1_FIRST_CHILD(pItem);

        if (20 == pItem->length) /* sha-1 hash; specified in the RFC; hence lenght 20*/
        {
            ubyte* responderIdBuf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs, pItem->dataOffset, pItem->length);

            if (NULL == (pResponderId->value.keyHash = MALLOC(20)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY(pResponderId->value.keyHash, responderIdBuf, 20);
            if (responderIdBuf)
            {
                CS_stopaccess(pOcspContext->ocspProcess.client.cs, responderIdBuf);
            }
        }
    }

    *ppResponderId = pResponderId;
    pResponderId   = NULL;

exit:
    if (pResponderId)
    {
        CA_MGMT_freeCertDistinguishedName(&(pResponderId->value.pName));
        FREE(pResponderId);
    }
    return status;

} /* OCSP_MESSAGE_getResponderId */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_sanityCheck(ocspContext *pOcspContext)
{
    MSTATUS status = OK;

    if (NULL == pOcspContext)
        goto exit;

    if ((NULL == pOcspContext->ocspProcess.client.pSingleResponse) &&
        (pOcspContext->ocspProcess.client.state < ocspSingleResponseRetrieved))
    {
        if (OK > (status = OCSP_MESSAGE_goToNextResponse(pOcspContext)))
            goto exit;

    }

    if (!pOcspContext->ocspProcess.client.pSingleResponse)
    {
        status = ERR_OCSP_NO_MORE_RESPONSE;
        goto exit;
    }

exit:
    return status;

} /* OCSP_MESSAGE_sanityCheck */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_verifySignature(ocspContext *pOcspContext, ASN1_ITEMPTR pResponseRoot, CStream cs)
{
    /* REVIEW: this function is too big.  I think it needs to be split into three functions (one which calls two other functions).  Fine for this release but future note to consider. */
    ASN1_ITEM*        pSeqAlgoId        = NULL;
    ASN1_ITEM*        pSignature        = NULL;
    ASN1_ITEM*        pResponderCerts   = NULL;
    CStream           responderCs;
    ASN1_ITEM*        pItem             = NULL;
    ASN1_ITEM*        pTbsResponseData  = NULL;
    ASN1_ITEMPTR      pResponderPubKey  = NULL;
    sbyte4            bytesToHash;
    const ubyte*      buffer            = NULL;
    void*             pComputedHash     = NULL;
    sbyte4            computedHashLen;
    ubyte             decryptedHash[CERT_MAXDIGESTSIZE];
    ubyte4            decryptedHashType;
    sbyte4            decryptedHashLen;
    sbyte4            result;
    AsymmetricKey*    pResponderKey     = NULL;
    ubyte*            signatureBuf      = NULL;
    ubyte4            hashType;
    ubyte4            pubKeyType;
    ubyte4            count             = 0;
    OCSP_responderId* pResponderId      = NULL;
 
    MSTATUS           status            = OK;

    /* get the algorithm identifier */
    /* go to signed struct */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pResponseRoot)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* algo id is the second child of signed */
    if (OK > (status = ASN1_GetNthChild(pItem, 2, &pSeqAlgoId)))
        goto exit;

    /* get the signature Algorithm*/
    status = X509_getCertSignAlgoType(pSeqAlgoId, cs, &hashType, &pubKeyType);

    pTbsResponseData = ASN1_FIRST_CHILD(pItem);

    /* now we need to compute the hash of the whole certificate */
    bytesToHash      = pTbsResponseData->length + pTbsResponseData->headerSize;
    buffer           = CS_memaccess(cs, pTbsResponseData->dataOffset - pTbsResponseData->headerSize,
                                    bytesToHash);
    if (0 == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    if (OK > (status = CRYPTO_ALLOC(pOcspContext->hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pComputedHash)))
        goto exit;

    if (OK > (status = CRYPTO_computeBufferHash(MOC_HASH(pOcspContext->hwAccelCtx) (ubyte*)buffer,
                                    bytesToHash, pComputedHash,
                                    &computedHashLen, hashType)))
    {
        goto exit;
    }

    /* decrypt the signature to get hash */
    pSignature = ASN1_NEXT_SIBLING(pSeqAlgoId);
    if (!pSignature)
    {
        status = ERR_OCSP_MISSING_SIGNATURE;
        goto exit;
    }

    if (buffer)
    {
        CS_stopaccess(cs, buffer);
    }

    /* the signer cert either comes attached or indicated in ResponderId and needs to be retrieved */
    pResponderCerts = ASN1_NEXT_SIBLING(pSignature);
    if (pResponderCerts && OK == ASN1_VerifyTag(pResponderCerts, 0))
    {
        pResponderCerts = ASN1_FIRST_CHILD(pResponderCerts);
        responderCs = cs;
    }
    else
    {
        /* if responder cert is not attached, the responder has to be the issuer of cert. */
        /* Otherwise, we generate error. */
        pResponderCerts = NULL;

        if (OK > (status = OCSP_MESSAGE_getResponderId(pOcspContext, &pResponderId)))
            goto exit;

        if (ocsp_byName == pResponderId->type)
        {
            ASN1_ITEMPTR pByName;
            ASN1_ITEMPTR pSubject;

            pByName = ASN1_FIRST_CHILD(pTbsResponseData);

            if (0 == pByName->tag) /* has Version */
            {
                pByName = ASN1_FIRST_CHILD(pByName);
            }

            /* unwrap tag for byName */
            pByName = ASN1_FIRST_CHILD(pByName);

            if (0 >= pOcspContext->pOcspSettings->certCount)
            {
                status = ERR_OCSP_INVALID_INPUT;
                goto exit;
            }

            /* Loop here to traverse all the issuers */
            count = pOcspContext->pOcspSettings->certCount - 1;

            while (1)
            {
                if (pOcspContext->ocspProcess.client.pIssuerRoot)
                {
                    if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subject, &pSubject)))
                        goto exit;

                    if (OK == ASN1_CompareItems(pByName, cs, pSubject, pOcspContext->ocspProcess.client.issuerCs))
                    {
                        pResponderCerts = pOcspContext->ocspProcess.client.pIssuerRoot;
                        responderCs = pOcspContext->ocspProcess.client.issuerCs;

                        break; /* get out of loop we got out matching issuer */
                    }
                }

                /* Last issuer reached break the loop */
                if (0 == count)
                    break;

                /* Traverse to the previous issuer */
                count = count - 1;

                if ((pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath) &&
                    (0 < pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen))
                {
                    MF_attach(&pOcspContext->ocspProcess.client.issuerMemFile, pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen,
                              pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath);

                    CS_AttachMemFile(&pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.issuerMemFile);

                    /* Free the previous value */
                    if (pOcspContext->ocspProcess.client.pIssuerRoot)
                        TREE_DeleteTreeItem((TreeItem *)pOcspContext->ocspProcess.client.pIssuerRoot);

                    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.pIssuerRoot)))
                        goto exit;

                    if (NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }

                }
            }/* end of while(1) loop */

            if ((0 < pOcspContext->pOcspSettings->trustedResponderCount) && (NULL == pResponderCerts))
            {
                /* Validate here with trusted responders */
                for (count = 0; count < pOcspContext->pOcspSettings->trustedResponderCount; count++)
                {
                    ASN1_ITEMPTR pTRespRoot = NULL;

                    /* Basic test before moving forward */
                    if ((NULL == pOcspContext->pOcspSettings->pTrustedResponders[count].pCertPath) ||
                        (0 >= pOcspContext->pOcspSettings->pTrustedResponders[count].certLen))
                    {
                        status = ERR_OCSP_INVALID_INPUT;
                        goto exit;
                    }

                    MF_attach(&pOcspContext->ocspProcess.client.trustedMemFile,
                               pOcspContext->pOcspSettings->pTrustedResponders[count].certLen,
                               pOcspContext->pOcspSettings->pTrustedResponders[count].pCertPath);

                    CS_AttachMemFile(&pOcspContext->ocspProcess.client.trustedCs,
                                     &pOcspContext->ocspProcess.client.trustedMemFile);

                    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.trustedCs, &pTRespRoot)))
                        goto exit;

                    if (NULL == pTRespRoot)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }

                    if (pTRespRoot)
                    {
                        if (OK > (status = OCSP_MESSAGE_getCertificateChild(pTRespRoot, cert_subject, &pSubject)))
                            goto exit;

                        if (OK == ASN1_CompareItems(pByName, cs, pSubject, pOcspContext->ocspProcess.client.trustedCs))
                        {
                            pResponderCerts = pTRespRoot;
                            responderCs     = pOcspContext->ocspProcess.client.trustedCs;
                            break;
                        }
                        else
                        {
                            /* If Not matched free the ASN1 root */
                            if (pTRespRoot)
                                TREE_DeleteTreeItem((TreeItem *)pTRespRoot);
                        }
                    }


                }
            }
        }
        else /* by keyHash */
        {
            ASN1_ITEMPTR pIssuerKey;

            if (0 >= pOcspContext->pOcspSettings->certCount)
            {
                status = ERR_OCSP_INVALID_INPUT;
                goto exit;
            }

            /* Loop here to traverse all issuer certs */
            count = pOcspContext->pOcspSettings->certCount - 1;

            while (1)
            {
                if (pOcspContext->ocspProcess.client.pIssuerRoot)
                {
                    if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subjectPublicKeyInfo, &pIssuerKey)))
                       goto exit;

                    if (OK == ASN1_GetNthChild(pIssuerKey, 2, &pIssuerKey))
                    {
                        void*  pKeyHash       = NULL;
                        sbyte4 keyHashLen;
                        ubyte* keyBuf         = NULL;
                        sbyte4 hashCmpResult;

                        if (OK > (status = CRYPTO_ALLOC(pOcspContext->hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pKeyHash)))
                            goto exit;

                        keyBuf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.issuerCs, pIssuerKey->dataOffset, pIssuerKey->length);
                        status = CRYPTO_computeBufferHash(MOC_HASH(pOcspContext->hwAccelCtx) (ubyte*)keyBuf,
                                                        pIssuerKey->length, pKeyHash,
                                                        &keyHashLen, sha1withRSAEncryption);

                        DIGI_MEMCMP(pResponderId->value.keyHash, pKeyHash, keyHashLen, &hashCmpResult);

                        /* Free Data */
                        if (keyBuf)
                        {
                            CS_stopaccess(pOcspContext->ocspProcess.client.issuerCs, keyBuf);
                        }

                        if (pKeyHash)
                        {
                            CRYPTO_FREE(pOcspContext->hwAccelCtx, TRUE, &pKeyHash);
                        }

                        if (0 == hashCmpResult)
                        {
                            /* Issuer matched */
                            pResponderCerts = pOcspContext->ocspProcess.client.pIssuerRoot;
                            responderCs     = pOcspContext->ocspProcess.client.issuerCs;

                            break;
                        }

                    }
                }

                /* Last issuer reached break the loop */
                if (0 == count)
                    break;

                /* Traverse to the previous issuer */
                count = count - 1;

                if ((pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath) &&
                    (0 < pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen))
                {
                    MF_attach(&pOcspContext->ocspProcess.client.issuerMemFile, pOcspContext->pOcspSettings->pIssuerCertInfo[count].certLen,
                              pOcspContext->pOcspSettings->pIssuerCertInfo[count].pCertPath);

                    CS_AttachMemFile(&pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.issuerMemFile);

                    /* Free the previous value */
                    if (pOcspContext->ocspProcess.client.pIssuerRoot)
                        TREE_DeleteTreeItem((TreeItem *)pOcspContext->ocspProcess.client.pIssuerRoot);

                    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.pIssuerRoot)))
                        goto exit;

                    if (NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }
                }
            }/* end of while (1) */

            if ((0 < pOcspContext->pOcspSettings->trustedResponderCount) && (NULL == pResponderCerts))
            {
                /* verify signature with trusted responders */
                for (count = 0; count < pOcspContext->pOcspSettings->trustedResponderCount; count++)
                {
                    ASN1_ITEMPTR pTRespRoot = NULL;

                    /* Basic test before moving forward */
                    if ((NULL == pOcspContext->pOcspSettings->pTrustedResponders[count].pCertPath) ||
                        (0 >= pOcspContext->pOcspSettings->pTrustedResponders[count].certLen))
                    {
                        status = ERR_OCSP_INVALID_INPUT;
                        goto exit;
                    }

                    MF_attach(&pOcspContext->ocspProcess.client.trustedMemFile, pOcspContext->pOcspSettings->pTrustedResponders[count].certLen,
                                        pOcspContext->pOcspSettings->pTrustedResponders[count].pCertPath);
                    CS_AttachMemFile(&pOcspContext->ocspProcess.client.trustedCs, &pOcspContext->ocspProcess.client.trustedMemFile);

                    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.trustedCs, &pTRespRoot)))
                        goto exit;

                    if (NULL == pTRespRoot)
                    {
                        status = ERR_NULL_POINTER;
                        goto exit;
                    }

                    if (pTRespRoot)
                    {
                        if (OK > (status = OCSP_MESSAGE_getCertificateChild(pTRespRoot, cert_subjectPublicKeyInfo, &pIssuerKey)))
                            goto exit;

                        if (OK == ASN1_GetNthChild(pIssuerKey, 2, &pIssuerKey))
                        {
                            void*  pKeyHash       = NULL;
                            sbyte4 keyHashLen;
                            ubyte* keyBuf         = NULL;
                            sbyte4 hashCmpResult;

                            if (OK > (status = CRYPTO_ALLOC(pOcspContext->hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pKeyHash)))
                                goto exit;

                            keyBuf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.trustedCs, pIssuerKey->dataOffset, pIssuerKey->length);
                            status = CRYPTO_computeBufferHash(MOC_HASH(pOcspContext->hwAccelCtx) (ubyte*)keyBuf,
                                                            pIssuerKey->length, pKeyHash,
                                                            &keyHashLen, sha1withRSAEncryption);

                            DIGI_MEMCMP(pResponderId->value.keyHash, pKeyHash, keyHashLen, &hashCmpResult);

                            /* Free data */
                            if (keyBuf)
                            {
                                CS_stopaccess(pOcspContext->ocspProcess.client.trustedCs, keyBuf);
                            }

                            if (pKeyHash)
                            {
                                CRYPTO_FREE(pOcspContext->hwAccelCtx, TRUE, &pKeyHash);
                            }

                            if (0 == hashCmpResult)
                            {
                                pResponderCerts = pTRespRoot;
                                responderCs     = pOcspContext->ocspProcess.client.trustedCs;

                                break;
                            }
                            else
                            {
                                /* Free pTRespRoot in case of non-match */
                                if (pTRespRoot)
                                    TREE_DeleteTreeItem((TreeItem *)pTRespRoot);
                            }
                        }
                    }
                }

            }
        }
    }

    if (!pResponderCerts)
    {
        pOcspContext->ocspProcess.client.pResponderCert = NULL;
        status = ERR_OCSP_MISSING_RSIGNER_CERTS;
        goto exit;
    }

    pOcspContext->ocspProcess.client.pResponderCert = pResponderCerts;
    DIGI_MEMCPY(&pOcspContext->ocspProcess.client.responderCs, &responderCs, sizeof(CStream));

    /* get the public key of the responder cert to verify the signature */
    if (OK > (status = OCSP_MESSAGE_getSignedCertificateChild(ASN1_FIRST_CHILD(pResponderCerts), cert_subjectPublicKeyInfo, &pResponderPubKey)))
        goto exit;

    if (NULL == (pResponderKey = MALLOC(sizeof(AsymmetricKey))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_initAsymmetricKey(pResponderKey)))
        goto exit;
    
    switch (pubKeyType)
    {
        case akt_rsa:
        {
            if (OK > (status = X509_extractRSAKey(MOC_RSA(pOcspContext->hwAccelCtx) pResponderPubKey, responderCs, pResponderKey)))
                goto exit;
            
            signatureBuf = (ubyte*)CS_memaccess(cs, pSignature->dataOffset, pSignature->length);
           
            if (OK > (status = X509_decryptRSASignatureBuffer(MOC_RSA(pOcspContext->hwAccelCtx) pResponderKey->key.pRSA,
                                                    signatureBuf, pSignature->length,
                                                    decryptedHash, &decryptedHashLen, &decryptedHashType)))
            {
                status = ERR_CERT_INVALID_SIGNATURE;
                goto exit;
            }
        
            /* compare */
            if ((decryptedHashType != hashType) || (decryptedHashLen != computedHashLen))
            {
                status = ERR_CERT_INVALID_SIGNATURE;
                goto exit;
            }
            
            if (OK > (status = DIGI_MEMCMP(pComputedHash, decryptedHash,
                                          decryptedHashLen, &result)))
                goto exit;
            
            if (0 != result)
            {
                status = ERR_OCSP_INVALID_SIGNATURE;
                goto exit;
            }
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        {
            if (OK > (status = X509_extractECCKey(MOC_ECC(pOcspContext->hwAccelCtx) pResponderPubKey, responderCs, pResponderKey)))
                goto exit;
            
            if (OK > (status = X509_verifyECDSASignature(MOC_ECC(pOcspContext->hwAccelCtx) ASN1_FIRST_CHILD(pSignature),cs, pResponderKey->key.pECC,
                                                         computedHashLen, pComputedHash)))
            {
                status = ERR_OCSP_INVALID_SIGNATURE;
                goto exit;
            }
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            /* Need to add support for this mandatory requirement in RFC */
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            break;
        }
#endif
        default:
        {
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            break;
        }
    }

exit:
    if (pResponderKey)
    {
        CRYPTO_uninitAsymmetricKey(pResponderKey, NULL);
        FREE(pResponderKey);
    }

    if (pResponderId)
    {
        if (ocsp_byName == pResponderId->type)
        {
            CA_MGMT_freeCertDistinguishedName(&(pResponderId->value.pName));
        }
        else if (pResponderId->value.keyHash)
        {
            FREE(pResponderId->value.keyHash);
        }

        FREE(pResponderId);
    }

    if (pComputedHash)
    {
        CRYPTO_FREE(pOcspContext->hwAccelCtx, TRUE, &pComputedHash);
    }

    if (signatureBuf)
    {
        CS_stopaccess(cs, signatureBuf);
    }

    return status;

} /* OCSP_MESSAGE_verifySignature */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_checkResponderId(ocspContext *pOcspContext)
{
    ASN1_ITEMPTR            pIssuerCertSignature    = NULL;
    ASN1_ITEMPTR            pIssuerName             = NULL;
    ASN1_ITEMPTR            pResponderCertSignature = NULL;
    ASN1_ITEMPTR            pResponderCertIssuer    = NULL;
    certDistinguishedName*  pResponderInfo          = NULL;
    AsymmetricKey           pubKey;
    sbyte4                  i;
    MSTATUS                 status                  = OK;

    if (NULL == pOcspContext || NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_getCertificateSignature(ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponderCert), &pResponderCertSignature)))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getSignedCertificateChild(ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponderCert), cert_issuer, &pResponderCertIssuer)))
        goto exit;

    if (OK > (status = CA_MGMT_allocCertDistinguishedName(&pResponderInfo)))
        goto exit;

    if (OK > (status = X509_extractDistinguishedNamesFromName(pResponderCertIssuer, pOcspContext->ocspProcess.client.responderCs, pResponderInfo)))
        goto exit;

    i = pOcspContext->pOcspSettings->certCount - 1;

    while (1)
    {
        /* 1. responder == issuer of cert */
        /* a. responder cert points to issuer cert */
        if (pOcspContext->ocspProcess.client.pResponderCert ==
            ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pIssuerRoot))
        {
            goto exit;
        }

        /* b. responder cert signature == issuer cert signature */
        if (OK > (status = OCSP_MESSAGE_getCertificateSignature(ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pIssuerRoot), &pIssuerCertSignature)))
            goto exit;

        status = ASN1_CompareItems(pIssuerCertSignature, pOcspContext->ocspProcess.client.issuerCs,
                             pResponderCertSignature, pOcspContext->ocspProcess.client.responderCs);

        if (OK == status)
        {
            goto exit;
        }

        /* 2. responder's issuer == issuer of cert */
        if (OK > (status = OCSP_MESSAGE_getCertificateChild(pOcspContext->ocspProcess.client.pIssuerRoot, cert_subject, &pIssuerName)))
            goto exit;

        status = ASN1_CompareItems(pIssuerName, pOcspContext->ocspProcess.client.issuerCs,
                       pResponderCertIssuer, pOcspContext->ocspProcess.client.responderCs);

        if (OK == status)
        {
            /* Verify whether the responder certificate is truly issued by the issuer */
            CRYPTO_initAsymmetricKey(&pubKey);

            if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(pOcspContext->hwAccelCtx)
                                                ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pIssuerRoot),
                                                pOcspContext->ocspProcess.client.issuerCs, &pubKey)))
                goto exit;

            if (OK > (status = X509_verifySignature(MOC_ASYM(pOcspContext->hwAccelCtx)
                                          ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponderCert),
                                          pOcspContext->ocspProcess.client.responderCs, &pubKey)))
                goto exit;

            /* Key usage over; uninit the key here */
            CRYPTO_uninitAsymmetricKey(&pubKey, NULL);

            if (OK == status)
            {

                byteBoolean isPresent = FALSE;

                /* Check for id-kp-OCSPsigning */
                if (OK > (status = OCSP_MESSAGE_checkOCSPSigning(pOcspContext, &isPresent)))
                    goto exit;

                if(TRUE == isPresent)
                    goto exit;
            }

        }

        /* Last issuer reached break the loop */
        if (0 == i)
            break;

        /* Traverse to the previous issuer */
        i = i -1;

        if ((pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath) &&
            (0 < pOcspContext->pOcspSettings->pIssuerCertInfo[i].certLen))
        {
            MF_attach(&pOcspContext->ocspProcess.client.issuerMemFile, pOcspContext->pOcspSettings->pIssuerCertInfo[i].certLen,
                      pOcspContext->pOcspSettings->pIssuerCertInfo[i].pCertPath);

            CS_AttachMemFile(&pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.issuerMemFile);

            /* Free the previous value */
            if (pOcspContext->ocspProcess.client.pIssuerRoot)
                TREE_DeleteTreeItem((TreeItem *)pOcspContext->ocspProcess.client.pIssuerRoot);

            if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.issuerCs, &pOcspContext->ocspProcess.client.pIssuerRoot)))
                goto exit;

            if (NULL == pOcspContext->ocspProcess.client.pIssuerRoot)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }
        }

    }

    /* 3. responder cert == locally configured */
    for (i = 0; i < (sbyte4) pOcspContext->pOcspSettings->trustedResponderCount; i++)
    {
        MemFile      mf;
        CStream      cs;
        ASN1_ITEMPTR pTRespRoot;
        ASN1_ITEMPTR pTRespSignature;

        if ((NULL == pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath) ||
            (0 >= pOcspContext->pOcspSettings->pTrustedResponders[i].certLen))
        {
            status = ERR_OCSP_INVALID_INPUT;
            goto exit;
        }

        MF_attach(&mf, pOcspContext->pOcspSettings->pTrustedResponders[i].certLen,
                       pOcspContext->pOcspSettings->pTrustedResponders[i].pCertPath);
        CS_AttachMemFile(&cs, &mf);

        if (OK > (status = ASN1_Parse(cs, &pTRespRoot)))
            goto exit;

        if (NULL == pTRespRoot)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* responder cert signature == trusted cert signature */
        if (OK > (status = OCSP_MESSAGE_getCertificateSignature(ASN1_FIRST_CHILD(pTRespRoot), &pTRespSignature)))
            goto exit;

        status = ASN1_CompareItems(pTRespSignature, cs, pResponderCertSignature,
                                   pOcspContext->ocspProcess.client.responderCs);

        /* Free the above Parsed Tree Item */
        if (pTRespRoot)
            TREE_DeleteTreeItem((TreeItem *)pTRespRoot);

        if (OK == status)
        {
            goto exit;
        }

    }

    status = ERR_OCSP_RESPONDER_CHECK;

exit:

    if (pResponderInfo)
    {
        CA_MGMT_freeCertDistinguishedName(&pResponderInfo);
    }

    return status;

} /* OCSP_MESSAGE_checkResponderId */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_checkTime(ocspContext *pOcspContext)
{
    MSTATUS     status       = OK;
    TimeDate    thisUpdate;
    TimeDate    nextUpdate;
    TimeDate    curTime;
    byteBoolean isNextUpdate = FALSE;
    sbyte4      secondsDiff1 = 0;
    sbyte4      secondsDiff2 = 0;

    if (NULL == pOcspContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Get the system time in GMT */
    if (OK > (status = RTOS_timeGMT(&curTime)))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentThisUpdate(pOcspContext, &thisUpdate)))
        goto exit;

    if (OK > (status = OCSP_MESSAGE_getCurrentNextUpdate(pOcspContext, &nextUpdate, &isNextUpdate)))
        goto exit;

    if (OK > (status = DATETIME_diffTime(&curTime, &thisUpdate, &secondsDiff1)))
        goto exit;

    if (isNextUpdate)
        if (OK > (status = DATETIME_diffTime(&nextUpdate, &curTime, &secondsDiff2)))
            goto exit;

    if ((0 >  (secondsDiff1 + pOcspContext->pOcspSettings->timeSkewAllowed)) ||
       ((0 >= (secondsDiff2 + pOcspContext->pOcspSettings->timeSkewAllowed) && isNextUpdate)))
    {
        status = ERR_OCSP_EXPIRED_RESPONSE;
    }

exit:
    return status;

} /* OCSP_MESSAGE_checkTime */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_checkNonce(ocspContext *pOcspContext)
{
    ASN1_ITEMPTR pTbsResponseData   = NULL;
    ASN1_ITEMPTR pItem              = NULL;
    ASN1_ITEMPTR pExts              = NULL;
    ASN1_ITEMPTR pNonce             = NULL;
    ASN1_ITEMPTR pVersion           = NULL;
    CStream      cs;
    ubyte*       nonceBuf           = NULL;
    sbyte4       cmpResult;
    MSTATUS      status             = OK;

    /* check that request has nonce. If not, no need to check */
    if ((!(pOcspContext->ocspProcess.client.nonce)) || (0 >= pOcspContext->ocspProcess.client.nonceLen))
        goto exit;

    pItem = pOcspContext->ocspProcess.client.pResponseRoot;
    cs    = pOcspContext->ocspProcess.client.cs; /* Contains the CStream of the response */

    /* unwrap root */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    if (NULL == (pTbsResponseData = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    /* Check if optional version is present */
    if (OK > (status = ASN1_GetChildWithTag(pTbsResponseData, 0, &pVersion)))
        goto exit;

    if (OK > (status = ASN1_GetNthChild(pTbsResponseData,(pVersion) ? 5:4, &pExts)))
    {
        status = ERR_OCSP_NONCE_CHECK_FAIL;
        goto exit;
    }

    if (OK > (status = ASN1_GetChildWithOID(ASN1_FIRST_CHILD(pExts), cs, id_pkix_ocsp_nonce_OID, &pNonce)))
        goto exit;

    if (NULL == pNonce)
    {
        status = ERR_OCSP_NONCE_CHECK_FAIL;
        goto exit;
    }

    if (NULL == (pNonce = ASN1_NEXT_SIBLING(pNonce)))
    {
        status = ERR_OCSP_NONCE_CHECK_FAIL;
        goto exit;
    }

    if (NULL == (pNonce = ASN1_FIRST_CHILD(pNonce)))
    {
        status = ERR_OCSP_NONCE_CHECK_FAIL;
        goto exit;
    }

    /* compare nonce */
    if (pNonce->length == pOcspContext->ocspProcess.client.nonceLen)
    {
        nonceBuf = (ubyte*)CS_memaccess(cs, pNonce->dataOffset, pNonce->length);

        if (OK > (status = DIGI_MEMCMP(pOcspContext->ocspProcess.client.nonce, nonceBuf, pNonce->length, &cmpResult)))
            goto exit;

        if (cmpResult != 0)
        {
            status = ERR_OCSP_NONCE_CHECK_FAIL;
            goto exit;
        }
    }
    else
    {
        status = ERR_OCSP_NONCE_CHECK_FAIL;
        goto exit;
    }

exit:
    if (nonceBuf)
    {
        CS_stopaccess(cs, nonceBuf);
    }

    return status;

} /* OCSP_MESSAGE_checkNonce */


/*------------------------------------------------------------------*/

static MSTATUS
OCSP_MESSAGE_checkOCSPSigning(ocspContext *pOcspContext, byteBoolean *pIsFound)
{
    ASN1_ITEMPTR pItem      = NULL;
    ASN1_ITEMPTR pCerts     = NULL;
    ASN1_ITEMPTR pExts      = NULL;
    ASN1_ITEMPTR pTemp      = NULL;
    ASN1_ITEMPTR pCritical  = NULL;
    CStream      cs;
    MSTATUS      status     = ERR_OCSP_INVALID_STRUCT;;

    pItem = pOcspContext->ocspProcess.client.pResponseRoot;
    cs    = pOcspContext->ocspProcess.client.cs;

    /* unwrap root */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    if (OK > (status = ASN1_GetChildWithTag(pItem, 0, &pItem)))
        goto exit;

     if (NULL == pItem)
        goto exit; /* No certs attached; Not an error */

    /* unwrap certs present */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    if (NULL == (pCerts = ASN1_FIRST_CHILD(pItem)))
        goto exit;

    /* Reach the extensions */
    if (OK > (status = ASN1_GetChildWithTag(pCerts, 3, &pExts)))
        goto exit;

    if (!pExts)
        goto exit;

    /* try to find a child with id_ce_extKeyUsage */
    if (OK > (status = ASN1_GetChildWithOID(pExts, cs, id_ce_extKeyUsage_OID, &pTemp)))
        goto exit;

    if (!pTemp)
        goto exit;

    /* Now traverse to the sequence of OIDs */
    if (NULL == (pTemp = ASN1_NEXT_SIBLING(pTemp)))
        goto exit;

    pCritical = pTemp;

    if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
    {
        /* Possibility of presence of critical = True field */
        /* Move to next sibling and then traverse the child */
        if (NULL == (pTemp = ASN1_NEXT_SIBLING(pCritical)))
            goto exit;

        if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
            goto exit;
    }

    if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
        goto exit;

    do
    {
        if (OK == ASN1_VerifyOID(pTemp, cs, id_kp_OCSPSigning_OID))
        {
            *pIsFound = TRUE;
            goto exit;
        }

        pTemp = ASN1_NEXT_SIBLING(pTemp);

    } while(pTemp);

exit:
    return status;

} /* OCSP_MESSAGE_checkOCSPSigning */


/*------------------------------------------------------------------*/


/* This method matches the response cert with that send in request   */
static MSTATUS
OCSP_MESSAGE_validateCertInfo(ocspContext *pOcspContext,OCSP_certID *pCertId)
{
    ubyte   count;
    sbyte4  result;
    MSTATUS status = OK;

    for (count = 0; count < pOcspContext->pOcspSettings->certCount; count++)
    {
        if (OK > (status = DIGI_MEMCMP(pCertId->serialNumber,
                                      (pOcspContext->ocspProcess.client.cachedCertId[count])->serialNumber,
                                      (pOcspContext->ocspProcess.client.cachedCertId[count])->serialNumberLength,
                                       &result)))
        {
            goto exit;
        }

        if (OK == result) /* Matching serial number found */
            break;
    }

    if (count == pOcspContext->pOcspSettings->certCount)
    {
        /* No Match found */
        status = ERR_OCSP_REQUEST_RESPONSE_MISMATCH;
        goto exit;
    }
    else
    {
        /* Match other attributes */
        if (OK > (status = DIGI_MEMCMP(pCertId->nameHash,
                                      (pOcspContext->ocspProcess.client.cachedCertId[count])->nameHash,
                                      (pOcspContext->ocspProcess.client.cachedCertId[count])->hashLength,
                                       &result)))
        {
            goto exit;
        }

        if (OK != result)
        {
            /* Mismatch */
            status = ERR_OCSP_REQUEST_RESPONSE_MISMATCH;
            goto exit;
        }

        if (OK > (status = DIGI_MEMCMP(pCertId->keyHash,
                              (pOcspContext->ocspProcess.client.cachedCertId[count])->keyHash,
                              (pOcspContext->ocspProcess.client.cachedCertId[count])->hashLength,
                               &result)))
        {
            goto exit;
        }

        if (OK != result)
        {
            /* Mismatch */
            status = ERR_OCSP_REQUEST_RESPONSE_MISMATCH;
            goto exit;
        }

    }

exit:
    return status;
}

/*------------------------------------------------------------------*/


/* we only deal with id-pkix-ocsp-basic response type; mandatory    */
/* This is extern function called by OCSP_CLIENT_parseResponse      */
extern MSTATUS
OCSP_MESSAGE_parseResponse(ocspContext *pOcspContext,
                           ubyte* pResponses, ubyte4 responsesLen)
{
    MemFile       memFile;
    CStream       cs;
    ASN1_ITEMPTR  pResponseRoot = NULL;
    ASN1_ITEMPTR  pTemp         = NULL;
    ASN1_ITEMPTR  pResponse     = NULL;
    ubyte*        responseBuf   = NULL;
    ubyte*        pTempRecdData = NULL;
    MSTATUS       status        = ERR_OCSP_INVALID_STRUCT;

    if ((NULL == pOcspContext) || (NULL == pResponses) || (0 >= responsesLen))
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    MF_attach(&memFile, responsesLen, pResponses);
    CS_AttachMemFile(&cs, &memFile);

    if (OK > (status = ASN1_Parse(cs, &pResponseRoot)))
        goto exit;

    if (NULL == pResponseRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* verify that we recognize the responseType */
    /* unwrap root */
    if (NULL == (pTemp = ASN1_FIRST_CHILD(pResponseRoot)))
        goto exit;

    /*
      OCSPResponse ::= SEQUENCE {
      responseStatus         OCSPResponseStatus,
      responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
    */

    /* first child of OCSPResponse is resposneStatus */
    if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
        goto exit;

    if (OK != ASN1_VerifyType(pTemp, ENUMERATED))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    switch ((ubyte4)pTemp->data.m_intVal)
    {
        case ocsp_successful:
        {
            pOcspContext->ocspProcess.client.status = ocsp_successful;
            break;
        }

        case ocsp_malformedRequest:
        {
            pOcspContext->ocspProcess.client.status = ocsp_malformedRequest;
            break;
        }

        case ocsp_internalError:
        {
            pOcspContext->ocspProcess.client.status = ocsp_internalError;
            break;
        }

        case ocsp_tryLater:
        {
            pOcspContext->ocspProcess.client.status = ocsp_tryLater;
            break;
        }

        case ocsp_sigRequired:
        {
            pOcspContext->ocspProcess.client.status = ocsp_sigRequired;
            break;
        }

        case ocsp_unauthorized:
        {
            pOcspContext->ocspProcess.client.status = ocsp_unauthorized;
            break;
        }

        default:
        {
            pOcspContext->ocspProcess.client.status = ocsp_status_unknown;
            status = ERR_OCSP_UNKNOWN_RESPONSE_STATUS;
            goto exit;
        }
    }

    /* stop if responseStatus is not successful */
    if (pOcspContext->ocspProcess.client.status != ocsp_successful)
    {
        pOcspContext->ocspProcess.client.state = ocspResponseParsed;
        goto exit;
    }

    /*
       ResponseBytes ::=       SEQUENCE {
       responseType   OBJECT IDENTIFIER,
       response       OCTET STRING }
    */
    if (NULL == (pTemp = ASN1_NEXT_SIBLING(pTemp)))
        goto exit;

    if (OK != ASN1_VerifyTag(pTemp, 0))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* ResponseBytes */
    if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* responseType */
    if (NULL == (pTemp = ASN1_FIRST_CHILD(pTemp)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (OK != ASN1_VerifyOID(pTemp, cs, id_pkix_ocsp_basic_OID))
    {
        status = ERR_OCSP_UNSUPPORTED_RESPONSE_TYPE;
        goto exit;
    }

    /* response -- octetstring */
    if (NULL == (pResponse = ASN1_NEXT_SIBLING(pTemp)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    responseBuf = (ubyte*)CS_memaccess(cs, pResponse->dataOffset, pResponse->length);

    if (NULL == (pTempRecdData = MALLOC(pResponse->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTempRecdData, responseBuf, pResponse->length);
    pOcspContext->receivedDataLength = pResponse->length;

    if (responseBuf)
    {
        CS_stopaccess(cs, responseBuf);
    }

    MF_attach(&pOcspContext->ocspProcess.client.memFile, pOcspContext->receivedDataLength, pTempRecdData);
    CS_AttachMemFile(&pOcspContext->ocspProcess.client.cs, &pOcspContext->ocspProcess.client.memFile);

    if (OK > (status = ASN1_Parse(pOcspContext->ocspProcess.client.cs, &pOcspContext->ocspProcess.client.pResponseRoot)))
        goto exit;

    if (NULL == pOcspContext->ocspProcess.client.pResponseRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* verify signature */
    if (OK > (status = OCSP_MESSAGE_verifySignature(pOcspContext, pOcspContext->ocspProcess.client.pResponseRoot,
                                                    pOcspContext->ocspProcess.client.cs)))
    {
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_checkResponderId(pOcspContext)))
        goto exit;

    /* check time */
    if (OK > (status = OCSP_MESSAGE_checkTime(pOcspContext)))
        goto exit;

    /*  check nonce. NOTE: nonce is optional. */
    if (OK > (status = OCSP_MESSAGE_checkNonce(pOcspContext)))
        goto exit;

    pOcspContext->ocspProcess.client.state = ocspResponseParsed;
    pOcspContext->pReceivedData            = pTempRecdData;
    pTempRecdData                          = NULL;

exit:
    if (pResponseRoot)
        TREE_DeleteTreeItem((TreeItem*)pResponseRoot);

    if (pTempRecdData)
        FREE(pTempRecdData);

    return status;

} /* OCSP_MESSAGE_parseResponse */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_goToNextResponse(ocspContext *pOcspContext)
{
    MSTATUS status = ERR_OCSP_INVALID_STRUCT;

    if (pOcspContext->ocspProcess.client.pSingleResponse)
    {
        pOcspContext->ocspProcess.client.pSingleResponse = ASN1_NEXT_SIBLING(pOcspContext->ocspProcess.client.pSingleResponse);
    }
    else if (pOcspContext->ocspProcess.client.state < ocspSingleResponseRetrieved)
    {
        ASN1_ITEMPTR pItem              = NULL;
        ASN1_ITEMPTR pTbsResponseData   = NULL;
        ASN1_ITEMPTR pVersion           = NULL;
        ASN1_ITEMPTR pResponses         = NULL;

        if (NULL == pOcspContext->ocspProcess.client.pResponseRoot)
            goto exit;

        if (NULL == (pItem = ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponseRoot)))
            goto exit;

        if (NULL == (pTbsResponseData = ASN1_FIRST_CHILD(pItem)))
            goto exit;

        if (OK > (status = ASN1_GetChildWithTag(pTbsResponseData, 0, &pVersion)))
            goto exit;

        if (OK > (status = ASN1_GetNthChild(pTbsResponseData, pVersion? 4 : 3, &pResponses)))
            goto exit;

        if (NULL == (pOcspContext->ocspProcess.client.pSingleResponse = ASN1_FIRST_CHILD(pResponses)))
            goto exit;

        pOcspContext->ocspProcess.client.state = ocspSingleResponseRetrieved;
    }

    status = OK;

exit:
    return status;

} /* OCSP_MESSAGE_goToNextResponse */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCurrentCertId(ocspContext *pOcspContext, OCSP_certID **ppCertId)
{
    ubyte*          buf         = NULL;
    OCSP_certID*    pTempCertId = NULL;
    ASN1_ITEMPTR    pCertId     = NULL;
    ASN1_ITEMPTR    pItem1      = NULL;
    ASN1_ITEMPTR    pItem2      = NULL;
    MSTATUS         status      = OK;

    *ppCertId = NULL;

    if (OK > (status = OCSP_MESSAGE_sanityCheck(pOcspContext)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (NULL == (pTempCertId = MALLOC(sizeof(OCSP_certID))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pTempCertId, 0x00, sizeof(OCSP_certID));

    if (NULL == (pCertId = ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pSingleResponse)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* algo identifier */
    if (NULL == (pItem1 = ASN1_FIRST_CHILD(pCertId)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* object identifier */
    if (NULL == (pItem2 = ASN1_FIRST_CHILD(pItem1)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (OK != ASN1_VerifyType(pItem2, OID))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pItem2->dataOffset, pItem2->length);

    switch (pItem2->length)
    {
        case 5:
        {
            pTempCertId->hashAlgo = sha1_OID;
            break;
        }

        case 8:
        {
            pTempCertId->hashAlgo = md5_OID;
            break;
        }

        case 9:
        {
            switch (buf[pItem2->length-1])
            {
                case 4:
                {
                    pTempCertId->hashAlgo = sha224_OID;
                     break;
                }

                case 1:
                {
                    pTempCertId->hashAlgo = sha256_OID;
                    break;
                }

                case 2:
                {
                    pTempCertId->hashAlgo = sha384_OID;
                    break;
                }

                case 3:
                {
                    pTempCertId->hashAlgo = sha512_OID;
                    break;
                }

                default:
                {
                    status = ERR_OCSP_BAD_ALGO;
                    break;
                }
            }

            break;
        }

        default:
        {
            status = ERR_OCSP_BAD_ALGO;
            break;
        }
    }

    CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);

    if (OK > status)
        goto exit;

    /* issuerNameHash */
    if (NULL == (pItem1 = ASN1_NEXT_SIBLING(pItem1)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    pTempCertId->hashLength = pItem1->length;

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pItem1->dataOffset, pItem1->length);

    if (NULL == (pTempCertId->nameHash = MALLOC(pItem1->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTempCertId->nameHash, buf, pItem1->length);
    CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);

    /* issuerKeyHash */
    if (NULL == (pItem1 = ASN1_NEXT_SIBLING(pItem1)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pItem1->dataOffset, pItem1->length);

    if (NULL == (pTempCertId->keyHash = MALLOC(pItem1->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTempCertId->keyHash, buf, pItem1->length);
    CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);

    /* serial number */
    if (NULL == (pItem1 = ASN1_NEXT_SIBLING(pItem1)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pItem1->dataOffset, pItem1->length);

    if (NULL == (pTempCertId->serialNumber = MALLOC(pItem1->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pTempCertId->serialNumber, buf, pItem1->length);

    CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);
    pTempCertId->serialNumberLength = pItem1->length;

    /* Check whether the cert was present in the reqquest sent */
    if (OK > (status = OCSP_MESSAGE_validateCertInfo(pOcspContext, pTempCertId)))
        goto exit;

    *ppCertId   = pTempCertId;
    pTempCertId = NULL;

exit:
    if (pTempCertId)
    {
        if (pTempCertId->serialNumber)
            FREE(pTempCertId->serialNumber);

        if (pTempCertId->nameHash)
            FREE(pTempCertId->nameHash);

        if (pTempCertId->keyHash)
            FREE(pTempCertId->keyHash);

        FREE(pTempCertId);
    }

    return status;

} /* OCSP_MESSAGE_getCurrentCertId */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCurrentCertStatus(ocspContext *pOcspContext, OCSP_certStatus **ppStatus)
{
    ubyte*           buf           = NULL;
    OCSP_certStatus* pTempStatus   = NULL;
    OCSP_certID*     pTempCertId   = NULL;
    ASN1_ITEMPTR     pCertStatus   = NULL;
    ASN1_ITEMPTR     pItem         = NULL;
    ASN1_ITEMPTR     pPrevPointer  = NULL;
    MSTATUS          status        = OK;

    if ((NULL == pOcspContext) || (NULL == ppStatus))
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    if (NULL == pOcspContext->ocspProcess.client.pSingleResponse)
    {
        status = ERR_OCSP_NO_MORE_RESPONSE;
        goto exit;
    }

    if (NULL == (pTempStatus = MALLOC(sizeof(OCSP_certStatus))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pTempStatus, 0x00, sizeof(OCSP_certStatus));

    if (OK > (status = ASN1_GetNthChild(pOcspContext->ocspProcess.client.pSingleResponse, 2, &pCertStatus)))
        goto exit;

    switch (pCertStatus->tag)
    {
        case ocsp_good:
        {
            pTempStatus->flag = ocsp_good;
            break;
        }

        case ocsp_revoked:
        {
            pTempStatus->flag = ocsp_revoked;

            /* getting other information */
            pItem = ASN1_FIRST_CHILD(pCertStatus);
            if (pItem)
            {
                buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                                           pItem->dataOffset, pItem->length);

                if (OK > (status = DATETIME_convertFromValidityString2(buf, pItem->length, &(pTempStatus->revocationTime))))
                    goto exit;

                pItem = ASN1_NEXT_SIBLING(pItem);

                if (pItem) /* has revocationReason */
                {
                    if (OK != ASN1_VerifyTag(pItem, 0))
                    {
                        status = ERR_OCSP_INVALID_STRUCT;
                        goto exit;
                    }

                    pItem = ASN1_FIRST_CHILD(pItem);
                    pTempStatus->revokeReasonFlag = pItem->data.m_intVal;
                }
            }
            else
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            break;
        }

        case ocsp_unknown:
        {
            pTempStatus->flag = ocsp_unknown;
            break;
        }

        default:
        {
            status = ERR_OCSP;
            goto exit;
        }
    }

    /* Check for request-response certificate mismatch */
    pPrevPointer = pOcspContext->ocspProcess.client.pSingleResponse;

    if (OK > (status = OCSP_MESSAGE_getCurrentCertId(pOcspContext,&pTempCertId)))
    {
        pOcspContext->ocspProcess.client.pSingleResponse = pPrevPointer;
        goto exit;
    }

    pOcspContext->ocspProcess.client.pSingleResponse = pPrevPointer;

    *ppStatus   = pTempStatus;
    pTempStatus = NULL;

exit:
    if (pTempCertId)
    {
        if (pTempCertId->keyHash)
            FREE(pTempCertId->keyHash);

        if (pTempCertId->nameHash)
            FREE(pTempCertId->nameHash);

        if (pTempCertId->serialNumber)
            FREE(pTempCertId->serialNumber);

        FREE(pTempCertId);
    }

    if (pTempStatus)
        FREE(pTempStatus);

    return status;

} /* OCSP_MESSAGE_getCurrentCertStatus */

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getProducedAt(ocspContext *pOcspContext, TimeDate *pTime)
{
    ubyte*       buf                = NULL;
    ASN1_ITEMPTR pTbsResponseData   = NULL;
    ASN1_ITEMPTR pVersion           = NULL;
    ASN1_ITEMPTR pItem              = NULL;
    ASN1_ITEMPTR pProducedAt        = NULL;
    MSTATUS      status             = OK;

    if ((NULL == pOcspContext) || (NULL == pTime))
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pTime, 0x00, sizeof(TimeDate));

    /* unwrap the root */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pOcspContext->ocspProcess.client.pResponseRoot)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* first child is tbsResponseData */
    if (NULL == (pTbsResponseData = ASN1_FIRST_CHILD(pItem)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    /* need to see if there is the optional version (tag 0) */
    if (NULL == (pVersion = ASN1_FIRST_CHILD(pTbsResponseData)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (OK != ASN1_VerifyTag(pVersion, 0))
    {
        pVersion = NULL;
    }

    if (OK > (status = ASN1_GetNthChild(pTbsResponseData, (pVersion == NULL) ? 2 : 3, &pProducedAt)))
        goto exit;

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pProducedAt->dataOffset, pProducedAt->length);

    if (OK > (status = DATETIME_convertFromValidityString2(buf, pProducedAt->length, pTime)))
        goto exit;

exit:
    if (buf)
    {
        CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);
    }

    return status;

} /* OCSP_MESSAGE_getProducedAt */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCurrentThisUpdate(ocspContext *pOcspContext, TimeDate *pTime)
{
    ASN1_ITEMPTR pThisUpdate  = NULL;
    ubyte*       buf          = NULL;
    MSTATUS      status       = OK;

    if ((NULL == pTime) || (NULL == pOcspContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)pTime, 0x00, sizeof(TimeDate));

    if (OK > (status = OCSP_MESSAGE_sanityCheck(pOcspContext)))
        goto exit;

    if (OK > (status = ASN1_GetNthChild(pOcspContext->ocspProcess.client.pSingleResponse, 3, &pThisUpdate)))
        goto exit;

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pThisUpdate->dataOffset, pThisUpdate->length);

    if (OK > (status = DATETIME_convertFromValidityString2(buf, pThisUpdate->length, pTime)))
        goto exit;

exit:
    if (buf)
    {
        CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);
    }

    return status;

} /* OCSP_MESSAGE_getCurrentThisUpdate */

/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCurrentNextUpdate(ocspContext *pOcspContext, TimeDate *pTime, byteBoolean *pIsNextUpdate)
{
    ASN1_ITEMPTR    pNextUpdate = NULL;
    ubyte*          buf         = NULL;
    MSTATUS         status      = OK;

    if ((NULL == pOcspContext) || (NULL == pTime) || (NULL == pIsNextUpdate))
        goto exit;

    DIGI_MEMSET((ubyte*)pTime, 0x00, sizeof(TimeDate));

    if (OK > (status = OCSP_MESSAGE_sanityCheck(pOcspContext)))
        goto exit;

    if (OK > (status = ASN1_GetNthChild(pOcspContext->ocspProcess.client.pSingleResponse, 4, &pNextUpdate)))
    {
        if (ERR_INDEX_OOB == status)
        {
            /* Next Update is not present, NOT ERROR as optional as per RFC
             * 2560.
             */
            status = OK;
            *pIsNextUpdate = FALSE;
            goto exit;
        }
    }

    if (OK != ASN1_VerifyTag(pNextUpdate, 0))
    {
        goto exit;
    }

    if (NULL == (pNextUpdate = ASN1_FIRST_CHILD(pNextUpdate)))
        goto exit;

    buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                               pNextUpdate->dataOffset, pNextUpdate->length);

    if (OK > (status = DATETIME_convertFromValidityString2(buf, pNextUpdate->length, pTime)))
        goto exit;

    *pIsNextUpdate = TRUE;

exit:
    if (buf)
    {
        CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);
    }

    return status;

} /* OCSP_MESSAGE_getCurrentNextUpdate */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getCurrentSingleExtensions(ocspContext *pOcspContext,
                                        extensions **ppExts,
                                        ubyte4 *pExtCount)
{
    ASN1_ITEMPTR pSingleResponse = NULL;
    ASN1_ITEMPTR pSingleExt      = NULL;
    MSTATUS      status          = OK;

    if ((NULL == pOcspContext) || (NULL == ppExts))
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    if (OK > (status = OCSP_MESSAGE_sanityCheck(pOcspContext)))
        goto exit;

    pSingleResponse = pOcspContext->ocspProcess.client.pSingleResponse;

    if (OK > (status = ASN1_GetChildWithTag(pSingleResponse, 1, &pSingleExt)))
        goto exit;

exit:
    return status;

} /* OCSP_MESSAGE_getCurrentNextUpdate */


/*------------------------------------------------------------------*/

static ubyte4
OCSP_MESSAGE_getChildCount(ASN1_ITEMPTR pItem)
{
    ubyte4       count  = 0;
    ASN1_ITEMPTR pChild = NULL;

    if (!pItem)
        return count;

    pChild = ASN1_FIRST_CHILD(pItem);
    while (pChild)
    {
        count++;
        pChild = ASN1_NEXT_SIBLING(pChild);
    }

    return count;

} /* OCSP_MESSAGE_getChildCount */


/*------------------------------------------------------------------*/

extern MSTATUS
OCSP_MESSAGE_getExtensions(ocspContext *pOcspContext, extensions **ppExts,
                                     ubyte4 *pExtCount)
{
    ASN1_ITEMPTR pOcspResponseRoot  = NULL;
    ASN1_ITEMPTR pTbsResponse       = NULL;
    ASN1_ITEMPTR pItem              = NULL;
    ASN1_ITEMPTR pExts              = NULL;
    extensions*  pTempExts          = NULL;
    MSTATUS      status             = OK;

    if (!ppExts || !pExtCount || !pOcspContext)
    {
        status = ERR_OCSP_INVALID_INPUT;
        goto exit;
    }

    if (pOcspContext->ocspProcess.client.state < ocspResponseParsed)
    {
        status = ERR_OCSP_ILLEGAL_STATE;
        goto exit;
    }

    *ppExts    = NULL;
    *pExtCount = 0;

    pOcspResponseRoot = pOcspContext->ocspProcess.client.pResponseRoot;

    /* unwrap root */
    if (NULL == (pItem = ASN1_FIRST_CHILD(pOcspResponseRoot)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (NULL == (pTbsResponse = ASN1_FIRST_CHILD(pItem)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (NULL == (pItem = ASN1_FIRST_CHILD(pTbsResponse)))
    {
        status = ERR_OCSP_INVALID_STRUCT;
        goto exit;
    }

    if (OK == ASN1_VerifyTag(pItem, 0))
    {
        /* has version */
        if (OK > (status = ASN1_GetNthChild(pTbsResponse, 5, &pExts)))
            goto exit;
    }
    else
    {
        if (OK > (status = ASN1_GetNthChild(pTbsResponse, 4, &pExts)))
            goto exit;
    }

    if (OK == ASN1_VerifyTag(pExts, 1))
    {
        /* unwrap tag */
        if (NULL == (pExts = ASN1_FIRST_CHILD(pExts)))
        {
            status = ERR_OCSP_INVALID_STRUCT;
            goto exit;
        }
    }
    else
    {
        goto exit; /* no extensions */
    }

    if (pExts)
    {
        ASN1_ITEMPTR pExt;
        ubyte4       count = 0;

        *pExtCount = OCSP_MESSAGE_getChildCount(pExts);

        if (0 == *pExtCount)
            goto exit;

        if (NULL == (pTempExts = MALLOC((*pExtCount)*sizeof(extensions))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (NULL == (pExt = ASN1_FIRST_CHILD(pExts)))
        {
            status = ERR_OCSP_INVALID_STRUCT;
            goto exit;
        }

        while (pExt)
        {
            ubyte *buf = NULL;

            if (NULL == (pItem = ASN1_FIRST_CHILD(pExt)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK != ASN1_VerifyType(pItem, OID))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK == ASN1_VerifyOID(pItem, pOcspContext->ocspProcess.client.cs, id_pkix_ocsp_nonce_OID))
            {
                (pTempExts+count)->oid = (ubyte *)id_pkix_ocsp_nonce_OID;
            }
            else if (OK == ASN1_VerifyOID(pItem, pOcspContext->ocspProcess.client.cs, id_pkix_ocsp_crl_OID))
            {
                (pTempExts+count)->oid = (ubyte *)id_pkix_ocsp_crl_OID;
            }
            else
            {
                /* unknown extension, ignore? */
            }

            if (NULL == (pItem = ASN1_NEXT_SIBLING(pItem)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            if (OK == ASN1_VerifyType(pItem, BOOLEAN))
            {
                (pTempExts+count)->isCritical = pItem->data.m_boolVal;
                if (NULL == (pItem = ASN1_NEXT_SIBLING(pItem)))
                {
                    status = ERR_OCSP_INVALID_STRUCT;
                    goto exit;
                }
            }
            else
            {
                (pTempExts+count)->isCritical = FALSE;
            }

            /* unwrap OCTETSTRING */
            if (NULL == (pItem = ASN1_FIRST_CHILD(pItem)))
            {
                status = ERR_OCSP_INVALID_STRUCT;
                goto exit;
            }

            buf = (ubyte*)CS_memaccess(pOcspContext->ocspProcess.client.cs,
                                       pItem->dataOffset, pItem->length);

            if (NULL ==((pTempExts+count)->value = MALLOC(pItem->length)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }

            DIGI_MEMCPY((pTempExts+count)->value, buf, pItem->length);
            (pTempExts+count)->valueLen = pItem->length;

            if (buf)
            {
                CS_stopaccess(pOcspContext->ocspProcess.client.cs, buf);
            }

            count = count + 1;
            pExt = ASN1_NEXT_SIBLING(pExt);
        }

        *ppExts   = pTempExts;
        pTempExts = NULL;
    }

exit:
    if (pTempExts)
    {
        ubyte count;

        for (count = 0; count < *pExtCount; count++)
        {
            if ((pTempExts+count)->value)
                FREE ((pTempExts+count)->value);
        }

        FREE (pTempExts);
    }

    return status;

} /* OCSP_MESSAGE_getExtensions */

#endif /* #ifdef __ENABLE_DIGICERT_OCSP_CLIENT__ */
