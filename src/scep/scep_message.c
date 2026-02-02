/**
 * @file  scep_message.c
 * @brief SCEP -- Simple Certificate Enrollment Protocol Messages
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
#include "../crypto/sha1.h"
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
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/asn1cert.h"
#include "../http/http_context.h"
#include "../common/dynarray.h"
#include "../crypto/pki_client_common.h"
#include "../scep/scep.h"
#include "../scep/scep_context.h"
#include "../scep/scep_message.h"
#include "../scep/scep_utils.h"
#include "../harness/harness.h"

#define BEGIN_CSR_BLOCK     "-----BEGIN CERTIFICATE REQUEST-----\x0d\x0a"
#define END_CSR_BLOCK       "-----END CERTIFICATE REQUEST-----\x0d\x0a"

/* SCEP Verisign private OIDs */
const ubyte verisign_OID[] =
    { 7, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45}; /*2 16 840 1 113733*/
const ubyte verisign_pki_OID[] =
    { 8, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01}; /*2 16 840 1 113733 1*/
const ubyte verisign_pkiAttrs_OID[] =
    { 9, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09}; /*2 16 840 1 113733 1 9*/
const ubyte verisign_pkiAttrs_messageType_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x02}; /*2 16 840 1 113733 1 9 2*/
const ubyte verisign_pkiAttrs_pkiStatus_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x03}; /*2 16 840 1 113733 1 9 3*/
const ubyte verisign_pkiAttrs_failInfo_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x04}; /*2 16 840 1 113733 1 9 4*/
const ubyte verisign_pkiAttrs_senderNonce_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x05}; /*2 16 840 1 113733 1 9 5*/
const ubyte verisign_pkiAttrs_recipientNonce_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x06}; /*2 16 840 1 113733 1 9 6*/
const ubyte verisign_pkiAttrs_transId_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x07}; /*2 16 840 1 113733 1 9 7*/
const ubyte verisign_pkiAttrs_extensionReq_OID[] =
    { 10, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x45, 0x01, 0x09, 0x08}; /*2 16 840 1 113733 1 9 8*/

const ubyte* AttributeOIDs[] =
{
    pkcs9_contentType_OID,
    pkcs9_signingTime_OID,
    pkcs9_messageDigest_OID,
    verisign_pkiAttrs_messageType_OID,
    verisign_pkiAttrs_pkiStatus_OID,
    verisign_pkiAttrs_failInfo_OID,
    verisign_pkiAttrs_senderNonce_OID,
    verisign_pkiAttrs_recipientNonce_OID,
    verisign_pkiAttrs_transId_OID
};

/* enum has to be in same order as AttributeOIDs */
typedef enum {
    contentType, signingTime, messageDigest, messageType, pkiStatus, failInfo, senderNonce, recipientNonce, transId
} attributeType;


typedef struct envelopeSignParams
{
    ubyte *pPayLoad;
    ubyte4 payLoadLen;
    AsymmetricKey *pRecipientKey;
    ASN1_ITEM *pRecipientCert;
    CStream rCS;
    const ubyte *encryptAlgoOID;
    RNGFun rngFun;
    void* rngFunArg;
    AsymmetricKey *pSignerKey;
    ASN1_ITEM *pSignerCert;
    CStream sCS;
    transactionAttributes *pTransAttrs;
    const ubyte *digestAlgoOID;

#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
    /* oaep params*/
    ubyte isOaep;
    ubyte4 oaepHashAlgo;
    sbyte *pOaepLabel;
#endif

} envelopeSignParams;

/*------------------------------------------------------------------*/

/* walk from contentInfo root to content; verify contentType is signedData*/
static WalkerStep walkFromContentInfoRootToContent[] =
{
    { GoFirstChild, 0, 0}, /* unwrap the root to get ContentInfo */
    { GoFirstChild, 0, 0}, /* First child of ContentInfo is contentType */
    { VerifyOID, 0, (ubyte*)pkcs7_signedData_OID},
    { GoNextSibling, 0, 0}, /* 2nd child is [0] */
    { VerifyTag, 0, 0},
    { GoFirstChild, 0, 0}, /* First child of [0] is content */
    { Complete, 0, 0}
};

/*------------------------------------------------------------------*/

/* modified from DIGI_ATOL. Uses length and non-numeric char to demarcate. */
static ubyte4
SCEP_MESSAGE_ATOL(const sbyte* s, ubyte4 length);

/*
 * Create the ContentInfo structure except the content part.
 *   ContentInfo ::= SEQUENCE {
 *     contentType  ContentType,
 *     content      [0] EXPLICIT CONTENTS.&Type({Contents}{@contentType})
 *   OPTIONAL
 *   }
 */
static MSTATUS
SCEP_MESSAGE_createContentInfo(const ubyte* contentType, /* oid */
                       DER_ITEMPTR *ppContentInfo, DER_ITEMPTR *ppContent);

/* Add an ASN1 item, including all TLV parts, to the parent item.
 * NOTE: only deal with tag <= 30
 */
static MSTATUS
SCEP_MESSAGE_addWholeItem(DER_ITEMPTR pParent, ubyte4 itemLen, ubyte* item, DER_ITEMPTR *ppChild);

/* This routine takes an Attribute ASN1 structure,
* and returns the index of the attributeType */
static MSTATUS
SCEP_MESSAGE_getAttributeType(ASN1_ITEMPTR pAuthAttrItem, CStream pStream,
                      attributeType *pAttrType);

/* process an Authenticated Attribute from PKCS#7 signedData structure,
* record the result in pTransAttris structure */
static MSTATUS
SCEP_MESSAGE_processTransactionAttribute(CStream cs, ASN1_ITEMPTR pAuthAttr,
                                   transactionAttributes *pTransAttrs);

/* get envelopedData content from pContent ASN1 structure */
static MSTATUS
SCEP_MESSAGE_getEnvelopedData(ASN1_ITEMPTR pContent, CStream cs,
                      MemFile *pMemFile,
                      ASN1_ITEM **ppEnvelopedData,
                      CStream *pStream,
                      ASN1_ITEM **ppRootToDelete,
                      ubyte **bufToDelete);

/* Initialize the transaction attributes.
 * selfCert is used for finding the certificate serial number to use for transactionId
 */
static MSTATUS
SCEP_MESSAGE_initTransactionAttributes(ubyte4 messageType,
                               CStream selfCertStream,
                               ASN1_ITEMPTR pSelfCertRoot,
                               transactionAttributes *pTransAttrs);

/* parse PKCS# 7 signed and enveloped data into scepContext */
static MSTATUS
SCEP_MESSAGE_parsePkcsSignedEnvelopedData(pkcsCtxInternal *pPkcsCtx,
                                          scepContext *pScepContext,
                                          ubyte* pMessage, ubyte4 messageLen);

/* extract certificates from PKCS# 7 degnerate signedData in pCertRep */
static MSTATUS
SCEP_MESSAGE_parsePkcs7DegenerateSignedData(scepContext *pScepContext,
                                            ubyte* pCertRep, ubyte4 certRepLen);
/*------------------------------------------------------------------*/

/* modified from DIGI_ATOL. Uses length to demarcate. */
static ubyte4
SCEP_MESSAGE_ATOL(const sbyte* s, ubyte4 length)
{
    ubyte4 retVal = 0;

    /* decimal part */
    while (length-- > 0 && *s >= '0' && *s <= '9')
    {
        retVal *= 10;
        retVal += *s - '0';
        ++s;
    }

    return retVal;
}

/*------------------------------------------------------------------*/
static MSTATUS
SCEP_MESSAGE_createContentInfo(const ubyte* contentType, /* oid */
                       DER_ITEMPTR *ppContentInfo, DER_ITEMPTR *ppContent)
{
    MSTATUS status = OK;

    if (!ppContentInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppContentInfo = NULL;
    if ( OK > ( status = DER_AddSequence( NULL, ppContentInfo)))
        goto exit;
    if ( OK > ( status = DER_AddOID( *ppContentInfo, contentType, NULL)))
        goto exit;
    if ( OK > ( status = DER_AddTag( *ppContentInfo, 0, ppContent)))
        goto exit;
exit:
    if (OK > status)
    {
        if (ppContentInfo && *ppContentInfo)
        {
            TREE_DeleteTreeItem((TreeItem*) *ppContentInfo);
            *ppContentInfo = NULL;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_initTransactionAttributes(ubyte4 messageType,
                               CStream selfCertStream,
                               ASN1_ITEM *pSelfCertRoot,
                               transactionAttributes *pTransAttrs)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pSerialNumber;
    ubyte* serialNumberBuf = NULL;

    /* walk from certificateRoot to serialNumber */
    static WalkerStep walkFromCertitificateRootToSerialNumber[] =
    {
        { GoFirstChild, 0, 0}, /* unwrap the root to get Certificate */
        { GoFirstChild, 0, 0}, /* first child of Certificate is TBSCertificate */
        { GoNthChild, 2, 0}, /* 2th child of TBSCertificate is serialNumber */
        { Complete, 0, 0}
    };

    if (!pTransAttrs)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTransAttrs->messageType = messageType;

    /* initialize the transactionID only when it's not initialized already */
    if (!pTransAttrs->transactionID)
    {
        if (!pSelfCertRoot)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > (status = ASN1_WalkTree( pSelfCertRoot, selfCertStream, walkFromCertitificateRootToSerialNumber, &pSerialNumber)))
            goto exit;

        /* will be deallocated when scepContext is released */
        if (NULL == (pTransAttrs->transactionID = (sbyte*)MALLOC(pSerialNumber->length*2+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        serialNumberBuf = (ubyte*)CS_memaccess(selfCertStream, pSerialNumber->dataOffset, pSerialNumber->length);
    if (OK > (status = SCEP_UTILS_integerToString(serialNumberBuf, pSerialNumber->length,
                                                  pTransAttrs->transactionID, (pSerialNumber->length*2+1))))
        goto exit;
        pTransAttrs->transactionIDLen = pSerialNumber->length*2;
    }
    pTransAttrs->failinfo = -1;
    pTransAttrs->pkiStatus = 0;
exit:
    if (serialNumberBuf)
    {
        CS_stopaccess(selfCertStream, serialNumberBuf);
    }
    if (OK > status)
    {
        /* deallocate memory */
        if (pTransAttrs && pTransAttrs->transactionID)
        {
            FREE(pTransAttrs->transactionID);
            pTransAttrs->transactionID = NULL;
            pTransAttrs->transactionIDLen = 0;
        }
    }
    return status;
}

/*------------------------------------------------------------------*/

/* NOTE: only deal with tag <= 30 */
static MSTATUS
SCEP_MESSAGE_addWholeItem(DER_ITEMPTR pParent, ubyte4 itemLen, ubyte* item, DER_ITEMPTR *ppChild)
{
    MSTATUS status = OK;
    ubyte  idOctect;
    ubyte4 headerLen;

    /* first octect is Identifier */
    idOctect = *(item);

    /* second octect is the start of the length octect(s);
    * if the 8th bit is 0, bit 1 through 7 give length;
    * otherwise, bit 1 through 7 give the number of octect in length
    */
    if ((*(item+1) & 0xff) & (1 << 7))
    {
        headerLen = 1 + 1 + (*(item+1) & 0x7f); /* one id octect, one length header octect */
    } else {
        headerLen = 2; /* one id octect, one length octect */
    }

    status = DER_AddItem(pParent, idOctect,  itemLen - headerLen, item + headerLen, ppChild);
exit:
    return status;
}

/*------------------------------------------------------------------*/
MSTATUS
SCEP_MESSAGE_generatePayLoad(AsymmetricKey *pKey, requestInfo *pReqInfo, ubyte** ppPayLoad, ubyte4* pPayLoadLen)
{
    MSTATUS         status;
    DER_ITEMPTR     pRoot = NULL;
    DER_ITEMPTR     pTemp;
    ubyte           revokeReason[4];

    if (!pReqInfo || !ppPayLoad)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppPayLoad = NULL;

    switch (pReqInfo->type)
    {
    case scep_PKCSReq:
        if (!pKey)
        {
            status = ERR_SCEP_INIT_FAIL;
            goto exit;
        }
        int digest = ht_sha256;
        if (OK > (status = PKCS10_GenerateCertReqFromDN(pKey, digest,
                                                    pReqInfo->value.certInfoAndReqAttrs.pSubject,
                                                    pReqInfo->value.certInfoAndReqAttrs.pReqAttrs,
                                                    ppPayLoad, pPayLoadLen)))
        {
            goto exit;
        }
        break;
    case scep_GetCertInitial:
        /* payload is issuerAndSubject:
            IssuerAndSubject ::= SEQUENCE {
            issuer          Name,
            subject         Name}
        */
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;

        if (OK > (status = ASN1CERT_StoreDistinguishedName(pRoot,
                                                           pReqInfo->value.issuerAndSubject.pIssuer)))
            goto exit;

        if (OK > (status = ASN1CERT_StoreDistinguishedName(pRoot,
                                                           pReqInfo->value.issuerAndSubject.pSubject)))
            goto exit;

        if (OK > (status = DER_Serialize(pRoot, ppPayLoad, pPayLoadLen)))
            goto exit;
        break;
    case scep_GetCert:
            /* payload is issuerAndSerialNumber:
                IssuerAndSerialNumber ::= SEQUENCE {
                  issuer        Name,
                  serialNumber  CertificateSerialNumber
                }
            */
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;

        if (OK > (status = ASN1CERT_StoreDistinguishedName(pRoot, pReqInfo->value.issuerAndSerialNo.pIssuer)))
            goto exit;

        if (OK > (status = DER_AddItem(pRoot, INTEGER|PRIMITIVE, pReqInfo->value.issuerAndSerialNo.serialNoLen, pReqInfo->value.issuerAndSerialNo.serialNo, NULL)))
            goto exit;

        if (OK > (status = DER_Serialize(pRoot, ppPayLoad, pPayLoadLen)))
            goto exit;
        break;
    case scep_GetCRL:
        /* payload is issuerAndSerialNumber:
              pkcsGetCRL issuerAndSerialNumber {
                  issuer "the certificate authority issuer name"
                  serialNumber "certificate authority certificate's serial number"
              }
            or
              pkcsGetCRL SEQUENCE {
                  crlIssuer  issuerAndSerialNumber
                  distributionPoint CE-CRLDistPoints
              }
          */
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;
        if (OK > (status = DER_AddSequence(pRoot, &pTemp)))
            goto exit;

        if (OK > (status = ASN1CERT_StoreDistinguishedName(pTemp, pReqInfo->value.issuerSerialNoAndDistPts.pIssuer)))
            goto exit;

        /* serialNo refers to certificate authority certificate's serial number */
        if (OK > (status = DER_AddItem(pTemp, INTEGER|PRIMITIVE, pReqInfo->value.issuerSerialNoAndDistPts.serialNoLen, pReqInfo->value.issuerSerialNoAndDistPts.serialNo, NULL)))
            goto exit;

        /* distributionPoint if available */
        if (pReqInfo->value.issuerSerialNoAndDistPts.distPts != NULL && pReqInfo->value.issuerSerialNoAndDistPts.distPtsLen > 0)
        {
            if (OK > (status = SCEP_MESSAGE_addWholeItem(pRoot, pReqInfo->value.issuerSerialNoAndDistPts.distPtsLen, pReqInfo->value.issuerSerialNoAndDistPts.distPts, NULL)))
            goto exit;

            pTemp = pRoot;
        }

        if (OK > (status = DER_Serialize(pTemp, ppPayLoad, pPayLoadLen)))
            goto exit;
        break;
    case scep_RevokeCert:
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;

        if (OK > (status = DER_AddItem(pRoot, INTEGER|PRIMITIVE, pReqInfo->value.revokeCert.serialNoLen, pReqInfo->value.revokeCert.serialNo, NULL)))
            goto exit;

        DIGI_HTONL(revokeReason, pReqInfo->value.revokeCert.reason);
        if (OK > (status = DER_AddItem(pRoot, INTEGER|PRIMITIVE, 4, (const ubyte*)revokeReason, NULL)))
            goto exit;

        if (OK > (status = DER_Serialize(pRoot, ppPayLoad, pPayLoadLen)))
            goto exit;

        break;
    case scep_PublishCRL:
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;

        if (OK > (status = DER_AddItem(pRoot, PRINTABLESTRING|PRIMITIVE, pReqInfo->value.caIdent.identLen, pReqInfo->value.caIdent.ident, NULL)))
            goto exit;
        if (OK > (status = DER_Serialize(pRoot, ppPayLoad, pPayLoadLen)))
            goto exit;
        break;
    case scep_RegisterEndEntity:
        if (OK > (status = DER_AddSequence(NULL, &pRoot)))
            goto exit;

        if (OK > (status = ASN1CERT_StoreDistinguishedName(pRoot, pReqInfo->value.endEntityInfo.pSubject)))
            goto exit;
        if (OK > (status = DER_AddItem(pRoot, PRINTABLESTRING|PRIMITIVE, DIGI_STRLEN(pReqInfo->value.endEntityInfo.password), (ubyte*)pReqInfo->value.endEntityInfo.password, NULL)))
            goto exit;

        if (OK > (status = DER_Serialize(pRoot, ppPayLoad, pPayLoadLen)))
            goto exit;
        break;
    case scep_ApproveCertEnroll:
    default:
        status = ERR_SCEP_NOT_SUPPORTED;
        break;
    }
exit:
    if (pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pRoot);
    }
    if (OK > status)
    {
        if (ppPayLoad && *ppPayLoad)
        {
            FREE(*ppPayLoad);
            *ppPayLoad = NULL;
        }
    }
    return status;
}

/*------------------------------------------------------------------*/

#define CSR_LINE_LENGTH     64
#define PEM_ARMOR		    1

MSTATUS
SCEP_MESSAGE_breakIntoLines(ubyte* pLineCsr, ubyte4 lineCsrLength,
        ubyte **ppRetCsr, ubyte4 *p_retCsrLength)
{
    ubyte*  pBlockCSR = NULL;
    ubyte*  pTempLineCsr;
    ubyte4  numLines;

    /* break the data up into (CSR_LINE_LENGTH) sized blocks */
    numLines     = ((lineCsrLength + (CSR_LINE_LENGTH - 1)) / CSR_LINE_LENGTH);
    pTempLineCsr = pLineCsr;

    /* calculate the new block length */
#if PEM_ARMOR
    *p_retCsrLength = (sizeof(BEGIN_CSR_BLOCK) - 1) + lineCsrLength + numLines + numLines + (sizeof(END_CSR_BLOCK) - 1);
#else
    *p_retCsrLength = (lineCsrLength + numLines + numLines);
#endif

    /* allocate the new csr block */
    if (NULL == (*ppRetCsr = pBlockCSR = MALLOC(*p_retCsrLength)))
    {
        return ERR_MEM_ALLOC_FAIL;
    }

#if PEM_ARMOR
    /* copy the start of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)BEGIN_CSR_BLOCK, (sizeof(BEGIN_CSR_BLOCK) - 1));
    pBlockCSR += (sizeof(BEGIN_CSR_BLOCK) - 1);
#endif

    /* copy contiguous blocks of data */
    while (1 < numLines)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, CSR_LINE_LENGTH);
        pBlockCSR[CSR_LINE_LENGTH] = MOC_CR;
        pBlockCSR[CSR_LINE_LENGTH + 1] = LF;

        pBlockCSR += CSR_LINE_LENGTH + 2;
        pTempLineCsr += CSR_LINE_LENGTH;
        lineCsrLength -= CSR_LINE_LENGTH;

        numLines--;
    }

    /* copy any remaining bytes */
    if (lineCsrLength)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, lineCsrLength);
        pBlockCSR += lineCsrLength;

        *pBlockCSR = MOC_CR; pBlockCSR++;
        *pBlockCSR = LF; pBlockCSR++;
    }

#if PEM_ARMOR
    /* copy the end of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)END_CSR_BLOCK, (sizeof(END_CSR_BLOCK) - 1));
#endif

    return OK;
}



/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_generatePkiMessage(envelopeSignParams *pEnvelopeSignParams,
                                ubyte **ppPkiMessage, ubyte4 *pPkiMessageLen)
{
    DER_ITEMPTR     pContentInfo1=NULL;
    DER_ITEMPTR     pContent1;
    DER_ITEMPTR     pContentInfo2=NULL;
    DER_ITEMPTR     pContent2;
    hwAccelDescr    hwAccelCtx;
    ubyte*          pPayLoad = NULL;
    ubyte4          payLoadLen = 0;
    CStream         pRecipientCStreams[1];
    ASN1_ITEMPTR    ppRecipientCertificates[1];
    ubyte4          numRecipients;
    ASN1_ITEMPTR    pIssuer, pSerialNumber;
    const ubyte     *encryptAlgoOID;
    ubyte*          pPkcsCertReqEnvelope = NULL;    /* enveloped cert req to include in the message */
    ubyte4          pkcsCertReqEnvelopeLen=0;
    signerInfo      mySignerInfo;
    signerInfoPtr   mySignerInfoPtr[1];             /* there is only one signer the cert requestor */
    Attribute*      pAuthAttributes = NULL;         /* SCEP requires transaction attributes */
    ubyte4          authAttributeLen = (NULL == pEnvelopeSignParams->pTransAttrs->senderNonce)? 3 : 4;
    sbyte           messageType[2];
    sbyte*          endPtr;
    ubyte4          senderNonceLen = 16;
    ubyte           senderNonce[64];
    ASN1_ITEMPTR    ppSignerCertificates[1];
    CStream         pSignerCStreams[1];
    ubyte4          offset = 0;
    MSTATUS         status = OK;

    if (!ppPkiMessage || !pPkiMessageLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    *ppPkiMessage = NULL;
    *pPkiMessageLen = 0;

    if (OK > (status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SCEP, &hwAccelCtx)))
        return status;

    if (pEnvelopeSignParams->pTransAttrs->pkiStatus != scep_SUCCESS)
    {
        authAttributeLen = authAttributeLen + 1;
    }

    /* create pkcsCertReqEnvolope message */
    /* wrap in ContentInfo */
    if ( OK > (status = SCEP_MESSAGE_createContentInfo(pkcs7_envelopedData_OID, &pContentInfo1, &pContent1)))
        goto exit;

    pRecipientCStreams[0] = pEnvelopeSignParams->rCS;
    ppRecipientCertificates[0] = pEnvelopeSignParams->pRecipientCert;
    numRecipients = 1;
    encryptAlgoOID = pEnvelopeSignParams->encryptAlgoOID;
    pPayLoad = pEnvelopeSignParams->pPayLoad;
    payLoadLen = pEnvelopeSignParams->payLoadLen;

    if (payLoadLen > 0)
    {
        if ( OK > ( status = PKCS7_EnvelopDataWoaep(MOC_HW(hwAccelCtx) pContentInfo1, pContent1, ppRecipientCertificates, pRecipientCStreams, numRecipients,
            encryptAlgoOID, pEnvelopeSignParams->rngFun, pEnvelopeSignParams->rngFunArg,
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
            pEnvelopeSignParams->isOaep, pEnvelopeSignParams->oaepHashAlgo, pEnvelopeSignParams->pOaepLabel,
#else
            0, 0, NULL,
#endif
            pPayLoad, payLoadLen,
            &pPkcsCertReqEnvelope, &pkcsCertReqEnvelopeLen)))
            goto exit;
    }

     /* if ( OK > ( status = DIGICERT_writeFile( "c:\\ws\\src\\scep\\test\\enveloped.der", pPkcsCertReqEnvelope, pkcsCertReqEnvelopeLen)))
        goto exit; */

    /* create signer infos */
    /* get issuer and serial number of certificate */
    if ( OK > ( status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pEnvelopeSignParams->pSignerCert),
                                                                &pIssuer, &pSerialNumber)))
    {
        goto exit;
    }

    mySignerInfo.pIssuer = pIssuer;
    mySignerInfo.pSerialNumber = pSerialNumber;
    mySignerInfo.cs = pEnvelopeSignParams->sCS;
    mySignerInfo.digestAlgoOID = pEnvelopeSignParams->digestAlgoOID;
    mySignerInfo.pKey = pEnvelopeSignParams->pSignerKey;
    mySignerInfo.pUnauthAttrs = NULL;
    mySignerInfo.unauthAttrsLen = 0;

    /* gather together authenticated Attributes, including transaction attributes */
    /* NOTE: manditory attributes like contentType and messageDigest are
     * added automatically in pkcs7 signedData */
    if (NULL == (pAuthAttributes = (Attribute *)MALLOC(sizeof(Attribute)*authAttributeLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* messageType */
    pAuthAttributes->typeOID = verisign_pkiAttrs_messageType_OID;
    pAuthAttributes->type = PRINTABLESTRING;
    endPtr = DIGI_LTOA(pEnvelopeSignParams->pTransAttrs->messageType, messageType, 2);
    pAuthAttributes->valueLen = (ubyte4)(endPtr-messageType);
    pAuthAttributes->value = MALLOC(pAuthAttributes->valueLen);
    DIGI_MEMCPY(pAuthAttributes->value, messageType, pAuthAttributes->valueLen);
    offset = offset + 1;

    /* recipientNonce */
    if (pEnvelopeSignParams->pTransAttrs->senderNonce)
    {
        (pAuthAttributes+offset)->typeOID = verisign_pkiAttrs_recipientNonce_OID;
        (pAuthAttributes+offset)->type = OCTETSTRING;
        (pAuthAttributes+offset)->value = (ubyte*)pEnvelopeSignParams->pTransAttrs->senderNonce;
        (pAuthAttributes+offset)->valueLen = pEnvelopeSignParams->pTransAttrs->senderNonceLen;
        offset = offset + 1;
    }

    /* senderNonce */
    if ( OK > ( status = RANDOM_numberGenerator(g_pRandomContext, senderNonce, senderNonceLen)))
        goto exit;
    (pAuthAttributes+offset)->typeOID = verisign_pkiAttrs_senderNonce_OID;
    (pAuthAttributes+offset)->type = OCTETSTRING;
    (pAuthAttributes+offset)->value = senderNonce;
    (pAuthAttributes+offset)->valueLen = senderNonceLen;
     offset = offset + 1;

    /* transactionId */
    (pAuthAttributes+offset)->typeOID = verisign_pkiAttrs_transId_OID;
    (pAuthAttributes+offset)->type = PRINTABLESTRING;
    (pAuthAttributes+offset)->value = (ubyte*)pEnvelopeSignParams->pTransAttrs->transactionID;
    (pAuthAttributes+offset)->valueLen = pEnvelopeSignParams->pTransAttrs->transactionIDLen;
    offset = offset + 1;

     /* failInfo */
    if (pEnvelopeSignParams->pTransAttrs->pkiStatus != scep_SUCCESS)
    {
        (pAuthAttributes+offset)->typeOID = verisign_pkiAttrs_failInfo_OID;
        (pAuthAttributes+offset)->type = PRINTABLESTRING;
        (pAuthAttributes+offset)->value = MALLOC(1);
        (pAuthAttributes+offset)->value[0] = '0' + pEnvelopeSignParams->pTransAttrs->failinfo;
        (pAuthAttributes+offset)->valueLen = 1;
    }

    /* initialize authenticated attributes for signer */
    mySignerInfo.pAuthAttrs = pAuthAttributes;
    mySignerInfo.authAttrsLen = authAttributeLen;
    mySignerInfoPtr[0] = &mySignerInfo;

    /* wrap in arrays */
    ppSignerCertificates[0] = pEnvelopeSignParams->pSignerCert;
    pSignerCStreams[0] = pEnvelopeSignParams->sCS;

    /* wrap in ContentInfo */
    if ( OK > (status = SCEP_MESSAGE_createContentInfo(pkcs7_signedData_OID, &pContentInfo2, &pContent2)))
        goto exit;

    /* create pkcsCertReqSigned message */
    if ( OK > ( status = PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0,
                                        pContentInfo2, pContent2,
                                         ppSignerCertificates, pSignerCStreams, 1,
                                         NULL, NULL, 0, /* no CRLs */
                                         mySignerInfoPtr, 1, /* one signer */
                                         pkcs7_data_OID,
                                         (payLoadLen > 0? pPkcsCertReqEnvelope : NULL),
                                         (payLoadLen > 0? pkcsCertReqEnvelopeLen : 0),
                                         pEnvelopeSignParams->rngFun,
                                         pEnvelopeSignParams->rngFunArg,
                                         ppPkiMessage, pPkiMessageLen)))
        goto exit;

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SCEP, &hwAccelCtx);

    if (pContentInfo1)
    {
        TREE_DeleteTreeItem((TreeItem*) pContentInfo1);
    }
    if (pContentInfo2)
    {
        TREE_DeleteTreeItem((TreeItem*) pContentInfo2);
    }

    if (pPkcsCertReqEnvelope)
    {
        FREE(pPkcsCertReqEnvelope);
    }

    if (pAuthAttributes && pEnvelopeSignParams->pTransAttrs->pkiStatus != scep_SUCCESS)
    {
        if ((pAuthAttributes+authAttributeLen-1)->value)
            FREE((pAuthAttributes+authAttributeLen-1)->value);
    }

    if (pAuthAttributes && (pAuthAttributes)->value)
        FREE((pAuthAttributes)->value);

    if (pAuthAttributes)
    {
        FREE(pAuthAttributes);
    }

    if (OK > status)
    {
        if (ppPkiMessage && *ppPkiMessage && pPkiMessageLen)
        {
            FREE(*ppPkiMessage);
            *ppPkiMessage = NULL;
            *pPkiMessageLen = 0;
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* NOTE: selfcert can be either self-signed or ca-issued */

extern MSTATUS
SCEP_MESSAGE_generatePkiRequestMessage(pkcsCtxInternal *pPkcsCtx,
                                       scepContext *pScepContext,
                                       ubyte** ppPkiMessage, ubyte4* pPkiMessageLen)

{
    MSTATUS         status;
    transactionAttributes *pTransAttrs;
    ubyte* pPayLoad = NULL;
    ubyte4 payLoadLen;

    envelopeSignParams *pEnvSignParams = NULL;

    if (pScepContext && pScepContext->roleType != SCEP_CLIENT)
    {
        status = ERR_SCEP_INVALID_ROLETYPE;
        goto exit;
    }

    if (!pScepContext || !pPkcsCtx ||
        !ppPkiMessage || !pPkiMessageLen)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pPkcsCtx->pRequesterCert)
    {
        status = ERR_SCEP_MISSING_SIGNER_INFO;
        goto exit;
    }

    *ppPkiMessage = NULL;
    *pPkiMessageLen = 0;

    if (NULL == (pEnvSignParams = MALLOC(sizeof(envelopeSignParams))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (!pScepContext->pTransAttrs)
    {
        if (NULL == (pScepContext->pTransAttrs = MALLOC(sizeof(transactionAttributes))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pScepContext->pTransAttrs, 0x00, sizeof(transactionAttributes));
    }
    pTransAttrs = pScepContext->pTransAttrs;

    if (pPkcsCtx->pPayLoad == NULL)
    {
        if (OK > (status = SCEP_MESSAGE_generatePayLoad(&(pPkcsCtx->key), pScepContext->pReqInfo, &pPayLoad, &payLoadLen)))
            goto exit;
    }
    else
    {
        if (OK > (status = DIGI_CALLOC((void**)&pPayLoad, 1, pPkcsCtx->payLoadLen)))
        {
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pPayLoad, pPkcsCtx->pPayLoad, pPkcsCtx->payLoadLen)))
        {
            goto exit;
        }
        payLoadLen = pPkcsCtx->payLoadLen;
    }

    /* Initialize transaction attributes */
    if (OK > (status = SCEP_MESSAGE_initTransactionAttributes(pScepContext->pReqInfo->type,
                                                              pPkcsCtx->requesterCertStream,
                                                              pPkcsCtx->pRequesterCert,
                                                              pTransAttrs)))
        goto exit;

    /* retrieve requester info */
    pEnvSignParams->pPayLoad = pPayLoad;
    pEnvSignParams->payLoadLen = payLoadLen;
    pEnvSignParams->pTransAttrs = pTransAttrs;
    pEnvSignParams->encryptAlgoOID = pPkcsCtx->encryptAlgoOID;
    pEnvSignParams->pRecipientKey = &pPkcsCtx->key;
    pEnvSignParams->rCS = pPkcsCtx->RACertStream;
    pEnvSignParams->pRecipientCert = pPkcsCtx->pRACertificate;
    pEnvSignParams->sCS = pPkcsCtx->requesterCertStream;
    pEnvSignParams->pSignerCert = pPkcsCtx->pRequesterCert;
    pEnvSignParams->digestAlgoOID = pPkcsCtx->digestAlgoOID;
    pEnvSignParams->pSignerKey = &pPkcsCtx->signKey;
    pEnvSignParams->rngFun = pPkcsCtx->rngFun;
    pEnvSignParams->rngFunArg = pPkcsCtx->rngFunArg;

#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP__
    pEnvSignParams->isOaep = pPkcsCtx->isOaep;
    pEnvSignParams->pOaepLabel = pPkcsCtx->pOaepLabel;
    pEnvSignParams->oaepHashAlgo = pPkcsCtx->oaepHashAlgo;
#endif

    /* create pkcsCertReqSigned message */
    if ( OK > ( status = SCEP_MESSAGE_generatePkiMessage(pEnvSignParams, ppPkiMessage, pPkiMessageLen)))
        goto exit;

exit:
    if (pEnvSignParams)
    {
        FREE(pEnvSignParams);
    }
    if (pPayLoad)
    {
        FREE(pPayLoad);
    }

    if (OK > status)
    {
        if (ppPkiMessage && *ppPkiMessage && pPkiMessageLen)
        {
            FREE(*ppPkiMessage);
            *ppPkiMessage = NULL;
            *pPkiMessageLen = 0;
        }
    }
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_getAttributeType(ASN1_ITEMPTR pAuthAttrItem, CStream pStream,
                      attributeType *pAttrType)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pOidItem;
    ubyte4 i;

    if (!pAuthAttrItem || !pAttrType)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize to unknown */
    *pAttrType = -1;

    pOidItem = ASN1_FIRST_CHILD(pAuthAttrItem);

    if (OK > (status = ASN1_VerifyType(pOidItem, OID)))
        goto exit;

    for (i = 0; i < COUNTOF(AttributeOIDs); i++)
    {
        if (OK == ASN1_VerifyOID(pOidItem, pStream, AttributeOIDs[i]))
        {
            *pAttrType = i;
            break;
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_processTransactionAttribute(CStream cs, ASN1_ITEMPTR pAuthAttr,
                                   transactionAttributes *pTransAttrs)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pAttrValue;
    ASN1_ITEMPTR pTemp;
    sbyte* attrValueStr = NULL;
    sbyte4 attrValueStrLen;
    attributeType attrType;
        sbyte4 result;

    if (!pAuthAttr || !pTransAttrs)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = SCEP_MESSAGE_getAttributeType(pAuthAttr, cs, &attrType)))
        goto exit;

    /* set of values is second child of the sequence */
    if (OK > (status = ASN1_GetNthChild(pAuthAttr, 2, &pTemp)))
        goto exit;

    /* value is first child inside the set */
    pAttrValue = ASN1_FIRST_CHILD(pTemp);
    attrValueStr = (sbyte*) CS_memaccess( cs, pAttrValue->dataOffset, pAttrValue->length);
    attrValueStrLen = pAttrValue->length;
    switch (attrType)
    {
    case contentType:
        break;
    case signingTime:
        break;
    case messageDigest:
        break;
    case messageType:
        pTransAttrs->messageType = SCEP_MESSAGE_ATOL(attrValueStr, attrValueStrLen);
        break;
    case pkiStatus:
        pTransAttrs->pkiStatus = SCEP_MESSAGE_ATOL(attrValueStr, attrValueStrLen);
        break;
    case failInfo:
        pTransAttrs->failinfo = SCEP_MESSAGE_ATOL(attrValueStr, attrValueStrLen);
        break;
    case senderNonce:
        if (NULL == (pTransAttrs->senderNonce = (sbyte*) MALLOC(attrValueStrLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pTransAttrs->senderNonce, attrValueStr, attrValueStrLen);
        pTransAttrs->senderNonceLen = attrValueStrLen;
        break;
    case recipientNonce:
        if (NULL == (pTransAttrs->recipientNonce = (sbyte*) MALLOC(attrValueStrLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pTransAttrs->recipientNonce, attrValueStr, attrValueStrLen);
        pTransAttrs->recipientNonceLen = attrValueStrLen;
        break;
    case transId:
        if (pTransAttrs->transactionID != NULL)
        {
            if (pTransAttrs->transactionIDLen != attrValueStrLen)
            {
                status = ERR_SCEP_TRANSACTIONID_NOMATCH;
                goto exit;
            }

            if (OK > (status = DIGI_MEMCMP((const ubyte*)attrValueStr, (const ubyte*)pTransAttrs->transactionID, attrValueStrLen, &result)))
                goto exit;

            if (result != 0)
            {
                status = ERR_SCEP_TRANSACTIONID_NOMATCH;
                goto exit;
            }
        } else
        {
            /* retrieve transactionid */
            if (NULL == (pTransAttrs->transactionID = (sbyte*) MALLOC(attrValueStrLen)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            DIGI_MEMCPY(pTransAttrs->transactionID, attrValueStr, attrValueStrLen);
            pTransAttrs->transactionIDLen = attrValueStrLen;
        }
        break;
    default:
        /* unprocessed attribute */
        break;
    }
exit:
    if (attrValueStr)
    {
        CS_stopaccess(cs, attrValueStr);
    }
    if (OK > status)
    {
        if (pTransAttrs)
        {
            if (pTransAttrs->recipientNonce)
            {
                FREE(pTransAttrs->recipientNonce);
                pTransAttrs->recipientNonce = NULL;
                pTransAttrs->recipientNonceLen = 0;
            }
            if (pTransAttrs->senderNonce)
            {
                FREE(pTransAttrs->senderNonce);
                pTransAttrs->senderNonce = NULL;
                pTransAttrs->senderNonceLen = 0;
            }
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_getEnvelopedData(ASN1_ITEMPTR pContent, CStream cs,
                      MemFile *pMemFile,
                      ASN1_ITEM **ppEnvelopedData,
                      CStream *pStream,
                      ASN1_ITEM **ppRootToDelete,
                      ubyte **bufToDelete)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pContentInfo;
    ubyte* envelopedDataBuf = NULL;
    ubyte4 length = 0;

    if (!ppEnvelopedData || !pStream || !ppRootToDelete || !bufToDelete)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* initialize */
    *ppRootToDelete = NULL;
    *bufToDelete = NULL;

    /* In normal case, pContent contains a SEQUENCE representing
     * envelopedData and content;
     * NOTE from SCEP draft:The PKCS#7 EncryptedContent
     * is specified as an octet string, but SCEP entities must
     * also accept a sequence of octet strings as a valid
     * alternate encoding.

     * This alternate encoding must be accepted wherever PKCS #7 Enveloped
     * Data is specified in this document.
    */
    if (OK == ASN1_VerifyType(pContent, SEQUENCE))
    {
        if (OK == ASN1_VerifyOID(ASN1_FIRST_CHILD(pContent), cs, pkcs7_envelopedData_OID))
        {
            if (OK > (status = ASN1_GetChildWithTag(pContent, 0, ppEnvelopedData)))
                goto exit;
            *pStream = cs;
        }
    }
    else
    {
        const ubyte* buf;
        ASN1_ITEMPTR pTemp;
        if (OK != ASN1_VerifyType(pContent, OCTETSTRING))
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }
        /* accommodate the following two cases:
            1. content is expressed as a sequence of octetstrings;
            2. content is expressed as children of an octetstring;
            */
        if (ASN1_FIRST_CHILD(pContent) &&
            (OK == ASN1_VerifyType(ASN1_FIRST_CHILD(pContent), OCTETSTRING)))
        {
            pContent = ASN1_FIRST_CHILD(pContent);
        }
        /* calculate the total length */
        length = 0;
        pTemp = pContent;
        while (pTemp && pTemp->length > 0
            && (OK == ASN1_VerifyType(pTemp, OCTETSTRING)))
        {
            length += pTemp->length;
            pTemp = ASN1_NEXT_SIBLING(pTemp);
        }
        if (NULL == (envelopedDataBuf = (ubyte*)MALLOC(length)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        *bufToDelete = envelopedDataBuf;
        length = 0;
        pTemp = pContent;
        while (pTemp && pTemp->length > 0
            && (OK == ASN1_VerifyType(pTemp, OCTETSTRING)))
        {
            buf = CS_memaccess(cs, pTemp->dataOffset, pTemp->length);
            if (OK > (status = DIGI_MEMCPY(envelopedDataBuf + length, buf, pTemp->length)))
                goto exit;
            length += pTemp->length;
            CS_stopaccess(cs, buf);
            pTemp = ASN1_NEXT_SIBLING(pTemp);
        }
        MF_attach(pMemFile, length, (ubyte*) envelopedDataBuf);
        CS_AttachMemFile(pStream, pMemFile );
        if (OK > (status = ASN1_Parse(*pStream, ppRootToDelete)))
            goto exit;

        /* if ( OK > ( status = DIGICERT_writeFile( "envelopedData.der", envelopedDataBuf, length)))
            goto exit;
            */
        /* unwrap root */
        pContentInfo = ASN1_FIRST_CHILD(*ppRootToDelete);

        if (OK != ASN1_VerifyType(pContentInfo, SEQUENCE))
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }

        if (OK != ASN1_VerifyOID(ASN1_FIRST_CHILD(pContentInfo),
                                 *pStream, pkcs7_envelopedData_OID))
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }

        if (OK > (status = ASN1_GetChildWithTag(pContentInfo, 0, ppEnvelopedData)))
            goto exit;

        if (!(*ppEnvelopedData))
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }
    }

exit:
    if (OK > status)
    {
        if (bufToDelete && *bufToDelete)
        {
            FREE(*bufToDelete);
            *bufToDelete = NULL;
        }
        if (ppRootToDelete && *ppRootToDelete)
        {
            TREE_DeleteTreeItem((TreeItem*) *ppRootToDelete);
            *ppRootToDelete = NULL;
        }
    }
    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
SCEP_MESSAGE_parsePkcsResponse(pkcsCtxInternal *pPkcsCtx,
                               scepContext *pScepContext, SCEP_responseType type,
                               ubyte* pCertRep, ubyte4 certRepLen)
{
    switch (type)
    {
    case x_pki_message:
    case xml:
        return SCEP_MESSAGE_parsePkcsSignedEnvelopedData(pPkcsCtx, pScepContext, pCertRep, certRepLen);
    case x_x509_ca_ra_cert:
    case x_x509_ca_ra_cert_chain:
        return SCEP_MESSAGE_parsePkcs7DegenerateSignedData(pScepContext, pCertRep, certRepLen);
    default:
        return ERR_SCEP_NOT_SUPPORTED;
    }
}

/*------------------------------------------------------------------*/
/*
      signerInfo  {
          version 1
          issuerAndSerialNumber {
              issuer "admin cert's issuer"
              serialNumber "admin cert's serialNo"
          }
          ......
*/

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_parsePkcsSignedEnvelopedData(pkcsCtxInternal *pPkcsCtx,
                                          scepContext *pScepContext,
                                          ubyte* pMessage, ubyte4 messageLen)
{
    PKCS7_Callbacks *callbacks;
    CStream         envelopedStream;
    MemFile         envelopedMemFile;
    CStream         signedStream;
    MemFile         signedMemFile;
    ASN1_ITEMPTR    pSignedRoot   = NULL;
    ASN1_ITEMPTR    pPkcsSigned;
    ASN1_ITEMPTR    pTemp;
    ASN1_ITEMPTR    pContent;
    ASN1_ITEMPTR    pEnvelopedData;
    ASN1_ITEMPTR    pSignerInfo;
    ASN1_ITEMPTR    pSignerInfos=0;
    ASN1_ITEMPTR    pAuthAttrs;
    ASN1_ITEMPTR    pRootToDelete = NULL;
    ASN1_ITEMPTR    pCertificates = NULL;
    ubyte*          bufToDelete   = NULL;
    ubyte*          pkcsData      = NULL;
    ubyte4          pkcsDataLen;
    ubyte4          numKnownSigners;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status        = OK;

    /* walk from contentInfo root to content; verify contentType is signedData*/
    static WalkerStep walkFromContentInfoRootToContent[] =
    {
        { GoFirstChild, 0, 0}, /* unwrap the root to get ContentInfo */
        { GoFirstChild, 0, 0}, /* First child of ContentInfo is contentType */
        { VerifyOID, 0, (ubyte*)pkcs7_signedData_OID},
        { GoNextSibling, 0, 0}, /* 2nd child is [0] */
        { VerifyTag, 0, 0},
        { GoFirstChild, 0, 0}, /* First child of [0] is content */
        { Complete, 0, 0}
    };

    static WalkerStep walkFromSignedDataToContent[] =
    {
        { GoNthChild, 3, 0}, /* 3rd child of SignedData is ContentInfo*/
        { GoNthChild, 2, 0}, /* 2nd child is [0] */
        { VerifyTag, 0, 0},
        { GoFirstChild, 0, 0}, /* First child of [0] is content */
        { Complete, 0, 0}
    };
    if (OK > (status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SCEP, &hwAccelCtx)))
        return status;

    if (!pMessage || !pScepContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (!pScepContext->pTransAttrs)
    {
        if (NULL == (pScepContext->pTransAttrs = MALLOC(sizeof(transactionAttributes))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)pScepContext->pTransAttrs, 0x00, sizeof(transactionAttributes));
    }

    /* initialize */
    callbacks = &pPkcsCtx->callbacks;

    /* parse the request/reply message -- it is signedData*/
    MF_attach(&signedMemFile, messageLen, (ubyte*) pMessage);
    CS_AttachMemFile(&signedStream, &signedMemFile );
    if (OK > (status = ASN1_Parse( signedStream, &pSignedRoot)))
        goto exit;

    /* signedData is wrapped inside ContentInfo */
    if (OK > (status = ASN1_WalkTree(pSignedRoot, signedStream,
                                     walkFromContentInfoRootToContent, &pPkcsSigned)))
        goto exit;

    /* get transaction attributes */
    /* The 4th child is either certificates, crls, or signerInfos */
    if ( OK > ( status = ASN1_GetNthChild(pPkcsSigned, 4, &pTemp)))
        goto exit;

    /* if tag equals 0 or 2, it's certificates;
     * else if tag equals 1 or 3, it's crls;
     * else it's signerInfos */
    pSignerInfos = NULL;
    while ( !pSignerInfos )
    {
        switch ( pTemp->tag )
        {
        case 0:
        case 2:
            pCertificates = pTemp;
            pTemp = ASN1_NEXT_SIBLING(pTemp);
            break;
        case 1:
        case 3:
            pTemp = ASN1_NEXT_SIBLING(pTemp);
            break;
        default:
            pSignerInfos = pTemp;
            break;
        }
    }

    /* there should be only one signerInfo */
    pSignerInfo = ASN1_FIRST_CHILD(pSignerInfos);
    /* authenticated attributes has tag 0 or 2 */
    if ( OK > ( status = ASN1_GetChildWithTag(pSignerInfo, 0, &pAuthAttrs)))
        goto exit;

    if ( !pAuthAttrs)
    {
        if ( OK > ( status = ASN1_GetChildWithTag(pSignerInfo, 2, &pAuthAttrs)))
            goto exit;
        if ( !pAuthAttrs)
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }
        /* when tag== 2, it is explicitly tagged, thus another layer of wrapping SEQUENCE */
        pAuthAttrs = ASN1_FIRST_CHILD(pAuthAttrs);
    }
    if ( !pAuthAttrs)
    {
        status = ERR_SCEP_BAD_MESSAGE;
        goto exit;
    }
    /* process transaction attributes */
    while (pAuthAttrs)
    {
        if (OK > (status = SCEP_MESSAGE_processTransactionAttribute(signedStream,
                                                               pAuthAttrs,
                                                               pScepContext->pTransAttrs)))
           goto exit;

        pAuthAttrs = ASN1_NEXT_SIBLING(pAuthAttrs);
    }

    /* 3. if status is SUCCESS, retrieve certificates or returned crls;
       otherwise, we have already processed the transaction attributes
    */
    if ((pScepContext->pReqInfo? pScepContext->pReqInfo->type <= scep_GetCRL : TRUE) &&
        pScepContext->pTransAttrs->pkiStatus == (SCEP_pkiStatus)scep_SUCCESS)
    {
        /* 1. pkcsCertRepEnvelope is wrapped in ContentInfo inside SignedData */
        if (OK > (status = ASN1_WalkTree(pPkcsSigned, signedStream,
                                         walkFromSignedDataToContent, &pContent)))
            goto exit;

        if (OK > (status = SCEP_MESSAGE_getEnvelopedData(pContent, signedStream,
                                                 &envelopedMemFile,
                                                 &pEnvelopedData,
                                                 &envelopedStream,
                                                 &pRootToDelete,
                                                 &bufToDelete)))
            goto exit;

        if (OK > (status = PKCS7_DecryptEnvelopedData(MOC_HW(hwAccelCtx) pEnvelopedData,
                                                      envelopedStream,
                                                      0,
                                                      callbacks->getPrivKeyFun,
                                                      &pkcsData,
                                                      (sbyte4 *)&pkcsDataLen)))
            goto exit;

        /* pkcsCertRep contains a degenerate PKCS# 7 message for distribution of certificates and crls */
        if (OK > (status = SCEP_MESSAGE_parsePkcs7DegenerateSignedData(pScepContext,
            pkcsData, pkcsDataLen)))
            goto exit;
    } /* else if pkiStatus == PENDING or FAILURE, nothing to do,
       * transaction attrs already processed */

    /* verify signedData signature last
     * because ca certificates could be attached in the degenerate SignedData
     * together with the newly issued certificate */
    if (pScepContext->roleType == SCEP_CLIENT &&
        ((pScepContext->pReqInfo? pScepContext->pReqInfo->type <= scep_GetCRL : TRUE)))
    {
        if ( OK > ( status = PKCS7_VerifySignedData(MOC_HASH(hwAccelCtx) pPkcsSigned, signedStream,
                                                    0,
                                                    callbacks->getCertFun,
                                                    callbacks->valCertFun,
                                                    NULL, 0,
                                                    (sbyte4 *)&numKnownSigners)))
        {
            goto exit;
        }
        if (numKnownSigners == 0)
        {
            status = ERR_SCEP_NO_KNOWN_SIGNERS;
            goto exit;
        }
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SCEP, &hwAccelCtx);

    if (pSignedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pSignedRoot);
    }
    if (pRootToDelete)
    {
        TREE_DeleteTreeItem((TreeItem*)pRootToDelete);
    }
    if (bufToDelete)
    {
        FREE(bufToDelete);
    }
    if (pkcsData)
    {
        FREE(pkcsData);
    }
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
SCEP_MESSAGE_parsePkcs7DegenerateSignedData(scepContext *pScepContext,
                                            ubyte* pCertRep, ubyte4 certRepLen)
{
    MSTATUS         status = OK;
    MemFile        certRepMemFile;
    CStream         certRepStream;
    ASN1_ITEMPTR    pCertRepSignedRoot = NULL;
    ASN1_ITEMPTR    pContent;
    ASN1_ITEMPTR    pCertificates = NULL;
    ASN1_ITEMPTR    pCrls = NULL;
    ASN1_ITEMPTR    pTemp;


    /* parse the certRep message */
    MF_attach(&certRepMemFile, certRepLen, (ubyte*) pCertRep);
    CS_AttachMemFile(&certRepStream, &certRepMemFile );
    if (OK > (status = ASN1_Parse( certRepStream, &pCertRepSignedRoot)))
        goto exit;

    if (OK > (status = ASN1_WalkTree(pCertRepSignedRoot, certRepStream,
        walkFromContentInfoRootToContent, &pContent)))
        goto exit;

    if (!pContent)
    {
        status = ERR_SCEP_BAD_MESSAGE;
        goto exit;
    }
    /* certificate is the 4th child of SignedData with tag 0 or 2 */
    if (OK> (status = ASN1_GetNthChild(pContent, 4, &pTemp)))
    {
        goto exit;
    }
    if(!pTemp)
    {
        status = ERR_SCEP_BAD_MESSAGE;
        goto exit;
    }

    switch ( pTemp->tag )
    {
    case 0:
    case 2:
        pCertificates = pTemp;
        break;
    case 1:
    case 3:
        pCrls = pTemp;
        break;
    default:
        break;
    }

    if (!pCertificates && !pCrls)
    {
        status = ERR_SCEP_BAD_MESSAGE;
        goto exit;
    }
    /* prepended with a [0], [2], [3], or [4] tag */

    /* return all certificates */
    if (pTemp)
    {
        ubyte4 certSetLen;
        const ubyte     *certificateBuffer;
        if (pTemp->length > 0)
        {
            certSetLen = pTemp->length;
        } else if (pTemp->indefinite)
        {
            ASN1_ITEMPTR pItem;
            ASN1_ITEMPTR pEOC;
            pItem = pEOC = ASN1_FIRST_CHILD(pTemp);
            while (pItem)
            {
                pEOC = pItem;
                pItem = ASN1_NEXT_SIBLING(pItem);
            }
            if (NULL == pEOC || (0 != pEOC->id || 0 != pEOC->length))
            {
                status = ERR_SCEP_BAD_MESSAGE;
                goto exit;
            }
            certSetLen = pEOC->dataOffset - pEOC->headerSize - pTemp->dataOffset;
        } else
        {
            status = ERR_SCEP_BAD_MESSAGE;
            goto exit;
        }

        if (NULL == (pScepContext->pReceivedData = (ubyte*) MALLOC(certSetLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        certificateBuffer = CS_memaccess(certRepStream, pTemp->dataOffset, certSetLen);
        pScepContext->receivedDataLength = certSetLen;
        DIGI_MEMCPY(pScepContext->pReceivedData, certificateBuffer, pScepContext->receivedDataLength);
        CS_stopaccess(certRepStream, certificateBuffer);
    }

exit:
    if (pCertRepSignedRoot)
    {
        TREE_DeleteTreeItem((TreeItem*)pCertRepSignedRoot);
    }

    if (OK > status)
    {
        if (pScepContext && pScepContext->pReceivedData)
        {
            FREE(pScepContext->pReceivedData);
            pScepContext->pReceivedData = NULL;
            pScepContext->receivedDataLength = 0;
        }
    }
    return status;
}

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */
