/*
 * pkcs7.c
 *
 * PKCS7 Utilities
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
@file       pkcs7.c
@brief      Mocana SoT Platform convenience API in support of PKCS&nbsp;\#7.

@details    This file contains the SoT Platform convenience
            API functions in support of PKCS&nbsp;\#7, as defined in RFC&nbsp;2315,
            <em>PKCS&nbsp;\#7: Cryptographic Message Syntax Version 1.5</em>,
            https://www.ietf.org/rfc/rfc2315.txt.
            RFC&nbsp;5273, <em> CMC: Certificate Management over CMS (CMC) </em>,
            https://www.ietf.org/rfc/rfc5273.txt

@todo_eng_review (all functions' descriptions in pkcs7.c; documentation added
                    since 5.3.1, and I don't know what eng-review it received)

For documentation for SoT Platform PKCS&nbsp;\#7 convenience API wrapper
functions, see pkcs.c.

@flags
To enable the SoT Platform PKCS&nbsp;\#7 convenience API functions, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__

@copydoc    overview_pkcs7
*/


#include "../common/moptions.h"
#ifdef __ENABLE_DIGICERT_PKCS7__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../harness/harness.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/des.h"
#include "../crypto/aes.h"
#include "../crypto/three_des.h"
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#include "../crypto/arc2.h"
#include "../crypto/rc2algo.h"
#include "../crypto/aes_keywrap.h"
#include "../crypto/pkcs1.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/pkcs_common.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/ansix9_63_kdf.h"
#include "../crypto/pkcs7.h"
#if (defined(__ENABLE_DIGICERT_TAP__))
#include "../tap/tap_smp.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#endif
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#include "../crypto_interface/crypto_interface_des.h"
#include "../crypto_interface/crypto_interface_arc4.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#endif
#endif
#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)
#include "../smp/smp_tpm2/tpm2_lib/tools/tpm2_server_helpers.h"
#endif


/* for CMS */
#include "../crypto/cms.h"
#include "../crypto/sec_key.h"

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
#include "../crypto/cms_resign_util.h"
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__
#ifndef __ENABLE_DIGICERT_PKCS1__
#error "Must define __ENABLE_DIGICERT_PKCS1__ when __ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__ is defined"
#endif
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_ECC__)
static ubyte4 g_keyType = akt_ecc;
#endif

/*--------------------------------------------------------------------------*/

/* private data structures */

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__)
ubyte* attestationReqTypes[] = {(ubyte *) "TPM2_ATTEST", (ubyte *) "SIM_ATTEST"};
const ubyte4 bodyPartIdBase = 5000;
#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) */

typedef struct SignedDataHash
{
    ubyte   hashType;      /* used for signing/verification */
    const ubyte* algoOID;  /* used for signing */
    const   BulkHashAlgo* hashAlgo;
    ubyte*  hashData;
    BulkCtx bulkCtx;
} SignedDataHash;


typedef struct PKCS7_SignatureInfo
{
    ASN1_ITEMPTR    pASN1;
    ubyte4          msgSigDigestLen;
    ubyte           msgSigDigest[CERT_MAXDIGESTSIZE];
} PKCS7_SignatureInfo;

typedef struct AttributeNode
{
    Attribute *pAttr;
    struct AttributeNode *pNext;

} AttributeNode;

static const ubyte kRFC5758_HASHTYPE_TO_RSA_HASHTYPE[] =
{
    ht_sha224,
    ht_sha256,
    ht_sha384,
    ht_sha512
};

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) && !defined(__RTOS_WIN32__)
const ubyte cct_pkiData_oid[] =
{8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0C, 0x02}; /* 1.3.6.1.5.5.7.12.2 */
const ubyte cct_PKIResponse_OID[] =
{ 8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x0C, 0x03 }; /* 1.3.6.1.5.5.7.12.3 */
const ubyte statusInfoV2_oid[] =
{ 8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x07, 0x19 }; /* 1.3.6.1.5.5.7.7.25 */
const ubyte batchRequests_oid[]  =
{0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x07, 0x1C}; /* 1.3.6.1.5.5.7.7.28 */
const ubyte batchResponses_oid[] =
{ 8, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x07, 0x1D }; /* 1.3.6.1.5.5.7.7.29 */
#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) && !defined(__RTOS_WIN32__) */

typedef struct
{
    const ubyte*    pHashOid;
    ubyte           hashId;

} rsaHashEntry;

#define RSA_OAEP_NUM_HASH_ALGOS 5

static const rsaHashEntry gRsaHashTable[RSA_OAEP_NUM_HASH_ALGOS] = 
{
    {sha1_OID,   sha1withRSAEncryption},
    {sha224_OID, sha224withRSAEncryption},
    {sha256_OID, sha256withRSAEncryption},
    {sha384_OID, sha384withRSAEncryption},
    {sha512_OID, sha512withRSAEncryption}
};

#ifndef RSA_OAEP_HASH_ALGO_DEFAULT_INDEX 
#define RSA_OAEP_HASH_ALGO_DEFAULT_INDEX 2 /* sha256 */
#endif

#ifndef RSA_OAEP_LABEL_DEFAULT
#define RSA_OAEP_LABEL_DEFAULT ""
#endif

/* RSAES-OAEP-params ::= SEQUENCE {
    hashAlgorithm     [0] HashAlgorithm    DEFAULT sha1,
    maskGenAlgorithm  [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
    pSourceAlgorithm  [2] PSourceAlgorithm DEFAULT pSpecifiedEmpty
 }
 */
#define RSA_OAEP_PARAMS_HASH_ALGO_TAG       0
#define RSA_OAEP_PARAMS_MASK_GEN_ALGO_TAG   1
#define RSA_OAEP_PARAMS_SOURCE_ALGO_TAG     2

/* SignerIdentifier ::= CHOICE {
    issuerAndSerialNumber IssuerAndSerialNumber,
    subjectKeyIdentifier [0] SubjectKeyIdentifier } */

#define SUBJECT_KEY_IDENTIFIER_TAG          0

/* static function prototypes */

static MSTATUS PKCS7_GetHashAlgoIdFromHashAlgoOID( ASN1_ITEMPTR pDigestAlgoOID, CStream s,
                                                  ubyte* hashAlgoId);

static MSTATUS PKCS7_GetHashAlgoIdFromHashAlgoOID2( const ubyte* digestAlgoOID,
                                                   ubyte* hashAlgoId);

static MSTATUS PKCS7_ProcessSignerInfoWithCert(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                               CStream s, ASN1_ITEMPTR pSignerInfo,
                                               CStream certificateStream,
                                               ASN1_ITEMPTR pCertificate,
                                               ASN1_ITEMPTR pContentType,
                                               sbyte4 numHashes,
                                               SignedDataHash hashes[/*numHashes*/],
                                               PKCS7_SignatureInfo* pSigInfo);

/* figure out the certificate that corresponds to the signer info */
static MSTATUS PKCS7_GetSignerInfoCertificate( CStream s,
                                                ASN1_ITEMPTR pSignerInfo,
                                                ASN1_ITEMPTR pCertificates,
                                                ASN1_ITEMPTR* ppCertificate,
                                                ubyte4 version);

/* this will figure out the chain of certifcates and will call the
 supplied callback to make sure the root of the chain is an accepted
 certificate. Used to verify SignedData */
static MSTATUS PKCS7_ValidateCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                         CStream s,
                                         ASN1_ITEMPTR pRootCertificate,
                                         CStream pkcs7cs,
                                         ASN1_ITEMPTR pCertificates,
                                         const void * callbackArg,
                                         void *valCertFun,
                                         byteBoolean isCmsValCert);

/*
 this routine creates a ContentInfo as a child of pParent.
 contentType is given in payLoadType;
 content is given in payLoad.
 it optionally returns a pointer to the ContentInfo.
ContentInfo ::= SEQUENCE {
  contentType  ContentType,
  content      [0] EXPLICIT CONTENTS.&Type({Contents}{@contentType})
OPTIONAL
}
*/
static MSTATUS
PKCS7_AddContentInfo(DER_ITEMPTR pParent,
               const ubyte* payLoadType, /* OID */
               const ubyte* pPayLoad,
               ubyte4 payLoadLen,
               DER_ITEMPTR *ppContentInfo);

/* this routine creates a node with the provided tag,
 with sets of or sequences of items (indicated by passing
the ASN1 type MOC_SET or SEQUENCE) as children.
 it returns a pointer to the node with tag.
[tag] MOC_SET (or SEQUENCE) {
item1,
item2,
...
}
*/
static MSTATUS
PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(DER_ITEMPTR pParent,
                                           ubyte tag, ubyte4 setOrSequence,
                                           CStream *itemStreams,
                                           ASN1_ITEMPTR *ppRootItems, ubyte4 numItems,
                                           DER_ITEMPTR *ppChild);

/* This routine add an item to parent.
 * it optionally returns the newly added item.
*/
static MSTATUS
PKCS7_AddItem1(DER_ITEMPTR pParent,
              CStream cs, ASN1_ITEMPTR pRootItem,
              DER_ITEMPTR *ppNewItem);

/* This routine add an item given by payLoad to parent.
 * it optionally returns the newly added item.
*/
static MSTATUS
PKCS7_AddItem2( DER_ITEMPTR pParent,
               const ubyte* pPayLoad, ubyte4 payLoadLen,
               DER_ITEMPTR *ppNewItem);


/* this routine creates an Attribute given
 an attribute type (an OID), an attribute value,
 as well as the value type (i.e. id|tag).
 it optionally returns a pointer to it.
Attribute       ::=     SEQUENCE {
type              AttributeType,
values    MOC_SET OF AttributeValue }
-- at least one value is required
*/
static MSTATUS
PKCS7_AddAttribute(DER_ITEMPTR pParent, const ubyte* typeOID,
                   const ubyte valueType, const ubyte* value, ubyte4 valueLen,
                   DER_ITEMPTR *ppAttribute);

/* this routine adds an IssuerAndSerialNumber structure to the pParent.
IssuerAndSerialNumber ::= SEQUENCE {
  issuer        Name,
  serialNumber  CertificateSerialNumber
}
*/
static MSTATUS
PKCS7_AddIssuerAndSerialNumber(DER_ITEMPTR pParent,
                               CStream cs,
                               ASN1_ITEMPTR pIssuer,
                               ASN1_ITEMPTR pSerialNumber,
                               DER_ITEMPTR *ppIssuerAndSerialNumber);

/* This routine adds per signerInfo to the parent.
 * pSignerInfo points to the signer info for one signer;
 * md5Hash and sha1Hash contains the message digest for the payload;
 * payLoadType is provided for adding contentType attribute value if appropriate;
 * pDataBuffer is used to keep track of the allocated buffers that needs to be deallocated later.
*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pParent,
                       signerInfoPtr pSignerInfo,
                        SignedDataHash* pDataHash,
                        ubyte *plainData, ubyte4 plainDataLen,
                        RNGFun rngFun, void* rngFunArg,
                        ubyte* payLoadType,
                        ubyte** ppDataBuffer );
#else
static MSTATUS
PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pParent,
                       signerInfoPtr pSignerInfo,
                        SignedDataHash* pDataHash,
                        RNGFun rngFun, void* rngFunArg,
                        ubyte* payLoadType,
                        ubyte** ppDataBuffer );
#endif

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__)

/* This routine adds per signerInfo to the parent.
 * pSignerInfo points to the signer info for one signer;
 * md5Hash and sha1Hash contains the message digest for the payload;
 * payLoadType is provided for adding contentType attribute value if appropriate;
 * pDataBuffer is used to keep track of the allocated buffers that needs to be deallocated later.
*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
CMC_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pParent,
                       cmcSignerInfoPtr pCmcSignerInfo,
                        SignedDataHash* pDataHash,
                        ubyte *plainData, ubyte4 plainDataLen,
                        RNGFun rngFun, void* rngFunArg,
                        ubyte* payLoadType,
                        ubyte** pDataBuffer );
#else
static MSTATUS
CMC_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pParent,
                       cmcSignerInfoPtr pCmcSignerInfo,
                        SignedDataHash* pDataHash,
                        RNGFun rngFun, void* rngFunArg,
                        ubyte* payLoadType,
                        ubyte** pDataBuffer );
#endif

static MSTATUS
CMC_AddSubjectKeyIdentifier(DER_ITEMPTR pParent,
                               CStream cs,
                               ASN1_ITEMPTR pSubjectKeyIdentifier,
                               DER_ITEMPTR *ppSubjectKeyIdentifier);

/*
 this routine creates a ContentInfo as a child of pParent.
 contentType is given in payLoadType;
 content is given in payLoad.
 it optionally returns a pointer to the ContentInfo.
ContentInfo ::= SEQUENCE {
  contentType  ContentType,
  content      [0] EXPLICIT CONTENTS.&Type({Contents}{@contentType})
OPTIONAL
}
*/
static MSTATUS
CMC_AddContentInfo(DER_ITEMPTR pParent,
               const ubyte* payLoadType, /* OID */
               const ubyte* pPayLoad,
               ubyte4 payLoadLen,
               DER_ITEMPTR *ppContentInfo);

#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) */

#ifdef __ENABLE_DIGICERT_ECC__

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS PKCS7_ECCEncryptKey(
    MOC_HW(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pHashAlgo,
    AsymmetricKey* pPublicKey,
    AsymmetricKey* pPrivateKey,
    const ubyte* keyWrapOID,
    const ubyte* ukmData,
    ubyte4 ukmDataLen,
    const ubyte* cek,
    ubyte4 cekLen,
    ubyte** encryptedKey,
    ubyte4* encryptedKeyLen
    );
#else
static MSTATUS PKCS7_ECCEncryptKey(MOC_HW(hwAccelDescr hwAccelCtx)
                    const BulkHashAlgo* pHashAlgo,
                    ECCKey* pECCKey, ConstPFEPtr k,
                    const ubyte* keyWrapOID,
                    const ubyte* ukmData, ubyte4 ukmDataLen,
                    const ubyte* cek, ubyte4 cekLen,
                    ubyte** encryptedKey, ubyte4* encryptedKeyLen);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS PKCS7_ECCDecryptKey(
    MOC_HW(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pHashAlgo,
    AsymmetricKey* pPublicKey,
    AsymmetricKey* pPrivateKey,
    const ubyte* keyWrapOID,
    const ubyte* ukmData,
    ubyte4 ukmDataLen,
    const ubyte* encryptedKey,
    ubyte4 encryptedKeyLen,
    ubyte** cek,
    ubyte4* cekLen
    );
#else
static MSTATUS PKCS7_ECCDecryptKey(MOC_HW(hwAccelDescr hwAccelCtx)
                    const BulkHashAlgo* pHashAlgo,
                    ECCKey* pECCKey, ConstPFEPtr k,
                    const ubyte* keyWrapOID,
                    const ubyte* ukmData, ubyte4 ukmDataLen,
                    const ubyte* encryptedKey, ubyte4 encryptedKeyLen,
                    ubyte** cek, ubyte4* cekLen);
#endif

#endif

/*--------------------------------------------------------------------------*/

static MSTATUS PKCS7_AttributeCompare(Attribute *pLHS, Attribute *pRHS, sbyte4 *pCmp)
{
    MSTATUS status = OK;
    DER_ITEMPTR pLHSder = NULL;
    DER_ITEMPTR pRHSder = NULL;
    ubyte *pLeft = NULL;
    ubyte *pRight = NULL;
    ubyte4 lhLen = 0;
    ubyte4 rhLen = 0;
    ubyte4 i = 0;

    /* internal method, NULL checks not necc */
    /* since first field after the sequence tag is a length we just check the lengths first */

    /* begin with the valueLen, we assume it's less than 2^16 */
    lhLen = pLHS->valueLen;
    rhLen = pRHS->valueLen;

    if (lhLen > 255) /* takes 3 bytes (2 extra) to specify the length */
    {
        lhLen += 2;
    }
    else if (lhLen > 127) /* takes 2 bytes (1 extra) to specify the length */
    {
        lhLen += 1;
    }

    if (rhLen > 255) /* takes 3 bytes (2 extra) to specify the length */
    {
        rhLen += 2;
    }
    else if (rhLen > 127) /* takes 2 bytes (1 extra) to specify the length */
    {
        rhLen += 1;
    }

    /* We assume oid length is < 128 so a single byte length field for both. */
    lhLen += pLHS->typeOID[0]; /* first byte in our stored value is the length */
    rhLen += pRHS->typeOID[0];

    /* rest of length components are same for both LHS and RHS so ignore */
    if (lhLen < rhLen)
    {
        *pCmp = -1; 
        return status;
    }
    else if (lhLen > rhLen)
    {
        *pCmp = 1;
        return status;
    }

    /* lengths matched, look at the full serialization */
    status = PKCS7_AddAttribute(NULL, pLHS->typeOID, (ubyte) pLHS->type, pLHS->value, pLHS->valueLen, &pLHSder);
    if (OK != status)
        goto exit;

    status = PKCS7_AddAttribute(NULL, pRHS->typeOID, (ubyte) pRHS->type, pRHS->value, pRHS->valueLen, &pRHSder);
    if (OK != status)
        goto exit;

    status = DER_Serialize(pLHSder, &pLeft, &lhLen);
    if (OK != status)
        goto exit;

    status = DER_Serialize(pRHSder, &pRight, &rhLen);
    if (OK != status)
        goto exit;

    /* sanity check */
    if (lhLen != rhLen)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    while (i < lhLen && pLeft[i] == pRight[i])
    {
        i++;
    }

    if (i == lhLen)
        *pCmp = 0;
    else if (pLeft[i] < pRight[i])
        *pCmp = -1;
    else
        *pCmp = 1;
            
exit:

    if (NULL != pLeft)
    {
        (void) DIGI_MEMSET_FREE(&pLeft, lhLen);
    }

    if (NULL != pRight)
    {
        (void) DIGI_MEMSET_FREE(&pRight, rhLen);
    }
    
    if (NULL != pLHSder)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pLHSder);
    }

    if (NULL != pRHSder)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pRHSder);
    }

    return status;
}

static MSTATUS PKCS7_insertAttributeToSetOf(AttributeNode **ppRoot, Attribute *pIn)
{
    MSTATUS status = ERR_NULL_POINTER;
    AttributeNode *pNew = NULL;
    AttributeNode *pPrev = NULL;
    AttributeNode *pCurrent = NULL;
    sbyte4 cmp = -1;

    if (NULL == ppRoot)
        goto exit;

    status = DIGI_MALLOC((void **) &pNew, sizeof(AttributeNode));
    if (OK != status)
        goto exit;

    pNew->pAttr = pIn;

    /* empty list or less than first node, then need new root */
    if (NULL == *ppRoot)
    {
        pNew->pNext = *ppRoot;
        *ppRoot = pNew; pNew = NULL;
        return status;
    }
    else
    {
        status = PKCS7_AttributeCompare(pIn, (*ppRoot)->pAttr, &cmp);
        if (OK != status)
            goto exit;

        if (cmp < 0)
        {
            pNew->pNext = *ppRoot;
            *ppRoot = pNew; pNew = NULL;
            return status;
        }
    }    

    pPrev = *ppRoot;
    pCurrent = pPrev->pNext;

    while(NULL != pCurrent)
    {
        status = PKCS7_AttributeCompare(pIn, pCurrent->pAttr, &cmp);
        if (OK != status)
            goto exit;

        if (cmp < 0)
        {
            pPrev->pNext = pNew;
            pNew->pNext = pCurrent;
            pNew = NULL;
            return status;
        }

        pPrev = pCurrent;
        pCurrent = pCurrent->pNext;
    }

    /* add to the end */
    pPrev->pNext = pNew;
    pNew->pNext = NULL;
    pNew = NULL;

exit:

    if (NULL != pNew)
    {
        (void) DIGI_FREE((void **) &pNew);
    }

    return status;
}

static void PKCS7_freeAttributeSetOf(AttributeNode **ppRoot)
{
    AttributeNode *pCurrent = NULL;
    AttributeNode *pNext = NULL;

    if (NULL == ppRoot || NULL == *ppRoot)
        return; /* nothing to do */

    pCurrent = *ppRoot; *ppRoot = NULL;

    do
    {
        pNext = pCurrent->pNext;
        (void) DIGI_FREE((void **) &pCurrent);
        pCurrent = pNext;
        
    }
    while (NULL != pCurrent);
}

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetHashAlgoIdFromHashAlgoOID( ASN1_ITEMPTR pDigestAlgoOID, CStream s,
                                    ubyte* hashAlgoId)
{
    ubyte sha2SubType;

    if (OK == ASN1_VerifyOID( pDigestAlgoOID, s, sha1_OID))
    {
        *hashAlgoId = ht_sha1;
    }
    else if ( OK == ASN1_VerifyOID( pDigestAlgoOID, s, md5_OID))
    {
        *hashAlgoId = ht_md5;
    }
    else if (OK == ASN1_VerifyOIDRoot( pDigestAlgoOID, s, sha2_OID, &sha2SubType))
    {
        switch(sha2SubType)
        {
        case sha256Digest:
            *hashAlgoId = ht_sha256;
            break;

        case sha384Digest:
            *hashAlgoId = ht_sha384;
            break;

        case sha512Digest:
            *hashAlgoId = ht_sha512;
            break;

        case sha224Digest:
            *hashAlgoId = ht_sha224;
            break;
        }
    }
    else
    {
        return ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
    }

    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetHashAlgoIdFromHashAlgoOID2( const ubyte* digestAlgoOID,
                                     ubyte* hashAlgoId)
{
    /* note we are using pointer comparison */
    if (EqualOID(digestAlgoOID, md5_OID))
    {
        *hashAlgoId = ht_md5;
    }
    else if (EqualOID(digestAlgoOID, sha1_OID))
    {
        *hashAlgoId = ht_sha1;
    }
    else if (EqualOID(digestAlgoOID, sha224_OID))
    {
        *hashAlgoId = ht_sha224;
    }
    else if (EqualOID(digestAlgoOID, sha256_OID))
    {
        *hashAlgoId = ht_sha256;
    }
    else if (EqualOID(digestAlgoOID, sha384_OID))
    {
        *hashAlgoId = ht_sha384;
    }
    else if (EqualOID(digestAlgoOID, sha512_OID))
    {
        *hashAlgoId = ht_sha512;
    }
    else
    {
        return ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
    }
    return OK;
}



/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_DestructHashes( MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 numHashes, SignedDataHash** ppHashes)
{
    ubyte4 i;
    SignedDataHash* pHashes;

    if (!ppHashes || !(*ppHashes))
        return ERR_NULL_POINTER;

    pHashes = *ppHashes;

    for (i = 0; i < numHashes; ++i)
    {
        if ( pHashes[i].bulkCtx)
        {
            pHashes[i].hashAlgo->freeFunc( MOC_HASH(hwAccelCtx)
                                               &pHashes[i].bulkCtx);
        }
        if ( pHashes[i].hashData)
        {
            CRYPTO_FREE(hwAccelCtx, TRUE, &pHashes[i].hashData);
        }
    }

    FREE(pHashes);
    *ppHashes = 0;

    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ConstructHashes(  MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 hashes,
                        ubyte4* numHashes, SignedDataHash** ppHashes)
{
    MSTATUS status = OK;
    ubyte4 i,j;
    SignedDataHash* pHashes = 0;

    /* compute the hashes here */
    *numHashes = DIGI_BITCOUNT( hashes);
    if (0 == *numHashes)
    {
        *ppHashes = 0;
        return OK;
    }

    pHashes = MALLOC( (*numHashes) * sizeof( SignedDataHash));
    if (!pHashes)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    DIGI_MEMSET( (ubyte*) pHashes, 0, (*numHashes) * sizeof( SignedDataHash));

    i = j = 0;
    while (hashes && j < *numHashes)
    {
        if ( 1 & hashes)
        {
            pHashes[j].hashType = (ubyte) i;
            if (OK > (status = CRYPTO_getHashAlgoOID( (ubyte) i, &pHashes[j].algoOID)))
            {
                goto exit;
            }
            if (OK > (status = CRYPTO_getRSAHashAlgo( (ubyte) i, &pHashes[j].hashAlgo)))
            {
               goto exit;
            }
            if (OK > (status = CRYPTO_ALLOC( hwAccelCtx,
                                      pHashes[j].hashAlgo->digestSize,
                                      TRUE, &(pHashes[j].hashData))))
            {
               goto exit;
            }
            pHashes[j].hashAlgo->allocFunc(MOC_HASH(hwAccelCtx)
                                             &pHashes[j].bulkCtx);
            pHashes[j].hashAlgo->initFunc( MOC_HASH(hwAccelCtx)
                                             pHashes[j].bulkCtx);
            ++j;
        }
        hashes >>= 1;
        i++;
    }

    *ppHashes = pHashes;
    pHashes = 0;

exit:

    if (pHashes)
    {
        PKCS7_DestructHashes(MOC_HASH(hwAccelCtx)*numHashes, &pHashes);
    }

    return status;
}


/*-------------------------------------------------------------------------*/

static ubyte4
PKCS7_getNumberChildren( ASN1_ITEMPTR pParent)
{
    ubyte4 retVal = 0;
    ASN1_ITEMPTR pChild;

    pChild = ASN1_FIRST_CHILD( pParent);
    while (pChild)
    {
        ++retVal;
        pChild = ASN1_NEXT_SIBLING(pChild);
    }

    return retVal;
}


/*--------------------------------------------------------------------------*/

/*
    pRootItem is the pointer to an ASN1_ITEM returned by
    ASN1_Parse
*/

extern MSTATUS
PKCS7_GetCertificates(ASN1_ITEM* pRootItem,
           CStream s,
           ASN1_ITEM** ppFirstCertificate)
{
    static WalkerStep pcks7WalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) pkcs7_signedData_OID },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoChildWithTag, 0, 0},
        { Complete, 0, 0}
    };

    return ASN1_WalkTree( pRootItem, s, pcks7WalkInstructions, ppFirstCertificate);
}

/*--------------------------------------------------------------------------*/

/* for a simple linked list of certs */
typedef struct _CERT_DATA_NODE
{
    ubyte *pCert;
    ubyte4 certLen;
    struct _CERT_DATA_NODE *pNext;

} CERT_DATA_NODE;

/*--------------------------------------------------------------------------*/

extern MSTATUS PKCS7_filterCertificates(
    MOC_ASYM(hwAccelDescr hwAccelCtx)
    ASN1_ITEM *pCerts,
    CStream certStream,
    AsymmetricKey *pPrivKey,
    byteBoolean chainOnly,
    CERTS_DATA **ppCertArray,
    ubyte4 *pCertArrayLen
)
{
    MSTATUS status = ERR_NULL_POINTER;
    ASN1_ITEMPTR pIter;
    ASN1_ITEMPTR pChild;
    ubyte4 certLen;
    ubyte *pCert;
    ubyte4 numCerts = 0;
    CERTS_DATA *pCertArray = NULL;
    CERT_DATA_NODE *pCertList = NULL;
    CERT_DATA_NODE *pCurrent = NULL;
    CERT_DATA_NODE *pNew = NULL;
    ubyte4 i;
 
    /* we assume at least one cert and the private key is passed in */
    if (NULL == pCerts || NULL == ppCertArray || NULL == pCertArrayLen ||
        (chainOnly && NULL == pPrivKey))
        goto exit;

    pIter = pCerts;

    /* 3 cases 
       1) chainOnly (privKey required)
       2) !chainOnly and privKey
       3) !chainonly and no privKey 
       
       case 3 first, just put all elements into the list.
    */
    if (!chainOnly && NULL == pPrivKey)
    {
        while (NULL != pIter)
        {
            certLen = pIter->headerSize + pIter->length;
            pCert = (ubyte *) CS_memaccess(certStream, pIter->dataOffset - pIter->headerSize, certLen);

            status = DIGI_MALLOC((void **) &pNew, sizeof(CERT_DATA_NODE));
            if (OK != status)
                goto exit;

            pNew->certLen = certLen;
            pNew->pCert = pCert;
            pNew->pNext = NULL;
            numCerts++;

            /* first node, mark the beginning of the list */
            if (NULL == pCurrent)
            {
                pCertList = pNew;
            }
            else /* add to the existing list */
            {
                pCurrent->pNext = pNew;
            }
            
            /* move the pointers */
            pCurrent = pNew;
            pIter = ASN1_NEXT_SIBLING(pIter);
        }
    }
    else /* case 1 or 2, look for the cert assoc with the private key first */
    {
        while (NULL != pIter)
        {
            byteBoolean isGood = FALSE;

            certLen = pIter->headerSize + pIter->length;
            pCert = (ubyte *) CS_memaccess(certStream, pIter->dataOffset - pIter->headerSize, certLen);

            status = CA_MGMT_verifyCertAndKeyPair(MOC_ASYM(hwAccelCtx) pCert, certLen, pPrivKey, &isGood);
            if (OK != status)
                goto exit;

            if (isGood)
            {
                status = DIGI_MALLOC((void **) &pNew, sizeof(CERT_DATA_NODE));
                if (OK != status)
                    goto exit;

                pNew->certLen = certLen;
                pNew->pCert = pCert;
                pNew->pNext = NULL;
                numCerts++;

                /* always first node, mark the beginning of the list */
                pCertList = pNew;
                pCurrent = pNew;
                pChild = pIter; /* save a copy of the the leaf in ASN1 form too */
                break;
            }

            pIter = ASN1_NEXT_SIBLING(pIter);
        }

        /* if we found no cert error */
        if (NULL == pIter)
        {
            status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
            goto exit;
        }
        
        if (!chainOnly) /* case 2 next, just get rest of certs */
        {
            /* back to the beginning */
            pIter = pCerts;
            while (NULL != pIter)
            {
                certLen = pIter->headerSize + pIter->length;
                pCert = (ubyte *) CS_memaccess(certStream, pIter->dataOffset - pIter->headerSize, certLen);

                /* add if not the one we already added */
                if ((uintptr) pCert != (uintptr) pCertList->pCert)
                {
                    status = DIGI_MALLOC((void **) &pNew, sizeof(CERT_DATA_NODE));
                    if (OK != status)
                        goto exit;

                    pNew->certLen = certLen;
                    pNew->pCert = pCert;
                    pNew->pNext = NULL;
                    numCerts++;

                    pCurrent->pNext = pNew;
                    pCurrent = pNew;
                }
            
                pIter = ASN1_NEXT_SIBLING(pIter);
            }
        }
        else /* case 1, look for each parent */
        {
            byteBoolean done = FALSE;

            /* now we have case 1, look for the parent, or case 2 get rest of certs */
            while(!done)
            {
                ASN1_ITEMPTR pIssuer;
                ASN1_ITEMPTR pSubject;

                /* look for the issuer of the child */
                status = X509_getCertificateIssuerSerialNumber(pChild, &pIssuer, NULL);
                if (OK != status)
                    goto exit;

                /* back to the beginning */
                pIter = pCerts;
                while (NULL != pIter)
                {
                    if ((uintptr) pIter != (uintptr) pChild)
                    {
                        status = X509_getCertificateSubject(pIter, &pSubject);
                        if (OK != status)
                            goto exit;

                        status = ASN1_CompareItems(pIssuer, certStream, pSubject, certStream);
                        if (OK == status)
                        {
                            status = X509_validateLink(MOC_ASYM(hwAccelCtx) pChild, certStream,
                                                       pIter, certStream, numCerts);
                            if (OK == status)
                            {
                                /* found it! */
                                certLen = pIter->headerSize + pIter->length;
                                pCert = (ubyte *) CS_memaccess(certStream, pIter->dataOffset - pIter->headerSize, certLen);

                                status = DIGI_MALLOC((void **) &pNew, sizeof(CERT_DATA_NODE));
                                if (OK != status)
                                    goto exit;

                                pNew->certLen = certLen;
                                pNew->pCert = pCert;
                                pNew->pNext = NULL;
                                numCerts++;

                                pCurrent->pNext = pNew;
                                pCurrent = pNew;
                                break;
                            }
                        }
                    }

                    pIter = ASN1_NEXT_SIBLING(pIter);
                }

                if (NULL == pIter) /* no parent found */
                {
                    done = TRUE;
                }
                else  /* found parent */
                {
                    pChild = pIter; /* move child to the next one */
                }
            }
        }
    }

    /* convert the linked list to the array list */
    if (numCerts > 0)
    {
        status = DIGI_MALLOC((void **) &pCertArray, numCerts * sizeof(CERTS_DATA));
        if (OK != status)
            goto exit;
    }

    pCurrent = pCertList;
    for (i = 0; i < numCerts; i++)
    {
        pCertArray[i].pCertData = pCurrent->pCert;
        pCertArray[i].certDataLen = pCurrent->certLen;
        pCurrent = pCurrent->pNext;
    }
    
    *ppCertArray = pCertArray; pCertArray = NULL;
    *pCertArrayLen = numCerts;

exit:

    if (NULL != pCertArray) /* defensive code since last alloc was pCertArray */
    {        
        (void) DIGI_MEMSET_FREE((ubyte **) &pCertArray, numCerts * sizeof(CERTS_DATA));
    }
    
    pCurrent = pCertList;
    while (NULL != pCurrent)
    {
        pNew = pCurrent; /* use pNew to hold the one we are about to free */
        pCurrent = pCurrent->pNext;
        (void) DIGI_MEMSET_FREE((ubyte **) &pNew, sizeof(CERT_DATA_NODE));
    }

    return status;
}

/*--------------------------------------------------------------------------*/

static MSTATUS PKCS7_FindCertificate( CStream s,
                                     ASN1_ITEMPTR pIssuer,
                                     ASN1_ITEMPTR pSerialNumber,
                                     CStream certificatesStream,
                                     ASN1_ITEMPTR pCertificates,
                                     ASN1_ITEMPTR* ppCertificate)
{
    ASN1_ITEMPTR pCurrCertificate;

    if ( 0 == ppCertificate || 0 == pIssuer ||
        0 == pSerialNumber || 0 == pCertificates)
    {
        return ERR_NULL_POINTER;
    }

    *ppCertificate = 0;

    /* loop over the certificates */
    pCurrCertificate = pCertificates;
    while ( 0 != pCurrCertificate)
    {
        /* certificate part or TBSCertificate is the first child of certificae */
        if (OK == X509_checkCertificateIssuerSerialNumber(pIssuer, pSerialNumber,
                                                          s, pCurrCertificate,
                                                          certificatesStream))
        {
            *ppCertificate = pCurrCertificate;
            break;
        }
        pCurrCertificate = ASN1_NEXT_SIBLING( pCurrCertificate);
    }

    /* always return OK */
    return OK;
}

/*--------------------------------------------------------------------------*/

static MSTATUS PKCS7_findCertificateBySKI( ubyte *pSki,
                                           ubyte4 skiLen,
                                           CStream certificatesStream,
                                           ASN1_ITEMPTR pCertificates,
                                           ASN1_ITEMPTR* ppCertificate)
{
    MSTATUS status = ERR_NULL_POINTER;
    ASN1_ITEMPTR pCurrCertificate, pExtensions, pSKIExtension;
    intBoolean critical;

    if ( 0 == ppCertificate || 0 == pSki || 0 == pCertificates)
    {
        goto exit;
    }

    *ppCertificate = 0;

    /* loop over the certificates */
    pCurrCertificate = pCertificates;
    while ( 0 != pCurrCertificate)
    {
        /* get the extensions */
        status = X509_getCertificateExtensions( pCurrCertificate, &pExtensions);
        if (OK == status && NULL != pExtensions)
        {
            /* look for the Subject Key Extension */
            status = X509_getCertExtension( pExtensions, certificatesStream, subjectKeyIdentifier_OID, &critical, &pSKIExtension);
            if (OK == status && NULL != pSKIExtension)
            {
                sbyte4 cmp = -1;
                ubyte *pRawSki = (ubyte *)CS_memaccess( certificatesStream, pSKIExtension->dataOffset, pSKIExtension->length);
                if (NULL == pRawSki)
                {
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }

                if (pSKIExtension->length == skiLen)
                {
                    (void) DIGI_MEMCMP(pSki, pRawSki, skiLen, &cmp); /* null checks already done, no return code check needed */
                    if (0 == cmp)
                    {
                        CS_stopaccess(certificatesStream, pRawSki);
                        *ppCertificate = pCurrCertificate;
                        status = OK;
                        goto exit;                        
                    }
                }

                CS_stopaccess(certificatesStream, pRawSki);
            }
        }

        pCurrCertificate = ASN1_NEXT_SIBLING( pCurrCertificate);
    }

    status = ERR_NOT_FOUND;

exit:

    return status;
}

/*--------------------------------------------------------------------------*/

static MSTATUS PKCS7_FindParentCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           CStream s,
                                           ASN1_ITEMPTR pCertificate,
                                           CStream certificatesStream,
                                           ASN1_ITEMPTR pCertificates,
                                           sbyte4 chainLength,
                                           ASN1_ITEMPTR* ppParentCertificate)
{
    ASN1_ITEMPTR pCurrCertificate;
    ASN1_ITEMPTR pIssuer;

    if ( 0 == ppParentCertificate || 0 == pCertificate || 0 == pCertificates)
    {
        return ERR_NULL_POINTER;
    }

    *ppParentCertificate = 0;

    /* don't save status as we'll always return OK anyway */
    if (OK > X509_getCertificateIssuerSerialNumber(pCertificate, &pIssuer, NULL))
    {
        goto exit;
    }

    /* loop over the certificates */
    pCurrCertificate = pCertificates;
    while ( 0 != pCurrCertificate)
    {
        ASN1_ITEMPTR pSubject;

        if (OK <= X509_getCertificateSubject(pCurrCertificate, &pSubject))
        {
            if (OK == ASN1_CompareItems(pIssuer, s,
                                        pSubject, certificatesStream))
            {
                /* issuer is subject  -- verify the link is valid */
                if (OK <= X509_validateLink(MOC_ASYM(hwAccelCtx)
                                            pCertificate, s,
                                            pCurrCertificate, certificatesStream,
                                            chainLength))
                {
                    *ppParentCertificate = pCurrCertificate;
                    break;
                }
            }
        }

        pCurrCertificate = ASN1_NEXT_SIBLING( pCurrCertificate);
    }

exit:
    /* always return OK */
    return OK;
}


/*--------------------------------------------------------------------------*/

/* warning: this returns a certificate, not a root item and not a TBScertificate
   rootItem -> certificate -> TBScertificate */
static MSTATUS PKCS7_GetSignerInfoCertificate( CStream s,
                                                ASN1_ITEMPTR pSignerInfo,
                                                ASN1_ITEMPTR pCertificates,
                                                ASN1_ITEMPTR* ppCertificate,
                                                ubyte4 version)
{
    if (1 == version) /* Issuer and Serial Number */
    {
        ASN1_ITEMPTR pIssuerSerialNumber;
        ASN1_ITEMPTR pIssuer, pSerialNumber;

        if ( OK > ASN1_GetNthChild( pSignerInfo, 2, &pIssuerSerialNumber) ||
                OK > ASN1_VerifyType( pIssuerSerialNumber, SEQUENCE))
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        pIssuer = ASN1_FIRST_CHILD( pIssuerSerialNumber);
        if ( NULL == pIssuer)
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        pSerialNumber = ASN1_NEXT_SIBLING( pIssuer);
        if ( NULL == pSerialNumber)
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        return PKCS7_FindCertificate(s, pIssuer, pSerialNumber,
                                    s, pCertificates,
                                    ppCertificate);
    }
    else if (3 == version) /* SubjectKeyIdentifier */
    {
        MSTATUS status = OK;
        ASN1_ITEMPTR pSubjectKeyIdentifier = NULL;
        ubyte4 tagValue = 1; /* not SUBJECT_KEY_IDENTIFIER_TAG */
        ubyte *pRawSki = NULL;

        if (OK > ASN1_GetNthChild( pSignerInfo, 2, &pSubjectKeyIdentifier))
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        /* Extract the parameter tag */
        if (OK > ASN1_GetTag(pSubjectKeyIdentifier, &tagValue))
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        if (SUBJECT_KEY_IDENTIFIER_TAG != tagValue)
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        pRawSki = (ubyte *)CS_memaccess( s, pSubjectKeyIdentifier->dataOffset, pSubjectKeyIdentifier->length);
        if (NULL == pRawSki)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        status = PKCS7_findCertificateBySKI(pRawSki, pSubjectKeyIdentifier->length, s, pCertificates, ppCertificate);
        CS_stopaccess(s, pRawSki);
        return status;
    }

    return ERR_PKCS7_INVALID_STRUCT;
}

/*--------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS PKCS7_VerifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                                        CStream s,
                                        ASN1_ITEMPTR pEncryptedDigest,
                                        RSAKey* pRSAKey,
                                        const ubyte* hash,ubyte4 hashLen,
                                        ubyte4 hashType, ubyte4 keyType)
#else
static MSTATUS PKCS7_VerifyRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                                        CStream s,
                                        ASN1_ITEMPTR pEncryptedDigest,
                                        RSAKey* pRSAKey,
                                        const ubyte* hash,ubyte4 hashLen,
                                        ubyte4 hashType)
#endif
{
    MSTATUS status;
    ubyte* buffer = NULL;
    ubyte4  hashId;
    ubyte decryptedSignature[CERT_MAXDIGESTSIZE];
    sbyte4 decryptedSignatureLen, resCmp;

    buffer = (ubyte *)CS_memaccess( s, pEncryptedDigest->dataOffset,
                                   pEncryptedDigest->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = X509_decryptRSASignatureBufferEx(MOC_RSA(hwAccelCtx) pRSAKey,
                                                      buffer,
                                                      pEncryptedDigest->length,
                                                      decryptedSignature,
                                                      &decryptedSignatureLen,
                                                      &hashId, keyType)))
#else
    if (OK > (status = X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelCtx) pRSAKey,
                                                      buffer,
                                                      pEncryptedDigest->length,
                                                      decryptedSignature,
                                                      &decryptedSignatureLen,
                                                      &hashId)))
#endif
    {
        goto exit;
    }

    if ( hashType != hashId || decryptedSignatureLen != (sbyte4) hashLen)
    {
        status = ERR_PKCS7_INVALID_SIGNATURE;
        goto exit;
    }

    if (OK > ( status = DIGI_CTIME_MATCH( decryptedSignature, hash, hashLen, &resCmp)))
    {
        goto exit;
    }

    if ( 0 != resCmp)
    {
        status = ERR_PKCS7_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    if ( buffer)
    {
        CS_stopaccess( s, buffer);
    }

    return status;
}

#endif /* __DISABLE_DIGICERT_RSA__ */

#ifdef __ENABLE_DIGICERT_ECC__
/*--------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS PKCS7_VerifyECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) CStream s,
                                          ASN1_ITEMPTR pEncryptedDigest,
                                          ECCKey* pECCKey,
                                          const ubyte* hash, ubyte4 hashLen,
                                          ubyte4 hashType, ubyte4 keyType)
#else
static MSTATUS PKCS7_VerifyECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) CStream s,
                                          ASN1_ITEMPTR pEncryptedDigest,
                                          ECCKey* pECCKey,
                                          const ubyte* hash, ubyte4 hashLen,
                                          ubyte4 hashType)
#endif
{
    MSTATUS status;
    ASN1_ITEMPTR pSequence;

    pSequence = ASN1_FIRST_CHILD( pEncryptedDigest);
    if ( OK > ( status = ASN1_VerifyType( pSequence, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* call the exported routine */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = X509_verifyECDSASignatureEx( MOC_ECC(hwAccelCtx) pSequence, s, pECCKey, hashLen, hash, keyType);
#else
    status = X509_verifyECDSASignature( MOC_ECC(hwAccelCtx) pSequence, s, pECCKey, hashLen, hash);
#endif
exit:
    return status;
}
#endif

/*--------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS PKCS7_VerifyQsSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) CStream s,
                                       ASN1_ITEMPTR pEncryptedDigest,
                                       QS_CTX *pCtx,
                                       const ubyte* hash, ubyte4 hashLen,
                                       ubyte4 hashType)
{
    MSTATUS status;
    ASN1_ITEMPTR pSequence;

    pSequence = ASN1_FIRST_CHILD( pEncryptedDigest);
    if ( OK > ( status = ASN1_VerifyType( pSequence, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    status = X509_verifyQsSignature( MOC_ASYM(hwAccelCtx) ASN1_FIRST_CHILD(pSequence), s, pCtx, hashLen, (ubyte *) hash);

exit:

    return status;
}
#endif

/*--------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DSA__
static MSTATUS PKCS7_VerifyDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                                        CStream s,
                                        ASN1_ITEMPTR pEncryptedDigest,
                                        DSAKey* pDSAKey,
                                        const ubyte* hash, ubyte4 hashLen,
                                        ubyte4 hashType)
{
    MSTATUS status;
    ASN1_ITEMPTR pSequence;

    pSequence = ASN1_FIRST_CHILD( pEncryptedDigest);
    if ( OK > ( status = ASN1_VerifyType( pSequence, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* call the exported routine */
    status = X509_verifyDSASignature(MOC_DSA(hwAccelCtx) pSequence,
                                     s, pDSAKey, hashLen, hash);
exit:
    return status;
}
#endif

/*--------------------------------------------------------------------------*/


static MSTATUS PKCS7_ValidateCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                         CStream signerInfoCertificateStream,
                                         ASN1_ITEMPTR pSignerInfoCertificate,
                                         CStream certificatesStream,
                                         ASN1_ITEMPTR pCertificates, /* can be null */
                                         const void * callbackArg,
                                         void *valCertFun,
                                         byteBoolean isCmsValCert)
{
    /* warning: the pSignerInfoCertificate is a pointer to a certificate,
     not a root item ( parse result) or a TBS certificate; remember:
     root item -> certificate -> TBS certificate */
    MSTATUS status = OK;
    CStream currStream;
    ASN1_ITEMPTR pCurrentCertificate;
    sbyte4 chainLength;

    pCurrentCertificate = pSignerInfoCertificate;
    currStream = signerInfoCertificateStream;

    if (!valCertFun)
    {
        return ERR_PKCS7_NO_CERT_VALIDATION_CALLBACK;
    }

    chainLength = 1;
    if (pCertificates)
    {
        /* try to walk the chain and then call the validation callback with the
         root of the chain */
        ASN1_ITEMPTR pParentCertificate;

        /* stop if self-signed certificate */
        while (ERR_FALSE ==
               (status = X509_isRootCertificate(pCurrentCertificate, currStream)))
        {
            if (OK > (status = PKCS7_FindParentCertificate(MOC_ASYM(hwAccelCtx)
                                                           currStream,
                                                           pCurrentCertificate,
                                                           certificatesStream,
                                                           pCertificates,
                                                           chainLength,
                                                           &pParentCertificate)))
            {
                goto exit;
            }

            if (!pParentCertificate)
            {
                break;
            }

            /* advance the chain */
            pCurrentCertificate = pParentCertificate;
            currStream = certificatesStream;
            ++chainLength;
        }
    }

    if (isCmsValCert)
    {
        status = ((CMS_ValidateRootCertificate) valCertFun)(callbackArg, currStream, 
                                                            pCurrentCertificate);                                                    
    }
    else
    {
        status = ((PKCS7_ValidateRootCertificate) valCertFun)(callbackArg, currStream, 
                                                              pCurrentCertificate, chainLength);
    }

exit:

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessSignerInfoWithCert(MOC_ASYM(hwAccelDescr hwAccelCtx) CStream s,
                                ASN1_ITEMPTR pSignerInfo,
                                CStream certificateStream, /* might be different from s */
                                ASN1_ITEMPTR pCertificate,
                                ASN1_ITEMPTR pContentType,
                                sbyte4 numHashes, SignedDataHash hashes[/*numHashes*/],
                                PKCS7_SignatureInfo* pSigInfo)
{
    ASN1_ITEMPTR pDigestAlgoOID, pDigestAlgo;
    ASN1_ITEMPTR pAuthenticatedAttributes;
    ASN1_ITEMPTR pEncryptedDigest;
    ASN1_ITEMPTR pDigestEncryptionAlgo;
    ubyte* attr = 0;
    ubyte4 attrLen = 0;
    const ubyte *pHashResult;
    ubyte *pTempBuf = NULL;
    ubyte *messageDigest = NULL; /* the messageDigest contained inside AuthenticatedAttributes */
    ubyte4 messageDigestLen = 0;
    /* enough space for either digest type */
    sbyte4 cmpResult = -1;
    MSTATUS status = OK;
    DER_ITEMPTR pSetOf = NULL;
    ubyte *dataBuf = NULL;
    ubyte4 dataBufLen;
    sbyte4 i;
    ubyte hashType = 0, subType = 0xFF;
    SignedDataHash *pHashInfo = 0;
    AsymmetricKey certKey = {0};

    if (OK > ASN1_VerifyType( pSignerInfo, SEQUENCE))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    if (OK > ASN1_GetNthChild( pSignerInfo, 3, &pDigestAlgo) ||
        OK > ASN1_VerifyType( pDigestAlgo, SEQUENCE) )
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pDigestAlgoOID = ASN1_FIRST_CHILD( pDigestAlgo);
    if ( OK > ASN1_VerifyType( pDigestAlgoOID, OID))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    /* DigestEncryption and Encrypted Digest are the next siblings
        unless there is Authenticated Attributes identified by tag 0 */
    pDigestEncryptionAlgo = ASN1_NEXT_SIBLING( pDigestAlgo);
    if ( 0 == pDigestEncryptionAlgo)
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    if (OK == ASN1_VerifyTag( pDigestEncryptionAlgo, 0))
    {
        pAuthenticatedAttributes = pDigestEncryptionAlgo;
        pDigestEncryptionAlgo = ASN1_NEXT_SIBLING( pAuthenticatedAttributes);
    }
    else
    {
        pAuthenticatedAttributes = 0;
    }

    if ( OK > ASN1_VerifyType( pDigestEncryptionAlgo, SEQUENCE) ||
        OK > ASN1_VerifyType( ( pEncryptedDigest = ASN1_NEXT_SIBLING( pDigestEncryptionAlgo)),
                                OCTETSTRING))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    if ( OK > ( status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                             pCertificate,
                                                             certificateStream,
                                                             &certKey)))
    {
        goto exit;
    }

    if (akt_rsa == certKey.type )
    {
        if ( OK > ASN1_VerifyOID( ASN1_FIRST_CHILD(pDigestEncryptionAlgo), s, rsaEncryption_OID))
        {
            /* could be rsaEncryption + hash -- certicom library does that */
            if (OK > ASN1_VerifyOIDRoot( ASN1_FIRST_CHILD(pDigestEncryptionAlgo),
                                        s, pkcs1_OID, &subType))
            {
                status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                goto exit;
            }
            /* we will test the subtype to verify it matches the hashType */
        }
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( akt_dsa == certKey.type )
    {
        ASN1_ITEMPTR pAlgoOID = ASN1_FIRST_CHILD( pDigestEncryptionAlgo);

        /* certicom uses the dsa_OID, most others dsaWithSHA1 */
        if ( OK > ASN1_VerifyOID( pAlgoOID, s, dsaWithSHA1_OID) &&
             OK > ASN1_VerifyOID( pAlgoOID, s, dsa_OID) )
        {
            /* DSA with SHA384 or SHA512 is unspecified per [RFC-5754, section 3.1] */
            if (OK > ASN1_VerifyOIDRoot( pAlgoOID, s, dsaWithSHA2_OID, &subType)
                || 0 == subType || subType > 2)
            {
                status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                goto exit;
            }
            /* we will match the subtype so convert to hashtype */
            subType = kRFC5758_HASHTYPE_TO_RSA_HASHTYPE[subType-1];          }
        else
        {
            subType = ht_sha1;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( akt_ecc == certKey.type )
    {
        ASN1_ITEMPTR pAlgoOID = ASN1_FIRST_CHILD( pDigestEncryptionAlgo);

        if ( OK > ASN1_VerifyOID( pAlgoOID, s, ecdsaWithSHA1_OID) )
        {
            if (OK > ASN1_VerifyOIDRoot( pAlgoOID, s, ecdsaWithSHA2_OID, &subType)
                || 0 == subType || subType > 4)
            {
                status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                goto exit;
            }
            /* we will match the subtype so convert to hashtype */
            subType = kRFC5758_HASHTYPE_TO_RSA_HASHTYPE[subType-1];
        }
        else
        {
            subType = ht_sha1;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if ( akt_qs == certKey.type )
    {
        ASN1_ITEMPTR pAlgoOID = ASN1_FIRST_CHILD( pDigestEncryptionAlgo);

        if ( OK != ASN1_VerifyOIDRoot( pAlgoOID, s, pure_pqc_sig_OID, &subType))
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;          
        }

        if (subType >= cid_PQC_MLDSA_44 && subType <= cid_PQC_SLHDSA_SHAKE_256F)
        {
            /* we validated subType is valid, set back to 0xff */
            subType = 0xff;
        }
        else
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        }
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    if (OK > ( status = PKCS7_GetHashAlgoIdFromHashAlgoOID( pDigestAlgoOID, s,
                                                            &hashType)))
    {
        goto exit;
    }

    if (subType != 0xFF && subType != hashType)
    {
        status = ERR_PKCS7_MISMATCH_SIG_HASH_ALGO;
        goto exit;
    }

    for (i = 0; i < numHashes; ++i)
    {
        if ( hashes[i].hashType == hashType)
        {
            pHashInfo = hashes+i;
            break;
        }
    }

    if (!pHashInfo)
    {
        status = ERR_PKCS7_INVALID_STRUCT; /* ERR_PKCS7_UNEXPECTED_SIGNER_INFO_HASH */
        goto exit;
    }

    if ( pAuthenticatedAttributes )
    {
        /* retrieve the messageDigest value to be compared to the passed in
         * content message digest */
        ASN1_ITEMPTR pMDItem;

        if (OK > (status = ASN1_GetChildWithOID(pAuthenticatedAttributes, s, pkcs9_messageDigest_OID, &pMDItem)))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        if (NULL == pMDItem)
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        /* message digest value is 2nd child of the attribute*/
        if (NULL == (pMDItem = ASN1_NEXT_SIBLING(pMDItem)))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        if (NULL == (pMDItem = ASN1_FIRST_CHILD(pMDItem)))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }

        messageDigestLen = pMDItem->length;
        messageDigest = (ubyte*) CS_memaccess( s, pMDItem->dataOffset, pMDItem->length);

        if (messageDigestLen != pHashInfo->hashAlgo->digestSize)
        {
            status = ERR_PKCS7_INVALID_SIGNATURE;
            goto exit;
        }
        /* compare both content digest and authenticatedAttribute digest */
        DIGI_CTIME_MATCH( pHashInfo->hashData, messageDigest, messageDigestLen, &cmpResult);
        if ( cmpResult)
        {
            status = ERR_PKCS7_INVALID_SIGNATURE;
            goto exit;
        }

        /* verify the other mandatory attribute is there */
        if (OK > ASN1_GetChildWithOID( pAuthenticatedAttributes, s, pkcs9_contentType_OID,
                                            &pMDItem))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        if (NULL == pMDItem)
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        /* move to attribute value */
        if (NULL == (pMDItem = ASN1_NEXT_SIBLING(pMDItem)))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }
        if (NULL == (pMDItem = ASN1_FIRST_CHILD(pMDItem)))
        {
            status = ERR_PKCS7_MISSING_AUTH_ATTRIBUTE;
            goto exit;
        }

        /* and it matches the pContentType */
        if (OK > ASN1_CompareItems( pContentType, s, pMDItem, s))
        {
            status = ERR_PKCS7_INVALID_SIGNATURE;
            goto exit;
        }

        /* From PKCS#7: The Attributes value's tag is MOC_SET OF,
         * and the DER encoding of the MOC_SET OF tag,
         * rather than of the IMPLICIT [0] tag,
         * is to be digested along with the length
         * and contents octets of the Attributes value. */
        dataBufLen = pAuthenticatedAttributes->length;

        dataBuf = (ubyte*) CS_memaccess( s,
                                        pAuthenticatedAttributes->dataOffset,
                                        dataBufLen);
        if ( 0 == dataBuf)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        /* create a MOC_SET OF structure */
        if (OK > (status = DER_AddItem(NULL, CONSTRUCTED|MOC_SET, dataBufLen, dataBuf, &pSetOf)))
            goto exit;

        if (OK > (status = DER_Serialize(pSetOf, &attr, &attrLen)))
            goto exit;

        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx,
                                        attrLen + pHashInfo->hashAlgo->digestSize,
                                        TRUE, &pTempBuf)))
        {
            goto exit;
        }

        if (attrLen > 0)
        {
            DIGI_MEMCPY(pTempBuf, attr, attrLen);
        }

        pHashInfo->hashAlgo->initFunc( MOC_HASH(hwAccelCtx) pHashInfo->bulkCtx);
        pHashInfo->hashAlgo->updateFunc( MOC_HASH(hwAccelCtx) pHashInfo->bulkCtx,
                                        pTempBuf, attrLen);
        pHashInfo->hashAlgo->finalFunc( MOC_HASH(hwAccelCtx) pHashInfo->bulkCtx,
                                        pTempBuf + attrLen);

        pHashResult = pTempBuf + attrLen;
    }
    else
    {
        pHashResult = pHashInfo->hashData;
    }
    if ( akt_rsa == (certKey.type & 0xff))
    {
#ifndef __DISABLE_DIGICERT_RSA__
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if ( OK > ( status = PKCS7_VerifyRSASignature(MOC_RSA(hwAccelCtx)s,
                                            pEncryptedDigest,
                                            certKey.key.pRSA,
                                            pHashResult,
                                            pHashInfo->hashAlgo->digestSize,
                                            pHashInfo->hashType, certKey.type)))
#else
        if ( OK > ( status = PKCS7_VerifyRSASignature(MOC_RSA(hwAccelCtx)s,
                                            pEncryptedDigest,
                                            certKey.key.pRSA,
                                            pHashResult,
                                            pHashInfo->hashAlgo->digestSize,
                                            pHashInfo->hashType)))
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
        {
            goto exit;
        }
#else /* ifndef __DISABLE_DIGICERT_RSA__ */
        status = ERR_RSA_DISABLED;
        goto exit;
#endif /* ifndef __DISABLE_DIGICERT_RSA__ */
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( akt_dsa == certKey.type )
    {
        if ( OK > ( status = PKCS7_VerifyDSASignature(MOC_DSA(hwAccelCtx) s,
                                            pEncryptedDigest,
                                            certKey.key.pDSA,
                                            pHashResult,
                                            pHashInfo->hashAlgo->digestSize,
                                            pHashInfo->hashType)))
        {
            goto exit;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( akt_ecc == (certKey.type & 0xff))
    {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if ( OK > ( status = PKCS7_VerifyECDSASignature(MOC_ECC(hwAccelCtx) s,
                                            pEncryptedDigest,
                                            certKey.key.pECC,
                                            pHashResult,
                                            pHashInfo->hashAlgo->digestSize,
                                            pHashInfo->hashType, certKey.type)))
#else
        if ( OK > ( status = PKCS7_VerifyECDSASignature(MOC_ECC(hwAccelCtx) s,
                                            pEncryptedDigest,
                                            certKey.key.pECC,
                                            pHashResult,
                                            pHashInfo->hashAlgo->digestSize,
                                            pHashInfo->hashType)))
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
        {
            goto exit;
        }
    }
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
    else if ( akt_qs == (certKey.type & 0xff))
    {
        if ( OK > ( status = PKCS7_VerifyQsSignature(MOC_ASYM(hwAccelCtx) s,
                                                     pEncryptedDigest,
                                                     certKey.pQsCtx,
                                                     pHashResult,
                                                     pHashInfo->hashAlgo->digestSize,
                                                     pHashInfo->hashType)))

        {
            goto exit;
        }
    }
#endif

    if (pSigInfo)
    {
        pSigInfo->pASN1 = pSignerInfo;
        pSigInfo->msgSigDigestLen = pHashInfo->hashAlgo->digestSize;
        DIGI_MEMCPY( pSigInfo->msgSigDigest, pHashResult,  pHashInfo->hashAlgo->digestSize);
    }

exit:

    if (pTempBuf)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    }

    if ( messageDigest)
    {
        CS_stopaccess( s, messageDigest);
    }

    if ( dataBuf)
    {
        CS_stopaccess( s, dataBuf);
    }

    if (attr)
    {
        FREE(attr);
    }

    if (pSetOf)
    {
        TREE_DeleteTreeItem((TreeItem*) pSetOf);
    }

    CRYPTO_uninitAsymmetricKey(&certKey, NULL);

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetDigestAlgorithmHash(ASN1_ITEMPTR pDigestAlgorithm, CStream s,
                                 ubyte4* pHashes)
{
    ASN1_ITEMPTR pDigestAlgorithmOID;
    ubyte hashType = 0;
    const BulkHashAlgo* pBHA;

    if (OK > ASN1_VerifyType( pDigestAlgorithm, SEQUENCE))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pDigestAlgorithmOID = ASN1_FIRST_CHILD( pDigestAlgorithm);
    if ( 0 == pDigestAlgorithmOID ||
        OK > ASN1_VerifyType( pDigestAlgorithmOID, OID) )
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    /* get the hash type and make sure it can be instantiated */
    if (OK <= PKCS7_GetHashAlgoIdFromHashAlgoOID( pDigestAlgorithmOID, s,
                                                  &hashType) &&
        OK <= CRYPTO_getRSAHashAlgo( hashType, &pBHA) )
    {
        (*pHashes) |= (1 << hashType);
    }

    return OK;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_CollectHashAlgos(MOC_HASH(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pDigestAlgorithms,
                       CStream s, ubyte4* numAlgos, SignedDataHash** ppHashes)
{
    MSTATUS status;
    ASN1_ITEMPTR pDigestAlgorithm;
    ubyte4 hashes;

    hashes = 0;
    /* generate hash of content info for each digest algorithms we know about ?*/
    pDigestAlgorithm = ASN1_FIRST_CHILD(pDigestAlgorithms);
    while ( pDigestAlgorithm) /* can be empty */
    {
        if (OK > (status = PKCS7_GetDigestAlgorithmHash(pDigestAlgorithm, s,
                                                        &hashes)))
        {
            goto exit;
        }
        pDigestAlgorithm = ASN1_NEXT_SIBLING( pDigestAlgorithm);
    }

    if (OK > ( status = PKCS7_ConstructHashes( MOC_HASH(hwAccelCtx) hashes,
                                                numAlgos, ppHashes)))
    {
        goto exit;
    }

exit:

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                        ASN1_ITEMPTR pContentInfo,
                        ASN1_ITEMPTR pSignerInfo,
                        ASN1_ITEMPTR pCertificates,
                        CStream s, ubyte4 numHashes,
                        SignedDataHash* pSignedDataHash,
                        PKCS7_SignatureInfo* pSigInfo,
                        const void* callbackArg,
                        PKCS7_GetCertificate getCertFun,
                        PKCS7_GetCertificateVersion3 getCertFunV3,
                        void *valCertFun,
                        byteBoolean isCmsValCert)
{
    MSTATUS status = ERR_NOT_FOUND;
    CStream certCS = s; /* CStream for pSignerInfoCertificate */
    MemFile externalCertMF;
    ASN1_ITEMPTR pIssuerAndSerialNumber, pIssuer, pSerialNumber, pSubjectKeyIdentifier;
    ASN1_ITEMPTR pSignerInfoCertificate = 0; /* points to a certificate not a root item */
    ASN1_ITEMPTR pRootItem = 0;
    ubyte* externalCert = 0;
    ubyte4 externalCertLen = 0;
    ubyte4 version = 0;
    ASN1_ITEMPTR pVersionItem;
    
    if (OK > ASN1_GetNthChild( pSignerInfo, 1, &pVersionItem) || 
           OK > ASN1_VerifyType( pVersionItem, INTEGER))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    version = (ubyte4) pVersionItem->data.m_intVal;

    /* first look in the certificates area of the PKCS#7 if any*/
    if (pCertificates)
    {
        if (OK > ( status = PKCS7_GetSignerInfoCertificate(s, pSignerInfo,
                                                           pCertificates,
                                                           &pSignerInfoCertificate, version)))
        {
            goto exit;
        }
    }

    if (pSignerInfoCertificate)
    {
        certCS = s;
    }
    else if ( (!getCertFun && 1 == version) || (!getCertFunV3 && 3 == version))
    {
        status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
        goto exit;
    }
    else
    {
        /* if not found, ask the callback */
        if (1 == version)
        {
            status = ASN1_GetNthChild(pSignerInfo, 2, &pIssuerAndSerialNumber);
            if (OK != status)
            {
                status = ERR_PKCS7_INVALID_STRUCT;
                goto exit;
            }

            pIssuer = ASN1_FIRST_CHILD(pIssuerAndSerialNumber);
            pSerialNumber = ASN1_NEXT_SIBLING(pIssuer);

            status = getCertFun(callbackArg,
                                s, pSerialNumber, pIssuer,
                                &externalCert,
                                &externalCertLen);
            if (OK > status )
            {
                goto exit;
            }
        }
        else if (3 == version)
        {
            status = ASN1_GetNthChild(pSignerInfo, 2, &pSubjectKeyIdentifier);
            if (OK != status)
            {
                status = ERR_PKCS7_INVALID_STRUCT;
                goto exit;
            }

            status = getCertFunV3(callbackArg, s, pSubjectKeyIdentifier,
                &externalCert, &externalCertLen);
            if (OK > status )
            {
                goto exit;
            }
        }
        else
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }

        if (externalCert || externalCertLen)
        {
            MF_attach(&externalCertMF, externalCertLen, externalCert);
            CS_AttachMemFile(&certCS, &externalCertMF);

            if (OK > (status = X509_parseCertificate(certCS, &pRootItem)))
            {
                goto exit;
            }

            pSignerInfoCertificate = ASN1_FIRST_CHILD(pRootItem);
        }
    }

    if (pSignerInfoCertificate)
    {
        if ( OK > (status =
                   PKCS7_ProcessSignerInfoWithCert(MOC_ASYM(hwAccelCtx) s,
                                                   pSignerInfo,
                                                   certCS,
                                                   pSignerInfoCertificate,
                                                   ASN1_FIRST_CHILD(pContentInfo),
                                                   numHashes, pSignedDataHash,
                                                   pSigInfo)))
        {
            goto exit;
        }
        if (OK > PKCS7_ValidateCertificate(MOC_ASYM(hwAccelCtx)
                                           certCS, pSignerInfoCertificate,
                                           s, pCertificates,
                                           callbackArg, valCertFun, isCmsValCert))
        {
            /* everything OK except cert not validated */
            status = ERR_PKCS7_UNKNOWN_CERTIFICATE_AUTHORITY;
        }
    }
    else
    {
        status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
        goto exit;
    }

exit:

    if (NULL != externalCert)
    {
       FREE(externalCert);
    }

    if (pRootItem)
    {
        TREE_DeleteTreeItem((TreeItem*) pRootItem);
    }

    return status;
}



/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_VerifySignatures(MOC_ASYM(hwAccelDescr hwAccelCtx)
                       ASN1_ITEMPTR pSignedData, ASN1_ITEMPTR pContentInfo,
                       CStream s, ubyte4 numHashes,
                       SignedDataHash* pSignedDataHash,
                       const void* callbackArg,
                       PKCS7_GetCertificate getCertFun,
                       PKCS7_GetCertificateVersion3 getCertFunV3,
                       void *valCertFun,
                       byteBoolean isCmsValCert,
                       ubyte4* pNumSigners, PKCS7_SignatureInfo **ppSigInfos,
                       const void *pResignData)
{
    MSTATUS status;
    ASN1_ITEMPTR pCertificates;
    ASN1_ITEMPTR pSignerInfos, pSignerInfo, pNextSibling;
    ubyte4 numSigners, numValidSigners = 0;
    PKCS7_SignatureInfo* pSigInfos = 0;
	ubyte4 totalSignatures = 0;
#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    CStream certificatesStream = s;
#endif
    /* now go to the certificates part if any/need to validate which one we accept */
    /* certificates is an optional part with tag [0] MOC_SET or [2] SEQUENCE */
    if (OK > (status = ASN1_GetChildWithTag(pSignedData, 0, &pCertificates)))
        goto exit;

    if ( 0 == pCertificates)
    {
        ASN1_GetChildWithTag( pSignedData, 2, &pCertificates);
    }

    /* now go to the signer Info: this is the last child of the sequence */
    pSignerInfos = ASN1_NEXT_SIBLING( pContentInfo);
    if ( 0 == pSignerInfos)
    {
        /* must be at least one */
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pNextSibling = ASN1_NEXT_SIBLING( pSignerInfos);
    /* if the last child is EOC, it is the second to last child */
    while ( pNextSibling &&
        !(pNextSibling->tag == 0 && pNextSibling->id == 0 && pNextSibling->length==0))
    {
        pSignerInfos = pNextSibling;
        pNextSibling = ASN1_NEXT_SIBLING( pSignerInfos);
    }

    if ( OK > ASN1_VerifyType( pSignerInfos, SEQUENCE) &&
        OK > ASN1_VerifyType( pSignerInfos, MOC_SET))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_RE_SIGNER__

    CMS_ResignData_CTX RSCtx = (CMS_ResignData_CTX)pResignData;  /* Copy of the ptr, don't free it.*/
    if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
    {
        if (NULL != pCertificates)
        {
            ubyte* pCerts = NULL;
            ubyte4 certLen = 0;
            ASN1_ITEMPTR pParent = ASN1_PARENT(pCertificates);

            /* Get data inside TAG/SETOF */
            if (OK > (status = CS_seek(certificatesStream, pParent->dataOffset, MOCANA_SEEK_SET)))
            {
                goto exit;
            }

            pCerts = (ubyte *) MALLOC(pParent->length);
            if (!pCerts)
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            certLen = pParent->length;

            if (OK > (status = CS_read(pCerts, certLen, 1, certificatesStream)))
            {
                FREE(pCerts);
                goto exit;
            }

            /* Copy certificates found in CMS */
            status = CMS_RESIGN_setExtractedCertificates (RSCtx, pCerts, certLen);
            FREE(pCerts);
            if (OK != status)
                goto exit;
        }

        /* Save the signature block here when we are re-signing */
        if (OK > (status = CS_seek(s, pSignerInfos->dataOffset, MOCANA_SEEK_SET)))
        {
            goto exit;
        }

        ubyte *sig = (ubyte *) MALLOC(pSignerInfos->length);
        if (!sig)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        if (OK > (status = CS_read(sig, pSignerInfos->length, 1, s)))
        {
            FREE(sig);
            goto exit;
        }

        status = CMS_RESIGN_setExtractedSignature(RSCtx, sig, pSignerInfos->length);
        if (OK > status)
        {
            FREE(sig);
            goto exit;
        }

        FREE(sig);

    }

#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

    /* if the caller requested an array with the signer infos, allocate it */
    if (ppSigInfos)
    {
        numSigners = PKCS7_getNumberChildren( pSignerInfos);
        pSigInfos = (PKCS7_SignatureInfo*) MALLOC( numSigners * sizeof (PKCS7_SignatureInfo));
        if (!pSigInfos)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    /* go through all of them to see which signer we accept */
    pSignerInfo = ASN1_FIRST_CHILD( pSignerInfos);

    totalSignatures = 0;
    while (pSignerInfo)
    {
        /* ignore end-of-content octets (for interop with Symantec) */
        if(0 != pSignerInfo->tag || 0 != pSignerInfo->length)
        {
            ++totalSignatures;
            status = PKCS7_ProcessSignerInfo(MOC_ASYM(hwAccelCtx)
                                             pContentInfo, pSignerInfo,
                                             pCertificates, s,
                                             numHashes, pSignedDataHash,
                                             (pSigInfos) ? pSigInfos + numValidSigners : NULL,
                                             callbackArg, getCertFun, getCertFunV3, valCertFun, isCmsValCert);
            if (OK == status)
            {
                ++numValidSigners;
            }
            else if (ERR_PKCS7_UNKNOWN_CERTIFICATE_AUTHORITY != status &&
                     ERR_PKCS7_NO_CERT_FOR_SIGNER != status)
            {
                break; /* fatal error */
            }
        }
        pSignerInfo = ASN1_NEXT_SIBLING( pSignerInfo);
    }

    if (numValidSigners != totalSignatures && OK == status)
    {
        status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
    }

    *pNumSigners = numValidSigners;
    if (ppSigInfos)
    {
        *ppSigInfos = pSigInfos;
    }
    pSigInfos = 0;

exit:
    if (pSigInfos)
        FREE(pSigInfos);

    return status;
}

/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS7_VerifySignedData(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         ASN1_ITEM* pSignedData, CStream s,
                       /* getCertFun can be NULL, if certificates
                        * are included in signedData
                       */
                         const void* callbackArg,
                         PKCS7_GetCertificate getCertFun,
                         PKCS7_ValidateRootCertificate valCertFun,
                         const ubyte* payLoad, /* for detached signatures */
                         ubyte4 payLoadLen,
                         sbyte4* numKnownSigners)
{
    return PKCS7_VerifySignedDataV3(MOC_ASYM(hwAccelCtx) pSignedData, s, callbackArg, getCertFun, NULL,
                                    valCertFun, payLoad, payLoadLen, numKnownSigners);
}

/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS7_VerifySignedDataV3(MOC_ASYM(hwAccelDescr hwAccelCtx)
                         ASN1_ITEM* pSignedData, CStream s,
                       /* getCertFun can be NULL, if certificates
                        * are included in signedData
                       */
                         const void* callbackArg,
                         PKCS7_GetCertificate getCertFun,
                         PKCS7_GetCertificateVersion3 getCertFunV3,
                         PKCS7_ValidateRootCertificate valCertFun,
                         const ubyte* payLoad, /* for detached signatures */
                         ubyte4 payLoadLen,
                         sbyte4* numKnownSigners)
{
    /*
    SignedData ::= SEQUENCE {
          version         INTEGER {sdVer1(1), sdVer2(2)} (sdVer1 | sdVer2),
          digestAlgorithms
                          DigestAlgorithmIdentifiers,
          contentInfo     ContentInfo,
          certificates CHOICE {
            certSet       [0] IMPLICIT ExtendedCertificatesAndCertificates,
            certSequence  [2] IMPLICIT Certificates
          } OPTIONAL,
          crls CHOICE {
            crlSet        [1] IMPLICIT CertificateRevocationLists,
            crlSequence   [3] IMPLICIT CRLSequence
          } OPTIONAL,
          signerInfos     SignerInfos
        } (WITH COMPONENTS { ..., version (sdVer1),
             digestAlgorithms   (WITH COMPONENTS { ..., daSet PRESENT }),
             certificates       (WITH COMPONENTS { ..., certSequence ABSENT }),
             crls               (WITH COMPONENTS { ..., crlSequence ABSENT }),
             signerInfos        (WITH COMPONENTS { ..., siSet PRESENT })
           } |
           WITH COMPONENTS { ..., version (sdVer2),
              digestAlgorithms  (WITH COMPONENTS { ..., daSequence PRESENT }),
              certificates      (WITH COMPONENTS { ..., certSet ABSENT }),
              crls              (WITH COMPONENTS { ..., crlSet ABSENT }),
              signerInfos       (WITH COMPONENTS { ..., siSequence PRESENT })
        })
    */

    static WalkerStep gotoPKCS7ContentInfoToContent[] =
    {
        { GoNthChild, 2, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };

    ASN1_ITEMPTR pVersion;
    ASN1_ITEMPTR pDigestAlgorithms;
    ASN1_ITEMPTR pContentInfo;

    ASN1_ITEMPTR pContent;
    ubyte* toHash;

    /* we will compute multiple hashes possibly */
    ubyte4 i, numHashes = 0;
    SignedDataHash* pSignedDataHash = 0;
    ubyte *pTempBuf = 0;
    MSTATUS status = OK;

    *numKnownSigners = 0;

    pVersion = ASN1_FIRST_CHILD( pSignedData);
    if ( 0 == pVersion)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pDigestAlgorithms = ASN1_NEXT_SIBLING( pVersion);
    if ( 0 == pDigestAlgorithms)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }
    pContentInfo = ASN1_NEXT_SIBLING( pDigestAlgorithms);
    if ( 0 == pContentInfo)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    if (OK > ( status = PKCS7_CollectHashAlgos(MOC_HASH(hwAccelCtx)
                                                pDigestAlgorithms, s,
                                                &numHashes, &pSignedDataHash)))
    {
        goto exit;
    }

    if (numHashes)
    {
        status = ASN1_WalkTree( pContentInfo, s, gotoPKCS7ContentInfoToContent,
                                    &pContent);
        if (OK == status)
        {
            if (pContent->indefinite && ASN1_FIRST_CHILD(pContent))
            {
                ASN1_ITEMPTR pTemp;

                /* NOTE:The PKCS#7 EncryptedContent is specified as an octet string, but
                * SCEP entities must also accept a sequence of octet strings as a valid
                * alternate encoding.
                * This alternate encoding must be accepted wherever PKCS #7 Enveloped
                * Data is specified in this document.
                */
                pTemp = ASN1_FIRST_CHILD(pContent);
                /* accumulate octetstring content until reaching EOC */
                while (pTemp->length > 0)
                {
                    toHash = (ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
                    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, pTemp->length, TRUE, &pTempBuf)))
                        goto exit;
                    DIGI_MEMCPY(pTempBuf, toHash, pTemp->length);
                    for (i = 0; i < numHashes; ++i)
                    {
                        pSignedDataHash[i].hashAlgo->updateFunc( MOC_HASH(hwAccelCtx)
                                                            pSignedDataHash[i].bulkCtx,
                                                            pTempBuf, pTemp->length);
                    }
                    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
                    pTempBuf = NULL;
                    pTemp = ASN1_NEXT_SIBLING(pTemp);
                    CS_stopaccess( s, toHash);
                }
            }
            else
            {
                toHash = (ubyte*) CS_memaccess( s, pContent->dataOffset, pContent->length);
                if (pContent->length > 0)
                {
                    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, pContent->length, TRUE, &pTempBuf)))
                        goto exit;

                    DIGI_MEMCPY(pTempBuf, toHash, pContent->length);
                }
                for (i = 0; i < numHashes; ++i)
                {
                    pSignedDataHash[i].hashAlgo->updateFunc( MOC_HASH(hwAccelCtx)
                                                           pSignedDataHash[i].bulkCtx,
                                                           pTempBuf, pContent->length);
                }

                CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
                pTempBuf = NULL;
                CS_stopaccess( s, toHash);
            }
        }
        else
        {
            /* external signature. content should be provided in payLoad */
            if (payLoad && payLoadLen > 0)
            {
#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
                pTempBuf = payLoad;
#else
                if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, payLoadLen, TRUE, &pTempBuf)))
                    goto exit;

                DIGI_MEMCPY(pTempBuf, payLoad, payLoadLen);
#endif
                for (i = 0; i < numHashes; ++i)
                {
                    pSignedDataHash[i].hashAlgo->updateFunc( MOC_HASH(hwAccelCtx)
                                                           pSignedDataHash[i].bulkCtx,
                                                           pTempBuf, payLoadLen);

                }
#ifndef __DISABLE_DIGICERT_HARDWARE_ACCEL__
                CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
#endif
                pTempBuf = NULL;
            } else
            {
                status = ERR_PKCS7_NO_CONTENT;
                goto exit;
            }
        }

        for (i = 0; i < numHashes; ++i)
        {
            pSignedDataHash[i].hashAlgo->finalFunc( MOC_HASH(hwAccelCtx)
                                                    pSignedDataHash[i].bulkCtx,
                                                    pSignedDataHash[i].hashData);

        }
    }
    else if ( ASN1_FIRST_CHILD(pDigestAlgorithms))
    {
        /* there were some hashes but we didn't recognize/support any! */
        status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
        goto exit;
    }

    if (OK > (status = PKCS7_VerifySignatures( MOC_ASYM(hwAccelCtx)
                                              pSignedData, pContentInfo, s,
                                              numHashes, pSignedDataHash,
                                              callbackArg,
                                              getCertFun, getCertFunV3, (void *) valCertFun, FALSE,
                                              (ubyte4*)numKnownSigners, NULL, NULL)))
    {
        goto exit;
    }

exit:
    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    if (numHashes)
        PKCS7_DestructHashes(MOC_HASH(hwAccelCtx) numHashes, &pSignedDataHash);

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetIssuerSerialNumber( ASN1_ITEMPTR pIssuerSerialNumber,
                            CMSIssuerSerialNumber* pISN)
{
/*
  IssuerAndSerialNumber ::= SEQUENCE {
     issuer Name,
     serialNumber CertificateSerialNumber }
*/

    pISN->pIssuer = ASN1_FIRST_CHILD( pIssuerSerialNumber);
    if (!pISN->pIssuer || OK > ASN1_VerifyType( pISN->pIssuer, SEQUENCE))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pISN->pSerialNumber = ASN1_NEXT_SIBLING( pISN->pIssuer);
    if (!pISN->pSerialNumber)
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }
    return OK;
}


/*--------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__

static MSTATUS
PKCS7_GetOriginatorPublicKey( ASN1_ITEMPTR pSequence,
                              CMSOriginatorPublicKey* pOriginatorKey)
{
    ASN1_ITEMPTR pTemp;
    CStream dummyStream = {0, 0}; /* the walk steps will not access the stream */
/*
  OriginatorPublicKey ::= SEQUENCE {
     algorithm AlgorithmIdentifier,
     publicKey BIT STRING }
  AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm   OBJECT IDENTIFIER,
     parameters  ANY DEFINED BY algorithm OPTIONAL  }
*/
    static WalkerStep walkInstructions1[] =
    {
        { VerifyType, SEQUENCE, 0 },
        { GoFirstChild, 0, 0},    /* version */
        { VerifyType, SEQUENCE, 0 },
        { GoFirstChild, 0, 0 },
        { VerifyType, OID, 0 },
        { Complete, 0, 0}
    };
    static WalkerStep walkInstructions2[] =
    {
        { GoParent, 0, 0 },
        { GoNextSibling, 0, 0},    /* version */
        { VerifyType, BITSTRING, 0 },
        { Complete, 0, 0}
    };

    if (OK > ASN1_WalkTree( pSequence, dummyStream, walkInstructions1, &pTemp))
        return ERR_PKCS7_INVALID_STRUCT;

    pOriginatorKey->pAlgoOID = pTemp;

    pTemp = ASN1_NEXT_SIBLING(pTemp);

    if (!pTemp) { return ERR_PKCS7_INVALID_STRUCT; }

    pOriginatorKey->pAlgoParameters = pTemp;

    if (OK > ASN1_WalkTree( pTemp, dummyStream, walkInstructions2, &pTemp))
        return ERR_PKCS7_INVALID_STRUCT;

    pOriginatorKey->pPublicKey = pTemp;

    return OK;
}

#endif

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessRSARecipientKeyInfo(ASN1_ITEMPTR  pKeyTransRecipientInfo,
                                 CStream       inputStream,
                                 intBoolean*   pIsOaep,
                                 ubyte*        pHashId,
                                 ubyte**       ppLabel,
                                 ubyte4*       pLabelLen)
{
    MSTATUS         status = OK;
    ASN1_ITEMPTR    pKeyEncryptionAlgorithmIdentifier = NULL;
    ASN1_ITEMPTR    pKeyEncryptionAlgorithmOid = NULL;
    ASN1_ITEMPTR    pRsaesOaepParams = NULL;
    ASN1_ITEMPTR    pTag = NULL;
    ASN1_ITEMPTR    pHashAlgoParams = NULL;
    ASN1_ITEMPTR    pMgfAlgorithmIdentifier = NULL;
    ASN1_ITEMPTR    pMgfAlgorithmOid = NULL;
    ASN1_ITEMPTR    pSourceAlgorithmIdentifier = NULL;
    ASN1_ITEMPTR    pSourceAlgorithmOid = NULL;
    ASN1_ITEMPTR    pMessageLabel = NULL;
    ubyte4          tagValue = 0;
    intBoolean      processedMaskGenAlgoTag = FALSE;
    intBoolean      processedSourceAlgoTag = FALSE;
    ubyte4          i = 0;
    ubyte4          rsaHashAlgoIndex = 0; /* If no OAEP parameters sha1 is the default! Not our build default */

    /* Internal method, NULL checks not necc */
    *pIsOaep = FALSE;

    /* Extract the key encryption algorithm identifier from the recipient info for examination */
    status = ASN1_GetNthChild(pKeyTransRecipientInfo, 3, &pKeyEncryptionAlgorithmIdentifier);
    if (OK != status)
        goto exit;

    status = ASN1_VerifyType(pKeyEncryptionAlgorithmIdentifier, SEQUENCE);
    if (OK != status)
        goto exit;

    pKeyEncryptionAlgorithmOid = ASN1_FIRST_CHILD(pKeyEncryptionAlgorithmIdentifier);

    /* check for oaep */
    status = ASN1_VerifyOID(pKeyEncryptionAlgorithmOid, inputStream, rsaEsOaep_OID);
    if (OK == status)
    {
        /* We look for the following asn1 structure

        SEQUENCE (2 elem)
            rsaOAEP OID 
            SEQUENCE (3 elem)
                [0] Hash Algorithm
                    SEQUENCE (2 elem)
                        hash OID
                        NULL
                [1] MGF algorithm
                    SEQUENCE (2 elem)
                        mgf OID
                        SEQUENCE (2 elem)
                            hash OID
                            NULL
                [2] Source algorithm
                    SEQUENCE (2 elem)
                        rsaOAEP-pSpecified OID
                        OCTET STRING (0 elem)
        */

        pRsaesOaepParams = ASN1_NEXT_SIBLING(pKeyEncryptionAlgorithmOid);
        if (NULL == pRsaesOaepParams)
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }

        status = ASN1_VerifyType(pRsaesOaepParams, SEQUENCE);
        if (OK != status)
            goto exit;

        /* Check to see if explicit parameters have been specified.
           If they are not then default parameters will be used.
        */
        pTag = ASN1_FIRST_CHILD(pRsaesOaepParams);

        /* Process all explicitly specified RSAES-OAEP parameters */
        while (NULL != pTag)
        {
            /* Extract the parameter tag and verify the sequence tag */
            status = ASN1_GetTag(pTag, &tagValue);
            if (OK != status)
                goto exit;

            status = ASN1_VerifyType(ASN1_FIRST_CHILD(pTag), SEQUENCE);
            if (OK != status)
                goto exit;

            switch (tagValue)
            {
                case RSA_OAEP_PARAMS_HASH_ALGO_TAG:
                {
                    /* Verify that other algorithm parameters haven't appeared first
                       (validates that they follow a SEQUENCE and not a MOC_SET) */
                    if (processedMaskGenAlgoTag)
                    {
                        status = ERR_PKCS7_INVALID_TAG_VALUE;
                        break;
                    }

                    if (processedSourceAlgoTag)
                    {
                        status = ERR_PKCS7_INVALID_TAG_VALUE;
                        break;
                    }

                    /* get the hash alorithm */
                    pHashAlgoParams = ASN1_FIRST_CHILD(pTag);

                    for (i = 0; i < RSA_OAEP_NUM_HASH_ALGOS; i++)
                    {
                        status = ASN1_VerifyOID(ASN1_FIRST_CHILD(pHashAlgoParams), inputStream, gRsaHashTable[i].pHashOid);
                        if (OK == status)
                        {
                            rsaHashAlgoIndex = i;
                            break;
                        }
                    }

                    if (RSA_OAEP_NUM_HASH_ALGOS == i)
                    {
                        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                    }

                    /* We don't care whether the NULL tag is there or not.
                       There's no need to test that it's there and valid. */
                    break;
                }

                case RSA_OAEP_PARAMS_MASK_GEN_ALGO_TAG:
                {
                    /* Verify that other algorithm parameters haven't appeared first
                       (validates that they follow a SEQUENCE and not a MOC_SET) */
                    if (processedSourceAlgoTag)
                    {
                        status = ERR_PKCS7_INVALID_TAG_VALUE;
                        break;
                    }

                    /* extract mgf oid */
                    pMgfAlgorithmIdentifier = ASN1_FIRST_CHILD(pTag);
                    pMgfAlgorithmOid        = ASN1_FIRST_CHILD(pMgfAlgorithmIdentifier);

                    status = ASN1_VerifyOID(pMgfAlgorithmOid, inputStream, pkcs1Mgf_OID);
                    if (OK != status)
                    {
                        break;
                    }

                    /* extract hash id for the mgf */
                    pHashAlgoParams = ASN1_NEXT_SIBLING(pMgfAlgorithmOid);
                    if (NULL == pHashAlgoParams)
                    {
                        status = ERR_PKCS7_INVALID_STRUCT;
                        break;
                    }

                    for (i = 0; i < RSA_OAEP_NUM_HASH_ALGOS; i++)
                    {
                        status = ASN1_VerifyOID(ASN1_FIRST_CHILD(pHashAlgoParams), inputStream, gRsaHashTable[i].pHashOid);
                        if (OK == status)
                        {
                            /* We do not support the mgf hash being different than the oaep hash */
                            if (i != rsaHashAlgoIndex)
                            {
                                status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                            }
                            break;
                        }
                    }

                    if (RSA_OAEP_NUM_HASH_ALGOS == i)
                    {
                        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
                        break;
                    }

                    processedMaskGenAlgoTag = TRUE;
                    break;
                }

                case RSA_OAEP_PARAMS_SOURCE_ALGO_TAG:
                {
                    /* Extract source algorithm identifier and verify that
                       it matches our only supported algorithm: pSpecified */

                    pSourceAlgorithmIdentifier  = ASN1_FIRST_CHILD(pTag);
                    pSourceAlgorithmOid         = ASN1_FIRST_CHILD(pSourceAlgorithmIdentifier);

                    status = ASN1_VerifyOID(pSourceAlgorithmOid, inputStream, pSpecified_OID);
                    if (OK != status)
                        break;
                    
                    /* extract the message label */
                    pMessageLabel = ASN1_NEXT_SIBLING(pSourceAlgorithmOid);

                    if (NULL == pMessageLabel)
                    {
                        status = ERR_PKCS7_INVALID_STRUCT;
                        break;
                    }

                    status = ASN1_VerifyType(pMessageLabel, OCTETSTRING);
                    if (OK != status)
                        break;

                    if (pMessageLabel->length)
                    {
                        *ppLabel = (ubyte *)CS_memaccess(inputStream, pMessageLabel->dataOffset, pMessageLabel->length);
                        if (NULL == *ppLabel)
                        {
                            status = ERR_PKCS7_INVALID_STRUCT;
                            break;
                        }

                        *pLabelLen = pMessageLabel->length;
                    }

                    processedSourceAlgoTag = TRUE;
                    break;
                }

                default:
                {
                    status = ERR_PKCS7_INVALID_TAG_VALUE;
                    break;
                }
            }

            if (OK != status)
                goto exit;

            pTag = ASN1_NEXT_SIBLING(pTag);
        }

        /* Set remaining RSAES-OAEP parameters now that parsing is complete */
        *pIsOaep     = TRUE;
        *pHashId  = gRsaHashTable[rsaHashAlgoIndex].hashId;
    }
#if !defined(__DISABLE_DIGICERT_CMS_RSA_PKCS15_DECRYPT__)
    else
    {
        /* Not RSAES-OAEP. Sanity check if it's regular PKCS#1 v1.5 RSA */
        status = ASN1_VerifyOID(pKeyEncryptionAlgorithmOid, inputStream, rsaEncryption_OID);
    }
#endif

exit:

    return status;
}

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessKeyTransRecipientInfo(MOC_RSA(hwAccelDescr hwAccelCtx)
                                   ASN1_ITEMPTR pKeyTransRecipientInfo, CStream s,
                                   const void* callbackArg,
                                   PKCS7_GetPrivateKey getPrivateKeyFun,
                                   CMS_GetPrivateKey getPrivateKeyFunEx,
                                   ubyte** ppSymmetricKey, ubyte4* pSymmetricKeyLen)
{
    MSTATUS         status;
    ubyte4          accessFlag;
    AsymmetricKey   asymmetricKey;
    ubyte*          pSymmetricKey = 0;
    CMSRecipientId  recipientId;
    ASN1_ITEMPTR    pRecipientIdentifier;
    ASN1_ITEMPTR    pEncryptedKey;
    ASN1_ITEMPTR    pTemp;
    ubyte*          cipherText;
    sbyte4          cipherMaxLen;
    RSAKey*         pRSAKey = NULL;
    intBoolean      isOaep = FALSE;
    ubyte           rsaHashAlgoId = 0;
    ubyte*          pLabel = NULL;
    ubyte4          labelLen = 0;

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    MocAsymKey      pMocAsymKey = NULL;
#endif
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
#if (!defined (__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    MKeyOperatorData    decryptInfo;
    MKeyOperatorBuffer  bufferReturn;
#endif
#endif

    accessFlag = 0;

    if (OK > ( status = CRYPTO_initAsymmetricKey( &asymmetricKey)))
        goto exit;

    /*   KeyTransRecipientInfo ::= SEQUENCE {
     *     version CMSVersion,  -- always set to 0 or 2
     *     rid RecipientIdentifier,
     *     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     *     encryptedKey EncryptedKey }
     *
     *   RecipientIdentifier ::= CHOICE {
     *     issuerAndSerialNumber IssuerAndSerialNumber,
     *     subjectKeyIdentifier [0] SubjectKeyIdentifier }
     */
    status = ASN1_GetNthChild( pKeyTransRecipientInfo, 2, &pRecipientIdentifier);
    if ( status < OK) goto exit;

    recipientId.type = NO_TAG;

    if (OK <= ASN1_VerifyType( pRecipientIdentifier, SEQUENCE))
    {
        /* pTemp = issuer and serial number */
        if (OK > PKCS7_GetIssuerSerialNumber(pRecipientIdentifier,
                    &recipientId.ri.ktrid.u.issuerAndSerialNumber))
        {
            goto exit;
        }
        recipientId.ri.ktrid.type = NO_TAG;
    }
    else if (OK <= ASN1_GetTag( pRecipientIdentifier, &recipientId.ri.ktrid.type) &&
                0 == recipientId.ri.ktrid.type)
    {
        /* temp's 1st child = subject key identifier */
        pTemp = ASN1_FIRST_CHILD( pRecipientIdentifier);
        if (OK >  ASN1_VerifyType( pTemp, OCTETSTRING))
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }
        recipientId.ri.ktrid.u.subjectKeyIdentifier = pTemp;
    }
    else
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    if (getPrivateKeyFun && NO_TAG == recipientId.ri.ktrid.type)
    {
        if ( OK > (*getPrivateKeyFun)(callbackArg, s,
                    recipientId.ri.ktrid.u.issuerAndSerialNumber.pSerialNumber,
                    recipientId.ri.ktrid.u.issuerAndSerialNumber.pIssuer,
                    &asymmetricKey))
        {
            status = ERR_FALSE;
            goto exit;
        }
    }
    else if (getPrivateKeyFunEx)
    {
        if ( OK > (*getPrivateKeyFunEx)(callbackArg, s, &recipientId,
                                        &asymmetricKey))
        {
            status = ERR_FALSE;
            goto exit;
        }
    }
    else
    {
        status = ERR_PKCS7_WRONG_CALLBACK;
        goto exit;
    }

    /* Get the encrypted symmetric key
     */
    status =  ASN1_GetNthChild (pKeyTransRecipientInfo, 4, &pEncryptedKey);
    if (OK != status)
        goto exit;

    status = ERR_MEM_ALLOC_FAIL;
    cipherText = (ubyte *)CS_memaccess (s, pEncryptedKey->dataOffset, pEncryptedKey->length);
    if (NULL == cipherText)
        goto exit;

    accessFlag = 1;
    cipherMaxLen = pEncryptedKey->length;

    /* We need an RSA key, but it might be a MocAsym key.
     */
    if (akt_rsa == asymmetricKey.type || akt_tap_rsa == asymmetricKey.type)
    {
        pRSAKey = asymmetricKey.key.pRSA;

        /* For RSA determine if it's pkcs1.5 or oaep padding */
        status = PKCS7_ProcessRSARecipientKeyInfo(pKeyTransRecipientInfo, s, &isOaep, &rsaHashAlgoId, &pLabel, &labelLen);
        if (OK != status)
            goto exit;

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if (akt_tap_rsa == asymmetricKey.type && !isOaep)
        {
            pMocAsymKey = asymmetricKey.key.pMocAsymKey;
        }
#endif
    }
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    else if (akt_moc == asymmetricKey.type)
    {
        pMocAsymKey = asymmetricKey.key.pMocAsymKey;
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    if (!isOaep)
    {
        status = DIGI_MALLOC ((void **)&pSymmetricKey, cipherMaxLen);
        if (OK != status)
            goto exit;
    }
    /* Decrypt the encrypted symmetric key with the key we have.
     */
    if (NULL != pRSAKey)
    {
#if (!defined(__DISABLE_DIGICERT_RSA__) && !defined(__DISABLE_DIGICERT_RSA_DECRYPTION__))

        if (isOaep)
        {
#if defined(__ENABLE_DIGICERT_PKCS1__)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt(MOC_RSA(hwAccelCtx) pRSAKey, rsaHashAlgoId, MOC_PKCS1_ALG_MGF1, rsaHashAlgoId, cipherText,
                                                           cipherMaxLen, labelLen ? (const ubyte *) pLabel : NULL, labelLen, &pSymmetricKey, pSymmetricKeyLen);
#else
            status = PKCS1_rsaesOaepDecrypt(MOC_RSA(hwAccelCtx) pRSAKey, rsaHashAlgoId, PKCS1_MGF1, cipherText, cipherMaxLen,
                                            labelLen ? (const ubyte *) pLabel : NULL, labelLen, &pSymmetricKey, pSymmetricKeyLen);
#endif
#else
            status = ERR_RSA_DISABLED;
#endif
        }
        else
        {
#if !defined(__DISABLE_DIGICERT_CMS_RSA_PKCS15_DECRYPT__)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_decrypt (MOC_RSA (hwAccelCtx) pRSAKey, cipherText, pSymmetricKey, pSymmetricKeyLen, NULL, 0, NULL, akt_rsa);
#else
            status = RSA_decrypt (MOC_RSA (hwAccelCtx) pRSAKey, cipherText, pSymmetricKey, pSymmetricKeyLen, NULL, 0, NULL);
#endif
#else
            status = ERR_RSA_INVALID_PKCS1_V1P5;
#endif
        }
        if (OK != status)
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    else if (akt_tap_rsa == asymmetricKey.type && !isOaep) /* sanity check on isOaep */
    {
#if !defined(__DISABLE_DIGICERT_RSA__)
        if (OK != (status = CRYPTO_INTERFACE_RSA_decrypt(MOC_RSA (hwAccelCtx) pMocAsymKey, cipherText,
                        pSymmetricKey, pSymmetricKeyLen,
                        NULL, 0, NULL,
                        asymmetricKey.type)))
        {
            goto exit;
        }
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#else /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    else if(akt_moc == asymmetricKey.type && !isOaep)
    {
        decryptInfo.pData = cipherText;
        decryptInfo.length = cipherMaxLen;
        bufferReturn.pBuffer = pSymmetricKey;
        bufferReturn.bufferSize = cipherMaxLen;
        bufferReturn.pLength = pSymmetricKeyLen;
        status = pMocAsymKey->KeyOperator (
                pMocAsymKey, NULL, MOC_ASYM_OP_DECRYPT, (void *)&decryptInfo,
                (void *)&bufferReturn, NULL);
        if (OK != status)
            goto exit;
    }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    else 
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;     
    }
#endif /* #if (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

    *ppSymmetricKey = pSymmetricKey;
    pSymmetricKey = NULL;

exit:

    if (0 != accessFlag)
    {
      CS_stopaccess (s, cipherText);
    }

    CRYPTO_uninitAsymmetricKey (&asymmetricKey, NULL);

    if (NULL != pSymmetricKey)
    {
        DIGI_FREE ((void **)&pSymmetricKey);
    }

    return status;
}


#ifdef __ENABLE_DIGICERT_ECC__
/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessKeyAgreeRecipientInfo(MOC_HW(hwAccelDescr hwAccelCtx)
                                   ASN1_ITEMPTR pRecipientInfo, CStream s,
                                   const void* callbackArg,
                                   PKCS7_GetPrivateKey getPrivateKeyFun,
                                   CMS_GetPrivateKey getPrivateKeyFunEx,
                                   ubyte** ppSymmetricKey,
                                   ubyte4* pSymmetricKeyLen)
{
    MSTATUS status;
    AsymmetricKey privateKey = {0};
    AsymmetricKey ephemeralKey = {0};
    ASN1_ITEMPTR pTemp, pTemp1, pEncryptedKey, pUKM;
    ASN1_ITEMPTR pECCBitString, pKeyEncryptionAlgo;
    CMSRecipientId recipientId;
    const ubyte* ukmData = 0;
    ubyte4 ukmLen = 0;
    const ubyte* point = 0;
    const ubyte* keyWrapOID = 0;
    const ubyte* encryptedKey = 0;
    const BulkHashAlgo* pHashAlgo;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4 eccCurveId;
    ECCKey *pKey = NULL;
#endif

    static WalkerStep ecPublicKeyBitStringWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},    /* version */
        { VerifyInteger, 3, 0},   /* must always be 3 */
        { GoNextSibling, 0, 0},   /* OriginatorIdentifierOrKey */
        { VerifyTag, 0, 0 },      /* [0] */
        { GoFirstChild, 0, 0 },
        { VerifyTag, 1, 0 },      /* [1] -> originatorKey */
        { GoFirstChild, 0, 0 },
        { VerifyType, SEQUENCE, 0 },
        { GoFirstChild, 0, 0 },
        { VerifyOID, 0, (ubyte*) ecPublicKey_OID },
        { GoParent, 0, 0 },
        { GoNextSibling, 0, 0 },
        { VerifyType, BITSTRING, 0 },
        { Complete, 0, 0}
    };

    if (OK > ( status = CRYPTO_initAsymmetricKey( &privateKey)))
        goto exit;

    if (OK > ( status = CRYPTO_initAsymmetricKey( &ephemeralKey)))
        goto exit;

    if (OK > ( status = ASN1_WalkTree(pRecipientInfo, s,
             ecPublicKeyBitStringWalkInstructions, &pECCBitString)))
    {
        goto exit;
    }

    /* check if there's an ukm present */
    if (OK > ( status = ASN1_GetChildWithTag( pRecipientInfo, 1, &pUKM)))
    {
        goto exit;
    }

    /* !!!!!!!!!!! default status for exit !!!!!!!!!!!!!!!*/
    status = ERR_PKCS7_INVALID_STRUCT;

    if ( OK > ASN1_GetNthChild( pRecipientInfo, pUKM ? 4 : 3, &pKeyEncryptionAlgo))
    {
        goto exit;
    }

    pTemp1 = ASN1_NEXT_SIBLING( pKeyEncryptionAlgo);
    if ( !pTemp1)
    {
        goto exit;
    }

    /* pTemp1 is the last child: recipientEncryptedKeys */
    pTemp1 = ASN1_FIRST_CHILD( pTemp1);
    if (!pTemp1)
    {
        goto exit;
    }

    /* pTemp1 -> recipientEncryptedKey */
    pTemp1 = ASN1_FIRST_CHILD( pTemp1);
    if (!pTemp1)
    {
        goto exit;
    }

    recipientId.type = 1;

    if (OK <= ASN1_VerifyType( pTemp1, SEQUENCE))
    {
        /* pTemp1 is IssuerAndSerialNumber */
        if (OK > PKCS7_GetIssuerSerialNumber(pTemp1,
                    &recipientId.ri.karid.u.issuerAndSerialNumber))
        {
            goto exit;
        }
        recipientId.ri.karid.type = NO_TAG;
    }
    else if ( OK <= ASN1_GetTag( pTemp1, &recipientId.ri.karid.type))
    {
        pTemp = ASN1_FIRST_CHILD( pTemp1);
        if (!pTemp)
        {
            goto exit;
        }

        if ( 0 == recipientId.ri.karid.type)
        {
            if (OK > ASN1_VerifyType( pTemp, OCTETSTRING))
            {
                goto exit;
            }
            recipientId.ri.karid.u.subjectKeyIdentifier = pTemp;
        }
        else if ( 1 ==recipientId.ri.karid.type)
        {
            if (OK > PKCS7_GetOriginatorPublicKey( pTemp,
                                    &recipientId.ri.karid.u.originatorKey))
            {
                goto exit;
            }
        }
        else
        {
            status = ERR_FALSE; /* don't understand this type */
            goto exit;
        }
    }
    else
    {
         goto exit;
    }

    pEncryptedKey = ASN1_NEXT_SIBLING( pTemp1);

    if (getPrivateKeyFun && NO_TAG == recipientId.ri.karid.type)
    {
        if ( OK > (*getPrivateKeyFun)(callbackArg, s,
                    recipientId.ri.karid.u.issuerAndSerialNumber.pSerialNumber,
                    recipientId.ri.karid.u.issuerAndSerialNumber.pIssuer,
                    &privateKey))
        {
            status = ERR_FALSE;
            goto exit;
        }
    }
    else if (getPrivateKeyFunEx)
    {
        if ( OK > (*getPrivateKeyFunEx)(callbackArg, s,
                                        &recipientId, &privateKey))
        {
            status = ERR_FALSE;
            goto exit;
        }
    }
    else
    {
        status = ERR_PKCS7_WRONG_CALLBACK;
        goto exit;
    }

    if ( akt_ecc != privateKey.type || !(privateKey.key.pECC->privateKey))
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    /* read the public key -- make sure it's the same curve as the private key */
    point = (const ubyte *) CS_memaccess( s, pECCBitString->dataOffset, pECCBitString->length);
    if (!point)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(
            privateKey.key.pECC, &eccCurveId, privateKey.type)))
        goto exit;

    /* Use the curveId and keyType from the privateKey */
    if (OK > (status = CRYPTO_INTERFACE_EC_newPublicKeyFromByteString(MOC_ECC(hwAccelCtx) eccCurveId,
                        (void **) &pKey, (ubyte *) point, pECCBitString->length, privateKey.type)))
        goto exit;

    if (OK > (status = CRYPTO_loadAsymmetricKey(
            &ephemeralKey, akt_ecc, (void **) &pKey)))
        goto exit;
#else
    if (OK > (status = CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) &ephemeralKey, CRYPTO_getECCurveId(&privateKey),
                                                point, pECCBitString->length, NULL, 0)))
    {
        goto exit;
    }
#endif

    /* figure out the hash algo and the key wrap OID */
    pTemp1 = ASN1_FIRST_CHILD( pKeyEncryptionAlgo);
    if ( OK <= ASN1_VerifyOID( pTemp1, s, dhSinglePassStdDHSha1KDF_OID))
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgo( ht_sha1, &pHashAlgo)))
            goto exit;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, dhSinglePassStdDHSha224KDF_OID))
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgo( ht_sha224, &pHashAlgo)))
            goto exit;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, dhSinglePassStdDHSha256KDF_OID))
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgo( ht_sha256, &pHashAlgo)))
            goto exit;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, dhSinglePassStdDHSha384KDF_OID))
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgo( ht_sha384, &pHashAlgo)))
            goto exit;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, dhSinglePassStdDHSha512KDF_OID))
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgo( ht_sha512, &pHashAlgo)))
            goto exit;
    }
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_KDF;
        goto exit;
    }

    /* KeyWrapAlgorithm  ::=  AlgorithmIdentifier */
    pTemp1 = ASN1_NEXT_SIBLING(pTemp1);
    if (!pTemp1)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pTemp1 = ASN1_FIRST_CHILD( pTemp1);

    if ( OK <= ASN1_VerifyOID( pTemp1, s, aes128Wrap_OID))
    {
        keyWrapOID = aes128Wrap_OID;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, aes192Wrap_OID))
    {
        keyWrapOID = aes192Wrap_OID;
    }
    else if ( OK <= ASN1_VerifyOID( pTemp1, s, aes256Wrap_OID))
    {
        keyWrapOID = aes256Wrap_OID;
    }
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_KEY_WRAP;
        goto exit;
    }

    if (pUKM)
    {
        ukmLen = pUKM->length;
        ukmData = (const ubyte *) CS_memaccess( s, pUKM->dataOffset, pUKM->length);
        if (!ukmData)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }

    encryptedKey = (const ubyte *) CS_memaccess( s, pEncryptedKey->dataOffset, pEncryptedKey->length);
    if (!encryptedKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = PKCS7_ECCDecryptKey(
            MOC_HW(hwAccelCtx) pHashAlgo, &ephemeralKey, &privateKey,
            keyWrapOID, ukmData, ukmLen, encryptedKey, pEncryptedKey->length,
            ppSymmetricKey, pSymmetricKeyLen)))
#else
    if (OK > ( status = PKCS7_ECCDecryptKey(MOC_HW(hwAccelCtx)
                                            pHashAlgo,
                                            ephemeralKey.key.pECC,
                                            privateKey.key.pECC->k, keyWrapOID,
                                            ukmData, ukmLen,
                                            encryptedKey, pEncryptedKey->length,
                                            ppSymmetricKey, pSymmetricKeyLen)))
#endif
    {
        goto exit;
    }

exit:

    if (encryptedKey)
    {
        CS_stopaccess( s, encryptedKey);
    }

    if (point)
    {
        CS_stopaccess( s, point);
    }

    if (ukmData)
    {
        CS_stopaccess( s, ukmData);
    }

    CRYPTO_uninitAsymmetricKey( &privateKey, NULL);
    CRYPTO_uninitAsymmetricKey( &ephemeralKey, NULL);

    return status;
}

#endif


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_ProcessRecipientInfos( MOC_HW(hwAccelDescr hwAccelCtx)
                            ASN1_ITEM* pRecipientInfos,
                            CStream s,
                            const void* callbackArg,
                            PKCS7_GetPrivateKey getPrivateKeyFun,
                            CMS_GetPrivateKey getPrivateKeyFun2,
                            ubyte** ppSymmetricKey,
                            ubyte4* pSymmetricKeyLen,
                            sbyte4* recipientIndex)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pRecipientInfo;
    sbyte4 index = 0;

    /* find which recipient info corresponds to us */
    pRecipientInfo = ASN1_FIRST_CHILD( pRecipientInfos);
    if ( !pRecipientInfo) return ERR_PKCS7_INVALID_STRUCT; /* there must be at least one */

    while (pRecipientInfo)
    {
        if (OK <= ASN1_VerifyType( pRecipientInfo, SEQUENCE))
        {
            if (OK <= PKCS7_ProcessKeyTransRecipientInfo(MOC_RSA(hwAccelCtx)
                                                         pRecipientInfo, s,
                                                         callbackArg,
                                                         getPrivateKeyFun,
                                                         getPrivateKeyFun2,
                                                         ppSymmetricKey,
                                                         pSymmetricKeyLen))
            {
               goto exit; /* found a match */
            }
        }
        else /* must be a tag */
        {
            ubyte4 tag;

            if (OK > ASN1_GetTag( pRecipientInfo, &tag))
            {
                status = ERR_PKCS7_INVALID_STRUCT;
                goto exit;
            }

            /* the sequence is implicit */
            switch( tag)
            {
            case 1:
#ifdef __ENABLE_DIGICERT_ECC__
                 if (OK <= PKCS7_ProcessKeyAgreeRecipientInfo(MOC_HW(hwAccelCtx)
                                                              pRecipientInfo, s,
                                                              callbackArg,
                                                              getPrivateKeyFun,
                                                              getPrivateKeyFun2,
                                                              ppSymmetricKey,
                                                              pSymmetricKeyLen))
                {
                    goto exit;
                }
                break;
#endif
            case 2:
            case 3:
            case 4:
            default:
                break;
            }
        }
        pRecipientInfo = ASN1_NEXT_SIBLING( pRecipientInfo);
        ++index;
    }

    status = ERR_PKCS7_NO_RECIPIENT_KEY_MATCH;

exit:
    if (recipientIndex)
    {
        *recipientIndex = (OK > status)? -1 : index;
    }

    return status;
}



/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetBulkAlgo( MOC_SYM(hwAccelDescr hwAccelCtx) ASN1_ITEM* pContentEncryptAlgo,
                   CStream s,
                   ubyte* pSymmetricKey,
                   ubyte4 symmetricKeyLen,
                   ubyte* iv,
                   BulkCtx* pBulkCtx,
                   const BulkEncryptionAlgo** ppBulkAlgo)
{
    ASN1_ITEM* pEncryptedAlgoOID;
    ubyte encryptionSubType;
#ifdef __ENABLE_ARC2_CIPHERS__
    sbyte4          effectiveKeyBits;
#endif
    MSTATUS status;

    /* first child is the OID identifying the algorithm */
    pEncryptedAlgoOID = ASN1_FIRST_CHILD( pContentEncryptAlgo);
    if ( 0 == pEncryptedAlgoOID ||
            OK > ASN1_VerifyType( pEncryptedAlgoOID, OID))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* determine the algorithm */
    /* we support 3DES_EDE_CBC, RC4, RC2 CBC initially add more as necesssary */
    status = ASN1_VerifyOIDRoot(pEncryptedAlgoOID, s,
                    rsaEncryptionAlgoRoot_OID, &encryptionSubType);

    if (OK == status ) /* match */
    {
        switch ( encryptionSubType)
        {
#ifdef __ENABLE_ARC2_CIPHERS__
        case 2: /* RC2CBC*/
            if (OK > (status = PKCS_GetRC2CBCParams( pEncryptedAlgoOID, s,
                &effectiveKeyBits, iv)))
            {
                goto exit;
            }
            *ppBulkAlgo = &CRYPTO_RC2EffectiveBitsSuite;
            /* special createFunc for RC2 that allows effective keyBits */
            *pBulkCtx = CreateRC2Ctx2(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                            symmetricKeyLen, effectiveKeyBits);
            break;
#endif

#ifndef __DISABLE_ARC4_CIPHERS__
        case 4: /* RC4 */
            /* no parameter */
            *ppBulkAlgo = &CRYPTO_RC4Suite;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            *pBulkCtx = CRYPTO_INTERFACE_CreateRC4Ctx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                        symmetricKeyLen, 0);
#else
            *pBulkCtx = CreateRC4Ctx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                        symmetricKeyLen, 0);
#endif
            break;
#endif

#ifndef __DISABLE_3DES_CIPHERS__
        case 7: /* desEDE3CBC */
            /* iv OCTET STRING (SIZE(8)) */
            if (OK > (status = PKCS_GetCBCParams(pEncryptedAlgoOID, s,
                                                    DES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            *ppBulkAlgo = &CRYPTO_TripleDESSuite;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            *pBulkCtx = CRYPTO_INTERFACE_Create3DESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                            symmetricKeyLen, 0);
#else
            *pBulkCtx = Create3DESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                            symmetricKeyLen, 0);
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/

            break;
#endif

        default:
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }
    }
    else
    {
        /* SCEP can use this */
#ifdef __ENABLE_DES_CIPHER__
        if ( OK == ASN1_VerifyOID(pEncryptedAlgoOID, s, desCBC_OID ))
        {
            /* iv OCTET STRING (SIZE(8)) */
            if ( OK > (status = PKCS_GetCBCParams(pEncryptedAlgoOID, s,
                                                    DES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            *ppBulkAlgo = &CRYPTO_DESSuite;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            *pBulkCtx = CRYPTO_INTERFACE_CreateDESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                            symmetricKeyLen, 0);
#else
            *pBulkCtx = CreateDESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                                            symmetricKeyLen, 0);
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
        }
        else
#endif
#ifndef __DISABLE_AES_CIPHERS__
        if ((OK == ASN1_VerifyOID(pEncryptedAlgoOID, s, aes128CBC_OID )) ||
            (OK == ASN1_VerifyOID(pEncryptedAlgoOID, s, aes192CBC_OID))  ||
            (OK == ASN1_VerifyOID(pEncryptedAlgoOID, s, aes256CBC_OID )))
        {
            if (OK > (status = PKCS_GetCBCParams(pEncryptedAlgoOID, s, AES_BLOCK_SIZE, iv)))
            {
                goto exit;
            }
            *ppBulkAlgo = &CRYPTO_AESSuite;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            *pBulkCtx = CRYPTO_INTERFACE_CreateAESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                symmetricKeyLen, 0);
#else
            *pBulkCtx = CreateAESCtx(MOC_SYM(hwAccelCtx) pSymmetricKey,
                symmetricKeyLen, 0);
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
        }
        else
        /* add others here if necessary */
#endif
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }
    }

    if (NULL == *pBulkCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

exit:

    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS7_DecryptEnvelopedDataAux(MOC_HW(hwAccelDescr hwAccelCtx)
                              ASN1_ITEM* pEnvelopedData, CStream s,
                              const void* callbackArg,
                              PKCS7_GetPrivateKey getPrivateKeyFun,
                              encryptedContentType* pType,
                              ASN1_ITEM** ppEncryptedContent,
                              BulkCtx* pBulkCtx,
                              const BulkEncryptionAlgo** ppBulkAlgo,
                              ubyte iv[/*16=MAX_IV_SIZE*/])
{
    ASN1_ITEMPTR    pVersion;
    ASN1_ITEMPTR    pRecipientInfos;
    ASN1_ITEMPTR    pEncryptedContentInfo, pContentEncryptAlgo;
    ubyte*          pSymmetricKey = 0;
    ubyte4          symmetricKeyLen = 0;
    MSTATUS         status;

    if ( NULL == pEnvelopedData|| NULL == pBulkCtx || NULL == ppBulkAlgo)
    {
        return ERR_NULL_POINTER;
    }

    pVersion = ASN1_FIRST_CHILD(pEnvelopedData);
    if ( !pVersion)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pRecipientInfos = ASN1_NEXT_SIBLING( pVersion);
    if (!pRecipientInfos)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    pEncryptedContentInfo = ASN1_NEXT_SIBLING( pRecipientInfos);
    if ( ! pEncryptedContentInfo)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* look at the recipient infos and see if we are one of them */
    /* depending on the version of the PKCS#7 it's either a MOC_SET OF or a SEQUENCE OF */
    if ( OK > ASN1_VerifyType( pRecipientInfos, MOC_SET) &&
        OK > ASN1_VerifyType( pRecipientInfos, SEQUENCE))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* check here the type of EncryptedContentInfo */
    if (OK > ASN1_VerifyType( pEncryptedContentInfo, SEQUENCE))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    if (OK > ( status = PKCS7_ProcessRecipientInfos( MOC_HW(hwAccelCtx)
                                                    pRecipientInfos, s,
                                                    callbackArg,
                                                    getPrivateKeyFun, NULL,
                                                    &pSymmetricKey,
                                                    &symmetricKeyLen, NULL)))
    {
        goto exit;
    }

    if (!pSymmetricKey || !symmetricKeyLen)
    {
        status = ERR_PKCS7_NO_RECIPIENT_KEY_MATCH;
        goto exit;
    }

    /* content encryption -- what's encryted differs
     between PKCS#7 v1.5 and v1.6. This implements version 1.5 or RFC2315 */

    status = ASN1_GetNthChild( pEncryptedContentInfo, 2, &pContentEncryptAlgo);
    if ( status < OK) goto exit;

    if (OK > ( status = PKCS7_GetBulkAlgo(MOC_SYM(hwAccelCtx) pContentEncryptAlgo, s,
                    pSymmetricKey, symmetricKeyLen, iv, pBulkCtx,
                    ppBulkAlgo)))
    {
        goto exit;
    }

    /* now decrypt */
    *ppEncryptedContent = ASN1_NEXT_SIBLING(pContentEncryptAlgo);
    if ( 0 == (*ppEncryptedContent)) /* optional not an error */
    {
        goto exit;
    }

    /* encryptedContent [0] IMPLICIT OCTETSTRING OPTIONAL */
    if ( OK > ASN1_VerifyTag( *ppEncryptedContent, 0))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* from SCEP draft:
    * NOTE:The PKCS#7 EncryptedContent is specified as an octet string, but
    * SCEP entities must also accept a sequence of octet strings as a valid
    * alternate encoding.
    */
    if ((*ppEncryptedContent)->indefinite &&
        ASN1_FIRST_CHILD(*ppEncryptedContent))
    {
        *pType = SCEP;
        *ppEncryptedContent = ASN1_FIRST_CHILD(*ppEncryptedContent);
    }
    else /*the content of [0] tag is the encrypted content */
    {
        *pType = NORMAL;
    }


exit:

    if (pSymmetricKey)
    {
        FREE(pSymmetricKey);
    }

    if (OK > status && NULL != *pBulkCtx)
    {
        /* assert( *ppBulkAlgo) */
        if (NULL != *ppBulkAlgo)
        {
            (*ppBulkAlgo)->deleteFunc(MOC_SYM(hwAccelCtx) pBulkCtx);
        }
    }

    return status;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS PKCS7_DecryptEnvelopedData( MOC_HW(hwAccelDescr hwAccelCtx)
                                            ASN1_ITEM* pEnvelopedData,
                                            CStream s, const void* callbackArg,
                                            PKCS7_GetPrivateKey getPrivateKeyFun,
                                            ubyte** decryptedInfo,
                                            sbyte4* decryptedInfoLen)
{
    ubyte           iv[16] = {0}; /* all supported algos have a 8 byte IV; aes has 16 byte */
    BulkCtx         pBulkCtx = NULL;
    const BulkEncryptionAlgo* pBulkAlgo = NULL;
    encryptedContentType    type;
    ASN1_ITEM* pEncryptedContent;
    MSTATUS         status;

    if ( NULL == pEnvelopedData|| NULL == decryptedInfo || NULL == decryptedInfoLen)
    {
        return ERR_NULL_POINTER;
    }

    if ( OK > ( status = PKCS7_DecryptEnvelopedDataAux( MOC_HW(hwAccelCtx)
                                                       pEnvelopedData, s,
                                                       callbackArg,
                                                       getPrivateKeyFun,
                                                       &type,
                                                       &pEncryptedContent,
                                                       &pBulkCtx,
                                                       &pBulkAlgo, iv)))
    {
        goto exit;
    }

    /* call the common routine */
    status = PKCS_BulkDecryptEx(MOC_SYM(hwAccelCtx) type, pEncryptedContent, s,
                                pBulkCtx, pBulkAlgo, iv,
                                decryptedInfo, decryptedInfoLen);

exit:

    if (NULL != pBulkCtx)
    {
        /* assert( pBulkAlgo) */
        if (NULL != pBulkAlgo)
            pBulkAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &pBulkCtx);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_ECC__

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GenerateECCCMSSharedInfo(const ubyte* keyInfoOID,
                               const ubyte* ukmData, ubyte4 ukmDataLen,
                               ubyte4 kekLen,
                               ubyte** sharedInfo, ubyte4 *sharedInfoLen)
{
    MSTATUS status;
    DER_ITEMPTR pTag, pSequence = 0;
    ubyte copyData[MAX_DER_STORAGE];

    if (OK > ( status = DER_AddSequence( NULL, &pSequence)))
    {
        goto exit;
    }

    if (OK > ( status = DER_StoreAlgoOID( pSequence, keyInfoOID, TRUE)))
    {
        goto exit;
    }

    if (ukmData)
    {
        if (OK > ( status = DER_AddTag( pSequence, 0, &pTag)))
        {
            goto exit;
        }
        if (OK > ( status = DER_AddItem( pTag, OCTETSTRING, ukmDataLen, ukmData, NULL)))
        {
            goto exit;
        }
    }

    kekLen = kekLen * 8; /* suppPubInfo length in bits */
    BIGEND32( copyData, kekLen);
    if (OK > ( status = DER_AddTag( pSequence, 2, &pTag)))
    {
        goto exit;
    }
    if (OK > ( status = DER_AddItemCopyData( pTag, OCTETSTRING, 4, copyData, NULL)))
    {
        goto exit;
    }

    /* Serialize */
    if (OK > ( status = DER_Serialize( pSequence, sharedInfo, sharedInfoLen)))
    {
        goto exit;
    }

exit:

    if (pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    return status;
}



/*--------------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
PKCS7_GenerateECCKeyEncryptionKey(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pHashAlgo,
    AsymmetricKey* pPublicKey,
    AsymmetricKey* pPrivateKey,
    const ubyte* keyWrapOID,
    const ubyte* ukmData,
    ubyte4 ukmDataLen,
    ubyte4 kekLen,
    ubyte** p_kek
    )
#else
static MSTATUS
PKCS7_GenerateECCKeyEncryptionKey(MOC_ECC(hwAccelDescr hwAccelCtx)
                    const BulkHashAlgo* pHashAlgo,
                    ECCKey* pECCKey, ConstPFEPtr k,
                    const ubyte* keyWrapOID,
                    const ubyte* ukmData, ubyte4 ukmDataLen,
                    ubyte4 kekLen, ubyte** p_kek)
#endif
{
    MSTATUS status;

    ubyte* sharedInfo = 0;
    ubyte4 sharedInfoLen;
    ubyte* z = 0;
    ubyte4 zLen;
    ubyte* kek = 0;

    /* do the DH operation to get Z shared secret */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeys( MOC_ECC(hwAccelCtx)
            pPrivateKey->key.pECC, pPublicKey->key.pECC, &z, &zLen,
            ECDH_X_CORD_ONLY, NULL, pPrivateKey->type)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = ECDH_generateSharedSecretAux(pECCKey->pCurve,
                            pECCKey->Qx, pECCKey->Qy, k, &z, (sbyte4*)&zLen, 1)))
    {
        goto exit;
    }
#endif

    /* generate the sharedInfo -> DER encoding of ECC-CMS-SharedInfo --
     the kekLen is identical to cekLen -- compatible with RFC 5008 */
    if (OK > ( status = PKCS7_GenerateECCCMSSharedInfo(keyWrapOID,
                               ukmData, ukmDataLen, kekLen,
                               &sharedInfo, &sharedInfoLen)))
    {
        goto exit;
    }

    kek = MALLOC( kekLen);
    if (!kek)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > ( status = ANSIX963KDF_generate( MOC_HASH( hwAccelCtx)
                                                pHashAlgo, z, zLen,
                                                sharedInfo, sharedInfoLen,
                                                kekLen, kek)))
    {
        goto exit;
    }

    *p_kek = kek;
    kek = 0;

exit:

    if ( z)
    {
        FREE( z);
    }

    if ( sharedInfo)
    {
        FREE(sharedInfo);
    }

    if ( kek)
    {
        FREE( kek);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS PKCS7_ECCEncryptKey(
    MOC_HW(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pHashAlgo,
    AsymmetricKey* pPublicKey,
    AsymmetricKey* pPrivateKey,
    const ubyte* keyWrapOID,
    const ubyte* ukmData,
    ubyte4 ukmDataLen,
    const ubyte* cek,
    ubyte4 cekLen,
    ubyte** encryptedKey,
    ubyte4* encryptedKeyLen
    )
#else
static MSTATUS
PKCS7_ECCEncryptKey(MOC_HW(hwAccelDescr hwAccelCtx)
                    const BulkHashAlgo* pHashAlgo,
                    ECCKey* pECCKey, ConstPFEPtr k,
                    const ubyte* keyWrapOID,
                    const ubyte* ukmData, ubyte4 ukmDataLen,
                    const ubyte* cek, ubyte4 cekLen,
                    ubyte** encryptedKey, ubyte4* encryptedKeyLen)
#endif
{
    MSTATUS status;

    ubyte* kek = 0;
    ubyte* wrappedKey = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = PKCS7_GenerateECCKeyEncryptionKey(
            MOC_ECC(hwAccelCtx) pHashAlgo, pPublicKey, pPrivateKey, keyWrapOID,
            ukmData, ukmDataLen, cekLen, &kek)))
#else
    if (OK > ( status = PKCS7_GenerateECCKeyEncryptionKey(
                    MOC_ECC(hwAccelCtx) pHashAlgo,
                    pECCKey, k, keyWrapOID, ukmData, ukmDataLen,
                    cekLen, &kek)))
#endif
    {
        goto exit;
    }

    wrappedKey = MALLOC( cekLen + 8);

    if ( OK > ( status = AESKWRAP_encrypt( MOC_SYM(hwAccelCtx) kek, cekLen,
                  cek, cekLen, wrappedKey)))
    {
        goto exit;
    }

    *encryptedKey = wrappedKey;
    *encryptedKeyLen = cekLen + 8;
    wrappedKey = 0;

exit:

    if ( wrappedKey)
    {
        FREE( wrappedKey);
    }

    if ( kek)
    {
        FREE( kek);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS PKCS7_ECCDecryptKey(
    MOC_HW(hwAccelDescr hwAccelCtx)
    const BulkHashAlgo* pHashAlgo,
    AsymmetricKey *pPublicKey,
    AsymmetricKey *pPrivateKey,
    const ubyte* keyWrapOID,
    const ubyte* ukmData,
    ubyte4 ukmDataLen,
    const ubyte* encryptedKey,
    ubyte4 encryptedKeyLen,
    ubyte** cek,
    ubyte4* cekLen
    )
#else
static MSTATUS
PKCS7_ECCDecryptKey(MOC_HW(hwAccelDescr hwAccelCtx)
                    const BulkHashAlgo* pHashAlgo,
                    ECCKey* pECCKey, ConstPFEPtr k,
                    const ubyte* keyWrapOID,
                    const ubyte* ukmData, ubyte4 ukmDataLen,
                    const ubyte* encryptedKey, ubyte4 encryptedKeyLen,
                    ubyte** cek, ubyte4* cekLen)
#endif
{
    MSTATUS status;
    ubyte* kek = 0;
    ubyte* unwrappedKey = 0;
    ubyte4 wrapKeyLength = MAX_ENC_KEY_LENGTH; /* 32 - aes256Wrap_OID */

    if ( EqualOID( keyWrapOID, aes192Wrap_OID)){
          wrapKeyLength = 24;
    } else if ( EqualOID( keyWrapOID, aes128Wrap_OID)){
          wrapKeyLength = 16;
    }


    *cekLen = encryptedKeyLen - 8;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = PKCS7_GenerateECCKeyEncryptionKey(
            MOC_ECC(hwAccelCtx) pHashAlgo, pPublicKey, pPrivateKey, keyWrapOID,
            ukmData, ukmDataLen, wrapKeyLength, &kek)))
#else
    if (OK > ( status = PKCS7_GenerateECCKeyEncryptionKey(
                    MOC_ECC(hwAccelCtx) pHashAlgo,
                    pECCKey, k, keyWrapOID, ukmData, ukmDataLen,
                    wrapKeyLength, &kek)))
#endif
    {
        goto exit;
    }

    unwrappedKey = MALLOC( *cekLen);

    if ( OK > ( status = AESKWRAP_decrypt( MOC_SYM(hwAccelCtx) kek, wrapKeyLength,
                  encryptedKey, encryptedKeyLen, unwrappedKey)))
    {
        goto exit;
    }

    *cek = unwrappedKey;
    unwrappedKey = 0;

exit:

    if ( unwrappedKey)
    {
        FREE( unwrappedKey);
    }

    if ( kek)
    {
        FREE( kek);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_HashOfEcKey(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey* pKey,
    ubyte* result,
    MSTATUS (*completeDigest)(
        MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen,
        ubyte *pDigestOutput)
    )
{
    MSTATUS status;
    ubyte* ptBuf = NULL;
    ubyte* keyBuf = NULL;
    sbyte4 keyBufLen = 0;

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ECCKey *pECCKey = pKey->key.pECC;
#endif

    /* generate public key hash */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc( MOC_ECC(hwAccelCtx)
            pKey->key.pECC, &ptBuf, (ubyte4 *) &keyBufLen, pKey->type)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = EC_pointToByteString( pECCKey->pCurve,
                                              pECCKey->Qx,
                                              pECCKey->Qy,
                                              &ptBuf,
                                              &keyBufLen)))
    {
        goto exit;
    }
#endif

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, keyBufLen,
                                    TRUE, &keyBuf)))
    {
        goto exit;
    }

    DIGI_MEMCPY(keyBuf, ptBuf, keyBufLen);

    status = completeDigest(MOC_HASH(hwAccelCtx) keyBuf, keyBufLen, result);

exit:
    CRYPTO_FREE(hwAccelCtx, TRUE, &keyBuf);

    if (ptBuf)
    {
        FREE(ptBuf);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddEcKeyIdentifier(MOC_ECC(hwAccelDescr hwAccelCtx) DER_ITEMPTR pParent,
                         AsymmetricKey* pKey, ubyte4 hashType)
{
    MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput);
    MSTATUS status;
    DER_ITEMPTR pTag;
    ubyte* hashResult = NULL;
    ubyte4 digestSize = 0;

    switch(hashType)
    {
        case ht_sha1:
            digestSize = SHA1_RESULT_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            completeDigest = CRYPTO_INTERFACE_SHA1_completeDigest;
#else
            completeDigest = SHA1_completeDigest;
#endif
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
            digestSize = SHA224_RESULT_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            completeDigest = CRYPTO_INTERFACE_SHA224_completeDigest;
#else
            completeDigest = SHA224_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
            digestSize = SHA256_RESULT_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            completeDigest = CRYPTO_INTERFACE_SHA256_completeDigest;
#else
            completeDigest = SHA256_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
            digestSize = SHA384_RESULT_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            completeDigest = CRYPTO_INTERFACE_SHA384_completeDigest;
#else
            completeDigest = SHA384_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
            digestSize = SHA512_RESULT_SIZE;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            completeDigest = CRYPTO_INTERFACE_SHA512_completeDigest;
#else
            completeDigest = SHA512_completeDigest;
#endif
            break;
#endif

        default:
            status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
            goto exit;
    }

    hashResult = (ubyte*)MALLOC(digestSize);
    if (!hashResult)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = PKCS7_HashOfEcKey(
        MOC_ECC(hwAccelCtx) pKey, hashResult, completeDigest)))
    {
        goto exit;
    }

    /* rKeyId [0] IMPLICIT RecipientKeyIdentifier */
    if (OK > (status = DER_AddTag(pParent, 0, &pTag)))
    {
        goto exit;
    }

    status = DER_AddItemOwnData(pTag, OCTETSTRING,
                                digestSize, &hashResult, NULL);

exit:
    if (hashResult)
    {
        FREE(hashResult);
    }

    return status;
}


/*--------------------------------------------------------------------------*/

static MSTATUS PKCS7_AddECDHRecipientInfo(
    MOC_HW(hwAccelDescr hwAccelCtx)
    DER_ITEMPTR pRecipientInfos,
    AsymmetricKey* pKey,
    const BulkEncryptionAlgo* pBulkEncryptionAlgo,
    const ubyte* ceKey,
    ubyte4 ceKeyLen,
    ASN1_ITEMPTR pCertificate,
    CStream certificateStream,
    ubyte4 keyIdHashType,
    RNGFun rngFun,
    void* rngFunArg
    )
{
    MSTATUS status;
    const BulkHashAlgo* pHashAlgo;
    ubyte hashType; /* for X9.63 key derivation */
    const ubyte* keyDerivationOID;
    const ubyte* keyWrapOID;
    DER_ITEMPTR pRecipientInfo, pTag, pTemp;
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    ubyte copyData[MAX_DER_STORAGE];
    ubyte* ukmData = 0;
    ubyte* ukmDataCopy;
    sbyte4 ecdhKeyLen;
    ubyte* ecdhKeyBuffer = 0;
    ubyte4 encryptedKeyBufferLen = 0;
    ubyte* encryptedKeyBuffer = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    AsymmetricKey priKey;
    ECCKey *pEphemeralKey = NULL;
    ubyte4 eccCurveId;

    if (OK > (status = CRYPTO_initAsymmetricKey(&priKey)))
        goto exit;
#else
    PFEPtr k = 0, Qx = 0, Qy = 0;
    PrimeFieldPtr pPF;
    ECCKey *pECCKey = pKey->key.pECC;
    pPF = EC_getUnderlyingField(pECCKey->pCurve);
#endif

    /* add implicit tag [1] for KeyAgreeRecipientInfo */
    if (OK > ( status = DER_AddTag(pRecipientInfos, 1, &pRecipientInfo)))
        goto exit;

    /* CMSVersion */
    copyData[0] = 3;
    if ( OK > ( status = DER_AddItemCopyData( pRecipientInfo, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* tag [0] for OriginatorIdentifierOrKey */
    if ( OK > ( status = DER_AddTag( pRecipientInfo, 0, &pTag)))
        goto exit;

    /* implicit tag [1] for OriginatorPublicKey */
    if ( OK > ( status = DER_AddTag( pTag, 1, &pTemp)))
        goto exit;

    /* AlgorithmIdentifier -- RFC3278 required NULL parameters, but the
    revision recommends the ecCurve or ABSENT -- test backward compatibility...*/
    if (OK > ( status = DER_StoreAlgoOID( pTemp, ecPublicKey_OID, TRUE)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_getCurveIdFromKey(
            pKey->key.pECC, &eccCurveId, pKey->type)))
        goto exit;

    if (OK > (status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc( MOC_ECC(hwAccelCtx)
            eccCurveId, (void **) &pEphemeralKey, rngFun, rngFunArg, g_keyType, NULL)))
        goto exit;

    /* Obtain buffer length to match size expected by
     * 'CRYPTO_INTERFACE_EC_writePublicKeyToBuffer()'
     */
    if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenEx(
            pKey->key.pECC, (ubyte4 *) &ecdhKeyLen, pKey->type)))
        goto exit;
#else
    /* generate an ephemeral ECDH key */
    if (OK > (status = PRIMEFIELD_newElement( pPF, &k)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qx)) ||
        OK > (status = PRIMEFIELD_newElement( pPF, &Qy)))
    {
        goto exit;
    }

    if (OK > (status = EC_generateKeyPair( pECCKey->pCurve, rngFun,
                                            rngFunArg, k, Qx, Qy)))
    {
        goto exit;
    }

    /* allocate a buffer for the key parameter */
    if (OK > (status = EC_getPointByteStringLen( pECCKey->pCurve, &ecdhKeyLen)))
        goto exit;
#endif

    if (0 == ecdhKeyLen)
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    /* add an extra byte = 0 (unused bits) */
    ecdhKeyBuffer = MALLOC( ecdhKeyLen+1);
    if (!ecdhKeyBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    ecdhKeyBuffer[0] = 0; /* unused bits */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_writePublicKeyToBuffer( MOC_ECC(hwAccelCtx)
            pEphemeralKey, ecdhKeyBuffer + 1, ecdhKeyLen, g_keyType)))
        goto exit;
#else
    if (OK > ( status = EC_writePointToBuffer( pECCKey->pCurve, Qx, Qy,
                                                ecdhKeyBuffer+1, ecdhKeyLen)))
    {
        goto exit;
    }
#endif

    if (OK > ( status = DER_AddItemOwnData( pTemp, BITSTRING, ecdhKeyLen+1, &ecdhKeyBuffer, NULL)))
        goto exit;

    /* ukm SHOULD be generated -- we generate encryptKeyLen */
    ukmData = ukmDataCopy = MALLOC( ceKeyLen);
    if(!ukmData)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if ( OK != (status = (MSTATUS) rngFun( rngFunArg, ceKeyLen, ukmData)))
        goto exit;

    if (OK > ( status = DER_AddTag( pRecipientInfo, 1, &pTag)))
        goto exit;

    if (OK > ( status = DER_AddItemOwnData( pTag, OCTETSTRING, ceKeyLen, &ukmData, NULL)))
        goto exit;

    /* keyEncryptionAlgorithmIdentifier */
    if (OK > ( status = DER_AddSequence( pRecipientInfo, &pTemp)))
        goto exit;

    /* we pick up the key derivation function that makes
       sense for the strength of the ECC key --
       also compatible with RFC 5008 */
#ifdef __ENABLE_DIGICERT_ECC_P192__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (cid_EC_P192 == eccCurveId)
#else
    if (EC_compareEllipticCurves(pECCKey->pCurve, EC_P192))
#endif
    {
        keyDerivationOID = dhSinglePassStdDHSha1KDF_OID;
        hashType = ht_sha1;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (cid_EC_P224 == eccCurveId)
#else
    if (EC_compareEllipticCurves(pECCKey->pCurve, EC_P224))
#endif
    {
        keyDerivationOID = dhSinglePassStdDHSha224KDF_OID;
        hashType = ht_sha224;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (cid_EC_P256 == eccCurveId)
#else
    if (EC_compareEllipticCurves(pECCKey->pCurve, EC_P256))
#endif
    {
        keyDerivationOID = dhSinglePassStdDHSha256KDF_OID;
        hashType = ht_sha256;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (cid_EC_P384 == eccCurveId)
#else
    if (EC_compareEllipticCurves(pECCKey->pCurve, EC_P384))
#endif
    {
        keyDerivationOID = dhSinglePassStdDHSha384KDF_OID;
        hashType = ht_sha384;
    }
    else
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (cid_EC_P521 == eccCurveId)
#else
    if (EC_compareEllipticCurves(pECCKey->pCurve, EC_P521))
#endif
    {
        keyDerivationOID = dhSinglePassStdDHSha512KDF_OID;
        hashType = ht_sha512;
    }
    else
#endif
    {
        status = ERR_EC_UNSUPPORTED_CURVE;
        goto exit;
    }

    if (OK > ( status = CRYPTO_getRSAHashAlgo(hashType, &pHashAlgo) ))
        goto exit;

    /* KeyEncryptionAlgorithmIdentifier */
    /* OID is the keyDerivation */
    if (OK > ( status = DER_AddOID( pTemp, keyDerivationOID, NULL)))
        goto exit;
    /* and parameters the KeyWrapAlgorithm */
    /* depending on the bulk encryption algo */
    /* for the moment, support only AES (suite B) */
#ifndef __DISABLE_AES_CIPHERS__
    if ( pBulkEncryptionAlgo == &CRYPTO_AESSuite)
    {
        switch (ceKeyLen)
        {
        case 16: /* AES 128 */
            keyWrapOID = aes128Wrap_OID;
            break;
        case 24:
            keyWrapOID = aes192Wrap_OID;
            break;
        case 32:
            keyWrapOID = aes256Wrap_OID;
            break;
        default:
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;  /* Should this be a fatal error? */
        }
    }
    else
#endif
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }
    /* KeyWrapAlgorithm  ::=  AlgorithmIdentifier */
    if (OK > ( status = DER_StoreAlgoOID( pTemp, keyWrapOID, TRUE)))
        goto exit;

    /* get the encrypted (wrapped) key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_loadAsymmetricKey(&priKey, g_keyType, (void **) &pEphemeralKey)))
        goto exit;

    pEphemeralKey = NULL;

    if (OK > (status = PKCS7_ECCEncryptKey(
            MOC_HW(hwAccelCtx) pHashAlgo, pKey, &priKey,
            keyWrapOID, ukmDataCopy, ceKeyLen, ceKey, ceKeyLen,
            &encryptedKeyBuffer, &encryptedKeyBufferLen)))
#else
    if (OK > ( status = PKCS7_ECCEncryptKey(
                    MOC_HW(hwAccelCtx)
                    pHashAlgo,
                    pECCKey, k, keyWrapOID,
                    ukmDataCopy, ceKeyLen,
                    ceKey, ceKeyLen,
                    &encryptedKeyBuffer,
                    &encryptedKeyBufferLen)))
#endif
    {
        goto exit;
    }

    /* write out the recipientEncryptedKeys */
    if ( OK > ( status = DER_AddSequence( pRecipientInfo, &pTemp)))
    {
        goto exit;
    }

    if ( OK > ( status = DER_AddSequence( pTemp, &pTemp)))
    {
        goto exit;
    }

    if (pCertificate)
    {
        /* add issuerAndSerialNumber */
        /* get issuer and serial number of certificate */
        if ( OK > ( status = X509_getCertificateIssuerSerialNumber( pCertificate,
                                                                   &pIssuer,
                                                                   &pSerialNumber)))
            goto exit;

        /* isssuerAndSerialNumber */
        if ( OK > ( status = PKCS7_AddIssuerAndSerialNumber( pTemp, certificateStream,
                                                            pIssuer, pSerialNumber, NULL)))
        {
            goto exit;
        }
    }
    else
    {
        if ( OK > ( status = PKCS7_AddEcKeyIdentifier(MOC_ECC(hwAccelCtx) pTemp,
                                                      pKey, keyIdHashType)))
        {
            goto exit;
        }
    }

    /* finally add the  encrypted (wrapped key) */
    if (OK > ( status = DER_AddItemOwnData( pTemp, OCTETSTRING,
                                           encryptedKeyBufferLen,
                                           &encryptedKeyBuffer, NULL)))
    {
        goto exit;
    }

exit:

    if ( ecdhKeyBuffer)
    {
        FREE( ecdhKeyBuffer);
    }

    if ( ukmData)
    {
        FREE( ukmData);
    }

    if ( encryptedKeyBuffer)
    {
        FREE( encryptedKeyBuffer);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != pEphemeralKey)  /* error case condition */
    {
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pEphemeralKey);
    }
    else
    {
        CRYPTO_uninitAsymmetricKey(&priKey, NULL);
    }
#else
    PRIMEFIELD_deleteElement( pPF, &k);
    PRIMEFIELD_deleteElement( pPF, &Qx);
    PRIMEFIELD_deleteElement( pPF, &Qy);
#endif

    return status;
}
#endif


/*--------------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_RSA__

#ifdef __ENABLE_DIGICERT_PKCS1__

static MSTATUS
PKCS7_AddRSAOAEPRecipientKeyInfo(MOC_RSA(hwAccelDescr hwAccelCtx)
                                 DER_ITEMPTR   pRecipientInfo,
                                 RSAKey*       pRSAKey,
                                 const ubyte*  encryptKey,
                                 ubyte4        encryptKeyLen,
                                 void*         rngFunArg,
                                 ubyte4        hashId,
                                 sbyte*        pLabel,
                                 ubyte**       encryptedKey,
                                 ubyte4*       encryptedKeyLen)
{
    MSTATUS status = OK;
    DER_ITEMPTR pRsaesOaepAlgorithmIdentifier = NULL;
    DER_ITEMPTR pTag = NULL;
    DER_ITEMPTR pRsaesOaepParameters = NULL;
    DER_ITEMPTR pMgfAlgorithmIdentifier = NULL;
    DER_ITEMPTR pSourceAlgorithmIdentifier = NULL;

    ubyte4 labelLen = (NULL != pLabel ? DIGI_STRLEN(pLabel) : 0);
    ubyte *pHashOid = NULL;

    switch (hashId)
    {
        case ht_sha1:
           pHashOid = (ubyte *) gRsaHashTable[0].pHashOid;
           break;
        case ht_sha224:
           pHashOid = (ubyte *) gRsaHashTable[1].pHashOid;
           break;
        case ht_sha256:
           pHashOid = (ubyte *) gRsaHashTable[2].pHashOid;
           break;
        case ht_sha384:
           pHashOid = (ubyte *) gRsaHashTable[3].pHashOid;
           break;
        case ht_sha512:
           pHashOid = (ubyte *) gRsaHashTable[4].pHashOid;
           break;           
    }

    /* We form the following asn1 structure

        SEQUENCE (2 elem)
            rsaOAEP OID 
            SEQUENCE (3 elem)
                [0] Hash Algorithm
                    SEQUENCE (2 elem)
                        hash OID
                        NULL
                [1] MGF algorithm
                    SEQUENCE (2 elem)
                        mgf OID
                        SEQUENCE (2 elem)
                            hash OID
                            NULL
                [2] Source algorithm
                    SEQUENCE (2 elem)
                        rsaOAEP-pSpecified OID
                        OCTET STRING (0 elem)
    */
    status = DER_AddSequence(pRecipientInfo, &pRsaesOaepAlgorithmIdentifier);
    if (OK != status)
        goto exit;

    /* OID */
    status = DER_AddOID(pRsaesOaepAlgorithmIdentifier, rsaEsOaep_OID, NULL);
    if (OK != status)
        goto exit;

    /* RSAES-OAEP parameters */
    status = DER_AddSequence(pRsaesOaepAlgorithmIdentifier, &pRsaesOaepParameters);
    if (OK != status)
        goto exit;

    /* Only add OAEP params that are not the default. From RFC 4055...
        "Implementations that perform encryption
        MUST omit the <...> field ...
        indicating that the default value was used."
        */
    if (ht_sha1 != hashId)
    {
        /* [0] */
        status = DER_AddTag(pRsaesOaepParameters, RSA_OAEP_PARAMS_HASH_ALGO_TAG, &pTag);
        if (OK != status)
            goto exit;

        /* hash OID */
        status = DER_StoreAlgoOID(pTag, (const ubyte *) pHashOid, TRUE);
        if (OK != status)
            goto exit;

        /* [1] */
        status = DER_AddTag(pRsaesOaepParameters, RSA_OAEP_PARAMS_MASK_GEN_ALGO_TAG, &pTag);
        if (OK != status)
            goto exit;

        /* MGF */
        status = DER_AddSequence(pTag, &pMgfAlgorithmIdentifier);
        if (OK != status)
            goto exit;

        /* MGF OID */
        status = DER_AddOID(pMgfAlgorithmIdentifier, pkcs1Mgf_OID, NULL);
        if (OK != status)
            goto exit;

        /* hash id again */
        status = DER_StoreAlgoOID(pMgfAlgorithmIdentifier, (const ubyte *) pHashOid, TRUE);
        if (OK != status)
            goto exit;
    }

    if (labelLen)
    {
        /* [2] */
        status = DER_AddTag(pRsaesOaepParameters, RSA_OAEP_PARAMS_SOURCE_ALGO_TAG, &pTag);
        if (OK != status)
            goto exit;

        /* source algo */
        status = DER_AddSequence(pTag, &pSourceAlgorithmIdentifier);
        if (OK != status)
            goto exit;

        /* pSpecified OID */
        status = DER_AddOID(pSourceAlgorithmIdentifier, pSpecified_OID, NULL);
        if (OK != status)
            goto exit;

        /* message label */
        status = DER_AddItem(pSourceAlgorithmIdentifier, OCTETSTRING, labelLen, (ubyte *) pLabel, NULL);
        if (OK != status)
            goto exit;
    }

    /* Encrypt! */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt(MOC_RSA(hwAccelCtx) (randomContext *) rngFunArg, pRSAKey, (ubyte) hashId, MOC_PKCS1_ALG_MGF1, (ubyte) hashId, 
                                                   encryptKey, encryptKeyLen, labelLen ? (ubyte *) pLabel : NULL, labelLen, encryptedKey, encryptedKeyLen);
#else
    status = PKCS1_rsaesOaepEncrypt(MOC_RSA(hwAccelCtx) (randomContext *) rngFunArg, pRSAKey, (ubyte) hashId, PKCS1_MGF1, encryptKey, encryptKeyLen, 
                                    labelLen ? (ubyte *) pLabel : NULL, labelLen, encryptedKey, encryptedKeyLen);
#endif

exit:

    return status;
}

#endif

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddRSARecipientInfo(MOC_RSA(hwAccelDescr hwAccelCtx)
                           DER_ITEMPTR pRecipientInfos,
                           RSAKey* pRSAKey,
                           const ubyte* encryptKey,
                           ubyte4 encryptKeyLen,
                           ASN1_ITEMPTR pCertificate,
                           CStream certificateStream,
                           RNGFun rngFun,
                           void* rngFunArg,
                           ubyte isOaep,
                           ubyte4 oaepHashAlgo,
                           sbyte *pOaepLabel)
{
    MSTATUS status;
    DER_ITEMPTR pRecipientInfo;
    ubyte copyData[MAX_DER_STORAGE];
    ASN1_ITEMPTR pIssuer, pSerialNumber;
    ubyte* encryptedKey = 0;
    ubyte4 encryptedKeyLen;
    ubyte *pRsaOid = (ubyte *) (isOaep ? rsaEsOaep_OID : rsaEncryption_OID);

    if ( OK > ( status = DER_AddSequence( pRecipientInfos, &pRecipientInfo)))
        goto exit;

    /* recipient info version = 0 */
    copyData[0] = 0;
    if ( OK > ( status = DER_AddItemCopyData( pRecipientInfo, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* get issuer and serial number of certificate */
    if ( OK > ( status = X509_getCertificateIssuerSerialNumber( pCertificate,
                                                               &pIssuer,
                                                               &pSerialNumber)))
    {
        goto exit;
    }
    /* isssuerAndSerialNumber */
    if ( OK > ( status = PKCS7_AddIssuerAndSerialNumber( pRecipientInfo,
                                                        certificateStream,
                                                        pIssuer, pSerialNumber,
                                                        NULL)))
    {
        goto exit;
    }

    if (isOaep)
    {
#if defined(__ENABLE_DIGICERT_PKCS1__)
        if (OK > (status = PKCS7_AddRSAOAEPRecipientKeyInfo(MOC_RSA(hwAccelCtx) pRecipientInfo, pRSAKey, encryptKey, encryptKeyLen,
                                                            rngFunArg, oaepHashAlgo, pOaepLabel, &encryptedKey, &encryptedKeyLen)))
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
    else
    {
        if ( OK > (status = DER_StoreAlgoOID( pRecipientInfo, pRsaOid, TRUE)))
            goto exit;

    /* encrypt key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if ( OK > ( status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *)(&encryptedKeyLen), akt_rsa)))
            goto exit;
#else
        if ( OK > ( status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, (sbyte4 *)(&encryptedKeyLen))))
            goto exit;
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/

        encryptedKey = MALLOC( encryptedKeyLen);
        if ( !encryptedKey)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* add the encrypted key as an OCTET string */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if ( OK > ( status = CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(hwAccelCtx) pRSAKey,
                                        encryptKey, encryptKeyLen,
                                        encryptedKey,
                                        rngFun, rngFunArg, NULL, akt_rsa)))
#else
        if ( OK > ( status = RSA_encrypt(MOC_RSA(hwAccelCtx) pRSAKey,
                                        encryptKey, encryptKeyLen,
                                        encryptedKey,
                                        rngFun, rngFunArg, NULL)))
#endif /*__ENABLE_DIGICERT_CRYPTO_INTERFACE__*/
            {
            goto exit;
        }
    }


    status = DER_AddItemOwnData( pRecipientInfo, OCTETSTRING,
                                    encryptedKeyLen, &encryptedKey, NULL);
exit:

    if (encryptedKey)
    {
        FREE( encryptedKey);
    }

    return status;
}
#endif

/*--------------------------------------------------------------------------*/

static MSTATUS
PKCS7_GetCryptoAlgoParams( const ubyte* encryptAlgoOID,
                          const BulkEncryptionAlgo** ppBulkEncryptionAlgo,
                          sbyte4 *keyLength)
{
#ifdef __ENABLE_DES_CIPHER__
    if ( EqualOID( desCBC_OID, encryptAlgoOID)) /* SCEP requires this but not sure about OID*/
    {
        *keyLength = DES_KEY_LENGTH;
        *ppBulkEncryptionAlgo = &CRYPTO_DESSuite;

    }
    else
#endif
#ifndef __DISABLE_3DES_CIPHERS__
    if ( EqualOID( desEDE3CBC_OID, encryptAlgoOID))
    {
        *keyLength = THREE_DES_KEY_LENGTH;
        *ppBulkEncryptionAlgo = &CRYPTO_TripleDESSuite;
    }
    else
#endif
#ifndef __DISABLE_AES_CIPHERS__
    if ( EqualOID( aes128CBC_OID, encryptAlgoOID))
    {
        *keyLength = 16;
        *ppBulkEncryptionAlgo = &CRYPTO_AESSuite;
    }
    else
    if ( EqualOID( aes192CBC_OID, encryptAlgoOID))
    {
        *keyLength = 24;
        *ppBulkEncryptionAlgo = &CRYPTO_AESSuite;
    }
    else
    if ( EqualOID( aes256CBC_OID, encryptAlgoOID))
    {
        *keyLength = 32;
        *ppBulkEncryptionAlgo = &CRYPTO_AESSuite;
    }
    else
        /* add others here if necessary */
#endif
    {
        return ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

    return OK;
}


/*--------------------------------------------------------------------------*/

extern MSTATUS
PKCS7_EnvelopData( MOC_HW(hwAccelDescr hwAccelCtx)
                    DER_ITEMPTR pStart, /* can be null */
                    DER_ITEMPTR pParent,
                    ASN1_ITEMPTR pCACertificatesParseRoots[/*numCACerts*/],
                    CStream pStreams[/*numCACerts*/],
                    sbyte4 numCACerts,
                    const ubyte* encryptAlgoOID,
                    RNGFun rngFun,
                    void* rngFunArg,
                    const ubyte* pPayLoad,
                    ubyte4 payLoadLen,
                    ubyte** ppEnveloped,
                    ubyte4* pEnvelopedLen)
{
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__
    ubyte isOaep = 1;
    ubyte4 oaepHashAlgo = (ubyte4) gRsaHashTable[RSA_OAEP_HASH_ALGO_DEFAULT_INDEX].hashId;
    sbyte *pOaepLabel = (sbyte *) RSA_OAEP_LABEL_DEFAULT;
#else
    ubyte isOaep = 0;
    ubyte4 oaepHashAlgo = 0;
    sbyte *pOaepLabel = NULL;
#endif

    return PKCS7_EnvelopDataWoaep(MOC_HW(hwAccelCtx) pStart, pParent, pCACertificatesParseRoots, pStreams, numCACerts, encryptAlgoOID,
                                  rngFun, rngFunArg, isOaep, oaepHashAlgo, pOaepLabel, pPayLoad, payLoadLen, ppEnveloped, pEnvelopedLen);
}

extern MSTATUS
PKCS7_EnvelopDataWoaep( MOC_HW(hwAccelDescr hwAccelCtx)
                        DER_ITEMPTR pStart, /* can be null */
                        DER_ITEMPTR pParent,
                        ASN1_ITEMPTR pCACertificatesParseRoots[/*numCACerts*/],
                        CStream pStreams[/*numCACerts*/],
                        sbyte4 numCACerts,
                        const ubyte* encryptAlgoOID,
                        RNGFun rngFun,
                        void* rngFunArg,
                        ubyte isOaep, 
                        ubyte4 oaepHashAlgo, 
                        sbyte *pOaepLabel,
                        const ubyte* pPayLoad,
                        ubyte4 payLoadLen,
                        ubyte** ppEnveloped,
                        ubyte4* pEnvelopedLen)
{
    MSTATUS         status = OK;
    DER_ITEMPTR     pEnvelopedData = 0;
    DER_ITEMPTR     pTemp,
                    pEncryptionAlgo,
                    pEncryptedPayload,
                    pRecipientInfos;
    ubyte*          pPlaceHolderData;
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte           iv[MAX_IV_LENGTH]; /* IV generation */
    ubyte           encryptKey[MAX_ENC_KEY_LENGTH];  /* big enough for AES-256 */
    sbyte4          i, keyLength, padSize = 0;
    const BulkEncryptionAlgo* pBulkEncryptionAlgo;
    AsymmetricKey   key;
    ubyte4          envelopedBufferLen;
    ubyte*          envelopedBuffer = 0;
    ubyte*          pCryptoBuf = NULL;
    ubyte*          pCryptoIv = NULL;

    if ( !pCACertificatesParseRoots || !pPayLoad || !ppEnveloped || !pEnvelopedLen || !rngFun)
    {
        return ERR_NULL_POINTER;
    }

    if ( OK > ( status = CRYPTO_initAsymmetricKey( &key)))
        goto exit;

    if ( OK > ( status = PKCS7_GetCryptoAlgoParams( encryptAlgoOID,
                                                    &pBulkEncryptionAlgo,
                                                    &keyLength)))
    {
        goto exit;
    }

    /* generate key and iv */
    if ( OK != (status = (MSTATUS) rngFun( rngFunArg, keyLength, encryptKey)))
        goto exit;

    if ( pBulkEncryptionAlgo->blockSize)
    {
        if ( OK != (status = (MSTATUS) rngFun( rngFunArg, pBulkEncryptionAlgo->blockSize, iv)))
            goto exit;
    }

    if ( OK > ( status = DER_AddSequence( pParent, &pEnvelopedData)))
        goto exit;

    /* version = 0 */
    copyData[0] = 0;
    if ( OK > ( status = DER_AddItem( pEnvelopedData, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* recipient information */
    if ( OK > ( status = DER_AddSet( pEnvelopedData, &pRecipientInfos)))
        goto exit;

    /* for each certificate, add a recipient info */
    for ( i = 0; i < numCACerts; ++i)
    {
        ASN1_ITEMPTR pCurrCert = ASN1_FIRST_CHILD(pCACertificatesParseRoots[i]);
        if ( OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                                pCurrCert,
                                                                pStreams[i], &key)))
        {
            goto exit;
        }

        if (akt_rsa == key.type)
	    {
#ifndef __DISABLE_DIGICERT_RSA__
            if (OK > ( status = PKCS7_AddRSARecipientInfo(MOC_RSA(hwAccelCtx)
                                    pRecipientInfos, key.key.pRSA,
                                    encryptKey, keyLength,
                                    pCurrCert, pStreams[i],
                                    rngFun, rngFunArg,
                                    isOaep, oaepHashAlgo, pOaepLabel)))
            {
                goto exit;
            }
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
        }
#ifdef __ENABLE_DIGICERT_ECC__
        else if ( akt_ecc == key.type)
        {
            /* need to change the version */
            if (copyData[0] < 2)
                copyData[0] = 2;

            if (OK > ( status = PKCS7_AddECDHRecipientInfo(MOC_HW(hwAccelCtx)
                                    pRecipientInfos, &key,
                                    pBulkEncryptionAlgo,
                                    encryptKey, keyLength,
                                    pCurrCert, pStreams[i], 0,
                                    rngFun, rngFunArg)))
            {
                goto exit;
            }
        }
#endif
        else
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
            goto exit;
        }

        if ( OK > ( status = CRYPTO_uninitAsymmetricKey(&key, NULL)))
            goto exit;
    }

    /* Encrypted Content Info */
    if ( OK > ( status = DER_AddSequence( pEnvelopedData, &pTemp)))
        goto exit;

    /* content type */
    if ( OK > ( status = DER_AddOID( pTemp, pkcs7_data_OID, NULL)))
        goto exit;

    /* encryption algo */
    if ( OK > ( status = DER_AddSequence( pTemp, &pEncryptionAlgo)))
        goto exit;

    if ( OK > ( status = DER_AddOID( pEncryptionAlgo, encryptAlgoOID, NULL)))
        goto exit;

    if ( pBulkEncryptionAlgo->blockSize > 0)
    {
        if ( OK > ( status = DER_AddItem( pEncryptionAlgo, OCTETSTRING,
                                        pBulkEncryptionAlgo->blockSize, iv, NULL)))
        {
            goto exit;
        }
        padSize = pBulkEncryptionAlgo->blockSize - ( payLoadLen % pBulkEncryptionAlgo->blockSize);
        if ( 0 == padSize) padSize = pBulkEncryptionAlgo->blockSize;
    }
    else
    {
        if ( OK > ( status = DER_AddItem( pEncryptionAlgo, NULLTAG, 0, NULL, NULL)))
            goto exit;
        padSize = 0;
    }

    /* now add the encrypted payload tag [0] place holder for now */
    if ( OK > ( status = DER_AddItem( pTemp, (CONTEXT|0), payLoadLen + padSize,
                                        NULL, &pEncryptedPayload )))
    {
        goto exit;
    }
    /* write everything to our buffer */
    if ( OK > ( status = DER_Serialize( pStart ? pStart : pEnvelopedData,
                                        &envelopedBuffer, &envelopedBufferLen)))
    {
        goto exit;
    }

    /* fill-in the place holders */
    /* encrypted payload */
    if  ( OK > ( status = DER_GetSerializedDataPtr( pEncryptedPayload, &pPlaceHolderData)))
        goto exit;

#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    DIGI_MEMCPY( pPlaceHolderData, pPayLoad, payLoadLen);
    pCryptoBuf = pPlaceHolderData;
#else
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, payLoadLen + padSize, TRUE, &pCryptoBuf)))
        goto exit;

    DIGI_MEMCPY(pCryptoBuf , pPayLoad, payLoadLen);
#endif

    /* add padding */
    for (i = 0; i < padSize; ++i)
    {
        pCryptoBuf[payLoadLen+i] = (ubyte) padSize;
    }

#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    pCryptoIv = iv;
#else
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 16, TRUE, &pCryptoIv)))
        goto exit;

    DIGI_MEMCPY(pCryptoIv , iv, 16);
#endif

    /* encrypt in place */
    if (OK > ( status = CRYPTO_Process(MOC_SYM(hwAccelCtx) pBulkEncryptionAlgo,
                            encryptKey, keyLength, pCryptoIv, pCryptoBuf, payLoadLen + padSize, 1)))
    {
        goto exit;
    }

    /* copy back the encrypted buffer */
    DIGI_MEMCPY(pPlaceHolderData, pCryptoBuf, payLoadLen + padSize);

    /* return the buffer */
    *ppEnveloped = envelopedBuffer;
    envelopedBuffer = NULL;
    *pEnvelopedLen = envelopedBufferLen;

exit:
#ifdef __DISABLE_DIGICERT_HARDWARE_ACCEL__
    /* nothing to do */
#else
    if (pCryptoBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pCryptoBuf);
    if (pCryptoIv)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pCryptoIv);
#endif

    if ( envelopedBuffer)
    {
        FREE( envelopedBuffer);
    }

    /* if there was no parent specified delete the DER tree */
    if ( !pParent && pEnvelopedData)
    {
        TREE_DeleteTreeItem( (TreeItem*) pEnvelopedData);
    }

    /* clear the key on the stack */
    DIGI_MEMSET( encryptKey, 0, MAX_ENC_KEY_LENGTH);

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    return status;
}


/*------------------------------------------------------------------*/
static MSTATUS
PKCS7_AddItem2( DER_ITEMPTR pParent,
               const ubyte* pPayLoad, ubyte4 payLoadLen,
               DER_ITEMPTR *ppNewItem)
{
    MSTATUS status;
    ASN1_ITEMPTR pRootItem, pPayLoadItem;
    CStream payLoadStream;
    const ubyte* payLoadMemAccessBuffer = NULL;
    MemFile memFile;

    /* a. construct the ASN1 item for the payload */
    MF_attach(&memFile, payLoadLen, (ubyte*) pPayLoad);
    CS_AttachMemFile(&payLoadStream, &memFile );

    if (OK > (status = ASN1_Parse(payLoadStream, &pRootItem)))
    {
        goto exit;
    }
    pPayLoadItem = ASN1_FIRST_CHILD(pRootItem);
    if (!pPayLoadItem)
    {
        status = ERR_ASN;
        goto exit;
    }
    /* b. do CS_memaccess on the dataOffset of the ASN1_ITEM: */
    payLoadMemAccessBuffer = (const ubyte *) CS_memaccess( payLoadStream, pPayLoadItem->dataOffset, pPayLoadItem->length);
    if ( !payLoadMemAccessBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* c. add it with the enclosing tag SEQUENCE to the parent item: */
    if ( OK > ( status = DER_AddItem( pParent, (CONSTRUCTED|SEQUENCE), pPayLoadItem->length, payLoadMemAccessBuffer, ppNewItem)))
        goto exit;

exit:
    if (pRootItem)
    {
        TREE_DeleteTreeItem((TreeItem *) pRootItem);
    }

    /* d. stop memaccess */
    if (payLoadMemAccessBuffer)
    {
        CS_stopaccess( payLoadStream, payLoadMemAccessBuffer);
    }
    return status;
}

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__)

/*------------------------------------------------------------------*/
static MSTATUS
CMC_AddContentInfo(DER_ITEMPTR pParent,
               const ubyte* payLoadType, /* OID, if NULL, degenerate case */
               const ubyte* pPayLoad, /* if payLoadType is not NULL, pPayLoad is NULL, external signatures */
               ubyte4 payLoadLen,
               DER_ITEMPTR *ppContentInfo)
{
    MSTATUS status;
    DER_ITEMPTR pContentInfo, pTempItem;

    if ( OK > ( status = DER_AddSequence( pParent, &pContentInfo)))
        goto exit;

        /* content type */
    if ( OK > ( status = DER_AddOID( pContentInfo, payLoadType, NULL)))
        goto exit;
    if (pPayLoad && payLoadLen > 0)
    {
        /* content */
        if ( OK > ( status = DER_AddTag( pContentInfo, 0, &pTempItem)))
            goto exit;

        /* Add pkiData as an OCTETSTRING */
        if ( OK > ( status = DER_AddItem( pTempItem, PRIMITIVE|OCTETSTRING, payLoadLen, pPayLoad, &pTempItem)))
            goto exit;
    }

    if (ppContentInfo)
    {
        *ppContentInfo = pContentInfo;
    }

exit:
    return status;
}

#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) */

/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddContentInfo(DER_ITEMPTR pParent,
               const ubyte* payLoadType, /* OID, if NULL, degenerate case */
               const ubyte* pPayLoad, /* if payLoadType is not NULL, pPayLoad is NULL, external signatures */
               ubyte4 payLoadLen,
               DER_ITEMPTR *ppContentInfo)
{
    MSTATUS status;
    DER_ITEMPTR pContentInfo, pTempItem;
    sbyte4 cmpResult;

    if ( OK > ( status = DER_AddSequence( pParent, &pContentInfo)))
        goto exit;

    if (payLoadType)
    {
        /* content type */
        if ( OK > ( status = DER_AddOID( pContentInfo, payLoadType, NULL)))
            goto exit;
       if (pPayLoad && payLoadLen > 0)
       {
           /* content */
           if ( OK > ( status = DER_AddTag( pContentInfo, 0, &pTempItem)))
               goto exit;

           DIGI_CTIME_MATCH(payLoadType, pkcs7_data_OID, pkcs7_data_OID[0], &cmpResult);

           if (cmpResult == 0) /* data */
           {
               if ( OK > ( status = DER_AddItem( pTempItem, PRIMITIVE|OCTETSTRING, payLoadLen, pPayLoad, &pTempItem)))
                   goto exit;
           }
           else
           {
               if (OK > (status = PKCS7_AddItem2(pTempItem, pPayLoad, payLoadLen, NULL)))
                   goto exit;
           }
       }
    }
    else
    {
        /* content type will be data in the degenerate case */
        if ( OK > ( status = DER_AddOID( pContentInfo, pkcs7_data_OID, NULL)))
            goto exit;
    }

    if (ppContentInfo)
    {
        *ppContentInfo = pContentInfo;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddItem1(DER_ITEMPTR pParent,
               CStream cs, ASN1_ITEMPTR pRootItem,
               DER_ITEMPTR *ppNewItem)
{
    MSTATUS status;
    const ubyte* memAccessBuffer;
    ASN1_ITEMPTR pItem;

    pItem = ASN1_FIRST_CHILD(pRootItem);
    memAccessBuffer = (const ubyte *) CS_memaccess(cs, pItem->dataOffset, pItem->length);
    if ( !memAccessBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if ( OK > ( status = DER_AddItem( pParent, (ubyte) (pItem->id|pItem->tag),
                                     pItem->length, memAccessBuffer, ppNewItem)))
    {
        goto exit;
    }
exit:
    if (memAccessBuffer)
    {
        CS_stopaccess( cs, memAccessBuffer);
    }
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(DER_ITEMPTR pParent,
                                           ubyte tag, ubyte4 setOrSequence,
                                           CStream *itemStreams,
                                           ASN1_ITEMPTR *ppRootItems, ubyte4 numItems,
                                           DER_ITEMPTR *ppChild)
{
    MSTATUS status;
    DER_ITEMPTR pChild, pTempItem = NULL;
    ubyte4 i;

    if (0 == numItems)
    {
        status = ERR_PKCS7;
        goto exit;
    }

    if ( OK > ( status = DER_AddTag( pParent, tag, &pChild)))
        goto exit;

    if (setOrSequence == MOC_SET)
    {
        if ( OK > ( status = DER_AddSet( pChild, &pTempItem)))
            goto exit;
    }
    else if (setOrSequence == SEQUENCE)
    {
        if ( OK > ( status = DER_AddSequence( pChild, &pTempItem)))
            goto exit;
    }
    else
    {
        /* IMPLICIT type MOC_SET or SEQUENCE */
        pTempItem = pChild;
    }
    for ( i = 0; i < numItems; ++i)
    {
        if (OK > (status = PKCS7_AddItem1(pTempItem, itemStreams[i], ppRootItems[i], NULL)))
            goto exit;
    }
    if (ppChild)
    {
        *ppChild = pChild;
    }
exit:
    return status;
}



/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddAttributeEx(DER_ITEMPTR pParent, const ubyte* typeOID,
                   const ubyte valueType, const ubyte* value, ubyte4 valueLen,
                   intBoolean derBuffer, DER_ITEMPTR *ppAttribute)
{
    MSTATUS status;
    DER_ITEMPTR pAttribute, pTempItem;

    if ( OK > ( status = DER_AddSequence( pParent, &pAttribute)))
        goto exit;

    if ( OK > ( status = DER_AddOID( pAttribute, typeOID, NULL)))
        goto exit;

    if ( OK > ( status = DER_AddSet( pAttribute, &pTempItem)))
        goto exit;

    if (derBuffer)
    {
        if ( OK > ( status = DER_AddDERBuffer( pTempItem, valueLen, value, NULL)))
            goto exit;
    }
    else
    {
        if ( OK > ( status = DER_AddItem( pTempItem, valueType, valueLen, value, NULL)))
            goto exit;
    }

    if (ppAttribute)
    {
        *ppAttribute = pAttribute;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddAttribute(DER_ITEMPTR pParent, const ubyte* typeOID,
                   const ubyte valueType, const ubyte* value, ubyte4 valueLen,
                   DER_ITEMPTR *ppAttribute)
{
    return PKCS7_AddAttributeEx(pParent, typeOID, valueType,
                                value, valueLen, 0, ppAttribute);
}


/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddIssuerAndSerialNumber(DER_ITEMPTR pParent,
                               CStream cs,
                               ASN1_ITEMPTR pIssuer,
                               ASN1_ITEMPTR pSerialNumber,
                               DER_ITEMPTR *ppIssuerAndSerialNumber)
{
    MSTATUS status;
    DER_ITEMPTR pIssuerAndSerialNumber;

    if (OK > (status = DER_AddSequence(pParent, &pIssuerAndSerialNumber)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pIssuer, cs, NULL)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pIssuerAndSerialNumber, pSerialNumber, cs, NULL)))
        goto exit;

    if (ppIssuerAndSerialNumber)
    {
        *ppIssuerAndSerialNumber = pIssuerAndSerialNumber;
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
/**
@brief      This function generates RSA signature and add it to the signerInfo Item.

@details    This function generates RSA Signature and adds the signature
            to the signerinfo. This API also supports TAP key for RSA Sign.
            Based on the keytype it calls appropriate RSA Sign API.

@param pSignerInfoItem   Pointer to the signerInfo Item.
@param pAsymKey          Pointer to the Asymmetric Key
@param digestAlgoOID     Pointer to the sign algo OID.
@param digest            Pointer to the digest to be signed.
@param digestLen         Length of the digest input
@param ppSignature       On return, signature output.
@param pSignatureLen     On return, length of the signature output.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

*/
static MSTATUS
PKCS7_AddRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfoItem, const AsymmetricKey *pAsymKey,
                      CMS_SignData signCallback, void* pCbInfo,
                      const ubyte *plainData, ubyte4 plainDataLen,
                      const ubyte* digestAlgoOID,
                      const ubyte* digest, ubyte4 digestLen,
                      ubyte** ppSignature, ubyte4* pSignatureLen)
#else
static MSTATUS
PKCS7_AddRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfoItem, const RSAKey* pRSA,
                      CMS_SignData signCallback, void* pCbInfo,
                      const ubyte* digestAlgoOID,
                      const ubyte* digest, ubyte4 digestLen,
                      ubyte** ppSignature, ubyte4* pSignatureLen)
#endif
{
    MSTATUS status;
    DER_ITEMPTR pDigestInfo = 0;
    ubyte* pDerDigestInfo = 0;
    ubyte4 derDigestInfoLen;
    ubyte* pEncryptedDigest = 0;
    ubyte4 encryptedDigestLen;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    void *pRSA = NULL;
#if !defined(__DISABLE_DIGICERT_RSA_SIGN__) && defined(__ENABLE_DIGICERT_TAP__)
    ubyte keyUsage = 0;
#endif

    if (pAsymKey->type == akt_tap_rsa)
    {
        pRSA = (void*)pAsymKey->key.pMocAsymKey;
    }
    else
    {
        pRSA = (void*)pAsymKey->key.pRSA;
    }
#endif

    /* for callback signing we pass raw digest, no digestInfo */
    if (NULL == signCallback)
    {
        /* create a DigestInfo */
        if ( OK > ( status = DER_AddSequence ( NULL, &pDigestInfo)))
            goto exit;

        if ( OK > ( status = DER_StoreAlgoOID ( pDigestInfo, digestAlgoOID,
                                                TRUE)))
        {
            goto exit;
        }
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */

        if ( OK > ( status = DER_AddItem( pDigestInfo, OCTETSTRING,
                                        digestLen, digest, NULL)))
        {
            goto exit;
        }

        if ( OK > ( status = DER_Serialize( pDigestInfo, &pDerDigestInfo,
                                            &derDigestInfoLen)))
        {
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK != (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelCtx) pRSA, (sbyte4 *) &encryptedDigestLen, pAsymKey->type)))
    {
        goto exit;
    }
#else
    if ( OK > ( status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSA,
                                    (sbyte4 *)(&encryptedDigestLen))))
    {
        goto exit;
    }
#endif

    pEncryptedDigest = MALLOC(encryptedDigestLen);
    if ( !pEncryptedDigest)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == signCallback)
    {
#ifndef __DISABLE_DIGICERT_RSA_SIGN__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_TAP__
        if (OK != (status = CRYPTO_INTERFACE_getKeyUsage(pRSA, pAsymKey->type, &keyUsage)))
        {
            goto exit;
        }
        if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
        {
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageEx(MOC_RSA(hwAccelCtx) pRSA,
                            plainData, plainDataLen,
                            pEncryptedDigest, NULL, pAsymKey->type)))
            {
                goto exit;
            }

        }
        else
#endif
        {
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(hwAccelCtx) pRSA,
                            pDerDigestInfo, derDigestInfoLen,
                            pEncryptedDigest, NULL, pAsymKey->type)))
            {
                goto exit;
            }
        }
#else
        if ( OK > ( status = RSA_signMessage(MOC_RSA(hwAccelCtx) pRSA,
            pDerDigestInfo, derDigestInfoLen, pEncryptedDigest, NULL)))
        {
            goto exit;
        }
#endif
#endif
    }
    else
    {
        status = signCallback(pCbInfo, digestAlgoOID, digest, digestLen,    
                              pEncryptedDigest, encryptedDigestLen);
        if (OK != status)
            goto exit;                      
    }

    /* add the encrypted digest as an OCTET string */
    if ( OK > ( status = DER_AddItem( pSignerInfoItem, OCTETSTRING, encryptedDigestLen,
                                        pEncryptedDigest, NULL)))
    {
        goto exit;
    }

    *ppSignature = pEncryptedDigest;
    pEncryptedDigest = 0;
    *pSignatureLen = encryptedDigestLen;

exit:

    if (pEncryptedDigest)
    {
        FREE(pEncryptedDigest);
    }

    if (pDerDigestInfo)
    {
        FREE(pDerDigestInfo);
    }

    if (pDigestInfo)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDigestInfo);
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
/**
@brief      This function generates ECDSA signature and add it to the signerInfo Item.

@details    This function generates ECDSA Signature and adds the signature
            to the signerinfo. This API also supports TAP key for ECDSA Sign.
            Based on the keytype it calls appropriate ECDSA Sign API.

@param pSignerInfoItem   Pointer to the signerInfo Item.
@param pAsymKey          Pointer to the Asymmetric Key.
@param rngFun            Random function callback.
@param rngArg            Argument to the random function callback.
@param hash              Pointer to the digest to be signed.
@param hashLen           Length of the digest input
@param ppSignature       On return, signature output.
@param pSignatureLen     On return, length of the signature output.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS PKCS7_AddECDSASignature(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    DER_ITEMPTR pSignerInfoItem,
    AsymmetricKey *pAsymKey,
    CMS_SignData signCallback,
    void* pCbInfo,
    const ubyte *plainData,
    ubyte4 plainDataLen,
    RNGFun rngFun,
    void* rngArg,
    const ubyte* hash,
    ubyte4 hashLen,
    ubyte** ppSignature,
    ubyte4* pSignatureLen
    )
#else
static MSTATUS
PKCS7_AddECDSASignature(MOC_ECC(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfoItem, ECCKey* pECCKey,
                      CMS_SignData signCallback, void* pCbInfo,
                      RNGFun rngFun, void* rngArg,
                      const ubyte* hash, ubyte4 hashLen,
                      ubyte** ppSignature, ubyte4* pSignatureLen)
#endif
{
    DER_ITEMPTR pTempItem;
    DER_ITEMPTR pTempSeq = 0;
    ubyte* pSignatureBuffer = 0;
    sbyte4 elementLen;
    ubyte* pRBuffer;
    ubyte* pSBuffer;
    MSTATUS status;
    ubyte *pBuffer = NULL;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ECCKey *pKey = pAsymKey->key.pECC;
    ubyte4 signatureLen;
#else
    PFEPtr sig_r = 0, sig_s = 0;
    PrimeFieldPtr pPF = { 0 };
#endif

    /* Allocate memory to hold the signature.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
            pKey, (ubyte4 *) &elementLen, pAsymKey->type)))
        goto exit;

    if (OK > (status = DIGI_MALLOC((void **) &pBuffer, elementLen * 2)))
        goto exit;
#else
    pPF = EC_getUnderlyingField( pECCKey->pCurve);

    if (OK > ( status = PRIMEFIELD_newElement( pPF, &sig_r)))
        goto exit;
    if (OK > ( status = PRIMEFIELD_newElement( pPF, &sig_s)))
        goto exit;

    if ( OK > ( status = PRIMEFIELD_getElementByteStringLen( pPF, &elementLen)))
        goto exit;
#endif

    if (NULL == signCallback)
    {
        /* Perform the sign operation. */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifdef __ENABLE_DIGICERT_TAP__
        ubyte keyUsage = 0;
        if (OK != (status = CRYPTO_INTERFACE_getKeyUsage(
                pKey, pAsymKey->type, &keyUsage)))
        {
            goto exit;
        }
        if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
        {
            if (OK > (status = CRYPTO_INTERFACE_ECDSA_signMessage(
                    pKey, rngFun, rngArg, (ubyte *)plainData, plainDataLen,
                    pBuffer, elementLen * 2, &signatureLen,
                    pAsymKey->type)))
                goto exit;
        }
        else
#endif
        {
            if (OK > (status = CRYPTO_INTERFACE_ECDSA_signDigest( MOC_ECC(hwAccelCtx)
                    pKey, rngFun, rngArg, (ubyte *)hash, hashLen, pBuffer,
                    elementLen * 2, &signatureLen, pAsymKey->type)))
                goto exit;
        }

#else
        if (OK > ( status = ECDSA_signDigestAux( pECCKey->pCurve,
                                pECCKey->k,
                                rngFun, rngArg,
                                hash, hashLen,
                                sig_r, sig_s)))
        {
            goto exit;
        }
#endif
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        status = DIGI_MALLOC((void **) &pBuffer, elementLen * 2);
        if (OK != status)
            goto exit;
#endif
        status = signCallback(pCbInfo, NULL, hash, hashLen,    
                              pBuffer, elementLen * 2);
        if (OK != status)
            goto exit;                      
    }

    /* Allocate memory for the signature. Two extra bytes are required to
     * handle the ASN.1 encoding
     */
    pSignatureBuffer = MALLOC( 2 + 2 * elementLen);
    if (! pSignatureBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Set the leading bytes for r and s as 0
     */
    pRBuffer = pSignatureBuffer;
    *pRBuffer = 0x00; /* leading 0 */
    pSBuffer = pSignatureBuffer + 1 + elementLen;
    *pSBuffer = 0x00; /* leading 0 */

    /* Copy over the signature into the R and S buffers
     */
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL == signCallback)
    {
        /* write R */
        if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, sig_r, pRBuffer+1, elementLen)))
            goto exit;

        /* write S */
        if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, sig_s, pSBuffer+1, elementLen)))
            goto exit;
    }
    else
#endif
    {
        if (OK > (status = DIGI_MEMCPY(pRBuffer + 1, pBuffer, elementLen)))
            goto exit;

        if (OK > (status = DIGI_MEMCPY(pSBuffer + 1, pBuffer + elementLen, elementLen)))
            goto exit;
    }

    /* create a sequence with the two integer -> signature */
    if (OK > ( status = DER_AddSequence( NULL, &pTempSeq)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, elementLen + 1, pRBuffer, NULL)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, elementLen + 1, pSBuffer, NULL)))
        goto exit;

    /* serialize the sequence */
    if (OK > ( status = DER_Serialize( pTempSeq, ppSignature, pSignatureLen)))
        goto exit;

    /* add the DER encoded buffer -- signature -- as is */
    if (OK > (status = DER_AddItem( pSignerInfoItem, OCTETSTRING, 0, NULL, &pTempItem)))
        goto exit;

    if (OK > ( status = DER_AddDERBuffer( pTempItem, *pSignatureLen, *ppSignature, NULL)))
        goto exit;

exit:

    if (pTempSeq)
    {
        TREE_DeleteTreeItem( (TreeItem*) pTempSeq);
    }

    FREE(pSignatureBuffer);
    FREE(pBuffer);

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    PRIMEFIELD_deleteElement( pPF, &sig_r);
    PRIMEFIELD_deleteElement( pPF, &sig_s);
#endif

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS
PKCS7_AddQsSignature(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfoItem, QS_CTX *pCtx,
                     CMS_SignData signCallback, void* pCbInfo,
                     RNGFun rngFun, void* rngArg,
                     const ubyte* hash, ubyte4 hashLen,
                     ubyte** ppSignature, ubyte4* pSignatureLen)
{
    DER_ITEMPTR pTempSeq = NULL;
    DER_ITEMPTR pTempItem = NULL;
    ubyte* pSig = 0;
    ubyte4 sigLen = 0;
    MSTATUS status;

    /* Allocate memory to hold the signature.
     */
    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pCtx, &sigLen);
    if (OK != status)
        goto exit;

    /* Add an initial 0x00 byte for the BITSTRING type */
    status = DIGI_MALLOC((void **) &pSig, sigLen + 1);
    if (OK != status)
        goto exit;

    pSig[0] = 0;
    if (NULL == signCallback)
    {
        status = CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(hwAccelCtx) pCtx, rngFun, rngArg, (ubyte *) hash, hashLen,
                                              pSig + 1, sigLen, &sigLen);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = signCallback(pCbInfo, NULL, hash, hashLen, pSig + 1, sigLen);
        if (OK != status)
            goto exit;                      
    }

    /* create a sequence with the bit string */
    status = DER_AddSequence( NULL, &pTempSeq);
    if (OK != status)
        goto exit;

    /* use AddItem so unneeded zero bits are kept and bits are not reversed */
    status = DER_AddItem (pTempSeq, BITSTRING, sigLen + 1, pSig, NULL);
    if (OK != status)
        goto exit;
    
    /* serialize the sequence */
    status = DER_Serialize( pTempSeq, ppSignature, pSignatureLen);
    if (OK != status)
        goto exit;

    /* add the DER encoded buffer -- signature -- as an octet string */
    status = DER_AddItem( pSignerInfoItem, OCTETSTRING, 0, NULL, &pTempItem);
    if (OK != status)
        goto exit;

    status = DER_AddDERBuffer( pTempItem, *pSignatureLen, *ppSignature, NULL);

exit:

    if (NULL != pSig)
    {
        (void) DIGI_MEMSET_FREE(&pSig, sigLen + 1);
    }

    if (NULL != pTempSeq)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pTempSeq);
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_DSA__
static MSTATUS
PKCS7_AddDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                      DER_ITEMPTR pSignerInfoItem, DSAKey* pDSAKey,
                      CMS_SignData signCallback, void* pCbInfo,
                      RNGFun rngFun, void* rngArg,
                      const ubyte* hash, ubyte4 hashLen,
                      ubyte** ppSignature, ubyte4* pSignatureLen)
{
    DER_ITEMPTR pTempItem;
    DER_ITEMPTR pTempSeq = 0;
    vlong *r = NULL, *s = NULL;
    ubyte* pSignatureBuffer = 0;
    sbyte4 rLen, sLen;
    ubyte* pRBuffer;
    ubyte* pSBuffer;
    ubyte* pBuffer = 0;
    ubyte4 elementLen = 0;
    MSTATUS status;

    if (NULL == signCallback)
    {
        if (OK > ( status = DSA_computeSignature2(MOC_DSA(hwAccelCtx) rngFun, rngArg,
                                                pDSAKey, hash, hashLen, &r, &s, NULL)))
        {
            goto exit;
        }
        /* add the signature */
        /* allocate buffer for sig_r and sig_s with leading zeroes */
        if (OK > ( status = VLONG_byteStringFromVlong( r, NULL, &rLen)))
            goto exit;
        if (OK > ( status = VLONG_byteStringFromVlong( s, NULL, &sLen)))
            goto exit;

        /* allocate 2 extra bytes for the possible zero padding */
        pSignatureBuffer = MALLOC( 2 + rLen + sLen);
        if (! pSignatureBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pRBuffer = pSignatureBuffer;
        *pRBuffer = 0x00; /* leading 0 */
        pSBuffer = pSignatureBuffer + 1 + rLen;
        *pSBuffer = 0x00; /* leading 0 */
        /* write R */
        if ( OK > ( status = VLONG_byteStringFromVlong( r, pRBuffer+1, &rLen)))
            goto exit;

        /* write S */
        if ( OK > ( status = VLONG_byteStringFromVlong( s, pSBuffer+1, &sLen)))
            goto exit;
    }
    else
    {
        status = DSA_getSignatureLength (MOC_DSA(hwAccelCtx) pDSAKey, &elementLen);
        if (OK != status)
            goto exit;

        status = DIGI_MALLOC((void **) &pBuffer, elementLen * 2); /* account for r and s */
        if (OK != status)
            goto exit;

        status = signCallback(pCbInfo, NULL, hash, hashLen,    
                              pBuffer, elementLen * 2);
        if (OK != status)
            goto exit;     

        /* allocate 2 extra bytes for the possible zero padding */
        pSignatureBuffer = MALLOC( 2 + elementLen * 2);
        if (! pSignatureBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pRBuffer = pSignatureBuffer;
        *pRBuffer = 0x00; /* leading 0 */
        pSBuffer = pSignatureBuffer + 1 + elementLen;
        *pSBuffer = 0x00; /* leading 0 */      

        status = DIGI_MEMCPY(pRBuffer + 1, pBuffer, elementLen);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pSBuffer + 1, pBuffer + elementLen, elementLen);
        if (OK != status)
            goto exit;

        rLen = elementLen;
        sLen = elementLen;
    }

    /* create a sequence with the two integer -> signature */
    if (OK > ( status = DER_AddSequence( NULL, &pTempSeq)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, rLen + 1, pRBuffer, NULL)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, sLen + 1, pSBuffer, NULL)))
        goto exit;

    /* serialize the sequence */
    if (OK > ( status = DER_Serialize( pTempSeq, ppSignature, pSignatureLen)))
        goto exit;

    /* add the DER encoded buffer -- signature -- as is */
    if (OK > (status = DER_AddItem( pSignerInfoItem, OCTETSTRING, 0, NULL, &pTempItem)))
        goto exit;

    if (OK > ( status = DER_AddDERBuffer( pTempItem, *pSignatureLen, *ppSignature, NULL)))
        goto exit;

exit:

    if (pTempSeq)
    {
        TREE_DeleteTreeItem( (TreeItem*) pTempSeq);
    }

    FREE(pSignatureBuffer);
    FREE(pBuffer);

    VLONG_freeVlong(&r, NULL);
    VLONG_freeVlong(&s, NULL);

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_DSA__) */

#ifdef __ENABLE_DIGICERT_DSA__

/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddDSADigestAlgoId(DER_ITEMPTR pSignerInfoItem, ubyte hashType)
{
    DER_ITEMPTR pOID = 0, pSequence;
    ubyte* oidBuffer = 0;
    ubyte4 oidBufferLen;
    ubyte dsaAlgoOID[1 + MAX_SIG_OID_LEN];
    MSTATUS status;

    if (OK > ( status = CRYPTO_getDSAHashAlgoOID( hashType, dsaAlgoOID)))
        goto exit;
    /* there is no parameters to the AlgoOID (even NULL) */
    if ( OK > ( status = DER_AddSequence( pSignerInfoItem, &pSequence)))
        goto exit;

    /* the memory management and the fact that OID are prefixed by their
        length makes it a bit involved... */
    /* creates a stand alone DER_ITEM with the correct OID */
    if ( OK > ( status = DER_AddOID( NULL, dsaAlgoOID, &pOID)))
        goto exit;

    /* serialize it */
    if (OK > ( status = DER_Serialize( pOID, &oidBuffer, &oidBufferLen)))
    {
        goto exit;
    }
    /* add the DER encoded buffer to pSequence transferring ownership */
    if (OK > ( status = DER_AddDERBufferOwn( pSequence, oidBufferLen, (const ubyte**) &oidBuffer, NULL)))
    {
        goto exit;
    }

exit:
    if (pOID)
    {
        TREE_DeleteTreeItem( (TreeItem*) pOID); /* don't forget to delete the stand alone DER_ITEM */
    }

    if (oidBuffer)
    {
        FREE(oidBuffer);
    }
    return status;
}
#endif


#ifdef __ENABLE_DIGICERT_ECC__

/*------------------------------------------------------------------*/

static MSTATUS
PKCS7_AddECDSADigestAlgoId(DER_ITEMPTR pSignerInfoItem, ubyte hashType)
{
    DER_ITEMPTR pOID = 0, pSequence;
    ubyte* oidBuffer = 0;
    ubyte4 oidBufferLen;
    ubyte ecdsaAlgoOID[1 + MAX_SIG_OID_LEN];
    MSTATUS status;

    if (OK > ( status = CRYPTO_getECDSAHashAlgoOID( hashType, ecdsaAlgoOID)))
        goto exit;
    /* RFC 5008 says that there is no parameters to the AlgoOID (even NULL) */
    if ( OK > ( status = DER_AddSequence( pSignerInfoItem, &pSequence)))
        goto exit;

    /* the memory management and the fact that OID are prefixed by their
        length makes it a bit involved... */
    /* creates a stand alone DER_ITEM with the correct OID */
    if ( OK > ( status = DER_AddOID( NULL, ecdsaAlgoOID, &pOID)))
        goto exit;

    /* serialize it */
    if (OK > ( status = DER_Serialize( pOID, &oidBuffer, &oidBufferLen)))
    {
        goto exit;
    }
    /* add the DER encoded buffer to pSequence transferring ownership */
    if (OK > ( status = DER_AddDERBufferOwn( pSequence, oidBufferLen, (const ubyte**) &oidBuffer, NULL)))
    {
        goto exit;
    }

exit:
    if (pOID)
    {
        TREE_DeleteTreeItem( (TreeItem*) pOID); /* don't forget to delete the stand alone DER_ITEM */
    }

    if (oidBuffer)
    {
        FREE(oidBuffer);
    }
    return status;
}
#endif

/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__)

static MSTATUS
CMC_AddSubjectKeyIdentifier(DER_ITEMPTR pParent,
                               CStream cs,
                               ASN1_ITEMPTR pSubjectKeyIdentifier,
                               DER_ITEMPTR *ppSubjectKeyIdentifier)
{
    MSTATUS status;
    DER_ITEMPTR pSKI;

    if (OK > (status = DER_AddTag(pParent, 0, &pSKI)))
        goto exit;

    if ( OK > (status = DER_AddASN1Item( pSKI, pSubjectKeyIdentifier, cs, NULL)))
        goto exit;

    if (ppSubjectKeyIdentifier)
    {
        *ppSubjectKeyIdentifier = pSKI;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
CMC_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfosItem,
                        cmcSignerInfoPtr pCmcSignerInfo, SignedDataHash* pHash,
                        ubyte *plainData, ubyte4 plainDataLen,
                        RNGFun rngFun, void* rngArg,
                        ubyte* payLoadType, ubyte** ppDataBuffer )
#else
static MSTATUS
CMC_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfosItem,
                        cmcSignerInfoPtr pCmcSignerInfo, SignedDataHash* pHash,
                        RNGFun rngFun, void* rngArg,
                        ubyte* payLoadType, ubyte** ppDataBuffer )
#endif
{
    MSTATUS         status;
    DER_ITEMPTR     pSignerInfoItem, pAttributeItem;
    DER_ITEMPTR     pSetOf = NULL;
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte           *pTempBuf = NULL;
    ubyte*          pDerAttributes = 0;
    ubyte4          derAttributesLen = 0;
    ubyte4          i;
    AttributeNode   *pAttrList = NULL;
    AttributeNode   *pIter = NULL;
    Attribute       contentType = {0};
    Attribute       messageDigest = {0};
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
#endif

    if (pCmcSignerInfo == NULL || pCmcSignerInfo->pSignerInfo == NULL)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ( OK > ( status = DER_AddSequence( pSignerInfosItem, &pSignerInfoItem)))
        goto exit;
    /*
      RFC 5652
      version is the syntax version number.  If the SignerIdentifier is
      the CHOICE issuerAndSerialNumber, then the version MUST be 1.  If
      the SignerIdentifier is subjectKeyIdentifier, then the version
      MUST be 3.

     */
    if (NULL == pCmcSignerInfo->pSubjectKeyIdentifier)
    {
         /* signer info version = 1 */
        copyData[0] = 1;
        if ( OK > ( status = DER_AddItemCopyData( pSignerInfoItem, INTEGER, 1, copyData, NULL)))
            goto exit;

        /* isssuerAndSerialNumber */
        if (OK > (status = PKCS7_AddIssuerAndSerialNumber(pSignerInfoItem,
                                        pCmcSignerInfo->pSignerInfo->cs, pCmcSignerInfo->pSignerInfo->pIssuer,
                                        pCmcSignerInfo->pSignerInfo->pSerialNumber, NULL)))
        {
            goto exit;
        }
    }
    else
    {
        /* signer info version = 3 */
        copyData[0] = 3;
        if ( OK > ( status = DER_AddItemCopyData( pSignerInfoItem, INTEGER, 1, copyData, NULL)))
            goto exit;

        /* CMC_AddSubjectKeyIdentifier*/
        if (OK > (status = CMC_AddSubjectKeyIdentifier(pSignerInfoItem,
                                        pCmcSignerInfo->pSignerInfo->cs, pCmcSignerInfo->pSubjectKeyIdentifier, NULL)))
        {
            goto exit;
        }
    }
   /* digestAlgorithm */
    if ( OK > ( status = DER_StoreAlgoOID( pSignerInfoItem, pCmcSignerInfo->pSignerInfo->digestAlgoOID, TRUE)))
        goto exit;

    /* OPTIONAL authenticatedAttributes */

    if (pCmcSignerInfo->pSignerInfo->authAttrsLen > 0 ||
        !EqualOID(pkcs7_data_OID, payLoadType) )
    {
        if ( OK > ( status = DER_AddTag( pSignerInfoItem, 0, &pAttributeItem)))
            goto exit;

        /*  from PKCS #7: The Attributes value's tag is MOC_SET OF,
        * and the DER encoding of the MOC_SET OF tag,
        * rather than of the IMPLICIT [0] tag,
        * is to be digested along with the length and
        * contents octets of the Attributes value. */

        /* pSetOf is a shadow structure used to compute the attribute digest */
        if ( OK > ( status = DER_AddSet(NULL, &pSetOf)))
            goto exit;

        /* Add the attributes to a linked list in order to order them correctly */
        for (i = 0; i < pCmcSignerInfo->pSignerInfo->authAttrsLen; i++)
        {
            Attribute *pAttr = pCmcSignerInfo->pSignerInfo->pAuthAttrs + i;

            status = PKCS7_insertAttributeToSetOf(&pAttrList, pAttr);
            if (OK != status)
                goto exit;
        }

        /* Add contentType */
        contentType.type = OID;
        contentType.typeOID = pkcs9_contentType_OID;
        contentType.value = payLoadType + 1;
        contentType.valueLen = payLoadType[0];
        status = PKCS7_insertAttributeToSetOf(&pAttrList, &contentType);
        if (OK != status)
            goto exit;
        
        /* Add messageDigest */
        messageDigest.type = PRIMITIVE|OCTETSTRING;
        messageDigest.typeOID = pkcs9_messageDigest_OID;
        messageDigest.value = pHash->hashData;
        messageDigest.valueLen = pHash->hashAlgo->digestSize;
        status = PKCS7_insertAttributeToSetOf(&pAttrList, &messageDigest);
        if (OK != status)
            goto exit;

        pIter = pAttrList;

        /* Now traverse the list and add the attributes */
        while (NULL != pIter)
        {
            Attribute *pAttr = pIter->pAttr;
            if ( OK > ( status = PKCS7_AddAttribute( pAttributeItem,
                                                    pAttr->typeOID,
                                                    (ubyte)pAttr->type,
                                                    pAttr->value,
                                                    pAttr->valueLen, NULL)))
            {
                goto exit;
            }

            if ( OK > ( status = PKCS7_AddAttribute( pSetOf, 
                                                    pAttr->typeOID,
                                                    (ubyte) pAttr->type,
                                                    pAttr->value,
                                                    pAttr->valueLen, NULL)))
            {
                goto exit;
            }

            pIter = pIter->pNext;
        }

        if (OK > (status = DER_Serialize(pSetOf, &pDerAttributes, &derAttributesLen)))
            goto exit;

        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx,
                                        derAttributesLen + pHash->hashAlgo->digestSize,
                                        TRUE, &pTempBuf)))
        {
            goto exit;
        }

        if (derAttributesLen > 0)
        {
            DIGI_MEMCPY(pTempBuf, pDerAttributes, derAttributesLen);
        }

        /* compute the second message digest on the authenticated attributes if present */
        pHash->hashAlgo->initFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx);
        pHash->hashAlgo->updateFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx, pTempBuf, derAttributesLen);
        pHash->hashAlgo->finalFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx, pTempBuf + derAttributesLen);
    }

    /* digestEncrytionAlgorithm */
    if  ((akt_rsa == pCmcSignerInfo->pSignerInfo->pKey->type ) ||
        (akt_tap_rsa == pCmcSignerInfo->pSignerInfo->pKey->type))
    {
#ifndef __DISABLE_DIGICERT_RSA__
        if ( OK > ( status = DER_StoreAlgoOID( pSignerInfoItem, rsaEncryption_OID, TRUE)))
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if (akt_dsa ==  pCmcSignerInfo->pSignerInfo->pKey->type)
    {
        if ( OK > ( status = PKCS7_AddDSADigestAlgoId(pSignerInfoItem, pHash->hashType)))
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ((akt_ecc == pCmcSignerInfo->pSignerInfo->pKey->type) ||
        (akt_tap_ecc == pCmcSignerInfo->pSignerInfo->pKey->type))

    {
        if (OK > ( status = PKCS7_AddECDSADigestAlgoId(pSignerInfoItem, pHash->hashType)))
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_qs == pCmcSignerInfo->pSignerInfo->pKey->type)
    {
        ubyte4 alg = 0;

        status = CRYPTO_INTERFACE_QS_getAlg(pCmcSignerInfo->pSignerInfo->pKey->pQsCtx, &alg);
        if (OK != status)
            goto exit;

        status = CRYPTO_getAlgoOIDAlloc(0, alg, &pOid, &oidLen);
        if (OK != status)
            goto exit;
        
        status = DER_StoreAlgoOIDownData( pSignerInfoItem, oidLen, &pOid, TRUE);
        if (OK != status)
            goto exit;
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    /* encrypt message digest */
    /* encrypt Der encoded DigestInfo if RSA */
    if ((akt_rsa == pCmcSignerInfo->pSignerInfo->pKey->type) ||
        (akt_tap_rsa == pCmcSignerInfo->pSignerInfo->pKey->type))
    {
#ifndef __DISABLE_DIGICERT_RSA__
        const ubyte* toSign;
        ubyte4 dummy;

       /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        toSign =  (pCmcSignerInfo->pSignerInfo->authAttrsLen > 0 ||
                    !EqualOID(pkcs7_data_OID, payLoadType) ) ?
                    pTempBuf + derAttributesLen:
                    pHash->hashData;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerInfoItem,
                                                    pCmcSignerInfo->pSignerInfo->pKey,
                                                    NULL, NULL,
                                                    plainData, plainDataLen,
                                                    pCmcSignerInfo->pSignerInfo->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    ppDataBuffer,
                                                    &dummy)))
        {
            goto exit;
        }

#else
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerInfoItem,
                                                    pCmcSignerInfo->pSignerInfo->pKey->key.pRSA,
                                                    NULL, NULL,
                                                    pCmcSignerInfo->pSignerInfo->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    ppDataBuffer,
                                                    &dummy)))
        {
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( pCmcSignerInfo->pSignerInfo->pKey->type == akt_dsa)
    {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pCmcSignerInfo->pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }

        if (OK > ( status = PKCS7_AddDSASignature(MOC_DSA(hwAccelCtx) pSignerInfoItem,
                                pCmcSignerInfo->pSignerInfo->pKey->key.pDSA,
                                NULL, NULL, rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( (pCmcSignerInfo->pSignerInfo->pKey->type == akt_ecc) ||
              (pCmcSignerInfo->pSignerInfo->pKey->type == akt_tap_ecc))
    {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pCmcSignerInfo->pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerInfoItem,
                                pCmcSignerInfo->pSignerInfo->pKey,
                                NULL, NULL,
                                plainData, plainDataLen,
                                rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }
#else
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerInfoItem,
                                pCmcSignerInfo->pSignerInfo->pKey->key.pECC,
                                NULL, NULL, rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }
#endif
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
   else if (pCmcSignerInfo->pSignerInfo->pKey->type == akt_qs)
   {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pCmcSignerInfo->pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }

        if (OK > ( status = PKCS7_AddQsSignature( MOC_ASYM(hwAccelCtx) pSignerInfoItem,
                                                  pCmcSignerInfo->pSignerInfo->pKey->pQsCtx,
                                                  NULL, NULL,
                                                  rngFun, rngArg,
                                                  toSign, pHash->hashAlgo->digestSize,
                                                  ppDataBuffer, &dummy)))
        {
            goto exit;
        }
    }
#endif

    /* OPTIONAL unauthenticatedAttributes */

exit:

    PKCS7_freeAttributeSetOf(&pAttrList);

    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    if (pSetOf)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSetOf);
    }

    if (pDerAttributes)
    {
        FREE(pDerAttributes);
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pOid)
    {
        (void) DIGI_FREE((void **) &pOid);
    }
#endif

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) */


/*------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static MSTATUS
PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfosItem,
                        signerInfoPtr pSignerInfo, SignedDataHash* pHash,
                        ubyte *plainData, ubyte4 plainDataLen,
                        RNGFun rngFun, void* rngArg,
                        ubyte* payLoadType, ubyte** ppDataBuffer )
#else
static MSTATUS
PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignerInfosItem,
                        signerInfoPtr pSignerInfo, SignedDataHash* pHash,
                        RNGFun rngFun, void* rngArg,
                        ubyte* payLoadType, ubyte** ppDataBuffer )
#endif
{
    MSTATUS         status;
    DER_ITEMPTR     pSignerInfoItem, pAttributeItem;
    DER_ITEMPTR     pSetOf = NULL;
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte           *pTempBuf = NULL;

    ubyte*          pDerAttributes = 0;
    ubyte4          derAttributesLen = 0;
    ubyte4          i;
    AttributeNode   *pAttrList = NULL;
    AttributeNode   *pIter = NULL;
    Attribute       contentType = {0};
    Attribute       messageDigest = {0};
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte *pOid = NULL;
    ubyte4 oidLen = 0;
#endif

    if ( OK > ( status = DER_AddSequence( pSignerInfosItem, &pSignerInfoItem)))
        goto exit;

    /* signer info version = 1 */
    copyData[0] = 1;
    if ( OK > ( status = DER_AddItemCopyData( pSignerInfoItem, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* isssuerAndSerialNumber */
    if (OK > (status = PKCS7_AddIssuerAndSerialNumber(pSignerInfoItem,
                                    pSignerInfo->cs, pSignerInfo->pIssuer,
                                    pSignerInfo->pSerialNumber, NULL)))
    {
        goto exit;
    }

    /* digestAlgorithm */
    if ( OK > ( status = DER_StoreAlgoOID( pSignerInfoItem, pSignerInfo->digestAlgoOID, TRUE)))
        goto exit;

    /* OPTIONAL authenticatedAttributes */

    if (pSignerInfo->authAttrsLen > 0 ||
        !EqualOID(pkcs7_data_OID, payLoadType) )
    {
        if ( OK > ( status = DER_AddTag( pSignerInfoItem, 0, &pAttributeItem)))
            goto exit;

        /*  from PKCS #7: The Attributes value's tag is MOC_SET OF,
        * and the DER encoding of the MOC_SET OF tag,
        * rather than of the IMPLICIT [0] tag,
        * is to be digested along with the length and
        * contents octets of the Attributes value. */

        /* pSetOf is a shadow structure used to compute the attribute digest */
        if ( OK > ( status = DER_AddSet(NULL, &pSetOf)))
            goto exit;

        /* Add the attributes to a linked list in order to order them correctly */
        for (i = 0; i < pSignerInfo->authAttrsLen; i++)
        {
            Attribute *pAttr = pSignerInfo->pAuthAttrs + i;

            status = PKCS7_insertAttributeToSetOf(&pAttrList, pAttr);
            if (OK != status)
                goto exit;
        }

        /* Add contentType */
        contentType.type = OID;
        contentType.typeOID = pkcs9_contentType_OID;
        contentType.value = payLoadType + 1;
        contentType.valueLen = payLoadType[0];
        status = PKCS7_insertAttributeToSetOf(&pAttrList, &contentType);
        if (OK != status)
            goto exit;
        
        /* Add messageDigest */
        messageDigest.type = PRIMITIVE|OCTETSTRING;
        messageDigest.typeOID = pkcs9_messageDigest_OID;
        messageDigest.value = pHash->hashData;
        messageDigest.valueLen = pHash->hashAlgo->digestSize;
        status = PKCS7_insertAttributeToSetOf(&pAttrList, &messageDigest);
        if (OK != status)
            goto exit;

        pIter = pAttrList;

        /* Now traverse the list and add the attributes */
        while (NULL != pIter)
        {
            Attribute *pAttr = pIter->pAttr;
            if ( OK > ( status = PKCS7_AddAttribute( pAttributeItem,
                                                    pAttr->typeOID,
                                                    (ubyte)pAttr->type,
                                                    pAttr->value,
                                                    pAttr->valueLen, NULL)))
            {
                goto exit;
            }

            if ( OK > ( status = PKCS7_AddAttribute( pSetOf, 
                                                    pAttr->typeOID,
                                                    (ubyte) pAttr->type,
                                                    pAttr->value,
                                                    pAttr->valueLen, NULL)))
            {
                goto exit;
            }

            pIter = pIter->pNext;
        }

        if (OK > (status = DER_Serialize(pSetOf, &pDerAttributes, &derAttributesLen)))
            goto exit;

        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx,
                                        derAttributesLen + pHash->hashAlgo->digestSize,
                                        TRUE, &pTempBuf)))
        {
            goto exit;
        }

        if (derAttributesLen > 0)
        {
            DIGI_MEMCPY(pTempBuf, pDerAttributes, derAttributesLen);
        }

        /* compute the second message digest on the authenticated attributes if present */
        pHash->hashAlgo->initFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx);
        pHash->hashAlgo->updateFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx, pTempBuf, derAttributesLen);
        pHash->hashAlgo->finalFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx, pTempBuf + derAttributesLen);
    }

    /* digestEncrytionAlgorithm */
    if  ((akt_rsa == pSignerInfo->pKey->type ) ||
        (akt_tap_rsa == pSignerInfo->pKey->type))
    {
#ifndef __DISABLE_DIGICERT_RSA__
        if ( OK > ( status = DER_StoreAlgoOID( pSignerInfoItem, rsaEncryption_OID, TRUE)))
            goto exit;
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if (akt_dsa ==  pSignerInfo->pKey->type)
    {
        if ( OK > ( status = PKCS7_AddDSADigestAlgoId(pSignerInfoItem, pHash->hashType)))
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ((akt_ecc == pSignerInfo->pKey->type) ||
             (akt_tap_ecc == pSignerInfo->pKey->type))
    {
        if (OK > ( status = PKCS7_AddECDSADigestAlgoId(pSignerInfoItem, pHash->hashType)))
            goto exit;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if (akt_qs == pSignerInfo->pKey->type)
    {
        ubyte4 alg = 0;
        status = CRYPTO_INTERFACE_QS_getAlg(pSignerInfo->pKey->pQsCtx, &alg);
        if (OK != status)
            goto exit;

        status = CRYPTO_getAlgoOIDAlloc(0, alg, &pOid, &oidLen);
        if (OK != status)
            goto exit;
        
        status = DER_StoreAlgoOIDownData( pSignerInfoItem, oidLen, &pOid, TRUE);
        if (OK != status)
            goto exit;
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    /* encrypt message digest */
    /* encrypt Der encoded DigestInfo if RSA */
    if ((akt_rsa == pSignerInfo->pKey->type) ||
       (akt_tap_rsa == pSignerInfo->pKey->type))
    {
#ifndef __DISABLE_DIGICERT_RSA__
        const ubyte* toSign;
        ubyte4 dummy;

       /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        toSign =  (pSignerInfo->authAttrsLen > 0 ||
                    !EqualOID(pkcs7_data_OID, payLoadType) ) ?
                    pTempBuf + derAttributesLen:
                    pHash->hashData;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerInfoItem,
                                                    pSignerInfo->pKey,
                                                    NULL, NULL,
                                                    plainData, plainDataLen,
                                                    pSignerInfo->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    ppDataBuffer,
                                                    &dummy)))
        {
            goto exit;
        }

#else
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerInfoItem,
                                                    pSignerInfo->pKey->key.pRSA,
                                                    NULL, NULL,
                                                    pSignerInfo->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    ppDataBuffer,
                                                    &dummy)))
        {
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( pSignerInfo->pKey->type == akt_dsa)
    {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }

        if (OK > ( status = PKCS7_AddDSASignature(MOC_DSA(hwAccelCtx) pSignerInfoItem,
                                pSignerInfo->pKey->key.pDSA,
                                NULL, NULL, rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if (( pSignerInfo->pKey->type == akt_ecc) ||
            ( pSignerInfo->pKey->type == akt_tap_ecc))
    {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerInfoItem,
                                pSignerInfo->pKey,
                                NULL, NULL,
                                plainData, plainDataLen,
                                rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }

#else
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerInfoItem,
                                pSignerInfo->pKey->key.pECC,
                                NULL, NULL, rngFun, rngArg,
                                toSign, pHash->hashAlgo->digestSize,
                                ppDataBuffer, &dummy)))
        {
            goto exit;
        }
#endif
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
   else if (pSignerInfo->pKey->type == akt_qs)
   {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;
        ubyte4 dummy;

        if (pSignerInfo->authAttrsLen > 0 ||
            (pkcs7_data_OID[pkcs7_data_OID[0]] != payLoadType[payLoadType[0]]))
        {
            toSign = pTempBuf + derAttributesLen;
        }
        else
        {
            toSign = pHash->hashData;
        }

        if (OK > ( status = PKCS7_AddQsSignature( MOC_ASYM(hwAccelCtx) pSignerInfoItem,
                                                  pSignerInfo->pKey->pQsCtx,
                                                  NULL, NULL,
                                                  rngFun, rngArg,
                                                  toSign, pHash->hashAlgo->digestSize,
                                                  ppDataBuffer, &dummy)))
        {
            goto exit;
        }
    }
#endif

    /* OPTIONAL unauthenticatedAttributes */

exit:

    PKCS7_freeAttributeSetOf(&pAttrList);
    
    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    if (pSetOf)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSetOf);
    }

    if (pDerAttributes)
    {
        FREE(pDerAttributes);
    }

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pOid)
    {
        (void) DIGI_FREE((void **) &pOid);
    }
#endif

    return status;
}

#if defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__)

/*------------------------------------------------------------------*/
/*
 RFC: 5272
 <p>
PKIData ::= SEQUENCE {
     controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
     reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
     cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
     otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
 }

  bodyIdMax INTEGER ::= 4294967295

  BodyPartID ::= INTEGER(0..bodyIdMax)

 TaggedAttribute ::= SEQUENCE {
     bodyPartID         BodyPartID,
     attrType           OBJECT IDENTIFIER,
     attrValues         MOC_SET OF AttributeValue
 }

  AttributeValue ::= ANY

  TaggedRequest ::= CHOICE {
      tcr               [0] TaggedCertificationRequest,
      crm               [1] CertReqMsg,
      orm               [2] SEQUENCE {
          bodyPartID            BodyPartID,
          requestMessageType    OBJECT IDENTIFIER,
          requestMessageValue   ANY DEFINED BY requestMessageType
      }
  }

  TaggedCertificationRequest ::= SEQUENCE {
      bodyPartID            BodyPartID,
      certificationRequest  CertificationRequest
  }

  CertificationRequest ::= SEQUENCE {
    certificationRequestInfo  SEQUENCE {
      version                   INTEGER,
      subject                   Name,
      subjectPublicKeyInfo      SEQUENCE {
        algorithm                 AlgorithmIdentifier,
        subjectPublicKey          BIT STRING },
      attributes                [0] IMPLICIT MOC_SET OF Attribute },
    signatureAlgorithm        AlgorithmIdentifier,
    signature                 BIT STRING
  }

 TaggedContentInfo ::= SEQUENCE {
     bodyPartID              BodyPartID,
     contentInfo             ContentInfo
 }

 OtherMsg ::= SEQUENCE {
     bodyPartID        BodyPartID,
     otherMsgType      OBJECT IDENTIFIER,
     otherMsgValue     ANY DEFINED BY otherMsgType }
  </p>

 */
MOC_EXTERN MSTATUS
CMC_createPKIDataEx(taggedAttribute pTaggedAttributes[], ubyte4 numTaggedAttrs, ubyte *pDerCertificateRequest, ubyte4 derCertificateReqLen, taggedContentInfo pTaggedContentInfos[], ubyte4 numTaggedContents, otherMsg pOtherMsgs[], ubyte4 numOtherMsgs, ubyte **ppBuffer, ubyte4 *pBufferLen)
{
    MSTATUS     status;
    DER_ITEMPTR pPKIDataContent = NULL, pTempItem = NULL;
    DER_ITEMPTR pControlSeq = NULL, pReqSequence = NULL, pCmsSequence = NULL, pOthrMsgSequence = NULL;
    CStream       csrStream;
    MemFile       csrMemFile;
    ASN1_ITEMPTR  pReqRoot = NULL;
    ubyte4 i = 0, j = 0;

    if ((NULL == ppBuffer) || (NULL == pBufferLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create PKI Data */
	if (OK > (status = DER_AddSequence(NULL, &pPKIDataContent)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pControlSeq)))
    {
        goto exit;
    }
	if (pDerCertificateRequest)
	{
	    if (OK > (status = DER_AddSequence(pPKIDataContent, &pReqSequence)))
        {
            goto exit;
        }
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pCmsSequence)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pOthrMsgSequence)))
    {
        goto exit;
    }

    /* Add data inside controlsequence */
    for (i = 0; i < numTaggedAttrs; i++)
    {
        /*TaggedAttribute ::= SEQUENCE {
          bodyPartID         BodyPartID,
          attrType           OBJECT IDENTIFIER,
          attrValues         MOC_SET OF AttributeValue
          }*/
        DER_ITEMPTR pTempSeq = NULL;
        DER_ITEMPTR pSet = NULL;
        if (OK > (status = DER_AddSequence(pControlSeq, &pTempSeq)))
        {
            goto exit;
        }

        /* Bodypart id*/
        if ( OK > ( status = DER_AddIntegerEx( pTempSeq, pTaggedAttributes[i].bodyPartId, NULL)))
        {
            goto exit;
        }

        if (OK > (status = DER_AddOID( pTempSeq, pTaggedAttributes[i].pAttributeTypeOid, NULL)))
        {
            goto exit;
        }

		if ( OK > ( status = DER_AddSet( pTempSeq, &pSet)))
        {
            goto exit;
        }
        for (j = 0; j < pTaggedAttributes[i].numAttributeValues; j++)
        {

            if (OK > (status = DER_AddDERBuffer(pSet, pTaggedAttributes[i].pTaggedAttributeValues[j].dataLen,
                            pTaggedAttributes[i].pTaggedAttributeValues[j].pData, NULL)))
            {
                goto exit;
            }
        }
    }
    /* End of constructing controlsequence */
	if (pDerCertificateRequest)
	{
		MF_attach(&csrMemFile, derCertificateReqLen, pDerCertificateRequest);
		CS_AttachMemFile(&csrStream, &csrMemFile);
		if (OK > (status = ASN1_Parse(csrStream, &pReqRoot)))
		{
			goto exit;
		}

		/* Add data inside reqsequence */
		if (OK > (status = DER_AddTag(pReqSequence, 0, &pTempItem)))
			goto exit;

        /* Bodypart id*/
        if ( OK > ( status = DER_AddIntegerEx( pTempItem, 1, NULL)))
        {
            goto exit;
        }

        if (OK > (status = PKCS7_AddItem1(pTempItem, csrStream, pReqRoot, NULL)))
		{
			goto exit;
		}
	}
    /* End of constructing reqsequence */

    /* Add data inside cmssequence */
    for (i = 0; i < numTaggedContents; i++)
    {

        /*TaggedContentInfo ::= SEQUENCE {
          bodyPartID              BodyPartID,
          contentInfo             ContentInfo
          }*/
        DER_ITEMPTR pTempSeq = NULL;
        DER_ITEMPTR pContentSeq = NULL;

        if (OK > (status = DER_AddSequence(pCmsSequence, &pTempSeq)))
        {
            goto exit;
        }

        /* Bodypart id*/
        if ( OK > ( status = DER_AddIntegerEx( pTempSeq, pTaggedContentInfos[i].bodyPartId, NULL)))
        {
            goto exit;
        }

        if (OK > (status = DER_AddSequence(pTempSeq, &pContentSeq)))
        {
            goto exit;
        }

        if (pTaggedContentInfos[i].pTaggedContentInfo->dataLen > 0)
        {
            if (OK > (status = DER_AddDERBuffer(pContentSeq, pTaggedContentInfos[i].pTaggedContentInfo->dataLen,
                            pTaggedContentInfos[i].pTaggedContentInfo->pData, NULL)))
            {
                goto exit;
            }
        }
    }
    /* End of constructing cmssequence */

    /* Add data inside cmssequence */
    for (i = 0; i < numOtherMsgs; i++)
    {
        /*OtherMsg ::= SEQUENCE {
          bodyPartID        BodyPartID,
          otherMsgType      OBJECT IDENTIFIER,
          otherMsgValue     ANY DEFINED BY otherMsgType }*/

        DER_ITEMPTR pTempSeq = NULL;

        if (OK > (status = DER_AddSequence(pOthrMsgSequence, &pTempSeq)))
        {
            goto exit;
        }

        /* Bodypart id*/
        if ( OK > ( status = DER_AddIntegerEx( pTempSeq, pOtherMsgs[i].bodyPartId, NULL)))
        {
            goto exit;
        }

        if (OK > (status = DER_AddOID( pTempSeq, pOtherMsgs[i].pOtherMsgTypeOid, NULL)))
        {
            goto exit;
        }

        if (pOtherMsgs[i].pOtherMsgValue->dataLen > 0)
        {
            if (OK > (status = DER_AddItem(pTempSeq, OCTETSTRING, pOtherMsgs[i].pOtherMsgValue->dataLen,
                            pOtherMsgs[i].pOtherMsgValue->pData, NULL)))
            {
                goto exit;
            }
        }
    }
    /* End of constructing othermsgsequence */

    if (OK > (status = DER_Serialize(pPKIDataContent, ppBuffer, pBufferLen)))
    {
        goto exit;
    }

exit:
	if(pPKIDataContent != NULL)
    {
        TREE_DeleteTreeItem( (TreeItem*) pPKIDataContent);
    }

    if (pReqRoot != NULL)
    {
        TREE_DeleteTreeItem((TreeItem*)pReqRoot);
    }
	return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CMC_createPKIData(ASN1_ITEMPTR pControlItem, CStream *pControlStream, ASN1_ITEMPTR pReqItem, CStream *pReqStream, ubyte **ppBuffer, ubyte4 *pBufferLen)
{
    MSTATUS     status;
    DER_ITEMPTR pPKIDataContent = NULL, pTempItem = NULL;
    DER_ITEMPTR pControlSeq = NULL, pReqSequence = NULL, pCmsSequence = NULL, pOthrMsgSequence = NULL;
    ubyte       copyData[MAX_DER_STORAGE];

    /* Create PKI Data */
	if (OK > (status = DER_AddSequence(NULL, &pPKIDataContent)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pControlSeq)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pReqSequence)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pCmsSequence)))
    {
        goto exit;
    }
	if (OK > (status = DER_AddSequence(pPKIDataContent, &pOthrMsgSequence)))
    {
        goto exit;
    }

    /* Empty control sequence */
    /* Create a reqSequence */
    if ( OK > ( status = DER_AddTag( pReqSequence, 0, &pTempItem)))
        goto exit;

    /* version = 1 */
    copyData[0] = 1;
    if ( OK > ( status = DER_AddItemCopyData( pTempItem, INTEGER, 1, copyData, NULL)))
        goto exit;


    if (OK > (status = PKCS7_AddItem1(pTempItem, *pReqStream, pReqItem, NULL)))
    {
        goto exit;
    }
    if (OK > (status = DER_Serialize(pPKIDataContent, ppBuffer, pBufferLen)))
    {
        goto exit;
    }

exit:
	if(pPKIDataContent)
        TREE_DeleteTreeItem( (TreeItem*) pPKIDataContent);
	return status;

}
#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)
/*------------------------------------------------------------------*/

/**
   CMCStatusInfoV2 ::= SEQUENCE {
      cMCStatus             CMCStatus,
      bodyList              SEQUENCE SIZE (1..MAX) OF BodyPartReference,
      statusString          UTF8String OPTIONAL,
      otherInfo             OtherStatusInfo OPTIONAL
   }
    CMCStatus ::= INTEGER {
        success                (0),
        -- reserved            (1),
        failed                 (2),
        pending                (3),
        noSupport              (4),
        confirmRequired        (5),
        popRequired            (6),
        partial                (7)
    }

*/
MOC_EXTERN MSTATUS
CMC_addCMCStatusInfoV2(CMCStatus cmcStatus, sbyte4 referanceIds[], sbyte4 numRefIds, ubyte **ppBuffer, ubyte4 *pBufferLen)
{
    MSTATUS     status;
    DER_ITEMPTR pStatusInfo = NULL, pTempItem = NULL;
    sbyte4      i;

    if (OK > (status = DER_AddSequence(NULL, &pStatusInfo)))
    {
        goto exit;
    }

    if (OK >(status = DER_AddIntegerEx(pStatusInfo, cmcStatus, NULL)))
        goto exit;

    if (OK > (status = DER_AddSequence(pStatusInfo, &pTempItem)))
    {
        goto exit;
    }

    for (i = 0; i < numRefIds; i++)
    {
        if (OK > (status = DER_AddIntegerEx(pTempItem, referanceIds[i], NULL)))
            goto exit;
    }

    if (OK > (status = DER_Serialize(pStatusInfo, ppBuffer, pBufferLen)))
    {
        goto exit;
    }
exit:
	if (pStatusInfo) TREE_DeleteTreeItem((TreeItem *)pStatusInfo);
    return status;
}

/*------------------------------------------------------------------*/

/**
     TaggedAttribute ::= SEQUENCE {
         bodyPartID         BodyPartID,
         attrType           OBJECT IDENTIFIER,
         attrValues         MOC_SET OF AttributeValue
     }
*/
MOC_EXTERN MSTATUS
CMC_addTaggedAttribute(sbyte4 bodyPartID, ubyte *attrTypeOid, ubyte *attrValueData, ubyte4 attrValueLen, ubyte **ppBuffer, ubyte4 *pBufferLen)
{
    MSTATUS     status;
    DER_ITEMPTR pTaggerAttribute = NULL, pTempItem = NULL;

    if (OK > (status = DER_AddSequence(NULL, &pTaggerAttribute)))
    {
        goto exit;
    }

    if (OK >(status = DER_AddIntegerEx(pTaggerAttribute, bodyPartID, NULL)))
        goto exit;

    if (OK >(status = DER_AddOID(pTaggerAttribute, attrTypeOid, NULL)))
        goto exit;

    if (OK >(status = DER_AddSet(pTaggerAttribute, &pTempItem)))
        goto exit;

    if (OK >(status = DER_AddDERBuffer(pTempItem, attrValueLen, attrValueData, NULL)))
        goto exit;

    if (OK > (status = DER_Serialize(pTaggerAttribute, ppBuffer, pBufferLen)))
    {
        goto exit;
    }
exit:
	if (pTaggerAttribute) TREE_DeleteTreeItem((TreeItem *)pTaggerAttribute);
    return status;
}
#endif
/*------------------------------------------------------------------*/

MSTATUS
CMC_verifyAttestationReqType(ASN1_ITEM *pPKIInputData, CStream stream, byteBoolean *pAttestFlow, ubyte **ppOid)
{
    MSTATUS status = OK;
    ASN1_ITEM *pSequenceItem = NULL;
    ASN1_ITEM *pChildItem = NULL;
    ASN1_ITEM *pOID = NULL;
    static WalkerStep walkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0}, /*controlsequence */
        { Complete, 0, 0}
    };

    if ((NULL == pPKIInputData)  || (NULL == pAttestFlow))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pAttestFlow = FALSE;

    if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, walkInstructions, &pSequenceItem)))
    {
        goto exit;
    }

    pChildItem = ASN1_FIRST_CHILD(pSequenceItem);

    while(pChildItem != NULL)
    {
   		if (UNIVERSAL == (pChildItem->id & CLASS_MASK) &&
				SEQUENCE == pChildItem->tag)
		{
            /* OID tag lies in the 2nd position */
			if (OK != (status = ASN1_GetNthChild(pChildItem, 2, &pOID)))
            {
                goto exit;
            }
            if (OK == ASN1_VerifyOID(pOID, stream, mocana_attest_tpm2_oid))
            {
                *pAttestFlow = TRUE;
                if (NULL != ppOid)
                {
                    int len = mocana_attest_tpm2_oid[0] + 1;
                    if (OK != (status = DIGI_CALLOC((void**)ppOid, 1, len+1)))
                    {
                        goto exit;
                    }
                    if (OK != (status = DIGI_MEMCPY(*ppOid, mocana_attest_tpm2_oid, len)))
                    {
                        goto exit;
                    }
                }
                break;
            }
		}
        pChildItem = ASN1_NEXT_SIBLING (pChildItem);
    }

exit:
    return status;
}

MSTATUS
CMC_processCmsSequence(ASN1_ITEM *pPKIInputData, CStream stream, ubyte4 *pBodyPartsList, ubyte4 numBodyParts, byteBoolean isResponseData, ASN1_ITEMPTR **ppEnvelopDataItems, ubyte4 *pNumEnvelopDataItems)
{
    MSTATUS status = OK;
    ASN1_ITEM *pSequenceItem = NULL;
    ASN1_ITEM *pBodyPartIdItem = NULL;
    ASN1_ITEM *pChildItem = NULL;
    ubyte4 i = 0, j = 0;

    static WalkerStep pkiDataWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0}, /*cmssequence */
        { Complete, 0, 0}
    };

    static WalkerStep pkiResponseWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0}, /*cmssequence */
        { Complete, 0, 0}
    };


    if (isResponseData == TRUE)
    {
        if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, pkiResponseWalkInstructions, &pSequenceItem)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, pkiDataWalkInstructions, &pSequenceItem)))
        {
            goto exit;
        }
    }

    if (pSequenceItem == NULL)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if (OK != (status = DIGI_CALLOC((void**)ppEnvelopDataItems, numBodyParts, sizeof(ASN1_ITEM*))))
    {
        goto exit;
    }
    *pNumEnvelopDataItems = numBodyParts;
    pChildItem = ASN1_FIRST_CHILD(pSequenceItem);
    while(pChildItem != NULL)
    {
        ubyte4 bodyPartId = 0;
        pBodyPartIdItem = ASN1_FIRST_CHILD(pChildItem);
        if (OK != (status = ASN1_VerifyType(pBodyPartIdItem, INTEGER)))
        {
            goto exit;
        }
        bodyPartId = pBodyPartIdItem->data.m_intVal;
        /* Check if this bodyPartId has to be processed */
        for (; i < numBodyParts; i++)
        {
            if (bodyPartId ==  pBodyPartsList[i])
            {
                /* Process this bodypartId.*/
                *(*ppEnvelopDataItems + j) = ASN1_NEXT_SIBLING(pBodyPartIdItem);
                j++;
                break;
            }
        }
        pChildItem = ASN1_NEXT_SIBLING (pChildItem);
    }
exit:
    return status;
}

MSTATUS
CMC_processControlSequence(ASN1_ITEM *pPKIInputData, CStream stream, ubyte *pBatchOID, ubyte4 **ppBodyPartIds, ubyte4 *pNumBodyPartIds)
{
    MSTATUS status = OK;
    ASN1_ITEM *pSequenceItem = NULL;
    ASN1_ITEM *pOID = NULL;
    ASN1_ITEM *pChildItem = NULL;
    ASN1_ITEM *pInnerChildItem = NULL;
    static WalkerStep walkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0}, /*controlsequence */
        { Complete, 0, 0}
    };

    if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, walkInstructions, &pSequenceItem)))
    {
        goto exit;
    }

    if (pSequenceItem == NULL)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    pChildItem = ASN1_FIRST_CHILD(pSequenceItem);

    while(pChildItem != NULL)
    {
   		if (UNIVERSAL == (pChildItem->id & CLASS_MASK) &&
				SEQUENCE == pChildItem->tag)
		{
            /* OID tag lies in the 2nd position */
			if (OK != (status = ASN1_GetNthChild(pChildItem, 2, &pOID)))
            {
                goto exit;
            }
            if (OK == ASN1_VerifyOID(pOID, stream, pBatchOID))

            {/* This is batchRequest/batchResponse OID.*/

                /* batchRequest/batchResponse value lies in the 3rd position */
                if (OK != (status = ASN1_GetNthChild(pChildItem, 3, &pInnerChildItem)))
                {
                    goto exit;
                }
                if (OK != (status = ASN1_VerifyType(pInnerChildItem, MOC_SET)))
                {
                    goto exit;
                }
                pInnerChildItem = ASN1_FIRST_CHILD(pInnerChildItem);
                if (OK != (status = ASN1_VerifyType(pInnerChildItem, SEQUENCE)))
                {
                    goto exit;
                }
                pInnerChildItem = ASN1_FIRST_CHILD(pInnerChildItem);
                if (pInnerChildItem != NULL)
                {
                    int count = 0;
                    int pos = 0;
                    ASN1_ITEMPTR pTempItem = pInnerChildItem;
                    while (pTempItem != NULL)
                    {
                        count++;
                        pTempItem = ASN1_NEXT_SIBLING (pTempItem);
                    }
                    *pNumBodyPartIds = count;
                    if (OK != (status = DIGI_CALLOC((void**)ppBodyPartIds, count, sizeof(ubyte4))))
                    {
                        goto exit;
                    }
                    while (pInnerChildItem != NULL)
                    {
                        if (OK != (status = ASN1_VerifyType(pInnerChildItem, INTEGER)))
                        {
                            goto exit;
                        }
                        *ppBodyPartIds[pos] = pInnerChildItem->data.m_intVal;

                        pInnerChildItem = ASN1_NEXT_SIBLING (pInnerChildItem);
                    }
                }
            }
		}
        pChildItem = ASN1_NEXT_SIBLING (pChildItem);
    }
exit:
    return status;
}


MSTATUS
CMC_processOtherMsgSequence(ASN1_ITEM *pPKIInputData,
                    CStream stream, ubyte **ppOutData,
                    ubyte4 *pOutDataLen, byteBoolean isResponseData)
{
    MSTATUS status = OK;
    ASN1_ITEM *pSequenceItem = NULL;
    ASN1_ITEM *pChildItem = NULL;
    ASN1_ITEM *pContentItem = NULL;
    ASN1_ITEM *pOID = NULL;
    ubyte *pOtherSequenceData = NULL;

    static WalkerStep pkiDataWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 4, 0},
        { VerifyType, SEQUENCE, 0}, /*Othermsgsequence */
        { Complete, 0, 0}
    };

    static WalkerStep pkiResponseWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0}, /*Othermsgsequence */
        { Complete, 0, 0}
    };

    if (isResponseData == TRUE)
    {
        if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, pkiResponseWalkInstructions, &pSequenceItem)))
        {
            goto exit;
        }
    }
    else
    {
        if (OK != (status = ASN1_WalkTree(pPKIInputData, stream, pkiDataWalkInstructions, &pSequenceItem)))
        {
            goto exit;
        }
    }

    if (pSequenceItem == NULL)
    {
        goto exit;
    }
    pChildItem = ASN1_FIRST_CHILD(pSequenceItem);

    if (pChildItem == NULL)
    {
        goto exit;
    }

    if (OK != (status = ASN1_GetNthChild(pChildItem, 2, &pOID)))
    {
        goto exit;
    }

    if (OK != (status = ASN1_GetNthChild(pChildItem, 3, &pContentItem)))
    {
        goto exit;
    }
    if (OK > (status = DIGI_MALLOC((void **)ppOutData, pContentItem->length)))
    {
		goto exit;
	}

	pOtherSequenceData = (ubyte *) CS_memaccess(stream, pContentItem->dataOffset, pContentItem->length);
	if (OK > (status = DIGI_MEMCPY(*ppOutData, pOtherSequenceData, pContentItem->length)))
	{
    	goto exit;
    }
	*pOutDataLen = pContentItem->length;

exit:
    return status;
}


MSTATUS
CMC_getPKIResponse(ASN1_ITEM* pRootItem, CStream stream, ASN1_ITEM **ppPkiResponse)
{
    static WalkerStep walkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) pkcs7_signedData_OID },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) cct_PKIResponse_OID },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };

    return ASN1_WalkTree(pRootItem, stream, walkInstructions, ppPkiResponse);
}

MSTATUS
CMC_getPKIData(ASN1_ITEM* pRootItem, CStream stream, ASN1_ITEM **ppPkiRequest)
{
    static WalkerStep pkiDataWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) pkcs7_signedData_OID },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) cct_pkiData_oid },
        { Complete, 0, 0}
    };

    static WalkerStep walkInstructions[] =
    {
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) pkcs7_signedData_OID },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { VerifyType, SEQUENCE, 0},
        { GoNthChild, 3, 0},
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyOID, 0, (ubyte*) cct_pkiData_oid },
        { GoNextSibling, 0, 0},
        { VerifyTag, 0, 0 },
        { GoFirstChild, 0, 0},
        { Complete, 0, 0}
    };

    ASN1_ITEMPTR pkiOIDItem = NULL;
    if (OK > ASN1_WalkTree(pRootItem, stream, pkiDataWalkInstructions, &pkiOIDItem))
    {
        return ERR_CMC_NOT_ENROLLED;
    }

    return ASN1_WalkTree(pRootItem, stream, walkInstructions, ppPkiRequest);
}
#if defined(__ENABLE_DIGICERT_AIDE_SERVER__)
MSTATUS
CMC_verifyPKIResponseStatus(ASN1_ITEM *pPKIInputData, byteBoolean statusOk)
{
	return OK;
}

/*------------------------------------------------------------------*/

/**
* RFC 5272 Section 2.2
*    Simple PKI Request                      Simple PKI Response
*   -------------------------               --------------------------
*
*    +----------+                            +------------------+
*    | PKCS #10 |                            | CMS ContentInfo  |
*    +----------+--------------+             +------------------+------+
*    | Certification Request   |             | CMS Signed Data,        |
*    |                         |             |   no SignerInfo         |
*    | Subject Name            |             |
*    | Subject Public Key Info |             | SignedData contains one |
*    |   (K_PUB)               |             | or more certificates in |
*    | Attributes              |             | the certificates field  |
*    |                         |             | Relevant CA certs and   |
*    +-----------+-------------+             | CRLs can be included    |
*                | signed with |             | as well.                |
*                | matching    |             |                         |
*                | K_PRIV      |             | encapsulatedContentInfo |
*                +-------------+             | is absent.              |
*                                            +--------------+----------+
*                                                           | unsigned |
*                                                           +----------+
*
*/
MOC_EXTERN
MSTATUS CMC_createSimplePKIMessage(CERTS_DATA *pCertsData, sbyte4 certDataLen, ubyte **ppPkiMessage, ubyte4 *pPkiMessageLen)
{
	MSTATUS			status = OK;
	randomContext*	pRandomContext = NULL;
	DER_ITEMPTR     pContent;
	DER_ITEMPTR     pContentInfo = NULL;
	ASN1_ITEMPTR    *ppCertificates = NULL;
	CStream         *pCStreams = NULL;
	CStream         **ppCStreams = NULL;
    sbyte4          i = 0;

	if (!pCertsData || !certDataLen || !ppPkiMessage || !pPkiMessageLen)
	{
		status = ERR_NULL_POINTER;
		goto exit;
	}
	*ppPkiMessage = NULL;
	*pPkiMessageLen = 0;

	if (NULL == g_pRandomContext) {
		if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
		{
			goto exit;
		}
	}
	else
	{
		pRandomContext = g_pRandomContext;
	}

	if (OK > (status = DIGI_CALLOC((void **)&ppCertificates, certDataLen, sizeof(ASN1_ITEMPTR))))
	{
		goto exit;
	}
	if (OK > (status = DIGI_CALLOC((void **)&pCStreams, certDataLen, sizeof(CStream))))
	{
		goto exit;
	}
	if (OK > (status = DIGI_CALLOC((void **)&ppCStreams, certDataLen, sizeof(CStream *))))
	{
		goto exit;
	}
	for (i = 0; i < certDataLen; i++)
	{
		ASN1_ITEMPTR    pCert = NULL;
		MemFile         *pMemFile = NULL;
		CStream         *pCs = NULL;

		if (OK >(status = DIGI_MALLOC((void **)&pCs, sizeof(CStream))))
		{
			goto exit;
		}
		if (OK >(status = DIGI_MALLOC((void **)&pMemFile, sizeof(MemFile))))
		{
			goto exit;
		}
		MF_attach(pMemFile, pCertsData[i].certDataLen, (ubyte*)pCertsData[i].pCertData);
		CS_AttachMemFile(pCs, pMemFile);

		if (OK >(status = X509_parseCertificate(*pCs, &pCert)) || !pCert)
		{
			goto exit;
		}

		ppCertificates[i] = pCert;
		pCStreams[i] = *pCs;
		ppCStreams[i] = pCs;
	}
	/* wrap in ContentInfo */
	if (OK > (status = CMS_createContentInfo(pkcs7_signedData_OID, &pContentInfo, &pContent)))
		goto exit;

	/* create pkcsCertReqSigned message */
	if (OK > (status = PKCS7_SignData(MOC_ASYM(hwAccelCtx) 0,
		pContentInfo, pContent,
		ppCertificates, pCStreams, certDataLen,
		NULL, NULL, 0, /* no CRLs */
		NULL, 0, /* no signer */
		NULL,
		NULL, 0,
		RANDOM_rngFun,
		pRandomContext,
		ppPkiMessage, pPkiMessageLen)))
	{
		goto exit;
	}


exit:
	if (NULL == g_pRandomContext) {
		RANDOM_releaseContext(&pRandomContext);
	}
	if (ppCertificates)
	{
		for (i = 0; i < certDataLen; i++)
		{
            if (ppCertificates[i]) {
                TREE_DeleteTreeItem((TreeItem*)ppCertificates[i]);
            }
		}
		DIGI_FREE((void **)&ppCertificates);
	}
	if (ppCStreams)
	{
		for (i = 0; i < certDataLen; i++)
		{
            if (ppCStreams[i]) {
                DIGI_FREE((void **)&ppCStreams[i]);
            }
		}
		DIGI_FREE((void **)&ppCStreams);
	}
	if (pCStreams)
		DIGI_FREE((void **)&pCStreams);
	if (pContentInfo)
		TREE_DeleteTreeItem((TreeItem *)pContentInfo);
	return status;
}

static MSTATUS extractPublicKey(ubyte *pCertificate, ubyte4 certificateLen, AsymmetricKey *pPubKey)
{
    MSTATUS status = OK;
    MemFile         mf;
    CStream         cs;
    ASN1_ITEMPTR    pRoot = NULL;

    /* Input parameter check */
    if (NULL == pCertificate || NULL == pPubKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == certificateLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    MF_attach(&mf, certificateLen, pCertificate);
    CS_AttachMemFile(&cs, &mf);

    if (OK > (status = ASN1_Parse(cs, &pRoot)))
        goto exit;

    if (NULL == pRoot)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
        ASN1_FIRST_CHILD(pRoot),
        cs, pPubKey)))
    {
        goto exit;
    }

exit:
    if (pRoot)
        TREE_DeleteTreeItem((TreeItem *)pRoot);
    return status;
}

/*------------------------------------------------------------------*/

/**
*
*    Full PKI Request                        Full PKI Response
*    -----------------------                 ------------------------
*    +----------------+                      +----------------+
*    | CMS ContentInfo|                      | CMS ContentInfo|
*    | CMS SignedData |                      | CMS SignedData |
*    |   or Auth Data |                      |   or Auth Data |
*    |     object     |                      |     object     |
*    +----------------+--------+             +----------------+--------+
*    |                         |             |                         |
*    | PKIData                 |             | PKIResponseBody         |
*    |                         |             |                         |
*    | Sequence of:            |             | Sequence of:            |
*    | <enrollment control>*   |             | <enrollment control>*   |
*    | <certification request>*|             | <CMS object>*           |
*    | <CMS object>*           |             | <other message>*        |
*    | <other message>*        |             |                         |
*    |                         |             | where * == zero or more |
*    | where * == zero or more |             |                         |
*    |                         |             | All certificates issued |
*    | Certification requests  |             | as part of the response |
*    | are CRMF, PKCS #10, or  |             | are included in the     |
*    | Other.                  |             | "certificates" field    |
*    |                         |             | of the SignedData.      |
*    +-------+-----------------+             | Relevant CA certs and   |
*            | signed (keypair |             | CRLs can be included as |
*            | used may be pre-|             | well.                   |
*            | existing or     |             |                         |
*            | identified in   |             +---------+---------------+
*            | the request)    |                       | signed by the |
*            +-----------------+                       | CA or an LRA  |
*                                                      +---------------+
*/

MOC_EXTERN
MSTATUS CMC_createFullPKIMessage(ubyte* pSignerCertBytes, ubyte4 signerCertByteLen, AsymmetricKey *pSignerKey, CERTS_DATA *pCertsData, sbyte4 certDataLen, intBoolean isAttest, ubyte *pEkCertData, ubyte4 ekCertDataLen, ubyte *pOtherMsgData, ubyte4 otherMsgDataLen, ubyte **ppPkiMessage, ubyte4 *pPkiMessageLen)
{
	MSTATUS			status = OK;
	randomContext*	pRandomContext = NULL;
	DER_ITEMPTR     pContent;
	DER_ITEMPTR     pContentInfo = NULL;
	signerInfo      mySignerInfo;
	cmcSignerInfo   myCmcSignerInfo;
	cmcSignerInfoPtr myCmcSignerInfoPtr[1];
	ASN1_ITEMPTR    *ppCertificates = NULL;
	CStream         *pCStreams = NULL;
	CStream         **ppCStreams = NULL;
	ASN1_ITEMPTR    pSignerCert = NULL, pIssuer, pSerialNumber;
	MemFile         memFile;
	CStream         cs;
	ubyte4          pkiResponseDataLen, statusDataLen;
	ubyte           *pStatusData = NULL, *pAttributeData = NULL, *pPKIResponseData = NULL;
    ubyte           *pBatchRespRefData = NULL, *pBatchRespSeqData = NULL;
    ubyte4          batchRespRefDataLen;
	sbyte4          refIdArr[1];
    sbyte4          noOfControls = 0, noOfCMS = 0;
    sbyte4          i = 0;

    taggedContent *taggedAttributeValues = NULL;
    taggedAttribute *ppControlArr = NULL;
    taggedContentInfo *ppCMSArr = NULL;

	if (!pCertsData || !certDataLen || !ppPkiMessage || !pPkiMessageLen)
	{
		status = ERR_NULL_POINTER;
		goto exit;
	}
	*ppPkiMessage = NULL;
	*pPkiMessageLen = 0;

	if (NULL == g_pRandomContext) {
		if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
		{
			goto exit;
		}
	}
	else
	{
		pRandomContext = g_pRandomContext;
	}

	if (!pSignerCertBytes) {
		status = ERR_NULL_POINTER;
		goto exit;
	}
	MF_attach(&memFile, signerCertByteLen, (ubyte*)pSignerCertBytes);
	CS_AttachMemFile(&cs, &memFile);

	if (OK > (status = X509_parseCertificate(cs, &pSignerCert)))
	{
		goto exit;
	}

	if (!pSignerCert || !ASN1_FIRST_CHILD(pSignerCert))
	{
		status = ERR_CERT_INVALID_STRUCT;
		goto exit;
	}
	/* create signer infos */
	/* get issuer and serial number of certificate */
	if (OK > (status = X509_getCertificateIssuerSerialNumber(ASN1_FIRST_CHILD(pSignerCert),
		&pIssuer, &pSerialNumber)))
	{
		goto exit;
	}

	DIGI_MEMSET((ubyte*)&mySignerInfo, 0, sizeof(signerInfo));

	mySignerInfo.pIssuer = pIssuer;
	mySignerInfo.pSerialNumber = pSerialNumber;
	mySignerInfo.cs = cs;
	CRYPTO_getHashAlgoOID(sha256withRSAEncryption, &mySignerInfo.digestAlgoOID);
	mySignerInfo.pKey = pSignerKey;
	mySignerInfo.pUnauthAttrs = NULL;
	mySignerInfo.unauthAttrsLen = 0;
	mySignerInfo.pAuthAttrs = NULL;
	mySignerInfo.authAttrsLen = 0;
	myCmcSignerInfo.pSignerInfo = &mySignerInfo;
	myCmcSignerInfo.pSubjectKeyIdentifier = NULL;
	myCmcSignerInfoPtr[0] = &myCmcSignerInfo;

    noOfControls = 1; /* Status info */
    if (isAttest)
    {
        noOfControls += 2; /* TMP2_ATTEST control and Batch response referance. */
    }
	if (OK > (status = DIGI_CALLOC((void **)&ppControlArr, noOfControls, sizeof(taggedAttribute))))
	{
		goto exit;
	}

    if (isAttest)
    {
        ubyte *pEKeyBlob = NULL;
        AsymmetricKey	eAsymKey;
        DER_ITEMPTR pControlInfo = NULL, pTempItem = NULL;
        ASN1_ITEMPTR    pCertData = NULL;
        MemFile         *pCertMemFile = NULL;
        CStream         *pCertCs = NULL;

        if (OK > (status = CRYPTO_initAsymmetricKey(&eAsymKey)))
        {
            goto exit;
        }
        if (OK > (status = extractPublicKey(pEkCertData, ekCertDataLen, &eAsymKey)))
        {
            goto exit;
        }

	    if (OK > (status = DIGI_MALLOC((void **)&ppCMSArr, sizeof(taggedContentInfo) * certDataLen)))
	    {
		    goto attest_exit;
	    }

        if (OK > (status = DER_AddSequence(NULL, &pControlInfo)))
        {
            goto attest_exit;
        }

	    for (i = 0; i < certDataLen; i++)
	    {
            if (OK > (status = DER_AddIntegerEx(pControlInfo, (bodyPartIdBase + i), NULL)))
                goto attest_exit;

            ubyte *symmKey = NULL;
            ubyte *cmsEnv = NULL;
            ubyte4 cmsEnvLen;
	        DIGI_MALLOC((void **)&symmKey, THREE_DES_KEY_LENGTH);

            if (OK > (status = RANDOM_numberGenerator(pRandomContext, symmKey, THREE_DES_KEY_LENGTH)))
                goto exit;

            ubyte *secretKey = NULL, *pAsymKeyBlob = NULL;
            ubyte4 secretKeyLen;
            AsymmetricKey	asymKey;
            if (OK > (status = CRYPTO_initAsymmetricKey(&asymKey)))
            {
                goto attest_exit;
            }
            if (OK > (status = extractPublicKey(pCertsData[i].pCertData, pCertsData[i].certDataLen, &asymKey)))
            {
                goto attest_exit;
            }

            if (OK > (status = SMP_TPM2_wrapCredentialSecret(&asymKey, &eAsymKey, pOtherMsgData, otherMsgDataLen, symmKey, THREE_DES_KEY_LENGTH, &secretKey, &secretKeyLen)))
            {
                goto attest_exit;
            }

            ubyte decryptKeyIdData[19] = {0x30, 0x11, 0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x25, 0x31, 0x02, 0x05, 0x00};
            if (OK > (status = CMC_createCMSEnvelopForKekri((ubyte *)desEDE3CBC_OID, (BulkEncryptionAlgo *)&CRYPTO_TripleDESSuite, THREE_DES_KEY_LENGTH, decryptKeyIdData, 19, symmKey, THREE_DES_KEY_LENGTH, secretKey, secretKeyLen, (ubyte*)pCertsData[i].pCertData, pCertsData[i].certDataLen, &cmsEnv, &cmsEnvLen)))
            {
                goto attest_exit;
            }

            ppCMSArr[i].bodyPartId = bodyPartIdBase + i;
	        if (OK > (status = DIGI_MALLOC((void **)&taggedAttributeValues, sizeof(taggedContent))))
	        {
		        goto attest_exit;
	        }
            taggedAttributeValues[0].pData = cmsEnv;
            taggedAttributeValues[0].dataLen = cmsEnvLen;
            ppCMSArr[i].pTaggedContentInfo = taggedAttributeValues;

    	    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);
			if (symmKey)
				DIGI_FREE((void **)&symmKey);
        }
        noOfCMS = certDataLen;
        if (OK > (status = DER_Serialize(pControlInfo, &pBatchRespRefData, &batchRespRefDataLen)))
        {
            goto attest_exit;
        }

        /* Add signing certificate */
        if (OK > (status = DIGI_CALLOC((void **)&ppCertificates, 1, sizeof(ASN1_ITEMPTR))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_CALLOC((void **)&pCStreams, 1, sizeof(CStream))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_CALLOC((void **)&ppCStreams, 1, sizeof(CStream *))))
        {
            goto exit;
        }
        if (OK >(status = DIGI_MALLOC((void **)&pCertCs, sizeof(CStream))))
        {
            goto exit;
        }
        if (OK >(status = DIGI_MALLOC((void **)&pCertMemFile, sizeof(MemFile))))
        {
            goto exit;
        }
        MF_attach(pCertMemFile, signerCertByteLen, (ubyte*)pSignerCertBytes);
        CS_AttachMemFile(pCertCs, pCertMemFile);

        if (OK >(status = X509_parseCertificate(*pCertCs, &pCertData)) || !pCertData)
        {
            goto exit;
        }

        ppCertificates[0] = pCertData;
        pCStreams[0] = *pCertCs;
        ppCStreams[0] = pCertCs;

attest_exit:
        CRYPTO_uninitAsymmetricKey(&eAsymKey, NULL);
        if (pControlInfo) TREE_DeleteTreeItem((TreeItem *)pControlInfo);
        if (OK > status) goto exit;
    }
    else
    {
        if (OK > (status = DIGI_CALLOC((void **)&ppCertificates, certDataLen + 1, sizeof(ASN1_ITEMPTR))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_CALLOC((void **)&pCStreams, certDataLen + 1, sizeof(CStream))))
        {
            goto exit;
        }
        if (OK > (status = DIGI_CALLOC((void **)&ppCStreams, certDataLen + 1, sizeof(CStream *))))
        {
            goto exit;
        }
        for (i = 0; i < certDataLen + 1; i++)
        {
            ASN1_ITEMPTR    pCertData = NULL;
            MemFile         *pCertMemFile = NULL;
            CStream         *pCertCs = NULL;

            if (OK >(status = DIGI_MALLOC((void **)&pCertCs, sizeof(CStream))))
            {
                goto exit;
            }
            if (OK >(status = DIGI_MALLOC((void **)&pCertMemFile, sizeof(MemFile))))
            {
                goto exit;
            }
            if(i < certDataLen)
            {
                MF_attach(pCertMemFile, pCertsData[i].certDataLen, (ubyte*)pCertsData[i].pCertData);
                CS_AttachMemFile(pCertCs, pCertMemFile);
            }
            else
            {
                MF_attach(pCertMemFile, signerCertByteLen, (ubyte*)pSignerCertBytes);
                CS_AttachMemFile(pCertCs, pCertMemFile);
            }

            if (OK >(status = X509_parseCertificate(*pCertCs, &pCertData)) || !pCertData)
            {
                goto exit;
            }

            ppCertificates[i] = pCertData;
            pCStreams[i] = *pCertCs;
            ppCStreams[i] = pCertCs;
        }
    }
	/* wrap in ContentInfo */
	if (OK > (status = CMS_createContentInfo(pkcs7_signedData_OID, &pContentInfo, &pContent)))
		goto exit;

	refIdArr[0] = 0;
	if (OK > (status = CMC_addCMCStatusInfoV2(success, refIdArr, 1, &pStatusData, &statusDataLen)))
	{
		goto exit;
	}

    ppControlArr[0].bodyPartId = 201;
    ppControlArr[0].pAttributeTypeOid = (ubyte*)statusInfoV2_oid;

	if (OK > (status = DIGI_CALLOC((void **)&taggedAttributeValues, 1, sizeof(taggedContent))))
	{
		goto exit;
	}
    taggedAttributeValues[0].pData = pStatusData;
    taggedAttributeValues[0].dataLen = statusDataLen;
    ppControlArr[0].pTaggedAttributeValues = taggedAttributeValues;
    ppControlArr[0].numAttributeValues = 1;

    if (isAttest)
    {
        DER_ITEMPTR pTempItem = NULL;
        ubyte *pAttestData = NULL;
        ubyte4 attestDataLen;

        if (OK > (status = DER_AddItem( NULL, PRINTABLESTRING, 11, "TPM2-ATTEST", &pTempItem)))
        {
            goto exit;
        }
        if (OK > (status = DER_Serialize(pTempItem, &pAttestData, &attestDataLen)))
        {
            goto exit;
        }

	    if (pTempItem) TREE_DeleteTreeItem((TreeItem *)pTempItem);

        /* TPM2_ATTEST control */
        ppControlArr[1].bodyPartId = 202;
        ppControlArr[1].pAttributeTypeOid = (ubyte*)mocana_attest_tpm2_oid;
	    if (OK > (status = DIGI_MALLOC((void **)&taggedAttributeValues, sizeof(taggedContent))))
	    {
		    goto exit;
	    }
        taggedAttributeValues[0].pData = pAttestData;
        taggedAttributeValues[0].dataLen = attestDataLen;
        ppControlArr[1].pTaggedAttributeValues = taggedAttributeValues;
        ppControlArr[1].numAttributeValues = 1;


        /* Control for batch response referance ids */
        ppControlArr[2].bodyPartId = 203;
        ppControlArr[2].pAttributeTypeOid = (ubyte*)batchResponses_oid;
	    if (OK > (status = DIGI_MALLOC((void **)&taggedAttributeValues, sizeof(taggedContent))))
	    {
		    goto exit;
	    }
        taggedAttributeValues[0].pData = pBatchRespRefData;
        taggedAttributeValues[0].dataLen = batchRespRefDataLen;
        ppControlArr[2].pTaggedAttributeValues = taggedAttributeValues;
        ppControlArr[2].numAttributeValues = 1;
    }

    if (OK != (status = CMC_createPKIDataEx(ppControlArr, noOfControls, NULL, 0, ppCMSArr, noOfCMS, NULL, 0, &pPKIResponseData, &pkiResponseDataLen)))
    {
        goto exit;
    }

	if (OK > (status = CMC_SignData(MOC_ASYM(hwAccelCtx) 0,
		pContentInfo, pContent,
		ppCertificates, pCStreams, isAttest ? 1 : certDataLen + 1,
		NULL, NULL, 0, /* no CRLs */
		myCmcSignerInfoPtr, 1, /* one signer */
		cct_PKIResponse_OID,
		pPKIResponseData, pkiResponseDataLen,
		RANDOM_rngFun,
		pRandomContext,
		ppPkiMessage, pPkiMessageLen)))
	{
		goto exit;
	}

exit:
	if (NULL == g_pRandomContext) {
		RANDOM_releaseContext(&pRandomContext);
	}
	if (pSignerCert)
	{
		TREE_DeleteTreeItem((TreeItem*)pSignerCert);
	}
	if (ppCertificates)
	{
		for (i = 0; i < (isAttest ? 1 : certDataLen + 1); i++)
		{
            if (ppCertificates[i]) {
                TREE_DeleteTreeItem((TreeItem*)ppCertificates[i]);
            }
		}
		DIGI_FREE((void **)&ppCertificates);
	}
	if (ppCStreams)
	{
		for (i = 0; i < (isAttest ? 1 : certDataLen + 1); i++)
		{
            if (ppCStreams[i]) {
                DIGI_FREE((void **)&ppCStreams[i]);
            }
		}
		DIGI_FREE((void **)&ppCStreams);
	}
	if (pCStreams)
		DIGI_FREE((void **)&pCStreams);
	if (ppControlArr)
	{
		for (i = 0; i < noOfControls; i++)
		{
            if (ppControlArr[i].pTaggedAttributeValues) {
                ubyte4 j = 0;
                for (j = 0; j < ppControlArr[i].numAttributeValues; j++)
                {
                    if (ppControlArr[i].pTaggedAttributeValues[j].pData)
                        DIGI_FREE((void **)&ppControlArr[i].pTaggedAttributeValues[j].pData);
                }
                DIGI_FREE((void **)&ppControlArr[i].pTaggedAttributeValues);
            }
		}
		DIGI_FREE((void **)&ppControlArr);
	}
	if (ppCMSArr)
	{
		for (i = 0; i < noOfCMS; i++)
		{
            if (ppCMSArr[i].pTaggedContentInfo) {
                if (ppCMSArr[i].pTaggedContentInfo->pData)
                    DIGI_FREE((void **)&ppCMSArr[i].pTaggedContentInfo->pData);
                DIGI_FREE((void **)&ppCMSArr[i].pTaggedContentInfo);
            }
		}
		DIGI_FREE((void **)&ppCMSArr);
	}
	if (pContentInfo)
		TREE_DeleteTreeItem((TreeItem*)pContentInfo);
	if (pPKIResponseData)
		DIGI_FREE((void **)&pPKIResponseData);
	if (pAttributeData)
		DIGI_FREE((void **)&pAttributeData);
	return status;
}

/* Creates a CMS Enveloped data for KEKRecipientInfo */
MOC_EXTERN
MSTATUS CMC_createCMSEnvelopForKekri(ubyte *encryptAlgoOID, BulkEncryptionAlgo* pBulkEncryptionAlgo, sbyte4 keyLength,
	ubyte *decryptKeyIdentifierData, ubyte4 decryptKeyIdentifierDataLen,
	ubyte *pPreSharedKey, ubyte4 preSharedKeyLen,
    ubyte *pSecret, ubyte4 secretLen,
	ubyte *pPayload, ubyte4 payloadLen,
	ubyte** ppOutData, ubyte4 *pOutDataLen)
{
    MSTATUS status = OK;
    randomContext* pRandomContext = NULL;
    sbyte4 i, padSize = 0;
    DER_ITEMPTR pRoot, pEnvelopedData, pTemp, pEncryptionAlgo, pRecipientInfo;
    ubyte *pCryptoBuf = NULL;
    ubyte *iv = NULL, *ivCopy = NULL;
    ubyte version[MAX_DER_STORAGE] = {0};

	if (OK > (status = DER_AddSequence(NULL, &pRoot)))
		goto exit;

	if (OK > (status = DER_AddOID(pRoot, pkcs7_envelopedData_OID, NULL)))
		goto exit;

	if (OK > (status = DER_AddTag(pRoot, 0, &pTemp)))
		goto exit;

	if (OK > (status = DER_AddSequence(pTemp, &pEnvelopedData)))
		goto exit;

	version[0] = 2;
	if (OK > (status = DER_AddItemCopyData(pEnvelopedData, INTEGER, 1, version, NULL)))
		goto exit;

	/* add the recipient infos */
	/* recipient information */
	if (OK > (status = DER_AddSet(pEnvelopedData, &pTemp)))
		goto exit;

	if (OK > (status = DER_AddSequence(pTemp, &pRecipientInfo)))
		goto exit;

	/* recipient info version = 4 */
	version[0] = 4;
	if (OK > (status = DER_AddItemCopyData(pRecipientInfo, INTEGER, 1, version, NULL)))
		goto exit;

	if (OK > (status = DER_AddDERBuffer(pRecipientInfo, decryptKeyIdentifierDataLen, decryptKeyIdentifierData, NULL)))
		goto exit;

	/* digestAlgorithm */
	if (OK > (status = DER_StoreAlgoOID(pRecipientInfo, encryptAlgoOID, TRUE)))
		goto exit;

	ubyte *temp = NULL;
    if (pSecret)
    {
	    DIGI_MALLOC((void **)&temp, secretLen);
	    DIGI_MEMCPY(temp, pSecret, secretLen);
	    if (OK > (status = DER_AddItemOwnData(pRecipientInfo, OCTETSTRING,
		    secretLen, &temp, NULL)))
	    {
		    goto exit;
	    }
    }
    else
    {
        /* TODO Do we really want to add Symmetric key? because it is already shared between client and server. */
	    DIGI_MALLOC((void **)&temp, preSharedKeyLen);
	    DIGI_MEMCPY(temp, pPreSharedKey, preSharedKeyLen);
	    if (OK > (status = DER_AddItemOwnData(pRecipientInfo, OCTETSTRING,
		    preSharedKeyLen, &temp, NULL)))
	    {
		    goto exit;
	    }
    }
	if (temp) DIGI_FREE((void **)&temp);

	/* add the encrypted content info */
	if (OK > (status = DER_AddSequence(pEnvelopedData, &pTemp)))
		goto exit;

	/* content type */
	if (OK > (status = DER_AddOID(pTemp, pkcs7_data_OID, NULL)))
		goto exit;

	/* encryption algo */
	if (OK > (status = DER_AddSequence(pTemp, &pEncryptionAlgo)))
		goto exit;

	if (OK > (status = DER_AddOID(pEncryptionAlgo, encryptAlgoOID, NULL)))
		goto exit;


	/* Encrypt the CMS SignedData */
	padSize = pBulkEncryptionAlgo->blockSize - (payloadLen % pBulkEncryptionAlgo->blockSize);
	if (0 == padSize) padSize = pBulkEncryptionAlgo->blockSize;

	if (OK >(status = CRYPTO_ALLOC(MOC_RSA(hwAccelCtx), payloadLen + padSize, TRUE, &pCryptoBuf)))
		goto exit;

	DIGI_MEMCPY(pCryptoBuf, pPayload, payloadLen);

	for (i = 0; i < padSize; ++i)
	{
		pCryptoBuf[payloadLen + i] = (ubyte)padSize;
	}

	DIGI_MALLOC((void **)&iv, pBulkEncryptionAlgo->blockSize);

    if (NULL == g_pRandomContext)
    {
        if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
            goto exit;
    }
    else
    {
        pRandomContext = g_pRandomContext;
    }

	if (OK > (status = RANDOM_numberGenerator(pRandomContext, iv, pBulkEncryptionAlgo->blockSize)))
        goto exit;

	DIGI_MALLOC((void **)&ivCopy, pBulkEncryptionAlgo->blockSize);
	DIGI_MEMCPY(ivCopy, iv, pBulkEncryptionAlgo->blockSize);

	/* encrypt in place */
	if (OK >(status = CRYPTO_Process(MOC_SYM(hwAccelCtx) pBulkEncryptionAlgo,
		pPreSharedKey, preSharedKeyLen, iv, pCryptoBuf, payloadLen + padSize, 1)))
	{
		goto exit;
	}

	if (OK > (status = DER_AddItemOwnData(pEncryptionAlgo, OCTETSTRING,
		pBulkEncryptionAlgo->blockSize,
		&ivCopy, NULL)))
	{
		goto exit;
	}

	/* encrypted content */
	if (OK > (status = DER_AddTag(pTemp, 0, &pTemp)))
	{
		goto exit;
	}

	if (OK > (status = DER_AddItemOwnData(pTemp, OCTETSTRING,
		payloadLen + padSize, &pCryptoBuf, NULL)))
	{
		goto exit;
	}

	if (OK > (status = DER_Serialize(pRoot, ppOutData, pOutDataLen)))
	{
		goto exit;
	}

exit:
	if (pRoot) DER_Free(pRoot);
	if (iv) DIGI_FREE((void **)&iv);
	if (ivCopy) DIGI_FREE((void **)&ivCopy);
	if (NULL == g_pRandomContext) RANDOM_releaseContext(&pRandomContext);
	return status;
}

/* Creates a CMS Enveloped data for KeyTransRecipientInfo */
MOC_EXTERN
MSTATUS CMC_createCMSEnvelopForKtri(ubyte *encryptAlgoOID,
	ubyte *pPreSharedCert, ubyte4 preSharedCertLen,
	ubyte *pPayload, ubyte4 payloadLen,
	ubyte** ppRetKeyData, ubyte4 *pRetKeyDataLen)
{
	MSTATUS status = OK;
	CMS_envelopedDataContext envelopDataCtx = 0;
	randomContext*	pRandomContext = NULL;

	if (NULL == g_pRandomContext) {
		if (OK > (status = RANDOM_acquireContext(&pRandomContext)))
		{
			goto exit;
		}
	}
	else
	{
		pRandomContext = g_pRandomContext;
	}

	if (OK > (status = CMS_envelopedNewContext(&envelopDataCtx, encryptAlgoOID, RANDOM_rngFun, pRandomContext)))
	{
		goto exit;
	}

	if (OK > (status = CMS_envelopedAddRecipient(envelopDataCtx, pPreSharedCert, preSharedCertLen)))
	{
		goto exit;
	}
	if (OK > (status = CMS_envelopedUpdateContext(MOC_HW(hwAccelCtx) envelopDataCtx, pPayload, payloadLen, ppRetKeyData, pRetKeyDataLen, TRUE)))
	{
		goto exit;
	}

exit:
	if (envelopDataCtx) CMS_envelopedDeleteContext(MOC_HASH(hwAccelCtx) &envelopDataCtx);
	if (NULL == g_pRandomContext) RANDOM_releaseContext(&pRandomContext);
	return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
CMC_SignData( MOC_ASYM(hwAccelDescr hwAccelCtx)
               ubyte4 flags,
               DER_ITEMPTR pStart,
               DER_ITEMPTR pParent,
               ASN1_ITEMPTR pCACertificatesParseRoots[/*numCACerts*/],
               CStream pCAStreams[/*numCACerts*/],
               sbyte4 numCACerts,
               ASN1_ITEMPTR pCrlsParseRoots[/*numCrls*/],
               CStream pCrlStreams[/*numCrls*/],
               sbyte4 numCrls,
               cmcSignerInfoPtr *pCmcSignerInfos, /* if NULL, degenerate case */
               ubyte4 numSigners, /* number of signers */
               const ubyte* payLoadType, /* OID, if NULL, degenerate case*/
               const ubyte* pPayLoad,
               ubyte4 payLoadLen,
               RNGFun rngFun,
               void* rngFunArg,
               ubyte** ppSigned,
               ubyte4* pSignedLen)
{
    MSTATUS         status = OK;
    DER_ITEMPTR     pSignedData = NULL;
    DER_ITEMPTR     pTempItem,
                    pSignerInfosItem;
    ubyte**         pDataBuffers = 0; /* keep track of allocated buffers
                                      referenced by added DER_ITEM (signatures) */
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte4          i;
    ubyte4          signedBufferLen;
    ubyte          *signedBuffer = NULL;
    ubyte          *pTempBuf = NULL;
    SignedDataHash *pSignedDataHash = 0;
    ubyte4          numHashes = 0;
    ubyte4          hashes = 0;

    if (!ppSigned || !pSignedLen)
    {
        return ERR_NULL_POINTER;
    }

    if ( OK > ( status = DER_AddSequence( pParent, &pSignedData)))
        goto exit;

    /* version = 3 */
    copyData[0] = 3;
    if ( OK > ( status = DER_AddItemCopyData( pSignedData, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* digestAlgorithms */
    if ( OK > ( status = DER_AddSet( pSignedData, &pTempItem)))
        goto exit;

    /* Add all unique digestAlgos */
    /* NOTE: we are computing digest for each signer. one optimization,
     * when there are multiple signers present, is to compute the digest
     * once for each unique digest algorithm, and reuse the digest for all
     * signers with the same digest algorithm.
     */
    if (numSigners > 0)
    {
        if (payLoadLen > 0)
        {
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, payLoadLen, TRUE, &pTempBuf)))
                goto exit;

            DIGI_MEMCPY(pTempBuf, pPayLoad, payLoadLen);
        }

        for (i = 0; i < numSigners; i++)
        {
            ubyte hashId;
            if ( OK > (status = PKCS7_GetHashAlgoIdFromHashAlgoOID2(
                                    pCmcSignerInfos[i]->pSignerInfo->digestAlgoOID,
                                    &hashId)))
            {
                goto exit;
            }

            hashes |= (1 << hashId);
        }

        if (OK > (status = PKCS7_ConstructHashes( MOC_HASH(hwAccelCtx) hashes, &numHashes, &pSignedDataHash)))
        {
            goto exit;
        }

        for (i = 0; i < numHashes; ++i)
        {
            if ( OK > ( status = DER_StoreAlgoOID( pTempItem,
                                                   pSignedDataHash[i].algoOID,
                                                   TRUE)))
            {
                goto exit;
            }
            pSignedDataHash[i].hashAlgo->updateFunc( MOC_HASH(hwAccelCtx)
                                                    pSignedDataHash[i].bulkCtx,
                                                    pTempBuf, payLoadLen);
            pSignedDataHash[i].hashAlgo->finalFunc( MOC_HASH(hwAccelCtx)
                                                    pSignedDataHash[i].bulkCtx,
                                                    pSignedDataHash[i].hashData);
        }
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
        pTempBuf = NULL;
    }
    /* else the degenerate case will be an empty set */

    /* contentInfo */
    if (flags & PKCS7_EXTERNAL_SIGNATURES)
    {
        if (OK > (status = CMC_AddContentInfo(pSignedData, payLoadType, NULL, 0, NULL)))
            goto exit;
    }
    else
    {
        if (OK > (status = CMC_AddContentInfo(pSignedData, payLoadType, pPayLoad, payLoadLen, NULL)))
            goto exit;
    }

    /* OPTIONAL certificates, it should be present for ease of verification */
    if (numCACerts > 0)
    {
        if (OK > (status = PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(pSignedData,
            0, 0, pCAStreams, pCACertificatesParseRoots, numCACerts, NULL)))
            goto exit;
    }

    /* OPTIONAL crls */
    if (numCrls > 0)
    {
        if (OK > (status = PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(pSignedData,
            1, 0, pCrlStreams, pCrlsParseRoots, numCrls, NULL)))
            goto exit;
    }

    if ( OK > ( status = DER_AddSet ( pSignedData, &pSignerInfosItem)))
        goto exit;

    if (numSigners > 0)
    {
        /* allocate space for keeping track of signature buffers */
        if (NULL == (pDataBuffers = MALLOC( numSigners * sizeof( const ubyte*))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        for (i = 0; i < numSigners; i++)
        {
            pDataBuffers[i] = NULL;
        }

        for ( i = 0; i < numSigners; ++i)
        {
            /* figure out the hash for this signer */
            ubyte4 j;
            SignedDataHash* pHash = 0;

            for (j = 0; j< numHashes; ++j)
            {
                if ( EqualOID( pCmcSignerInfos[i]->pSignerInfo->digestAlgoOID,
                                pSignedDataHash[j].algoOID))
                {
                    pHash = pSignedDataHash+j;
                    break;
                }
            }

            if (!pHash)
            {
                status = ERR_PKCS7_INVALID_STRUCT;
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = CMC_AddPerSignerInfo(MOC_ASYM(hwAccelCtx) pSignerInfosItem,
                        pCmcSignerInfos[i], pHash, (ubyte *)pPayLoad, payLoadLen, rngFun,  rngFunArg,
                        (ubyte*)payLoadType, &(pDataBuffers[i]) )))
            {
                goto exit;
            }
#else
            if (OK > (status = CMC_AddPerSignerInfo(MOC_ASYM(hwAccelCtx) pSignerInfosItem,
                        pCmcSignerInfos[i], pHash, rngFun,  rngFunArg,
                        (ubyte*)payLoadType, &(pDataBuffers[i]) )))
            {
                goto exit;
            }
#endif
        }
    }

    /* write everything to our buffer */
    if ( OK > ( status = DER_Serialize( pStart ? pStart : pSignedData,
                                        &signedBuffer, &signedBufferLen)))
    {
        goto exit;
    }

    /* return the buffer */
    *ppSigned = signedBuffer;
    signedBuffer = NULL;
    *pSignedLen = signedBufferLen;

exit:
    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    /* delete the buffers holding the encryptedDigest */
    if (pDataBuffers)
    {
        for (i = 0; i < numSigners; i++)
        {
            if (pDataBuffers[i])
            {
                FREE(pDataBuffers[i]);
            }
        }
        FREE(pDataBuffers);
    }

    /* delete the DER tree */
    if (pSignedData)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSignedData);
    }

    if (pSignedDataHash)
    {
        PKCS7_DestructHashes(MOC_HASH(hwAccelCtx) numHashes, &pSignedDataHash);
    }

    return status;
}

#endif /* defined(__ENABLE_DIGICERT_CMS__) && defined(__ENABLE_DIGICERT_CMC__) */

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS7_SignData( MOC_ASYM(hwAccelDescr hwAccelCtx)
               ubyte4 flags,
               DER_ITEMPTR pStart,
               DER_ITEMPTR pParent,
               ASN1_ITEMPTR pCACertificatesParseRoots[/*numCACerts*/],
               CStream pCAStreams[/*numCACerts*/],
               sbyte4 numCACerts,
               ASN1_ITEMPTR pCrlsParseRoots[/*numCrls*/],
               CStream pCrlStreams[/*numCrls*/],
               sbyte4 numCrls,
               signerInfoPtr *pSignerInfos, /* if NULL, degenerate case */
               ubyte4 numSigners, /* number of signers */
               const ubyte* payLoadType, /* OID, if NULL, degenerate case*/
               const ubyte* pPayLoad,
               ubyte4 payLoadLen,
               RNGFun rngFun,
               void* rngFunArg,
               ubyte** ppSigned,
               ubyte4* pSignedLen)
{
    MSTATUS         status = OK;
    DER_ITEMPTR     pSignedData = NULL;
    DER_ITEMPTR     pTempItem,
                    pSignerInfosItem;
    ubyte**         pDataBuffers = 0; /* keep track of allocated buffers
                                      referenced by added DER_ITEM (signatures) */
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte4          i;
    ubyte4          signedBufferLen;
    ubyte          *signedBuffer = NULL;
    ubyte          *pTempBuf = NULL;
    SignedDataHash *pSignedDataHash = 0;
    ubyte4          numHashes = 0;
    ubyte4          hashes = 0;

    if (!ppSigned || !pSignedLen)
    {
        return ERR_NULL_POINTER;
    }

    if ( OK > ( status = DER_AddSequence( pParent, &pSignedData)))
        goto exit;

    /* version = 1 */
    copyData[0] = 1;
    if ( OK > ( status = DER_AddItemCopyData( pSignedData, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* digestAlgorithms */
    if ( OK > ( status = DER_AddSet( pSignedData, &pTempItem)))
        goto exit;

    /* Add all unique digestAlgos */
    /* NOTE: we are computing digest for each signer. one optimization,
     * when there are multiple signers present, is to compute the digest
     * once for each unique digest algorithm, and reuse the digest for all
     * signers with the same digest algorithm.
     */
    if (numSigners > 0)
    {
        if (payLoadLen > 0)
        {
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, payLoadLen, TRUE, &pTempBuf)))
                goto exit;

            DIGI_MEMCPY(pTempBuf, pPayLoad, payLoadLen);
        }

        for (i = 0; i < numSigners; i++)
        {
            ubyte hashId;
            if ( OK > (status = PKCS7_GetHashAlgoIdFromHashAlgoOID2(
                                    pSignerInfos[i]->digestAlgoOID,
                                    &hashId)))
            {
                goto exit;
            }

            hashes |= (1 << hashId);
        }

        if (OK > (status = PKCS7_ConstructHashes( MOC_HASH(hwAccelCtx) hashes, &numHashes, &pSignedDataHash)))
        {
            goto exit;
        }

        for (i = 0; i < numHashes; ++i)
        {
            if ( OK > ( status = DER_StoreAlgoOID( pTempItem,
                                                   pSignedDataHash[i].algoOID,
                                                   TRUE)))
            {
                goto exit;
            }
            pSignedDataHash[i].hashAlgo->updateFunc( MOC_HASH(hwAccelCtx)
                                                    pSignedDataHash[i].bulkCtx,
                                                    pTempBuf, payLoadLen);
            pSignedDataHash[i].hashAlgo->finalFunc( MOC_HASH(hwAccelCtx)
                                                    pSignedDataHash[i].bulkCtx,
                                                    pSignedDataHash[i].hashData);
        }
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
        pTempBuf = NULL;
    }
    /* else the degenerate case will be an empty set */

    /* contentInfo */
    if (flags & PKCS7_EXTERNAL_SIGNATURES)
    {
        if (OK > (status = PKCS7_AddContentInfo(pSignedData, payLoadType, NULL, 0, NULL)))
            goto exit;
    }
    else
    {
        if (OK > (status = PKCS7_AddContentInfo(pSignedData, payLoadType, pPayLoad, payLoadLen, NULL)))
            goto exit;
    }
    /* OPTIONAL certificates, it should be present for ease of verification */
    if (numCACerts > 0)
    {
        if (OK > (status = PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(pSignedData,
            0, 0, pCAStreams, pCACertificatesParseRoots, numCACerts, NULL)))
            goto exit;
    }

    /* OPTIONAL crls */
    if (numCrls > 0)
    {
        if (OK > (status = PKCS7_AddSetOfOrSequenceOfASN1ItemsWithTag(pSignedData,
            1, 0, pCrlStreams, pCrlsParseRoots, numCrls, NULL)))
            goto exit;
    }

    if ( OK > ( status = DER_AddSet ( pSignedData, &pSignerInfosItem)))
        goto exit;

    if (numSigners > 0)
    {
        /* allocate space for keeping track of signature buffers */
        if (NULL == (pDataBuffers = MALLOC( numSigners * sizeof( const ubyte*))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        for (i = 0; i < numSigners; i++)
        {
            pDataBuffers[i] = NULL;
        }

        for ( i = 0; i < numSigners; ++i)
        {
            /* figure out the hash for this signer */
            ubyte4 j;
            SignedDataHash* pHash = 0;

            for (j = 0; j< numHashes; ++j)
            {
                if ( EqualOID( pSignerInfos[i]->digestAlgoOID,
                                pSignedDataHash[j].algoOID))
                {
                    pHash = pSignedDataHash+j;
                    break;
                }
            }

            if (!pHash)
            {
                status = ERR_PKCS7_INVALID_STRUCT;
                goto exit;
            }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (OK > (status = PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelCtx) pSignerInfosItem,
                        pSignerInfos[i], pHash, (ubyte *)pPayLoad, payLoadLen,
                        rngFun,  rngFunArg,
                        (ubyte*)payLoadType, &(pDataBuffers[i]) )))
            {
                goto exit;
            }
#else
            if (OK > (status = PKCS7_AddPerSignerInfo(MOC_ASYM(hwAccelCtx) pSignerInfosItem,
                        pSignerInfos[i], pHash, rngFun,  rngFunArg,
                        (ubyte*)payLoadType, &(pDataBuffers[i]) )))
            {
                goto exit;
            }
#endif
        }
    }

    /* write everything to our buffer */
    if ( OK > ( status = DER_Serialize( pStart ? pStart : pSignedData,
                                        &signedBuffer, &signedBufferLen)))
    {
        goto exit;
    }

    /* return the buffer */
    *ppSigned = signedBuffer;
    signedBuffer = NULL;
    *pSignedLen = signedBufferLen;

exit:
    if (pTempBuf)
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);

    /* delete the buffers holding the encryptedDigest */
    if (pDataBuffers)
    {
        for (i = 0; i < numSigners; i++)
        {
            if (pDataBuffers[i])
            {
                FREE(pDataBuffers[i]);
            }
        }
        FREE(pDataBuffers);
    }

    /* delete the DER tree */
    if (pSignedData)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSignedData);
    }

    if (pSignedDataHash)
    {
        PKCS7_DestructHashes(MOC_HASH(hwAccelCtx) numHashes, &pSignedDataHash);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PKCS7_DigestData( MOC_HASH(hwAccelDescr hwAccelCtx)
                    DER_ITEMPTR pStart, /* can be null */
                    DER_ITEMPTR pParent,
                    const ubyte* payloadType, /* OID */
                    ubyte hashType,
                    const ubyte* pPayload,
                    ubyte4 payloadLen,
                    ubyte** ppDigested,
                    ubyte4* pDigestedLen)
{
    MSTATUS status;
    DER_ITEMPTR pDigested = 0;
    DER_ITEMPTR pDigestedData;
    DER_ITEMPTR pSeq, pTag;
    const BulkHashAlgo* pBHA = NULL;
    ubyte* digest = 0;
    const ubyte* oid;
    BulkCtx ctx = 0;

    if (!ppDigested || ! pDigestedLen)
    {
        return ERR_NULL_POINTER;
    }

    if (!payloadType)
    {
        payloadType = pkcs7_data_OID;
    }

    if (OK > ( status = CRYPTO_getHashAlgoOID( hashType, &oid)))
    {
        goto exit;
    }

    /* compute the hash */
    if (OK > ( status = CRYPTO_getRSAHashAlgo( hashType, &pBHA)))
    {
        goto exit;
    }

    if (OK > ( status = CRYPTO_ALLOC( hwAccelCtx, pBHA->digestSize, 1, &digest)))
    {
        goto exit;
    }

    if (OK > ( status = pBHA->allocFunc(MOC_HASH(hwAccelCtx) &ctx)))
    {
        goto exit;
    }
    if (OK > ( status = pBHA->initFunc(MOC_HASH(hwAccelCtx)ctx)))
    {
        goto exit;
    }
    if (OK > ( status = pBHA->updateFunc(MOC_HASH(hwAccelCtx) ctx, pPayload,
                                            payloadLen)))
    {
        goto exit;
    }
    if (OK > ( status = pBHA->finalFunc(MOC_HASH(hwAccelCtx) ctx, digest)))
    {
        goto exit;
    }

    /* build the DER */
    if (OK > ( status = DER_AddSequence(pParent, &pDigested)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddOID(pDigested, pkcs7_digestedData_OID, NULL)))
    {
        goto exit;
    }
    if (OK > ( status = DER_AddTag(pDigested, 0, &pTag)))
    {
        goto exit;
    }
    if (OK > ( status = DER_AddSequence(pTag, &pDigestedData)))
    {
        goto exit;
    }

    /* Version */
    if (OK > ( status = DER_AddIntegerEx(pDigestedData,
                                        EqualOID(payloadType, pkcs7_data_OID) ? 0 : 2,
                                        NULL)))
    {
        goto exit;
    }

    /* AlgorithmIdentifier */
    if (OK > ( status = DER_AddSequence( pDigestedData, &pSeq)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddOID( pSeq, oid, NULL)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddItem( pSeq, NULLTAG, 0, 0, NULL)))
    {
        goto exit;
    }

    /* EncapsulatedContentInfo */
    if (OK > ( status = DER_AddSequence( pDigestedData, &pSeq)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddOID( pSeq, payloadType, NULL)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddTag( pSeq, 0, &pTag)))
    {
        goto exit;
    }

    if (OK > ( status = DER_AddItem( pTag, OCTETSTRING, payloadLen, pPayload, NULL)))
    {
        goto exit;
    }
    if (OK > ( status = DER_AddItem( pDigestedData, OCTETSTRING, pBHA->digestSize, digest, NULL)))
    {
        goto exit;
    }

    /* write everything to our buffer */
    if ( OK > ( status = DER_Serialize( pStart ? pStart : pDigested,
                                        ppDigested, pDigestedLen)))
    {
        goto exit;
    }

exit:

    if (ctx)
    {
        if (NULL != pBHA)
          pBHA->freeFunc( MOC_HASH(hwAccelCtx) &ctx);
    }

    if (digest)
    {
        CRYPTO_FREE( hwAccelCtx, 1, &digest);
    }

    /* delete the DER tree */
    if (pDigested)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDigested);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
PKCS7_GetSignerDigestAlgo( ASN1_ITEMPTR pSignerInfo, CStream cs,
                          ubyte* hashAlgoId)
{
    MSTATUS status;
    ASN1_ITEMPTR pDigestAlgorithm, pOID;

    if (OK > ( status = ASN1_GetNthChild( pSignerInfo, 3, &pDigestAlgorithm)))
    {
        goto exit;
    }

    if (OK > ( status = ASN1_VerifyType( pDigestAlgorithm, SEQUENCE)))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD( pDigestAlgorithm);

    if (OK > ( status = ASN1_VerifyType( pOID, OID)))
    {
        goto exit;
    }

    if (OK > ( status = PKCS7_GetHashAlgoIdFromHashAlgoOID( pOID, cs, hashAlgoId)))
    {
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
PKCS7_GetSignerSignatureAlgo( ASN1_ITEMPTR pSignerInfo, CStream cs,
                             ubyte* pubKeyType)
{
    MSTATUS status;
    ASN1_ITEMPTR pSignatureAlgorithm, pOID;
#if defined(__ENABLE_DIGICERT_ECC__) || defined(__ENABLE_DIGICERT_DSA__)
    ubyte subType;
#endif

    if (OK > ( status = ASN1_GetNthChild( pSignerInfo, 4, &pSignatureAlgorithm)))
    {
        goto exit;
    }

    if (OK <= ASN1_VerifyTag( pSignatureAlgorithm, 0))
    {
        pSignatureAlgorithm = ASN1_NEXT_SIBLING( pSignatureAlgorithm);
    }

    if (OK > ( status = ASN1_VerifyType( pSignatureAlgorithm, SEQUENCE)))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD( pSignatureAlgorithm);

    if (OK > ( status = ASN1_VerifyType( pOID, OID)))
    {
        goto exit;
    }

    if ( OK <= ASN1_VerifyOID( pOID, cs, rsaEncryption_OID))
    {
        *pubKeyType = akt_rsa;
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( OK <= ASN1_VerifyOID( pOID, cs, dsaWithSHA1_OID) ||
            OK <= ASN1_VerifyOIDRoot( pOID, cs, dsaWithSHA2_OID, &subType))
    {
        *pubKeyType = akt_dsa;
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( OK <= ASN1_VerifyOID( pOID, cs, ecdsaWithSHA1_OID) ||
            OK <= ASN1_VerifyOIDRoot( pOID, cs, ecdsaWithSHA2_OID, &subType))
    {
        *pubKeyType = akt_ecc;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if (OK <= ASN1_VerifyOIDRoot( pOID, cs, pure_pqc_sig_OID, &subType))
    {
        if (subType >= cid_PQC_MLDSA_44 && subType <= cid_PQC_SLHDSA_SHAKE_256F)
        {
            *pubKeyType = akt_qs;
        }
        else
        {
            status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        }
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
    }

exit:

    return status;
}

/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PKCS7_GetSignerSignedAttributes( ASN1_ITEMPTR pSignerInfo,
                                ASN1_ITEMPTR *ppFirstSignedAttribute)
{
    return ASN1_GetChildWithTag( pSignerInfo, 0, ppFirstSignedAttribute);
}

/*--------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PKCS7_GetSignerUnsignedAttributes( ASN1_ITEMPTR pSignerInfo,
                        ASN1_ITEMPTR *ppFirstUnsignedAttribute)
{
    return ASN1_GetChildWithTag( pSignerInfo, 0, ppFirstUnsignedAttribute);
}


#ifdef __ENABLE_DIGICERT_CMS__
#ifdef __DISABLE_INC_FILES__
/* cms.inc is copied as cms_inc.h by install script as IDE
   doesn't support .inc files */
#include "cms_inc.h"
#else
#include "cms.inc"
#endif
#endif  /* __ENABLE_DIGICERT_CMS__ */

#endif /* __ENABLE_DIGICERT_PKCS7__ */
