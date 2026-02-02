/*
 * cms.inc
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

/**
@file       cms.inc
@brief      Mocana SoT Platform convenience API for Cryptographic Message Syntax
            (CMS) support.

@details    This file contains documentation for the definitions, enumerations,
            structures, and functions that are in the SoT Platform convenience
            API for the CMS (Cryptographic Message Syntax) objects defined in
            RFC&nbsp;5652, which defines the syntax required to digitally sign,
            digest, authenticate, or encrypt arbitrary message content.

@todo_eng_review (All functions' writeups in cms.inc because new since 5.3.1,
                    so I do not know what sort of eng-review they received, if
                    any.)
@todo_techpubs (further refine the groups, per the code comments in cms.h)

@flags
The CMS API, defined in cms.inc, is included in pkcs7.c if the following flags
are defined in moptions.h:
+ \c \__ENABLE_DIGICERT_CMS__
+ \c \__ENABLE_DIGICERT_PKCS7__

@flags
To enable any of the functions in cms.{c,h}, the following flags must be defined
in moptions.h:
+ \c \__ENABLE_DIGICERT_PKCS7__
+ \c \__ENABLE_DIGICERT_CMS__

@filedoc    cms.inc
*/

/* note that this file is included in pkcs7.c if
__ENABLE_DIGICERT_CMS__ is #defined */

#include "cms.h"
#include "../common/dynarray.h"

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
#include "../crypto/cms_resign_util.h"
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

#define EXTERNAL_ASN1_ITEM ((ASN1_ITEMPTR) -1)
#define CMS_RR_MESSAGE_ID_LEN (SHA1_RESULT_SIZE)

/*
 EnvelopedData ::= SEQUENCE {
     version CMSVersion,
     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
     recipientInfos RecipientInfos,
     encryptedContentInfo EncryptedContentInfo,
     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

OriginatorInfo ::= SEQUENCE {
     certs [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

EncryptedContentInfo ::= SEQUENCE {
     contentType ContentType,
     contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
     encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }

EncryptedContent ::= OCTET STRING

RecipientInfo ::= CHOICE {
     ktri KeyTransRecipientInfo,
     kari [1] KeyAgreeRecipientInfo,
     kekri [2] KEKRecipientInfo,
     pwri [3] PasswordRecipientInfo,
     ori [4] OtherRecipientInfo }

   KeyTransRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 0 or 2
     rid RecipientIdentifier,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   EncryptedKey ::= OCTET STRING

   RecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier }

   KeyAgreeRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 3
     originator [0] EXPLICIT OriginatorIdentifierOrKey,
     ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     recipientEncryptedKeys RecipientEncryptedKeys }

   OriginatorIdentifierOrKey ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier,
     originatorKey [1] OriginatorPublicKey }

   OriginatorPublicKey ::= SEQUENCE {
     algorithm AlgorithmIdentifier,
     publicKey BIT STRING }

   RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

   RecipientEncryptedKey ::= SEQUENCE {
     rid KeyAgreeRecipientIdentifier,
     encryptedKey EncryptedKey }

   KeyAgreeRecipientIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     rKeyId [0] IMPLICIT RecipientKeyIdentifier }

   RecipientKeyIdentifier ::= SEQUENCE {
     subjectKeyIdentifier SubjectKeyIdentifier,
     date GeneralizedTime OPTIONAL,
     other OtherKeyAttribute OPTIONAL }

   SubjectKeyIdentifier ::= OCTET STRING

   KEKRecipientInfo ::= SEQUENCE {
     version CMSVersion,  -- always set to 4
     kekid KEKIdentifier,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   KEKIdentifier ::= SEQUENCE {
     keyIdentifier OCTET STRING,
     date GeneralizedTime OPTIONAL,
     other OtherKeyAttribute OPTIONAL }

   PasswordRecipientInfo ::= SEQUENCE {
     version CMSVersion,   -- always set to 0
     keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
                                OPTIONAL,
     keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
     encryptedKey EncryptedKey }

   OtherRecipientInfo ::= SEQUENCE {
     oriType OBJECT IDENTIFIER,
     oriValue ANY DEFINED BY oriType }

*/

typedef struct CMS_EnvelopedDataCtx
{
    ASN1_ITEM*                  pContentEncryptAlgo;
    ubyte4                      decryptedOffset;    /* where we are in the pDecrypted */
    ASN1_ITEM*                  pOriginatorInfo;    /* ASN.1 item */
    sbyte4                      decryptRecipientIndex;
    intBoolean                  done;
    BulkCtx                     pBulkCtx;           /* crypto context */
    const BulkEncryptionAlgo*   pBulkAlgo;          /* crypto algo */
    ubyte4                      savedSize;
    ubyte                       saved[16];          /* bytes that did not fit in last block */
    ubyte                       iv[16];             /* iv for algo */
} CMS_EnvelopedDataCtx;

/*

 SignedData ::= SEQUENCE {
     version CMSVersion,
     digestAlgorithms DigestAlgorithmIdentifiers,
     encapContentInfo EncapsulatedContentInfo,
     certificates [0] IMPLICIT CertificateSet OPTIONAL,
     crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
     signerInfos SignerInfos }

   DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

   SignerInfos ::= SET OF SignerInfo

   EncapsulatedContentInfo ::= SEQUENCE {
     eContentType ContentType,
     eContent [0] EXPLICIT OCTET STRING OPTIONAL }

   SignerInfo ::= SEQUENCE {
     version CMSVersion,
     sid SignerIdentifier,
     digestAlgorithm DigestAlgorithmIdentifier,
     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
     signatureAlgorithm SignatureAlgorithmIdentifier,
     signature SignatureValue,
     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

   SignerIdentifier ::= CHOICE {
     issuerAndSerialNumber IssuerAndSerialNumber,
     subjectKeyIdentifier [0] SubjectKeyIdentifier }

   SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

   UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

   Attribute ::= SEQUENCE {
     attrType OBJECT IDENTIFIER,
     attrValues SET OF AttributeValue }

   AttributeValue ::= ANY

   SignatureValue ::= OCTET STRING
*/


typedef struct CMS_SignedDataCtx
{
    ASN1_ITEMPTR        pEContent;  /* does not necessarily exist  */
    ASN1_ITEMPTR        pEContentType;
    intBoolean          hashesDone;
    intBoolean          externalPayload;
    ubyte4              processedOffset;   /* where we are in the eContent  */
    ubyte4              numSigners;
    PKCS7_SignatureInfo *pSigners; /* [numSigners] */
    ubyte4              numAlgos;
    SignedDataHash      *pHashes; /* [numAlgos] */
} CMS_SignedDataCtx;

/*
DigestedData ::= SEQUENCE {
        version CMSVersion,
        digestAlgorithm DigestAlgorithmIdentifier,
        encapContentInfo EncapsulatedContentInfo,
        digest Digest }

      Digest ::= OCTET STRING
*/

/* DigestedData is a very simplified version of SignedData */
typedef struct CMS_DigestedDataCtx
{
    ASN1_ITEMPTR        pEContent;
    ASN1_ITEMPTR        pEContentType;
    intBoolean          hashDone;
    ubyte4              processedOffset;   /* where we are in the eContent  */
    SignedDataHash      *pHash;
} CMS_DigestedDataCtx;


typedef struct CMS_CTX
{
    hwAccelDescr            hwAccelCtx;
    ASN1_ParseState         asn1ParseState;    /* state of ASN.1 parsing */
    intBoolean              complete;
    CStream                 cs;                /* abstract stream */
    MemFile                 mf;                /* mem file */
    const void*             cbArg;
    CMS_Callbacks           cb;
    CMS_ContentType         type;
    ASN1_ITEM*              pContent;          /* content */
    union
    {
        CMS_EnvelopedDataCtx envCtx;
        CMS_SignedDataCtx    signedCtx;
        CMS_DigestedDataCtx  digestedCtx;
    } aux;
    void*                    pResData;
} CMS_CTX;


/* data structures used for creation */

typedef struct CMS_Data
{
    const ubyte* data;
    ubyte4 dataLen;
} CMS_Data;

typedef struct CMS_KeyData
{
    ubyte4 hashType;
    const ubyte* data;
    ubyte4 dataLen;
} CMS_KeyData;

typedef struct CMS_SignerCtx
{
    const ubyte*            cert;
    ubyte4                  certLen;
    ubyte4                  flags;
    const AsymmetricKey*    pKey;
    const ubyte*            digestAlgoOID;
    ubyte*                  signature;
    ubyte4                  signatureLen;
    ubyte*                  digest;
    ubyte4                  digestLen;
    DER_ITEMPTR             pAuthAttributes;
    DER_ITEMPTR             pUnauthAttributes;
    CMS_SignData            callback;
    void *                  pCbInfo;
} CMS_SignerCtx;

static MSTATUS CMS_deleteSignerCtx(CMS_SignerCtx** ppSigner);
static MSTATUS CMS_newSignerCtx(CMS_SignerCtx** ppSigner);


typedef struct CMS_Signed_CTX
{
    DER_ITEMPTR             pRoot;
    DER_ITEMPTR             pSignedData;
    DER_ITEMPTR             pOctetString;
    const ubyte*            payloadTypeOID;
    intBoolean              done;
    intBoolean              detached;
    RNGFun                  rngFun;
    void*                   rngFunArg;
    DynArray                certs;         /* CMS_Data [] */
    DynArray                crls;          /* CMS_Data [] */
    DynArray                signers;       /* CMS_SignerCtx* [] */
    SignedDataHash*         pSignedHashes;
    ubyte*                  receiptRequest;
    ubyte4                  receiptRequestLen;
    ubyte*                  messageID;    /* pointer to the receipt request message id */
    ubyte4                  numHashes;
    ubyte4                  outOffset;
    void*                   pResData;
} CMS_Signed_CTX;


typedef struct CMS_Enveloped_CTX
{
    DER_ITEMPTR             pRoot;
    DER_ITEMPTR             pEnvelopedData;
    DER_ITEMPTR             pZeroLabel;
    const ubyte*            encryptAlgoOID;
    intBoolean              done;
    const BulkEncryptionAlgo* pBulkEncryptionAlgo;
    BulkCtx                 encContext;
    ubyte                   iv[MAX_IV_LENGTH];
    ubyte                   last[MAX_IV_LENGTH];
    ubyte4                  lastSize;
    RNGFun                  rngFun;
    void*                   rngFunArg;
    DynArray                certs;         /* CMS_Data [] */
    DynArray                pubkeys;       /* CMS_KeyData [] */
    DER_ITEMPTR             pUnauthAttributes;
    ubyte4                  outOffset;
    ubyte                   version;
} CMS_Enveloped_CTX;


#ifdef __ENABLE_DIGICERT_RE_SIGNER__

/**
 * Install an instance of 'CMS_ResignData_CTX' into the CMS_context
 * This function adds a pointer to an object in which MOC_CMS will save extracted
 * CMS info to be used when Re-signing CMS messages.
 * Note: This is only needed by ump.c & ummaker.c when re-signing, so we are not
 * including it in header files.
 */
MOC_EXTERN void CMS_setResignCtx(CMS_context pContext, CMS_ResignData_CTX resCtx);
MOC_EXTERN void CMS_Signed_setResignCtx(CMS_signedDataContext pContext, CMS_ResignData_CTX resCtx);

#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

/*-------------------------------------------------------------------------------*/

static MSTATUS CMS_getOIDValue( CMS_CTX* pCtx, ASN1_ITEMPTR pOID, ubyte** ppOIDValue);

/*-------------------------------------------------------------------------------*/

static CMS_SignerCtx* CMS_GetSigner(const DynArray* pSigners, sbyte4 i)
{
    CMS_SignerCtx* pSigner = 0;
    DYNARR_Get( pSigners, i, &pSigner);
    return pSigner;
}


/*-------------------------------------------------------------------------*/

static ubyte4
CMS_getCurrentStreamSize( const CMS_CTX* pCtx)
{
    return pCtx->mf.size;
}

/*-------------------------------------------------------------------------*/

static MSTATUS
CMS_getContentTypeInt(CMS_CTX* pCtx)
{
    MSTATUS status;
    ASN1_ITEMPTR pSeq, pTemp, pZeroLabel;
    ubyte subType;
    ubyte4 numChildren;
/*
   ContentInfo ::= SEQUENCE {
     contentType ContentType,
     content [0] EXPLICIT ANY DEFINED BY contentType }

   ContentType ::= OBJECT IDENTIFIER
*/

    /* we want to get the contentType -- it's possible
    it's not there yet but if the content of the buffer
    is more than some limit then it's an error */

    if ( !pCtx->asn1ParseState.rootNode ||
         !(pSeq = ASN1_FIRST_CHILD(pCtx->asn1ParseState.rootNode)) )
    {
        return (pCtx->mf.size < ASN1_HEADER_MAX_SIZE) ? OK : ERR_PKCS7_INVALID_STRUCT;
    }

    numChildren = PKCS7_getNumberChildren( pSeq);
    if (numChildren < 2)
    {
        return ERR_EOF;
    }

    /* pSeq points to the parent of the content type and the content type is complete */
    pTemp = ASN1_FIRST_CHILD( pSeq); /* pTemp = contentType */
    pZeroLabel = ASN1_NEXT_SIBLING( pTemp); /* not null -> 2 children */
    pCtx->pContent = ASN1_FIRST_CHILD(pZeroLabel);
    if (!pCtx->pContent)
    {
        status = ERR_EOF;
        goto exit;
    }

    if (OK <= ASN1_VerifyOIDRoot( pTemp, pCtx->cs, pkcs7_root_OID, &subType)
        && 4 != subType)
    {
        pCtx->type = (CMS_ContentType) subType;
    }
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_CONTENT_TYPE;
        goto exit;
    }

    status = OK;

exit:

    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_newContext(CMS_context* pNewContext, const void* callbackArg,
               const CMS_Callbacks* pCallbacks)
{
    MSTATUS     status;
    CMS_CTX*  pNewCtx = 0;

    if (!pNewContext || !pCallbacks)
    {
        return ERR_NULL_POINTER;
    }

    pNewCtx = MALLOC( sizeof(CMS_CTX));
    if (!pNewCtx)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    /* sets everything to zero */
    DIGI_MEMSET( (ubyte*) pNewCtx, 0, sizeof(CMS_CTX));

    /* initialize the parse state */
    if (OK > ( status = ASN1_InitParseState( &pNewCtx->asn1ParseState)))
    {
        goto exit;
    }

    pNewCtx->cbArg = callbackArg;

    /* deep copy the callbacks */
    DIGI_MEMCPY( &pNewCtx->cb, pCallbacks, sizeof(CMS_Callbacks));

    /* initialize the abstract stream */
    CS_AttachMemFile( &pNewCtx->cs, &pNewCtx->mf);

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &pNewCtx->hwAccelCtx)))
    {
        goto exit;
    }

    *pNewContext = pNewCtx;
    pNewCtx = 0;

exit:

    if (pNewCtx)
    {
        HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &pNewCtx->hwAccelCtx);
        FREE( pNewCtx);
    }

    return status;
}


/*-------------------------------------------------------------------------*/

extern MSTATUS
CMS_deleteContext( CMS_context* pContext)
{
    CMS_CTX*  pCtx;

    if (!pContext|| !(*pContext))
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) *pContext;

    switch (pCtx->type)
    {
    case E_CMS_envelopedData:
        {
            CMS_EnvelopedDataCtx* pEnvCtx = &pCtx->aux.envCtx;
            if (pEnvCtx->pBulkAlgo && pEnvCtx->pBulkCtx)
            {
                pEnvCtx->pBulkAlgo->deleteFunc(MOC_SYM(pCtx->hwAccelCtx) &pEnvCtx->pBulkCtx);
            }
        }
        break;

    case E_CMS_signedData:
        {
            CMS_SignedDataCtx* pSigCtx = &pCtx->aux.signedCtx;
            PKCS7_DestructHashes(MOC_HASH(pCtx->hwAccelCtx) pSigCtx->numAlgos, &pSigCtx->pHashes);
            if (pSigCtx->pSigners)
            {
                FREE(pSigCtx->pSigners);
            }
        }
        break;

    case E_CMS_digestedData:
        {
            CMS_DigestedDataCtx* pDigestCtx = &pCtx->aux.digestedCtx;
            PKCS7_DestructHashes(MOC_HASH(pCtx->hwAccelCtx) 1, &pDigestCtx->pHash);
        }
        break;

    default:
        break;
    }


    /* release memory owned by the context */
    if (pCtx->asn1ParseState.rootNode)
    {
        TREE_DeleteTreeItem( (TreeItem*) pCtx->asn1ParseState.rootNode);
    }

    if (pCtx->mf.buff)
    {
        FREE( pCtx->mf.buff);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &pCtx->hwAccelCtx);

    /* zeroize everything */
    DIGI_MEMSET( (ubyte*) pCtx, 0, sizeof(CMS_CTX));

    /* finally release memory */
    FREE(pCtx);
    *pContext = 0;

    return OK;
}

/*-----------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_RE_SIGNER__

/**
 * Install an instance of 'CMS_ResignData_CTX' into the CMS_context
 * This function adds a pointer to an object in which MOC_CMS will save extracted
 * CMS info to be used when Re-signing CMS messages.
 * Note: This is only needed by ump.c, so we are not including it in header files.
 */
MOC_EXTERN void CMS_setResignCtx(CMS_context pContext, CMS_ResignData_CTX resCtx)
{
    CMS_CTX  *pCtx = NULL;
    if (pContext == NULL)
    {
        return;
    }
    pCtx = (CMS_CTX *)pContext;
    pCtx->pResData = (void*) resCtx;

}

/**
 * Install an instance of 'CMS_ResignData_CTX' into the CMS_context
 * Note: This is only needed by ummaker.c, so we are not including it in header files.
 */
MOC_EXTERN void CMS_Signed_setResignCtx(CMS_signedDataContext pContext, CMS_ResignData_CTX resCtx)
{
    CMS_Signed_CTX *pSI = NULL;
    if (pContext == NULL)
    {
        return;
    }
    pSI = (CMS_Signed_CTX *)pContext;
    pSI->pResData = (void*) resCtx;

}

MOC_EXTERN CMS_ResignData_CTX CMS_getResignCtx(CMS_context pContext)
{
    CMS_CTX*  pCtx = NULL;
    if (NULL == pContext)
    {
        return NULL;
    }

    pCtx = (CMS_CTX*) pContext;
    return (CMS_ResignData_CTX) pCtx->pResData;

}

MOC_EXTERN CMS_ResignData_CTX CMS_Signed_getResignCtx(CMS_signedDataContext pContext)
{
    CMS_Signed_CTX*  pCtx = NULL;
    if (NULL == pContext)
    {
        return NULL;
    }

    pCtx = (CMS_Signed_CTX*) pContext;
    return (CMS_ResignData_CTX) pCtx->pResData;

}
#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

/*-------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CMS_createContentInfo(const ubyte* contentType, /* oid */
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

/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getContentType( CMS_context context, CMS_ContentType* cmsContentType)
{
    if (!context || !cmsContentType)
        return ERR_NULL_POINTER;

    *cmsContentType = ((CMS_CTX*) context)->type;

    return OK;
}

/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getEncapContentType( CMS_context context, ubyte** ppOID)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !ppOID)
        return ERR_NULL_POINTER;

    *ppOID = 0;

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_envelopedData:
        if (!pCtx->aux.envCtx.pContentEncryptAlgo)
           return ERR_EOF;
        /* OK to get the eldest sibling if we have a younger one */
        status = CMS_getOIDValue( pCtx,
                        ASN1_FIRST_CHILD( ASN1_PARENT( pCtx->aux.envCtx.pContentEncryptAlgo)),
                        ppOID);
        break;

    case E_CMS_signedData:
        if (!pCtx->aux.signedCtx.pEContentType)
            return ERR_EOF;
        status = CMS_getOIDValue( pCtx,
                                pCtx->aux.signedCtx.pEContentType,
                                ppOID);
        break;

    case E_CMS_digestedData:
        if (!pCtx->aux.digestedCtx.pEContentType)
            return ERR_EOF;
        status = CMS_getOIDValue( pCtx,
                                pCtx->aux.digestedCtx.pEContentType,
                                ppOID);
        break;

    default:
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Env_GetRecipientInfos( CMS_CTX* pCtx,
                             ASN1_ITEMPTR * ppRecipientInfos)
{
    /* this function returns the pRecipientInfos and makes sure
    that it's complete -- by making sure it has a sibling */
    MSTATUS status;
    ubyte4 numChildren;
    ASN1_ITEMPTR pVersion, pRecipientInfos;
    CMS_EnvelopedDataCtx* pEnvCtx;

    /* need to process in two steps because of the optional OriginatorInfo */
    static WalkerStep getVersion[] =
    {
        { VerifyType, SEQUENCE, 0},     /* ... must be a SEQUENCE */
        { GoFirstChild, 0, 0},          /* 1st child of SEQUENCE ... */
        { VerifyType, INTEGER, 0},      /* ... must be INTEGER */
        { Complete, 0, 0}
    };

    /* verify we have three children at least */
    numChildren = PKCS7_getNumberChildren( pCtx->pContent);
    if ( numChildren < 3)
    {
        status = ERR_EOF;
        goto exit;
    }

    /* don't need to use ASN1_WalkPartialTree since we know there are already 3 children */
    if (OK > (status = ASN1_WalkTree( pCtx->pContent, pCtx->cs,
                                    getVersion, &pVersion)))
    {
        goto exit;
    }

    pEnvCtx = &pCtx->aux.envCtx;

    if ( pVersion->data.m_intVal > 0)
    {
        /* originator info might be present -- if yes, then second child is tagged with [0]
        Note that we checked there's at least 3 children */
        if (!pEnvCtx->pOriginatorInfo)
        {
            ASN1_ITEMPTR pSecondChild = ASN1_NEXT_SIBLING(pVersion);
            if ( OK <= ASN1_VerifyTag( pSecondChild, 0))
            {
                pEnvCtx->pOriginatorInfo = pSecondChild;
            }
        }
    }

    /* make sure we have enough children if pOriginatorInfo */
    if (pEnvCtx->pOriginatorInfo)
    {
        if (numChildren < 4)
        {
            status = ERR_EOF;
            goto exit;
        }
        pRecipientInfos = ASN1_NEXT_SIBLING( pEnvCtx->pOriginatorInfo);
    }
    else
    {
        pRecipientInfos = ASN1_NEXT_SIBLING( pVersion);
    }

    /* verify type */
    if (OK > (status = ASN1_VerifyType( pRecipientInfos, MOC_SET)))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    *ppRecipientInfos = pRecipientInfos;

exit:

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Env_GetEncryptionAlgo( CMS_CTX* pCtx)
{
    MSTATUS status;
    ASN1_ITEMPTR pRecipientInfos, pEncryptedContentInfo,
        pContentEncryptAlgo;
    ubyte4 numChildren;
    ubyte* pSymmetricKey = 0;
    ubyte4 symmetricKeyLen;
    CMS_EnvelopedDataCtx* pEnvCtx;

    if (OK > ( status = CMS_Env_GetRecipientInfos( pCtx, &pRecipientInfos)))
    {
        goto exit;
    }

    /* already know there are enough children */
    pEncryptedContentInfo = ASN1_NEXT_SIBLING( pRecipientInfos);
    /* verify type */
    if (OK > (status = ASN1_VerifyType( pEncryptedContentInfo, SEQUENCE)))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* verify that there are two children -- this means we can start building the algo */
    numChildren = PKCS7_getNumberChildren( pEncryptedContentInfo);
    if (numChildren <  2)
    {
        status = ERR_EOF;
        goto exit;
    }

    if (OK > ( status = ASN1_GetNthChild( pEncryptedContentInfo, 2, &pContentEncryptAlgo)))
    {
        goto exit;
    }

    /* if only 2 children, the last one might be incomplete: check */
    if ( 2 == numChildren)
    {
        intBoolean complete;
        if (OK > ( ASN1_IsItemComplete( &pCtx->asn1ParseState, pContentEncryptAlgo,
                                        pCtx->cs, &complete)))
        {
            goto exit;
        }
        if (!complete)
        {
            status = ERR_EOF;
            goto exit;
        }
    }

    pEnvCtx = &(pCtx->aux.envCtx);
    /* remember where we are: pContentEncryptAlgo = previous sibling of encryptedContent */
    pEnvCtx->pContentEncryptAlgo = pContentEncryptAlgo;
    /* process the recipient infos now  that we can build the crypto algo something */
    if (OK > ( status = PKCS7_ProcessRecipientInfos( MOC_HW(pCtx->hwAccelCtx)
                                                    pRecipientInfos, pCtx->cs,
                                                    pCtx->cbArg, NULL,
                                                    pCtx->cb.getPrivKeyFun,
                                                    &pSymmetricKey,
                                                    &symmetricKeyLen,
                                                    &pEnvCtx->decryptRecipientIndex)))
    {
        goto exit;
    }

    if (!pSymmetricKey || !symmetricKeyLen)
    {
        status = ERR_PKCS7_NO_RECIPIENT_KEY_MATCH;
        goto exit;
    }

    if (OK > ( status = PKCS7_GetBulkAlgo(MOC_SYM(pCtx->hwAccelCtx)
                                          pContentEncryptAlgo, pCtx->cs,
                                          pSymmetricKey, symmetricKeyLen,
                                          pEnvCtx->iv, &pEnvCtx->pBulkCtx,
                                          &pEnvCtx->pBulkAlgo)))
    {
        goto exit;
    }

    /* everything is set for decrypting the envelopped content */


exit:

    if (pSymmetricKey)
    {
        FREE(pSymmetricKey);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Env_DecryptData( CMS_CTX* pCtx, ubyte** pOutput, ubyte4* pOutputLen)
{
    MSTATUS status = OK;
    CMS_EnvelopedDataCtx* pEnvCtx;
    ASN1_ITEM* pEncryptedContent = 0;
    ubyte4 streamSize, copySize, offset, totalSize, blockSize;
    ubyte* buff = 0;
    ubyte lastByte;

    pEnvCtx = &pCtx->aux.envCtx;

    if (pEnvCtx->done)
    {
        *pOutput = 0;
        *pOutputLen = 0;
        return OK;
    }

    if (!pEnvCtx->pContentEncryptAlgo)
    {
        return ERR_INTERNAL_ERROR;
    }

    pEncryptedContent =
        ASN1_GetNextSiblingFromPartialParse( &pCtx->asn1ParseState,
                                             pEnvCtx->pContentEncryptAlgo,
                                             pCtx->cs);

    if (!pEncryptedContent)
    {
        status = ERR_EOF;
        goto exit;
    }

    streamSize = CMS_getCurrentStreamSize(pCtx);

    /* use ASN1_GetData */
    offset = pEnvCtx->decryptedOffset;
    copySize = ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs,
                            streamSize, pEncryptedContent, &offset,
                            pCtx->mf.buff, 0);

    if (ASN1_PARENT(pEncryptedContent))
    {
        if (OK > ( status = ASN1_IsItemComplete(&pCtx->asn1ParseState,
                                                pEncryptedContent, pCtx->cs,
                                                &pEnvCtx->done)))
        {
            goto exit;
        }
    }

    totalSize = copySize + pEnvCtx->savedSize;

    if (pEnvCtx->pBulkAlgo->blockSize > 0)
    {
        blockSize = totalSize % pEnvCtx->pBulkAlgo->blockSize;
        /* make sure we don't decrypt the last block if we are
        not done -- the EOC might be next */
        if ( !pEnvCtx->done && 0 == blockSize)
        {
            blockSize = pEnvCtx->pBulkAlgo->blockSize;
        }
    }
    else
    {
        blockSize = 0;
    }

    /* size must be a multiple of encryption block */
    if (pEnvCtx->done && blockSize)
    {
        status = ERR_PKCS7_INVALID_ENCRYPTED_LENGTH;
        goto exit;
    }

    /* something to return only if totalSize >= pEnvCtx->pBulkAlgo->blockSize */
    if ( totalSize < pEnvCtx->pBulkAlgo->blockSize)
    {
        *pOutput = 0;
        *pOutputLen = 0;
        goto exit;
    }

    /* easier to allocate enough for all the data */
    buff = MALLOC( totalSize);
    if (! buff)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* copy savedSize to the buffer */
    DIGI_MEMCPY(buff, pEnvCtx->saved, pEnvCtx->savedSize);

    /* collect all the data */
    ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs, streamSize,
                  pEncryptedContent, &pEnvCtx->decryptedOffset,
                  pCtx->mf.buff, buff + pEnvCtx->savedSize);

    /* save the bytes not in a block */
    totalSize -= blockSize;
    DIGI_MEMCPY( pEnvCtx->saved, buff + totalSize, blockSize);
    pEnvCtx->savedSize = blockSize;
    DIGI_MEMSET( buff + totalSize, 0, blockSize); /* don't leak encrypted bytes */

    if  (OK > ( status = pEnvCtx->pBulkAlgo->cipherFunc(MOC_SYM(pCtx->hwAccelCtx)
                                                        pEnvCtx->pBulkCtx,
                                                        buff, totalSize, 0,
                                                        pEnvCtx->iv)))
    {
        goto exit;
    }

    if ( pEnvCtx->done && pEnvCtx->pBulkAlgo->blockSize > 0)
    {
        /* look at last byte for padding */
        lastByte = buff[ totalSize - 1];
        if ( lastByte < 1 || lastByte > pEnvCtx->pBulkAlgo->blockSize)
        {
            status = ERR_CRYPTO_BAD_PAD;
            goto exit;
        }
    }
    else
    {
        lastByte = 0;
    }
    *pOutputLen = totalSize - lastByte;
    *pOutput = buff;
    buff = 0;

exit:

    if (buff)
    {
        FREE(buff);
    }

    /* delete pEncryptedContent if not linked to a Tree */
    if (pEncryptedContent && 0 == ASN1_PARENT(pEncryptedContent))
    {
        TREE_DeleteTreeItem( (TreeItem*) pEncryptedContent);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_EnvelopedData( CMS_CTX* pCtx, ubyte** output, ubyte4* pOutputLen)
{
    MSTATUS status;

    if (!pCtx->aux.envCtx.pBulkCtx)
    {
        /* look for it */
        if (OK > ( status = CMS_Env_GetEncryptionAlgo( pCtx)))
        {
            goto exit;
        }
    }

    if (pCtx->aux.envCtx.pBulkCtx)
    {
        if (OK > ( status = CMS_Env_DecryptData( pCtx, output, pOutputLen)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_EOF;
    }

exit:

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getNumRecipients( CMS_context context, sbyte4* numRecipients)
{
    MSTATUS status;
    CMS_CTX* pCtx;
    ASN1_ITEMPTR pRecipientInfos;
    intBoolean complete;

    if (!context || !numRecipients)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_envelopedData:
        if (OK > (status = CMS_Env_GetRecipientInfos( pCtx, &pRecipientInfos)))
            return status;
        if ( OK > ( status = ASN1_IsItemComplete( &pCtx->asn1ParseState,
                            pRecipientInfos, pCtx->cs, &complete)))
        {
            return status;
        }
        if (!complete)
        {
            return ERR_EOF;
        }
        *numRecipients = (sbyte4) PKCS7_getNumberChildren( pRecipientInfos);
        break;

    default:
        *numRecipients = 0;
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getRecipientInfo( CMS_context context, sbyte4 recipientIndexZeroBased,
                      const ASN1_ITEM** pRecipientInfo, CStream* pCS)
{
    MSTATUS status;
    CMS_CTX* pCtx;
    ASN1_ITEMPTR pRecipientInfos;
    intBoolean complete;
    ubyte4 nth;

    if (!context || !pRecipientInfo || !pCS)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_envelopedData:
        if (OK > (status = CMS_Env_GetRecipientInfos( pCtx, &pRecipientInfos)))
            return status;
        if ( OK > ( status = ASN1_IsItemComplete( &pCtx->asn1ParseState,
                            pRecipientInfos, pCtx->cs, &complete)))
        {
            return status;
        }
        if (!complete)
        {
            return ERR_EOF;
        }
        /* signed 0 based to unsigned 1 based */
        if ( recipientIndexZeroBased < 0)
        {
            return ERR_INDEX_OOB;
        }
        nth = (ubyte4) (recipientIndexZeroBased + 1);
        if (OK > ( status = ASN1_GetNthChild( pRecipientInfos, nth,
                                            (ASN1_ITEM**) pRecipientInfo)))
        {
            return status;
        }
        *pCS = pCtx->cs;
        break;

    default:
        *pRecipientInfo = 0;
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getDecryptingRecipient( CMS_context context,
                           sbyte4* recipientIndexZeroBased)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !recipientIndexZeroBased)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_envelopedData:
        /* verify we have instantiated the algo */
        if (!pCtx->aux.envCtx.pBulkCtx)
        {
            return ERR_EOF;
        }
        *recipientIndexZeroBased = pCtx->aux.envCtx.decryptRecipientIndex;
        status = OK;
        break;

    default:
        *recipientIndexZeroBased = -1;
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_getOIDValue( CMS_CTX* pCtx, ASN1_ITEMPTR pOID, ubyte** ppOIDValue)
{
    ubyte* buffer = 0;

    *ppOIDValue = 0;

    buffer = MALLOC( pOID->length + 1);
    if (!buffer)
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    DIGI_MEMCPY( buffer,
                pCtx->mf.buff + pOID->dataOffset - 1,
                pOID->length + 1);
    *ppOIDValue = buffer;

    return OK;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getEncryptionAlgo( CMS_context context, ubyte** ppEncryptionAlgoOID)
{
    MSTATUS status;
    CMS_CTX* pCtx;
    ASN1_ITEMPTR pTemp;

    if (!context || !ppEncryptionAlgoOID)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;
    *ppEncryptionAlgoOID = NULL;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_envelopedData:
        /* verify we have instantiated the member */
        if (!pCtx->aux.envCtx.pContentEncryptAlgo)
        {
            return ERR_EOF;
        }
        pTemp = ASN1_FIRST_CHILD( pCtx->aux.envCtx.pContentEncryptAlgo);
        if (!pTemp)
        {
            /* the code has changed since last time. Original code
            made sure the pContentEncryptAlgo had all its children */
            return ERR_INTERNAL_ERROR;
        }
        status = CMS_getOIDValue( pCtx, pTemp, ppEncryptionAlgoOID);
        break;

    default:
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Sig_GetHashAlgos( CMS_CTX* pCtx)
{
    MSTATUS status = OK;
    ASN1_ITEMPTR pDigestAlgorithms, pEncapsulatedContentInfo;
    CMS_SignedDataCtx* pSigCtx;
    ubyte4 numChildren;

    numChildren = PKCS7_getNumberChildren(pCtx->pContent);
    if (numChildren < 3)
    {
        status = ERR_EOF;
        goto exit;
    }

    pSigCtx = &pCtx->aux.signedCtx;

    /* three children so the whole digestAlgorithms is completely there */
    ASN1_GetNthChild( pCtx->pContent, 2, &pDigestAlgorithms);
    if (NULL == pDigestAlgorithms)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEncapsulatedContentInfo = ASN1_NEXT_SIBLING( pDigestAlgorithms);
/*
    EncapsulatedContentInfo ::= SEQUENCE {
        eContentType ContentType,
        eContent [0] EXPLICIT OCTET STRING OPTIONAL }
*/

    numChildren = PKCS7_getNumberChildren( pEncapsulatedContentInfo);
    if ( 0 == numChildren)
    {
        status = ERR_EOF;
        goto exit;
    }
    /* at least one child -- verify it's an OID */
    if (OK > ( ASN1_VerifyType( ASN1_FIRST_CHILD( pEncapsulatedContentInfo),
                                OID)))
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    if (numChildren < 2)
    {
        /* detached signature? */
        intBoolean itemComplete;
        if (OK > (ASN1_IsItemComplete( &pCtx->asn1ParseState,
                                        pEncapsulatedContentInfo,
                                        pCtx->cs, &itemComplete)))
        {
            goto exit;
        }
        if (itemComplete)
        {
            pSigCtx->externalPayload = TRUE;
        }
        else
        {
            status = ERR_EOF;
            goto exit;
        }
    }
    else
    {
        ASN1_GetNthChild( pEncapsulatedContentInfo, 2, &pSigCtx->pEContent);

        /* some software is quite lazy and uses BER encoding for detached signature....*/
        if (OK <= ASN1_VerifyType( pSigCtx->pEContent, EOC))
        {
            pSigCtx->pEContent = NULL;
            pSigCtx->externalPayload = TRUE;
        }
        else if (OK > ASN1_VerifyTag( pSigCtx->pEContent, 0) )
        {
            status = ERR_PKCS7_INVALID_STRUCT;
            goto exit;
        }
    }

    /* instantiate Algos using the common routine */
    if (OK > ( status = PKCS7_CollectHashAlgos( MOC_HASH(pCtx->hwAccelCtx)
                                                pDigestAlgorithms, pCtx->cs,
                                                &pSigCtx->numAlgos,
                                                &pSigCtx->pHashes)))
    {
        goto exit;
    }

    pSigCtx->pEContentType = ASN1_FIRST_CHILD( pEncapsulatedContentInfo);

exit:

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Sig_HashData( CMS_CTX* pCtx, ubyte** pOutput, ubyte4* pOutputLen)
{
    MSTATUS status = OK;
    CMS_SignedDataCtx* pSigCtx;
    ASN1_ITEMPTR pOS;
    ubyte4 streamSize, copySize, offset;
    ubyte* buff = 0;
    ubyte4 i;

    pSigCtx = &pCtx->aux.signedCtx;

    if (pSigCtx->hashesDone)
    {
        return OK;
    }

    if (!pSigCtx->pEContent)
    {
        return ERR_INTERNAL_ERROR;
    }

    pOS = ASN1_GetFirstChildFromPartialParse( &pCtx->asn1ParseState,
                                               pSigCtx->pEContent,
                                               pCtx->cs);
    if (!pOS)
    {
        status = ERR_EOF;
        goto exit;
    }

    streamSize = CMS_getCurrentStreamSize(pCtx);

    /* use ASN1_GetData */
    offset = pSigCtx->processedOffset;
    copySize = ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs,
                            streamSize, pOS, &offset,
                            pCtx->mf.buff, 0);

    /* are we done? */
    if (ASN1_PARENT(pOS))
    {
        if (OK > ( status = ASN1_IsItemComplete(&pCtx->asn1ParseState,
                                                pOS, pCtx->cs,
                                                &pSigCtx->hashesDone)))
        {
            goto exit;
        }
    }

    if ( copySize)
    {
        buff = MALLOC(copySize);
        if (! buff)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* collect all the data */
        ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs, streamSize,
                       pOS, &pSigCtx->processedOffset,
                       pCtx->mf.buff, buff);

        /* feed the data to all the hashes */
        for (i = 0; i < pSigCtx->numAlgos; ++i)
        {
            SignedDataHash* pHash = (pSigCtx->pHashes) + i;

            pHash->hashAlgo->updateFunc(MOC_HASH(pCtx->hwAccelCtx)
                                        pHash->bulkCtx,
                                        buff, copySize);
        }
    }

    /* call finalFunc if we are done */
    if (pSigCtx->hashesDone)
    {
        /* finish the hashes */
        for (i = 0; i < pSigCtx->numAlgos; ++i)
        {
            SignedDataHash* pHash = (pSigCtx->pHashes) + i;

            pHash->hashAlgo->finalFunc(MOC_HASH(pCtx->hwAccelCtx)
                                        pHash->bulkCtx,
                                        pHash->hashData);
#ifdef __ENABLE_DIGICERT_RE_SIGNER__
            /* Save the hashType here so that we may add it back in when re-signing */
            CMS_ResignData_CTX RSCtx = (CMS_ResignData_CTX)pCtx->pResData;
            if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
            {
                CMS_RESIGN_setExtractedSignatureHashType(RSCtx, pHash->hashType);
            }

#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */
        }
    }

    /* return values */
    *pOutputLen = copySize;
    *pOutput = buff;
    buff = 0;

exit:

    if (buff)
    {
        FREE(buff);
    }

    if (pOS && 0 == ASN1_PARENT(pOS))
    {
        TREE_DeleteTreeItem( (TreeItem*) pOS);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Sig_VerifySignatures( CMS_CTX* pCtx)
{
    /* this is called only when the whole ASN.1 has been parsed so
    we can use the PKCS7 code */
    MSTATUS status = OK;
    ASN1_ITEMPTR pContentInfo;
    CMS_SignedDataCtx* pSigCtx;

    if (OK > (ASN1_GetNthChild( pCtx->pContent, 3, &pContentInfo)))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pSigCtx = &pCtx->aux.signedCtx;

    status = PKCS7_VerifySignatures(MOC_ASYM(pCtx->hwAccelCtx) pCtx->pContent, pContentInfo,
                       pCtx->cs, pSigCtx->numAlgos, pSigCtx->pHashes,
                       pCtx->cbArg, pCtx->cb.getCertFun, pCtx->cb.getCertFunV3, (void *) pCtx->cb.valCertFun, TRUE,
                       &pSigCtx->numSigners, &pSigCtx->pSigners, pCtx->pResData);

    if ((OK == status) && (0 == pSigCtx->numSigners))
    {
        status = ERR_PKCS7_NO_CERT_FOR_SIGNER;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_SignedData( CMS_CTX* pCtx, ubyte** output, ubyte4* pOutputLen)
{
    MSTATUS status = OK;

    if (!pCtx->aux.signedCtx.pHashes)
    {
        /* look for it */
        if (OK > ( status = CMS_Sig_GetHashAlgos( pCtx)))
        {
            goto exit;
        }
    }

    if (pCtx->aux.signedCtx.externalPayload)
    {
        status = (pCtx->complete) ? OK : ERR_EOF;
        goto exit;
    }
    else
    {
        if (pCtx->aux.signedCtx.pHashes)
        {
            if (OK > ( status = CMS_Sig_HashData( pCtx, output, pOutputLen)))
            {
                goto exit;
            }
        }
        else
        {
            status = ERR_EOF;
        }

        /* if the hashes are done, then all the data was displayed; so it's OK
        to wait for a complete PARSE to process the signers in one pass */
        if (pCtx->aux.signedCtx.hashesDone && pCtx->complete)
        {
            if (OK > ( status = CMS_Sig_VerifySignatures( pCtx)))
            {
                goto exit;
            }
        }
        else
        {
            status = ERR_EOF;
        }
    }

exit:

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_setDetachedSignatureData( CMS_context context, const ubyte* payload,
                              ubyte4 payloadLen, intBoolean final)
{
    MSTATUS status = OK;
    CMS_SignedDataCtx* pSigCtx;
    CMS_CTX* pCtx;
    ubyte4 i;

    if (!context || !payload )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;
    /* context must be complete */
    if (!pCtx->complete)
    {
        return ERR_EOF;
    }

    pSigCtx = &pCtx->aux.signedCtx;
    if (!pSigCtx->externalPayload)
    {
        return ERR_PKCS7_NOT_DETACHED_SIGNATURE;
    }

    if (pSigCtx->hashesDone)
    {
        return ERR_PKCS7_DETACHED_DATA_ALREADY_SET;
    }


    /* 1 hash the data */
    /* feed the data to all the hashes */
    for (i = 0; i < pSigCtx->numAlgos; ++i)
    {
        SignedDataHash* pHash = (pSigCtx->pHashes) + i;

        pHash->hashAlgo->updateFunc(MOC_HASH(pCtx->hwAccelCtx)
                                    pHash->bulkCtx,
                                    payload, payloadLen);
    }


    /* call finalFunc if we are done */
    if ((pSigCtx->hashesDone = final))
    {
        ASN1_ITEMPTR pContentInfo;

        /* finish the hashes */
        for (i = 0; i < pSigCtx->numAlgos; ++i)
        {
            SignedDataHash* pHash = (pSigCtx->pHashes) + i;

            pHash->hashAlgo->finalFunc( MOC_HASH(pCtx->hwAccelCtx)
                                        pHash->bulkCtx,
                                        pHash->hashData);
        }

        if (OK > (ASN1_GetNthChild( pCtx->pContent, 3, &pContentInfo)))
        {
            return ERR_PKCS7_INVALID_STRUCT;
        }

        /* call the shared routines */
        status = PKCS7_VerifySignatures(MOC_ASYM(pCtx->hwAccelCtx) pCtx->pContent, pContentInfo,
                       pCtx->cs, pSigCtx->numAlgos, pSigCtx->pHashes,
                       pCtx->cbArg, pCtx->cb.getCertFun, pCtx->cb.getCertFunV3, (void *) pCtx->cb.valCertFun, TRUE,
                       &pSigCtx->numSigners, &pSigCtx->pSigners, pCtx->pResData);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_detachedSignature(CMS_context context, intBoolean* detached)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !detached)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_signedData:
        if (!pCtx->complete)
        {
            return ERR_EOF;
        }
        *detached = pCtx->aux.signedCtx.externalPayload;
        status = OK;
        break;

    default:
        *detached = 0;
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/


extern MSTATUS
CMS_getNumSigners( CMS_context context, sbyte4* numSigners)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !numSigners)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_signedData:
        if (!pCtx->complete)
        {
            return ERR_EOF;
        }
        if (!pCtx->aux.signedCtx.hashesDone)
        {
            return ERR_PKCS7_DETACHED_DATA;
        }
        *numSigners = pCtx->aux.signedCtx.numSigners;
        status = OK;
        break;

    default:

        *numSigners = -1;
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getSignerInfo( CMS_context context, sbyte4 index,
                  const ASN1_ITEM** ppRecipientInfo,
                  CStream* pCS)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !ppRecipientInfo)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    *ppRecipientInfo = 0;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;


    case E_CMS_signedData:
        {
            CMS_SignedDataCtx* pSigCtx;

            if (!pCtx->complete)
            {
                return ERR_EOF;
            }
            if (!pCtx->aux.signedCtx.hashesDone)
            {
                return ERR_PKCS7_DETACHED_DATA;
            }
            pSigCtx = &pCtx->aux.signedCtx;

            if (index < 0 || index >= (sbyte4)pSigCtx->numSigners)
            {
                return ERR_INDEX_OOB;
            }
            *ppRecipientInfo = pSigCtx->pSigners[index].pASN1;
            *pCS = pCtx->cs;
            status = OK;
        }
        break;

    default:
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/


MOC_EXTERN MSTATUS
CMS_getFirstCertificate( CMS_context context,
                         const ASN1_ITEM** ppCertificate,
                         CStream* pCS)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !ppCertificate || !pCS)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    *ppCertificate = 0;
    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_signedData:
        if (!pCtx->complete)
        {
            return ERR_EOF;
        }
        *pCS = pCtx->cs;
        return ASN1_GetChildWithTag( pCtx->pContent, 0, (ASN1_ITEM**) ppCertificate);

    default:
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*--------------------------------------------------------------------------*/

WalkerStep CMS_Sig_signerInfoToReceiptRequestWalkInstructions[] =
{
    { GoToTag, 0, 0},         /* [0] is signed attributes */
    { GoChildWithOID, 0, (ubyte*) smime_receiptRequest_OID},
    { GoNextSibling, 0, 0 },
    { VerifyType, MOC_SET, 0 },
    { GoFirstChild, 0, 0 },
    { VerifyType, SEQUENCE, 0},
    { Complete, 0, 0}
};


/*---------------------------------------------------------------------------*/

static MSTATUS
CMS_Sig_getReceiptData( CMS_CTX* pCtx, const PKCS7_SignatureInfo* pSigInfo,
                        ubyte** ppDERReceipt, ubyte4* pDERReceiptLen)
{
    MSTATUS status;
    ASN1_ITEMPTR pReceiptRequest, pTemp;
    DER_ITEMPTR pReceipt = 0;

    /* first verify that there's a receipt request */
    if (OK > ( status = ASN1_WalkTree(pSigInfo->pASN1, pCtx->cs,
             CMS_Sig_signerInfoToReceiptRequestWalkInstructions,
             &pReceiptRequest)))
    {
        status = ERR_PKCS7_NO_RECEIPT_REQUEST;
        goto exit;
    }

    if (OK > ( status = DER_AddSequence(NULL, &pReceipt)))
    {
        goto exit;
    }

    /* ESS version */
    if (OK > ( status = DER_AddIntegerEx( pReceipt, 1, NULL)))
        goto exit;

    /* contentType */
    if (OK > ( status = ASN1_GetNthChild( pCtx->pContent, 3, &pTemp)))
        goto exit;

    if (OK > ( status = DER_AddASN1Item( pReceipt, ASN1_FIRST_CHILD( pTemp),
                                            pCtx->cs, NULL)))
    {
        goto exit;
    }

    /* signed content identifier */
    if (OK > ( status = DER_AddASN1Item( pReceipt, ASN1_FIRST_CHILD( pReceiptRequest),
                                            pCtx->cs, NULL)))
    {
        goto exit;
    }

    /* originator signature value -> 6th child of the SignerInfo ASN.1 */
    if (OK > ( status = ASN1_GetNthChild( pSigInfo->pASN1, 6, &pTemp)))
        goto exit;

    if (OK > ( status = DER_AddASN1Item( pReceipt, pTemp,
                                            pCtx->cs, NULL)))
    {
        goto exit;
    }

    if (OK > ( status = DER_Serialize( pReceipt, ppDERReceipt,
                                        pDERReceiptLen)))
    {
        goto exit;
    }

exit:

    if (pReceipt)
    {
        TREE_DeleteTreeItem( (TreeItem*) pReceipt);
    }

    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
CMS_Sig_CreateReceipt( CMS_CTX* pCtx, const PKCS7_SignatureInfo* pSigInfo,
                        RNGFun rngFun, void* rngFunArg,
                        const ubyte* signerCert, ubyte4 signerCertLen,
                        const AsymmetricKey* pKey, const ubyte* hashAlgoOID,
                        ubyte** ppReceipt, ubyte4* pReceiptLen)
{
    MSTATUS status = OK;
    CMS_signedDataContext mySignCtx = 0;
    CMS_signerInfo mySignerInfo;
    ubyte* receiptData = 0;
    ubyte4 receiptDataLen;

    /* create the receipt */
    if (OK > ( CMS_Sig_getReceiptData(pCtx, pSigInfo,
                                        &receiptData, &receiptDataLen)))
    {
        goto exit;
    }

    /* embedded it in a signed data message */
    if (OK > ( status = CMS_signedNewContext( &mySignCtx, smime_receipt_OID,
                                                0, rngFun, rngFunArg)))
    {
        goto exit;
    }

    if (OK > ( status = CMS_signedAddSigner( mySignCtx, signerCert, signerCertLen,
                                            pKey, hashAlgoOID,
                                            (e_cms_signer_addCert | e_cms_signer_forceAuthAttr),
                                            &mySignerInfo)))
    {
        goto exit;
    }

    /* add the msgSigDigest to the authenticated attributes */
    if (OK > ( status = CMS_signedAddSignerAttribute( mySignCtx, mySignerInfo,
                                                        smime_msgSigDigest_OID,
                                                        OCTETSTRING,
                                                        pSigInfo->msgSigDigest,
                                                        pSigInfo->msgSigDigestLen, 1)))
    {
        goto exit;
    }

    if (OK > ( status = CMS_signedUpdateContext( MOC_ASYM(pCtx->hwAccelCtx) mySignCtx,
                                            receiptData, receiptDataLen,
                                            ppReceipt, pReceiptLen, 1)))
    {
        goto exit;
    }

exit:

    FREE(receiptData);

    CMS_signedDeleteContext(MOC_HASH(pCtx->hwAccelCtx) &mySignCtx);

    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
CMS_createSignedReceipt( CMS_context context, sbyte4 index,
                    RNGFun rngFun, void* rngFunArg,
                    const ubyte* signerCert, ubyte4 signerCertLen,
                    const AsymmetricKey* pKey, const ubyte* hashAlgoOID,
                    ubyte** ppReceipt, ubyte4* pReceiptLen)
{
    MSTATUS status;
    CMS_CTX* pCtx;

    if (!context || !ppReceipt || !pReceiptLen)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    switch (pCtx->type)
    {
    case E_CMS_undetermined:
        status = ERR_EOF;
        break;

    case E_CMS_signedData:
        {
            CMS_SignedDataCtx* pSigCtx;

            if (!pCtx->complete)
            {
                return ERR_EOF;
            }
            if (!pCtx->aux.signedCtx.hashesDone)
            {
                return ERR_PKCS7_DETACHED_DATA;
            }
            pSigCtx = &pCtx->aux.signedCtx;

            if (index < 0 || index >= (sbyte4)pSigCtx->numSigners)
            {
                return ERR_INDEX_OOB;
            }
            status = CMS_Sig_CreateReceipt( pCtx, pSigCtx->pSigners + index,
                                            rngFun, rngFunArg,
                                            signerCert, signerCertLen,
                                            pKey, hashAlgoOID,
                                            ppReceipt, pReceiptLen);
        }
        break;

    default:
        status = ERR_PKCS7_INVALID_TYPE_FOR_OP;
        break;
    }

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getReceiptMsgDigest( CMS_context context,
                         const ubyte** ppDigest, ubyte4* pDigestLen)
{
    MSTATUS status;
    ASN1_ITEMPTR pSignerInfo, pOctetString;
    CStream cs;
    CMS_CTX* pCtx;
    static WalkerStep signerInfoToMsgSigDigestWalkInstructions[] =
    {
        { GoToTag, 0, 0},
        { GoChildWithOID, 0, (ubyte*) smime_msgSigDigest_OID},
        { GoNextSibling, 0, 0 },
        { VerifyType, MOC_SET, 0 },
        { GoFirstChild, 0, 0 },
        { VerifyType, OCTETSTRING, 0},
        { Complete, 0, 0}
    };

    if (!context || !ppDigest || !pDigestLen)
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = CMS_getSignerInfo( context, 0, (const ASN1_ITEM**)&pSignerInfo, &cs)))
    {
        goto exit;
    }

    if (OK > ( status = ASN1_WalkTree( pSignerInfo, cs,
                                        signerInfoToMsgSigDigestWalkInstructions,
                                        &pOctetString)))
    {
        goto exit;
    }

    pCtx = (CMS_CTX*) context;

    *ppDigest = pCtx->mf.buff + pOctetString->dataOffset;
    *pDigestLen = pOctetString->length;

exit:
    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_getReceiptInfo( const ubyte* receipt, ubyte4 receiptLen,
                    const ubyte** messageId, ubyte4* messageIdLen,
                    const ubyte** signature, ubyte4* signatureLen)
{
    MSTATUS status;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pRoot = 0;
    ASN1_ITEMPTR pItem;

    if (!receipt || !messageId || !messageIdLen ||
        !signature || !signatureLen )
    {
        return ERR_NULL_POINTER;
    }

    if ( !receiptLen)
    {
        return ERR_INVALID_ARG;
    }

    MF_attach( &mf, receiptLen, (ubyte*) receipt);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pRoot)))
        goto exit;

    if (OK > ASN1_GetNthChild( ASN1_FIRST_CHILD( pRoot), 3, &pItem) )
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    *messageId = receipt + pItem->dataOffset;
    *messageIdLen = pItem->length;

    pItem = ASN1_NEXT_SIBLING( pItem);

    if (!pItem)
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    *signature = receipt + pItem->dataOffset;
    *signatureLen = pItem->length;

exit:

    if (pRoot)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Digested_GetHashAlgo( CMS_CTX* pCtx)
{
    MSTATUS status;
    ASN1_ITEMPTR pDigestAlgorithm, pEncapsulatedContentInfo;
    CMS_DigestedDataCtx* pDigestedCtx;
    ubyte4 numChildren, hashes, numAlgos;

    numChildren = PKCS7_getNumberChildren(pCtx->pContent);
    if (numChildren < 3)
    {
        status = ERR_EOF;
        goto exit;
    }

    pDigestedCtx = &pCtx->aux.digestedCtx;

    /* three children so the whole digestAlgorithm is completely there */
    ASN1_GetNthChild( pCtx->pContent, 2, &pDigestAlgorithm);

    if (NULL != pDigestAlgorithm)
    {
        pEncapsulatedContentInfo = ASN1_NEXT_SIBLING( pDigestAlgorithm);
    }
    else
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
/*
    EncapsulatedContentInfo ::= SEQUENCE {
        eContentType ContentType,
        eContent [0] EXPLICIT OCTET STRING OPTIONAL }
*/
    /* at the moment, we don't deal with external payloads */
    numChildren = PKCS7_getNumberChildren( pEncapsulatedContentInfo);
    if (numChildren < 2)
    {
        status = ERR_EOF;
        goto exit;
    }

    ASN1_GetNthChild( pEncapsulatedContentInfo, 2, &pDigestedCtx->pEContent);

    if (OK > ASN1_VerifyTag( pDigestedCtx->pEContent, 0) )
    {
        status = ERR_PKCS7_INVALID_STRUCT;
        goto exit;
    }

    /* instantiate Algos using the common routine */
    hashes = 0;
    if (OK > ( status = PKCS7_GetDigestAlgorithmHash( pDigestAlgorithm, pCtx->cs,
                                                       &hashes)))
    {
        goto exit;
    }

    /* if the bit field is still 0, then unsupported digest algo */
    if (0 == hashes)
    {
        status = ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
        goto exit;
    }

    if (OK > ( status = PKCS7_ConstructHashes( MOC_HASH(pCtx->hwAccelCtx) hashes,
                                                &numAlgos, &pDigestedCtx->pHash)))
    {
        goto exit;
    }

    if (1 != numAlgos)
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    pDigestedCtx->pEContentType = ASN1_FIRST_CHILD(pEncapsulatedContentInfo);

exit:

    return status;
}




/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Digested_HashData( CMS_CTX* pCtx, ubyte** pOutput, ubyte4* pOutputLen)
{
    MSTATUS status = OK;
    CMS_DigestedDataCtx* pDigestedCtx;
    SignedDataHash* pHash;
    ASN1_ITEMPTR pOS;
    ubyte4 streamSize, copySize, offset;
    ubyte* buff = 0;

    pDigestedCtx = &pCtx->aux.digestedCtx;

    if (pDigestedCtx->hashDone)
    {
        return OK;
    }

    if (!pDigestedCtx->pEContent)
    {
        return ERR_INTERNAL_ERROR;
    }

    pOS = ASN1_GetFirstChildFromPartialParse( &pCtx->asn1ParseState,
                                               pDigestedCtx->pEContent,
                                               pCtx->cs);
    if (!pOS)
    {
        status = ERR_EOF;
        goto exit;
    }

    streamSize = CMS_getCurrentStreamSize(pCtx);

    /* use ASN1_GetData */
    offset = pDigestedCtx->processedOffset;
    copySize = ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs,
                            streamSize, pOS, &offset,
                            pCtx->mf.buff, 0);

    /* are we done? */
    if (ASN1_PARENT(pOS))
    {
        if (OK > ( status = ASN1_IsItemComplete(&pCtx->asn1ParseState,
                                                pOS, pCtx->cs,
                                                &pDigestedCtx->hashDone)))
        {
            goto exit;
        }
    }

    pHash = pDigestedCtx->pHash;

    if ( copySize)
    {
        buff = MALLOC(copySize);
        if (! buff)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* collect all the data */
        ASN1_GetData( &pCtx->asn1ParseState, pCtx->cs, streamSize,
                       pOS, &pDigestedCtx->processedOffset,
                       pCtx->mf.buff, buff);

        /* feed the data to the hash */
        pHash->hashAlgo->updateFunc(MOC_HASH(pCtx->hwAccelCtx)
                                       pHash->bulkCtx,
                                       buff, copySize);
    }

    /* call finalFunc if we are done */
    if ( pDigestedCtx->hashDone)
    {
        /* finish the hash */
        pHash->hashAlgo->finalFunc(MOC_HASH(pCtx->hwAccelCtx)
                                   pHash->bulkCtx,
                                   pHash->hashData);

    }

    /* return values */
    *pOutputLen = copySize;
    *pOutput = buff;
    buff = 0;

exit:

    if (buff)
    {
        FREE(buff);
    }

    if (pOS && 0 == ASN1_PARENT(pOS))
    {
        TREE_DeleteTreeItem( (TreeItem*) pOS);
    }

    return status;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_Digested_VerifyHash( CMS_CTX* pCtx)
{
    /* this is called only when the whole ASN.1 has been parsed so
    we can use the PKCS7 code */
    ASN1_ITEMPTR pDigest;
    SignedDataHash* pSignedDataHash;
    sbyte4 resCmp;

    if (OK > ASN1_GetNthChild( pCtx->pContent, 4, &pDigest))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    if (OK > ASN1_VerifyType( pDigest, OCTETSTRING))
    {
        return ERR_PKCS7_INVALID_STRUCT;
    }

    pSignedDataHash = pCtx->aux.digestedCtx.pHash;

    DIGI_MEMCMP( pSignedDataHash->hashData,
                pCtx->mf.buff + pDigest->dataOffset,
                pSignedDataHash->hashAlgo->digestSize,
                &resCmp);

    return resCmp ? ERR_PKCS7_DIGEST_DONT_MATCH : OK;
}


/*-----------------------------------------------------------------------*/

static MSTATUS
CMS_DigestedData( CMS_CTX* pCtx, ubyte** output, ubyte4* pOutputLen)
{
    MSTATUS status;

    if (!pCtx->aux.digestedCtx.pHash)
    {
        /* look for it */
        if (OK > ( status = CMS_Digested_GetHashAlgo( pCtx)))
        {
            goto exit;
        }
    }

    if (pCtx->aux.digestedCtx.pHash)
    {
        if (OK > ( status = CMS_Digested_HashData( pCtx, output, pOutputLen)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_EOF;
    }

    /* if the hashes are done, then all the data was displayed; so it's OK
    to wait for a complete PARSE to process the signers in one pass */
    if (pCtx->aux.digestedCtx.hashDone && pCtx->complete)
    {
        if (OK > ( status = CMS_Digested_VerifyHash( pCtx)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_EOF;
    }

exit:

    return status;
}


/*-----------------------------------------------------------------------*/

extern MSTATUS
CMS_updateContext( CMS_context context,
                    const ubyte* input, ubyte4 inputLen,
                    ubyte** ppOutput, ubyte4* pOutputLen,
                    intBoolean* pFinished)
{
    MSTATUS status;
    CMS_CTX* pCtx;
    ubyte* pBuffer = 0;

    /* no input nothing to do */
    if (!inputLen)
    {
        return OK;
    }

    /* other wise check all the pointers */
    if (!context || !input || !ppOutput || !pOutputLen ||
         !pFinished)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    /* make a copy of the input -- for now, just allocate a new buffer */
    pBuffer = MALLOC( pCtx->mf.size + inputLen);
    if (!pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (pCtx->mf.buff)
    {
        DIGI_MEMCPY( pBuffer, pCtx->mf.buff, pCtx->mf.size);
        FREE(pCtx->mf.buff);
    }
    DIGI_MEMCPY( pBuffer + pCtx->mf.size, input, inputLen);

    pCtx->mf.buff = pBuffer;
    pCtx->mf.size += inputLen;
    pBuffer = 0;

    /* resume the parsing */
    status = ASN1_ParseASN1State( pCtx->cs, &pCtx->asn1ParseState,
                                  NULL, NULL);

    /* if error and error is not ERR_EOF -> stop there */
    if ( OK > status && status != ERR_EOF)
    {
        goto exit;
    }

    /* set up the out arg */
    *pFinished = pCtx->complete = (status != ERR_EOF);
    *ppOutput = 0;
    *pOutputLen = 0;

    /* have we determined a content type already? */
    if (E_CMS_undetermined == pCtx->type)
    {
        if (OK > ( status = CMS_getContentTypeInt( pCtx)))
        {
            goto exit;
        }
    }

    /* advance the process */
    switch ( pCtx->type)
    {
    case E_CMS_undetermined: /* we tried already */
        break;

    case E_CMS_data:
        break;

    case E_CMS_signedData:
        status = CMS_SignedData( pCtx, ppOutput, pOutputLen);
        break;

    case E_CMS_envelopedData:
        status = CMS_EnvelopedData( pCtx, ppOutput, pOutputLen);
        break;

    case E_CMS_digestedData:
        status = CMS_DigestedData( pCtx, ppOutput, pOutputLen);
        break;

    case E_CMS_encryptedData:
        break;

    case E_CMS_ct_authData:
        break;
    }

exit:

    if ( ERR_EOF == status && 0 == *pFinished)
    {
        status = OK;
    }

    if (pBuffer)
    {
        FREE(pBuffer);
    }

    return status;
}


/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_getContentTypeOnly( CMS_context context,
                        const ubyte* pInput, ubyte4 inputLen, CMS_ContentType* cType)
{
    MSTATUS status;
    CMS_CTX* pCtx;
    ubyte* pBuffer = 0;

    /* No input,  nothing to do */
    if (!inputLen)
    {
        return OK;
    }

    /* Otherwise check all the pointers */
    if (!context || !pInput || !cType)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_CTX*) context;

    /* Make a copy of the input */
    pBuffer = MALLOC( pCtx->mf.size + inputLen);
    if (!pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (pCtx->mf.buff)
    {
        DIGI_MEMCPY( pBuffer, pCtx->mf.buff, pCtx->mf.size);
        FREE(pCtx->mf.buff);
    }

    DIGI_MEMCPY( pBuffer + pCtx->mf.size, pInput, inputLen);

    pCtx->mf.buff = pBuffer;
    pCtx->mf.size += inputLen;
    pBuffer = 0;
    /* resume the parsing */
    status = ASN1_ParseASN1State( pCtx->cs, &pCtx->asn1ParseState,
                                  NULL, NULL);

    /* if error and error is not ERR_EOF -> stop there */
    if ( OK > status && status != ERR_EOF)
    {
        goto exit;
    }

    /* have we determined a content type already? */
    if (E_CMS_undetermined == pCtx->type)
    {
        if (OK > ( status = CMS_getContentTypeInt( pCtx)))
        {
            goto exit;
        }
    }
exit:

    if ( ERR_EOF == status)
    {
        status = OK;
    }

    *cType = pCtx->type;

    if (pBuffer)
    {
        FREE(pBuffer);
    }

    return status;
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_signedNewContext( CMS_signedDataContext* pNewCtx,
                            const ubyte* payloadTypeOID,
                            intBoolean detached, RNGFun rngFun,
                            void* rngFunArg)
{
    MSTATUS status = OK;
    CMS_Signed_CTX* pCtx;

    if (!pNewCtx || !payloadTypeOID || !rngFun )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Signed_CTX*) MALLOC( sizeof(CMS_Signed_CTX));

    if (!pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*) pCtx, 0, sizeof( CMS_Signed_CTX));

    pCtx->payloadTypeOID = payloadTypeOID;
    pCtx->detached = detached;
    pCtx->rngFun = rngFun;
    pCtx->rngFunArg = rngFunArg;

    DYNARR_Init( sizeof(CMS_Data), &pCtx->certs);
    DYNARR_Init( sizeof(CMS_Data), &pCtx->crls);
    DYNARR_Init( sizeof(CMS_SignerCtx*), &pCtx->signers);

    *pNewCtx = pCtx;
    pCtx = 0;

exit:

    return status;
}



/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_newSignerCtx(CMS_SignerCtx** ppSigner)
{
    MSTATUS status;
    CMS_SignerCtx* pNewSigner;

    if (!ppSigner)
    {
        return ERR_NULL_POINTER;
    }

    pNewSigner = MALLOC( sizeof( CMS_SignerCtx));
    if (!pNewSigner)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*) pNewSigner, 0, sizeof(CMS_SignerCtx));

    if (OK > ( status = DER_AddSet(NULL, &pNewSigner->pAuthAttributes)))
    {
        goto exit;
    }

    if (OK < ( status = DER_AddTag( NULL, 1, &pNewSigner->pUnauthAttributes)))
    {
        goto exit;
    }

    *ppSigner = pNewSigner;
    pNewSigner = 0;

exit:

    CMS_deleteSignerCtx( &pNewSigner);

    return status;
}



/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_deleteSignerCtx(CMS_SignerCtx** ppSigner)
{
    if (!ppSigner || !*ppSigner)
    {
        return ERR_NULL_POINTER;
    }

    if ((**ppSigner).signature)
    {
        FREE ((**ppSigner).signature);
    }

    if ((**ppSigner).digest)
    {
        FREE ((**ppSigner).digest);
    }

    /* release memory */
    TREE_DeleteTreeItem( (TreeItem*) (**ppSigner).pUnauthAttributes);
    TREE_DeleteTreeItem( (TreeItem*) (**ppSigner).pAuthAttributes);

    /* for signers with a callback there may be a public key that needs to be freed */
    if (NULL != (**ppSigner).callback && NULL != (**ppSigner).pKey)
    {
        (void) CRYPTO_uninitAsymmetricKey((AsymmetricKey *)(**ppSigner).pKey, NULL);
        (void) DIGI_FREE((void **) &((**ppSigner).pKey));
        (**ppSigner).callback = NULL;
    }

    FREE( *ppSigner);
    *ppSigner = 0;

    return OK;
}


/*-------------------------------------------------------------------------------*/


extern MSTATUS
CMS_signedDeleteContext(MOC_HASH(hwAccelDescr hwAccelCtx) CMS_signedDataContext* ppCtx)
{
    CMS_Signed_CTX* pCtx;
    sbyte4 i, numSigners;

    if (!ppCtx || !*ppCtx)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Signed_CTX*) (*ppCtx);

    FREE( pCtx->receiptRequest);

    DYNARR_Uninit( &pCtx->certs);
    DYNARR_Uninit( &pCtx->crls);

    DYNARR_GetElementCount( &pCtx->signers, &numSigners);
    for (i = 0; i < numSigners; ++i)
    {
        CMS_SignerCtx* pSigner;
        pSigner = CMS_GetSigner(&pCtx->signers, i);
        CMS_deleteSignerCtx( &pSigner);
    }
    DYNARR_Uninit( &pCtx->signers);

    if (pCtx->pSignedHashes)
    {
        PKCS7_DestructHashes(MOC_HASH(hwAccelCtx) pCtx->numHashes, &pCtx->pSignedHashes);
    }

    TREE_DeleteTreeItem( (TreeItem*) (pCtx->pRoot));

    FREE( pCtx);
    *ppCtx = 0;

    return OK;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_addASN1Data( DynArray* pArr, const ubyte* asn1, ubyte4 asn1Len)
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRootItem = 0;
    CMS_Data myData;

    if (!asn1 )
    {
        return ERR_NULL_POINTER;
    }
    if ( 0 == asn1Len)
    {
        return OK;
    }

    MF_attach( &mf, asn1Len, (ubyte*) asn1);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
    {
        goto exit;
    }

    myData.data = asn1;
    myData.dataLen = asn1Len;

    if (OK > ( status = DYNARR_Append( pArr, &myData)))
    {
        goto exit;
    }

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_addASN1KeyData( DynArray* pArr,
                   const ubyte* derKey, ubyte4 derKeyLen, ubyte4 hashType)
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRootItem = 0;
    CMS_KeyData myData;

    if (!derKey )
    {
        return ERR_NULL_POINTER;
    }
    if ( 0 == derKeyLen)
    {
        return OK;
    }

    MF_attach( &mf, derKeyLen, (ubyte*) derKey);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
    {
        goto exit;
    }

    myData.data = derKey;
    myData.dataLen = derKeyLen;
    myData.hashType = hashType;

    if (OK > ( status = DYNARR_Append( pArr, &myData)))
    {
        goto exit;
    }

exit:

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return status;
}


/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_signedAddCertificate( CMS_signedDataContext myCtx, const ubyte* cert,
                         ubyte4 certLen)
{
    CMS_Signed_CTX* pCtx;

    if (!myCtx)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Signed_CTX*)myCtx;

    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }

    return CMS_addASN1Data(&pCtx->certs, cert, certLen);
}


/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_signedAddCRL( CMS_signedDataContext myCtx, const ubyte* crl,
                  ubyte4 crlLen)
{
    CMS_Signed_CTX* pCtx;

    if (!myCtx)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Signed_CTX*)myCtx;

    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }
    return CMS_addASN1Data(&pCtx->crls, crl, crlLen);
}

/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedAddSignerInternal( CMS_signedDataContext myCtx, const ubyte* cert,
                             ubyte4 certLen, const AsymmetricKey* pKey,
                             CMS_SignData signCallback, void* pCbInfo,
                             const ubyte* digestAlgoOID, ubyte4 flags,
                             CMS_signerInfo* pNewSignerInfo)
{
    MSTATUS status;
    CMS_Signed_CTX* pCtx;
    CMS_SignerCtx* pNewSigner = 0;

    if (!myCtx || !cert || !pKey || !digestAlgoOID || !pNewSignerInfo)
    {
        return ERR_NULL_POINTER;
    }
    *pNewSignerInfo = 0;

    pCtx = (CMS_Signed_CTX*) myCtx;

    if (pCtx->pRoot)
    {
        status = ERR_PKCS7_ALREADY_STREAMING;
        goto exit;
    }

    if (OK > ( status = CMS_newSignerCtx( &pNewSigner)))
    {
        goto exit;
    }

    pNewSigner->cert = cert;
    pNewSigner->certLen = certLen;
    pNewSigner->digestAlgoOID = digestAlgoOID;
    pNewSigner->flags = flags;
    pNewSigner->pKey = pKey;

    if (NULL != signCallback)
    {
        pNewSigner->callback = signCallback;
        pNewSigner->pCbInfo = pCbInfo;
    }

    if (OK > ( status = DYNARR_Append( &pCtx->signers, &pNewSigner)))
    {
        goto exit;
    }

    if (flags & e_cms_signer_addCert)
    {
        if ( OK > ( status = CMS_signedAddCertificate(myCtx, cert, certLen)))
            goto exit;
    }

    *pNewSignerInfo = pNewSigner;
    pNewSigner = 0;

exit:

    /* If error in the callback case nullify the ptr so we don't double free */
    if (OK != status && NULL != signCallback && NULL != pNewSigner)
    {
        pNewSigner->pKey = NULL;
    }

    CMS_deleteSignerCtx( &pNewSigner);

    return status;
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_signedAddSigner( CMS_signedDataContext myCtx, const ubyte* cert,
                    ubyte4 certLen, const AsymmetricKey* pKey,
                    const ubyte* digestAlgoOID, ubyte4 flags,
                    CMS_signerInfo* pNewSignerInfo)
{
    return CMS_signedAddSignerInternal(myCtx, cert, certLen, pKey, NULL, NULL,
                                       digestAlgoOID, flags, pNewSignerInfo);
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS 
CMS_signedAddSignerWithCallback( MOC_HW(hwAccelDescr hwAccelCtx)
                                 CMS_signedDataContext myCtx,
                                 const ubyte* cert,
                                 ubyte4 certLen,
                                 CMS_SignData signCallback,
                                 void* pCbInfo,
                                 const ubyte* digestAlgoOID,
                                 ubyte4 flags,
                                 CMS_signerInfo* pNewSignerInfo)
{
    MSTATUS status = ERR_NULL_POINTER;
    AsymmetricKey *pPubKey = NULL;
    ASN1_ITEMPTR pRootItem = NULL, pCertificate = NULL;
    MemFile mf;
    CStream cs;
 
    if (NULL == signCallback)
        goto exit;

    MF_attach( &mf, (sbyte4) certLen, (ubyte *) cert);
    CS_AttachMemFile( &cs, &mf);

    status = ASN1_Parse( cs, &pRootItem);
    if (OK != status)
        goto exit;

    pCertificate = ASN1_FIRST_CHILD(pRootItem);

    status = DIGI_MALLOC((void **) &pPubKey, sizeof(AsymmetricKey));
    if (OK != status)
        goto exit;

    status = CRYPTO_initAsymmetricKey(pPubKey);
    if (OK != status)
        goto exit;

    status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx) pCertificate, cs, pPubKey);
    if (OK != status)
        goto exit;

    status = CMS_signedAddSignerInternal(myCtx, cert, certLen, pPubKey, signCallback, pCbInfo,
                                         digestAlgoOID, flags, pNewSignerInfo);
    if (OK != status)
        goto exit;

    /* The public key is now property of the Signer structure */
    pPubKey = NULL;

exit:

    if (NULL != pPubKey)
    {
        (void) CRYPTO_uninitAsymmetricKey(pPubKey, NULL);
        (void) DIGI_FREE((void **) &pPubKey);
    }

    (void) TREE_DeleteTreeItem( (TreeItem*) pRootItem);

    return status;                  
}

/*-------------------------------------------------------------------------------*/                                     

extern MSTATUS
CMS_signedAddSignerAttribute( CMS_signedDataContext myCtx,
                                CMS_signerInfo signerInfo,
                                const ubyte* typeOID,
                                ubyte4 type, /* id|tag */
                                const ubyte* value,
                                ubyte4 valueLen,
                                intBoolean authenticated)
{
    MSTATUS status;
    CMS_Signed_CTX* pCtx;
    CMS_SignerCtx* pSigner;

    if (!myCtx || !typeOID || !value)
    {
        return ERR_NULL_POINTER;
    }

    /* it should be OK to add a Signer Attribute if already streaming */

    pCtx = (CMS_Signed_CTX*) myCtx;

    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }

    if ( !signerInfo) /* add to all */
    {
        sbyte4 i, elemCount;
        const DynArray* pSigners = &pCtx->signers;

        if ( OK > ( status = DYNARR_GetElementCount( pSigners,
                                                    &elemCount)))
        {
            goto exit;
        }
        for (i = 0; i < elemCount; ++i)
        {
            pSigner = CMS_GetSigner( pSigners, i);
            if (OK > (status = PKCS7_AddAttribute(
                            (authenticated) ?
                                pSigner->pAuthAttributes :
                                pSigner->pUnauthAttributes,
                            typeOID, (ubyte)type, value, valueLen, NULL)))
            {
                goto exit;
            }
        }
    }
    else
    {
        pSigner = ( CMS_SignerCtx*) signerInfo;

        status = PKCS7_AddAttribute(
            (authenticated) ? pSigner->pAuthAttributes : pSigner->pUnauthAttributes,
            typeOID, (ubyte) type, value, valueLen, NULL);
    }


exit:

    return status;
}

/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_addGeneralNames( DER_ITEMPTR pParent, const ubyte** names, sbyte4 numNames)
{
    MSTATUS status = OK;
    sbyte4 i;
    DER_ITEMPTR pSeq;

    for (i = 0; i < numNames; ++i)
    {
        const ubyte* name = names[i];

        if ( name && *name)
        {
            if (OK > ( status = DER_AddSequence( pParent, &pSeq)))
                goto exit;

            if (OK > ( status = DER_AddItem( pSeq, (PRIMITIVE|CONTEXT|1),
                                            DIGI_STRLEN((const sbyte*) name),
                                            name, NULL)))
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

MSTATUS CMS_signedAddReceiptRequest( MOC_HASH(hwAccelDescr hwAccelCtx)
                                        CMS_signedDataContext myCtx,
                                        const ubyte** receiptFrom,
                                        sbyte4 numReceiptFrom,
                                        const ubyte** receiptTo,
                                        sbyte4 numReceiptTo)
{
    MSTATUS status;
    CMS_Signed_CTX* pCtx;
    DER_ITEMPTR pReceiptRequest = 0;
    DER_ITEMPTR pTemp = 0, pMessageId = 0;
    ubyte* receiptRequest;
    ubyte4 receiptRequestLen;
    ubyte id[CMS_RR_MESSAGE_ID_LEN];
    struct
    {
        TimeDate td;
        ubyte    rand[8];
    } hashInput;

    if (!myCtx || !receiptTo)
    {
        return ERR_NULL_POINTER;
    }

    if ( 0 == numReceiptTo)
    {
        return ERR_INVALID_ARG; /* must be specified */
    }

    if ( 0 < numReceiptFrom && !receiptFrom)
    {
        return ERR_INVALID_ARG; /* must be specified */
    }

    /* it should be OK to add a Signer Attribute if already streaming */

    pCtx = (CMS_Signed_CTX*) myCtx;
    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }

    /* the receipt request is added to the signed attributes of all SignerInfos */
    if (OK > ( status = DER_AddSequence( NULL, &pReceiptRequest)))
        goto exit;

    /* identifier -- must be unique -- do a SHA1 hash of time + random value */
    if (OK > ( status = RTOS_timeGMT(&hashInput.td)))
        goto exit;
    if (OK > ( status = pCtx->rngFun( pCtx->rngFunArg, sizeof(hashInput.rand), hashInput.rand)))
        goto exit;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ( OK > ( status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(hwAccelCtx) (ubyte*) &hashInput, sizeof( hashInput), id)))
#else
    if (OK > ( status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) (ubyte*) &hashInput, sizeof( hashInput), id)))
        goto exit;
#endif

    if (OK > ( status = DER_AddItem( pReceiptRequest, OCTETSTRING, CMS_RR_MESSAGE_ID_LEN, id, &pMessageId)))
        goto exit;

    /* from */
    if ( numReceiptFrom <= 0)
    {
        ubyte tagValue[MAX_DER_STORAGE];
        tagValue[0] = (numReceiptFrom == 0) ? 1 : 0;

        if (OK > ( status = DER_AddItemCopyData( pReceiptRequest, (PRIMITIVE|CONTEXT),
                                                    1, tagValue, NULL)))
        {
            goto exit;
        }
    }
    else
    {
        DER_ITEMPTR pTag;

        if (OK > ( status = DER_AddTag( pReceiptRequest, 1, &pTag)))
            goto exit;

        if (OK > ( status = CMS_addGeneralNames( pTag, receiptFrom, numReceiptFrom)))
            goto exit;
    }

    /* to */
    if (OK > ( status = DER_AddSequence( pReceiptRequest, &pTemp)))
        goto exit;

    if (OK > ( status = CMS_addGeneralNames( pTemp, receiptTo, numReceiptTo)))
        goto exit;


    if (OK > ( status = DER_Serialize(pReceiptRequest,
                    &receiptRequest, &receiptRequestLen)))
    {
        goto exit;
    }
    if (OK > ( status = DER_GetSerializedDataPtr( pMessageId, &pCtx->messageID)))
        goto exit;

    /* free a possible previous receiptRequest */
    FREE(pCtx->receiptRequest);
    pCtx->receiptRequest = receiptRequest;
    pCtx->receiptRequestLen = receiptRequestLen;

exit:

    if (pReceiptRequest)
    {
        TREE_DeleteTreeItem( (TreeItem*) pReceiptRequest);
    }

    return status;

}


/*-------------------------------------------------------------------------------*/

MSTATUS
CMS_signedGetRequestInfo( CMS_signedDataContext myCtx,
                            CMS_signerInfo signerInfo,
                            const ubyte** messageId, ubyte4* messageIdLen,
                            const ubyte** digest, ubyte4* digestLen,
                            const ubyte** signature, ubyte4* signatureLen)
{
    CMS_Signed_CTX* pCtx;
    CMS_SignerCtx* pSigner;

    if (!myCtx || !signerInfo || !messageId || !messageIdLen ||
        !digest || !digestLen || !signature || !signatureLen )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Signed_CTX*) myCtx;

    if (!pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_NOT_COMPLETED;
    }

    /* message id is common for all signers */
    *messageIdLen = CMS_RR_MESSAGE_ID_LEN;
    *messageId = pCtx->messageID;

    pSigner = (CMS_SignerCtx*) signerInfo;

    *digest = pSigner->digest;
    *digestLen = pSigner->digestLen;
    *signature = pSigner->signature;
    *signatureLen = pSigner->signatureLen;

    return OK;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedCreateHashes(MOC_HASH(hwAccelDescr hwAccelCtx) CMS_Signed_CTX* pCtx)
{
    MSTATUS status;
    sbyte4 i, numSigners;
    const DynArray* pSigners = &pCtx->signers;
    ubyte4 hashes;

    /* collect all the digest algos from the signers */
    if (OK > ( status = DYNARR_GetElementCount( pSigners, &numSigners)))
        goto exit;

    hashes = 0;
    for (i = 0; i < numSigners; i++)
    {
        ubyte hashId;
        CMS_SignerCtx* pSigner;

        pSigner = CMS_GetSigner( pSigners, i);

        if (OK > ( status = PKCS7_GetHashAlgoIdFromHashAlgoOID2(
                                pSigner->digestAlgoOID,
                                &hashId)))
        {
            goto exit;
        }

        hashes |= (1 << hashId);
    }

    if (OK > ( PKCS7_ConstructHashes( MOC_HASH(hwAccelCtx)
                                        hashes, &pCtx->numHashes,
                                        &pCtx->pSignedHashes)))
    {
        goto exit;
    }

exit:
    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedCreateDER(MOC_HASH(hwAccelDescr hwAccelCtx)
                    CMS_Signed_CTX* pCtx, int derEncoding)
{
    MSTATUS status;
    DER_ITEMPTR pSignedData, pTemp;
    ubyte4 i;
    ubyte4 version = 1;

    if (derEncoding)
    {
        if (OK > ( status = DER_AddSequence( NULL, &pCtx->pRoot)))
                goto exit;

        if (OK > ( status = DER_AddOID( pCtx->pRoot, pkcs7_signedData_OID, NULL)))
            goto exit;

        if (OK > ( status = DER_AddTag( pCtx->pRoot, 0, &pTemp)))
            goto exit;

        if (OK > ( status = DER_AddSequence( pTemp, &pSignedData)))
            goto exit;
    }
    else
    {
        if (OK > ( status = DER_AddBERSequence( NULL, &pCtx->pRoot)))
                goto exit;

        if (OK > ( status = DER_AddOID( pCtx->pRoot, pkcs7_signedData_OID, NULL)))
            goto exit;

        if (OK > ( status = DER_AddBERTag( pCtx->pRoot, 0, &pTemp)))
            goto exit;

        if (OK > ( status = DER_AddBERSequence( pTemp, &pSignedData)))
            goto exit;
    }

    /* version number: RFC-5652, Sec 5.1: version 3 if not pkcs7_data_OID or
    if any signerInfo is version 3, otherwise 1 */
    if (!EqualOID(pCtx->payloadTypeOID, pkcs7_data_OID))
    {
        version = 3;
    }
    else
    {
        sbyte4 numSigners;

        if (OK > ( status = DYNARR_GetElementCount( &pCtx->signers, &numSigners)))
            goto exit;

        for (i = 0; i < (ubyte4) numSigners; ++i)
        {
            CMS_SignerCtx* pSigner;

            pSigner = CMS_GetSigner(&pCtx->signers, (sbyte4) i);
            if (NULL == pSigner)
            {
                status = ERR_NULL_POINTER;
                goto exit;
            }

            if (pSigner->flags & e_cms_signer_version3)
            {
                version = 3;
                break;
            }
        }
    }

    if (OK > ( status = DER_AddIntegerEx( pSignedData, version, NULL)))
    {
        goto exit;
    }

    /* Set of digest algorithms */
    if (OK > ( status = DER_AddSet( pSignedData, &pTemp)))
        goto exit;

    /* instantiate the hashes */
    if (OK > ( status = CMS_signedCreateHashes(MOC_HASH(hwAccelCtx) pCtx)))
        goto exit;

    /* write them to the Set */
    for (i = 0; i < pCtx->numHashes; ++i)
    {
        if (OK > ( status = DER_StoreAlgoOID( pTemp,
                        pCtx->pSignedHashes[i].algoOID, TRUE)))
        {
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_RE_SIGNER__
    /* Restore any unique OIDs from previous signature blocks */

    int j;
    int maxAlgos = CMS_RESIGN_getNumSigningAlgos();
    ubyte **original_OID;
    CMS_ResignData_CTX RSCtx = (CMS_ResignData_CTX)pCtx->pResData;
    if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
    {
        CMS_RESIGN_getExtractedSignature_OIDs(RSCtx, &original_OID);

        /* Eliminate dupplicates from the saved list */
        for(i = 0; i < pCtx->numHashes; i++)
        {
            for(j = 0; j < maxAlgos; j++)
            {
                if ( (original_OID != NULL) &&
                     (EqualOID(original_OID[j], pCtx->pSignedHashes[i].algoOID)) )
                {
                    CMS_RESIGN_clearExtractedSignature_OID(RSCtx, j);
                }
            }
        }

        /* Add algorithm entries from previous signers */
        for(i = 0; i < (ubyte4)maxAlgos; i++)
        {
            if ((original_OID != NULL) && (original_OID[i]))
            {
                if (OK > ( status = DER_StoreAlgoOID( pTemp, original_OID[i], TRUE)))
                {
                    goto exit;
                }
            }
        }
    }

#endif /* __ENABLE_DIGICERT_RE_SIGNER__ */

    /* if detached, add the encap Content Info here */
    if (pCtx->detached)
    {
        DER_ITEMPTR pSeq;

        if (OK > ( status = DER_AddSequence( pSignedData, &pSeq)))
            goto exit;

        if (OK > ( status = DER_AddOID( pSeq, pCtx->payloadTypeOID, NULL)))
            goto exit;
    }

    pCtx->pSignedData = pSignedData;

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedCreateEncapsulatedContent(CMS_Signed_CTX* pCtx, intBoolean derEncoded)
{
    MSTATUS status;
    DER_ITEMPTR pParent;

    if (derEncoded)
    {
        /* encapsulated content info */
        if (OK > ( status = DER_AddSequence( pCtx->pSignedData, &pParent)))
            goto exit;

        if (OK > ( status = DER_AddOID( pParent, pCtx->payloadTypeOID, NULL)))
            goto exit;

        if (OK > (status = DER_AddTag( pParent, 0, &pCtx->pOctetString)))
        {
            goto exit;
        }
    }
    else
    {
        /* encapsulated content info */
        if (OK > ( status = DER_AddBERSequence( pCtx->pSignedData, &pParent)))
            goto exit;

        if (OK > ( status = DER_AddOID( pParent, pCtx->payloadTypeOID, NULL)))
            goto exit;

        if (OK > (status = DER_AddBERTag( pParent, 0, &pParent)))
        {
            goto exit;
        }

        if (OK > ( status = DER_AddBERItem( pParent, (CONSTRUCTED| OCTETSTRING),
                                            &pCtx->pOctetString)))
        {
            goto exit;
        }
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedAddDataToContext( MOC_HASH(hwAccelDescr hwAccelCtx)
                           CMS_Signed_CTX* pCtx, const ubyte* data, ubyte4 dataLen,
                           intBoolean derEncoded)
{
    MSTATUS status = OK;
    ubyte4 i;

    if (!data || !dataLen)
    {
        goto exit; /* nothing to do */
    }

    /* add to the BER OCTETSTRING if not detached */
    if ( !pCtx->detached)
    {
        if (!pCtx->pOctetString)
        {
            /* create a DER or BER OctetString */
            if (OK > ( status = CMS_signedCreateEncapsulatedContent( pCtx, derEncoded)))
                goto exit;
        }

        if (OK > ( status = DER_AddItem( pCtx->pOctetString, OCTETSTRING, dataLen, data, NULL)))
            goto exit;
    }

    /* always hash the data */
    for ( i = 0; i < pCtx->numHashes; ++i)
    {
        SignedDataHash* pCurrHash;

        pCurrHash = pCtx->pSignedHashes + i;

        pCurrHash->hashAlgo->updateFunc( MOC_HASH(hwAccelCtx) pCurrHash->bulkCtx, data, dataLen);
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedDataAddASN1Data( DER_ITEMPTR pSignedData, const DynArray* pArr, ubyte tag )
{
    MSTATUS status = OK;
    sbyte4 i, numElems;
    DER_ITEMPTR pImplicitSet;
    CMS_Data asn1Data;

    if (OK > ( status = DYNARR_GetElementCount(pArr, &numElems)))
    {
        goto exit;
    }

    if (numElems <= 0)
    {
        goto exit;
    }

    if (OK > ( status  = DER_AddTag( pSignedData, tag, &pImplicitSet)))
        goto exit;

    for (i = 0; i < numElems; ++i)
    {
        DYNARR_Get(pArr, i, &asn1Data);
        if (OK > ( status = DER_AddDERBuffer( pImplicitSet, asn1Data.dataLen, asn1Data.data,
                                                NULL)))
        {
            goto exit;
        }
    }

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedAddSignerInfo( MOC_ASYM(hwAccelDescr hwAccelCtx) CMS_Signed_CTX* pCtx,
                        DER_ITEMPTR pSet, CMS_SignerCtx* pSigner)
{
    MSTATUS status;
    DER_ITEMPTR pSignerItem;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pASN1Root = 0, pIssuer, pSerialNumber, pExtensions, pSKIExtension;
    SignedDataHash* pHash = NULL;
    ubyte4 i;
    ubyte* pDerAttributes = 0;
    ubyte4 derAttributesLen = 0;
    intBoolean critical;

    for (i = 0; i < pCtx->numHashes; ++i)
    {
        if ( EqualOID(pSigner->digestAlgoOID, pCtx->pSignedHashes[i].algoOID))
        {
            pHash = pCtx->pSignedHashes+i;
            break;
        }
    }

    /* get the parsed certificate for whichever version */
    MF_attach( &mf, pSigner->certLen, (ubyte*) pSigner->cert);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pASN1Root)))
        goto exit;

    /* create the signer item */
    if (OK > ( status = DER_AddSequence( pSet, &pSignerItem)))
        goto exit;

    if (pSigner->flags & e_cms_signer_version3)
    {
        ubyte *pRawSki = NULL;
        ubyte *pRawSkiCopy = NULL;

        /******************** version = 3 */
        if (OK > ( status = DER_AddIntegerEx( pSignerItem, 3, NULL)))
            goto exit;

        /* get the extensions */
        if ( OK > ( status = X509_getCertificateExtensions( ASN1_FIRST_CHILD(pASN1Root),
            &pExtensions)))
        {
            goto exit;
        }

        /* no extensions */
        if (NULL == pExtensions)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        /* look for the Subject Key Extension */
        if (OK > ( status = X509_getCertExtension( pExtensions, cs, subjectKeyIdentifier_OID, &critical, &pSKIExtension)))
        {
            goto exit;
        }

        if (NULL == pSKIExtension )
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        pRawSki = (ubyte *)CS_memaccess( cs, pSKIExtension->dataOffset, pSKIExtension->length);
        if (NULL == pRawSki)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* copy over to our own buffer */
        status = DIGI_MALLOC_MEMCPY((void **) &pRawSkiCopy, pSKIExtension->length, pRawSki, pSKIExtension->length);
        CS_stopaccess( cs, pRawSki);
        if (OK != status)
            goto exit;

        /* Adds Tag [0] with implicit data */
        if (OK > (status = DER_AddItemOwnData( pSignerItem, (PRIMITIVE|CONTEXT|SUBJECT_KEY_IDENTIFIER_TAG),
                                               pSKIExtension->length, &pRawSkiCopy, NULL)))
        {
            if (NULL != pRawSkiCopy)
            {
               (void) DIGI_FREE((void **) &pRawSkiCopy);
            }
            goto exit;
        }
    }
    else
    {
        /******************** version = 1 */
        if (OK > ( status = DER_AddIntegerEx( pSignerItem, 1, NULL)))
            goto exit;

        /******************** issuer and serial number */
        if (OK > ( status = X509_getCertificateIssuerSerialNumber( ASN1_FIRST_CHILD(pASN1Root),
                                                                    &pIssuer, &pSerialNumber)))
        {
            goto exit;
        }

        if (OK > (status = PKCS7_AddIssuerAndSerialNumber(pSignerItem, cs, pIssuer,
                                                            pSerialNumber, NULL)))
        {
            goto exit;
        }
    }

    /****************** digest Algorithm */
    if ( OK > ( status = DER_StoreAlgoOID( pSignerItem, pSigner->digestAlgoOID, TRUE)))
        goto exit;

    if (NULL == pHash)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /***************** OPTIONAL authenticatedAttributes */
    if ( DER_FIRST_CHILD(pSigner->pAuthAttributes) ||
            !EqualOID(pCtx->payloadTypeOID, pkcs7_data_OID) ||
            pCtx->receiptRequest ||
            (pSigner->flags & e_cms_signer_forceAuthAttr))
    {
        TimeDate td;
        DER_ITEMPTR pItem;

        /* add the required attributes */
        if ( OK > ( status = PKCS7_AddAttribute( pSigner->pAuthAttributes,
                                                 pkcs9_contentType_OID, OID,
                                                 pCtx->payloadTypeOID+1,
                                                 pCtx->payloadTypeOID[0], NULL)))
        {
            goto exit;
        }

        if ( OK > ( status = PKCS7_AddAttribute( pSigner->pAuthAttributes,
                                                pkcs9_messageDigest_OID,
                                                PRIMITIVE|OCTETSTRING,
                                                pHash->hashData,
                                                pHash->hashAlgo->digestSize, NULL)))
        {
            goto exit;
        }

        /* add signing time */
        if (OK > ( status = RTOS_timeGMT(&td)))
            goto exit;

        if (OK > ( status = DER_AddSequence( pSigner->pAuthAttributes, &pItem)))
            goto exit;

        if (OK > ( status = DER_AddOID( pItem, pkcs9_signingTime_OID, NULL)))
            goto exit;

        if (OK > ( status = DER_AddSet( pItem, &pItem)))
            goto exit;

        if (OK > ( status = DER_AddTime( pItem, &td, NULL)))
            goto exit;

        /* add the receipt request */
        if ( pCtx->receiptRequest)
        {
            if (OK > ( status = PKCS7_AddAttributeEx( pSigner->pAuthAttributes,
                                                        smime_receiptRequest_OID,
                                                        SEQUENCE,
                                                        pCtx->receiptRequest,
                                                        pCtx->receiptRequestLen, 1, NULL)))
            {
                goto exit;
            }
        }

        if ( OK > ( status = DER_GetLength( pSigner->pAuthAttributes, &derAttributesLen)))
            goto exit;

        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx,
                            derAttributesLen + pHash->hashAlgo->digestSize, TRUE,
                            &pDerAttributes)))
        {
            goto exit;
        }

        if (OK > (status = DER_SerializeInto(pSigner->pAuthAttributes,
                                            pDerAttributes, &derAttributesLen)))
        {
            goto exit;
        }

        pHash->hashAlgo->initFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx);
        pHash->hashAlgo->updateFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx,
                                        pDerAttributes, derAttributesLen);
        pHash->hashAlgo->finalFunc( MOC_HASH(hwAccelCtx) pHash->bulkCtx,
                                        pDerAttributes + derAttributesLen);

        /* save the digest if there's a receiptRequest */
        if (pCtx->receiptRequest)
        {
            pSigner->digest = MALLOC( pHash->hashAlgo->digestSize);
            if (!pSigner->digest)
            {
                status = ERR_MEM_ALLOC_FAIL; goto exit;
            }

            DIGI_MEMCPY( pSigner->digest, pDerAttributes + derAttributesLen,
                        pHash->hashAlgo->digestSize);
            pSigner->digestLen = pHash->hashAlgo->digestSize;
        }

        /* convert SET to [0] */
        if (OK > ( status = DER_SwitchType( pSigner->pAuthAttributes,
                                             (CONSTRUCTED|CONTEXT))))
        {
            goto exit;
        }

        /* transfer all authenticated attributes to pSignerItem */
        if (OK > ( status = TREE_AppendChild( (TreeItem*) pSignerItem,
                                                (TreeItem*) pSigner->pAuthAttributes) ))
        {
            goto exit;
        }
    }

    /********************* digestEncrytionAlgorithm */
    if ( (0xFFFF & pSigner->pKey->type) == akt_rsa)
    {
#ifndef __DISABLE_DIGICERT_RSA__         
        if ( OK > ( status = DER_StoreAlgoOID( pSignerItem, rsaEncryption_OID, TRUE)))
            goto exit;

        if (NULL != pSigner->callback)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if ( OK > (CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pSigner->pKey->key.pRSA, (sbyte4 *) &pSigner->signatureLen)))
#else
            if ( OK > (RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pSigner->pKey->key.pRSA, (sbyte4 *) &pSigner->signatureLen)))
#endif
                goto exit;
        }
#else
        status = ERR_RSA_DISABLED;
        goto exit;
#endif
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ( (0xFFFF & pSigner->pKey->type) == akt_dsa)
    {
        if ( OK > ( status = PKCS7_AddDSADigestAlgoId(pSignerItem, pHash->hashType)))
            goto exit;

        if (NULL != pSigner->callback)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if ( OK > (CRYPTO_INTERFACE_DSA_getSignatureLength(MOC_DSA(hwAccelCtx) pSigner->pKey->key.pDSA, &pSigner->signatureLen)))
#else
            if ( OK > (DSA_getSignatureLength(MOC_DSA(hwAccelCtx) pSigner->pKey->key.pDSA, &pSigner->signatureLen)))
#endif
                goto exit;

            pSigner->signatureLen *= 2; /* account for both r and s */
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( (0xFFFF & pSigner->pKey->type) == akt_ecc)
    {
        if (OK > ( status = PKCS7_AddECDSADigestAlgoId(pSignerItem, pHash->hashType)))
            goto exit;

        if (NULL != pSigner->callback)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if ( OK > (CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pSigner->pKey->key.pECC, &pSigner->signatureLen)))
#else
            if ( OK > (EC_getElementByteStringLen(pSigner->pKey->key.pECC, &pSigner->signatureLen)))
#endif
                goto exit;

            pSigner->signatureLen *= 2; /* account for both r and s */
        }
    }
#endif
    else
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

    /************************************ sign message digest */

    /* encrypt message digest */
    /* encrypt Der encoded DigestInfo if RSA */
    if ( (0xFFFF & pSigner->pKey->type) == akt_rsa)
    {
#ifndef __DISABLE_DIGICERT_RSA__        
        const ubyte* toSign;

        toSign = pDerAttributes ? pDerAttributes + derAttributesLen: pHash->hashData;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerItem,
                                                    pSigner->pKey,
                                                    pSigner->callback,
                                                    pSigner->pCbInfo,
                                                    NULL, 0,
                                                    pSigner->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    &pSigner->signature,
                                                    &pSigner->signatureLen)))
        {
            goto exit;
        }
#else
        if (OK > ( status = PKCS7_AddRSASignature(MOC_RSA(hwAccelCtx) pSignerItem,
                                                    pSigner->pKey->key.pRSA,
                                                    pSigner->callback,
                                                    pSigner->pCbInfo,
                                                    pSigner->digestAlgoOID,
                                                    toSign, pHash->hashAlgo->digestSize,
                                                    &pSigner->signature,
                                                    &pSigner->signatureLen)))
        {
            goto exit;
        }
#endif
#else
        status = ERR_RSA_DISABLED;
        goto exit;

#endif /* __DISABLE_DIGICERT_RSA__ */
    }
#ifdef __ENABLE_DIGICERT_DSA__
    else if ((0xFFFF & pSigner->pKey->type) == akt_dsa)
    {
    const ubyte* toSign;

        if (!pCtx->rngFun)
        {
            status = ERR_PKCS7_RNG_FUN_REQUIRED_FOR_ECC;
            goto exit;
        }

        toSign = pDerAttributes ? pDerAttributes + derAttributesLen: pHash->hashData;

        if (OK > ( status = PKCS7_AddDSASignature(MOC_DSA(hwAccelCtx) pSignerItem,
                                pSigner->pKey->key.pDSA,
                                pSigner->callback, pSigner->pCbInfo,
                                pCtx->rngFun, pCtx->rngFunArg,
                                toSign, pHash->hashAlgo->digestSize,
                                &pSigner->signature,
                                &pSigner->signatureLen)))
        {
            goto exit;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    else if ( (0xFFFF & pSigner->pKey->type) == akt_ecc)
    {
        /* if authenticated attributes is present, use second hash; else use pHash->hashData */
        const ubyte* toSign;

        if (!pCtx->rngFun)
        {
            status = ERR_PKCS7_RNG_FUN_REQUIRED_FOR_ECC;
            goto exit;
        }

        toSign = pDerAttributes ? pDerAttributes + derAttributesLen: pHash->hashData;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerItem,
                                (AsymmetricKey*)pSigner->pKey,
                                pSigner->callback, pSigner->pCbInfo,
                                NULL, 0,
                                pCtx->rngFun, pCtx->rngFunArg,
                                toSign, pHash->hashAlgo->digestSize,
                                &pSigner->signature,
                                &pSigner->signatureLen)))
        {
            goto exit;
        }
#else
        if (OK > ( status = PKCS7_AddECDSASignature( MOC_ECC(hwAccelCtx) pSignerItem,
                                pSigner->pKey->key.pECC, 
                                pSigner->callback, pSigner->pCbInfo,
                                pCtx->rngFun, pCtx->rngFunArg,
                                toSign, pHash->hashAlgo->digestSize,
                                &pSigner->signature,
                                &pSigner->signatureLen)))
        {
            goto exit;
        }
#endif
    }
#endif
    
    /************************************ OPTIONAL unauthenticatedAttributes */

    /* transfer all authenticated attributes to pSignerItem */
    if ( DER_FIRST_CHILD(pSigner->pUnauthAttributes))
    {
        if (OK > ( status = TREE_AppendChild( (TreeItem*) pSignerItem,
                                                (TreeItem*) pSigner->pUnauthAttributes) ))
        {
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_RE_SIGNER__

    /* When we are re-signing, add the saved signature block to the output
     * and then clear it after use so that we only add it once.            */

    ubyte *pSignature;
    ubyte4 sigLen;

    CMS_ResignData_CTX RSCtx = (CMS_ResignData_CTX)pCtx->pResData;
    if (NULL != RSCtx) /* NULL is OK, and means not saving Resign data.*/
    {
        CMS_RESIGN_getExtractedSignature(RSCtx, &pSignature, &sigLen);

        if (0 < sigLen)
        {
            CMS_RESIGN_clearExtractedSignature(RSCtx);
            DER_AddDERBuffer(pSet, sigLen, pSignature, &pSignerItem);
        }

    }

#endif /*__ENABLE_DIGICERT_RE_SIGNER__*/

exit:

    if (pDerAttributes)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pDerAttributes);
    }

    if (pASN1Root)
    {
        TREE_DeleteTreeItem( (TreeItem*) pASN1Root);
    }

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedAddSignersInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) CMS_Signed_CTX* pCtx)
{
    MSTATUS status;
    sbyte4 i, numSigners;
    DER_ITEMPTR pSignerInfosSet;

    /* always add a set */
    if ( OK > ( status = DER_AddSet ( pCtx->pSignedData, &pSignerInfosSet)))
        goto exit;

    if (OK > ( status = DYNARR_GetElementCount( &pCtx->signers, &numSigners)))
        goto exit;

    for (i = 0; i < numSigners; ++i)
    {
        CMS_SignerCtx* pSigner;

        pSigner = CMS_GetSigner(&pCtx->signers, i);
        if (NULL == pSigner)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > ( status = CMS_signedAddSignerInfo(MOC_ASYM(hwAccelCtx) pCtx,
                                                    pSignerInfosSet, pSigner)))
            goto exit;
    }


exit:
    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedDataFinalize(MOC_ASYM(hwAccelDescr hwAccelCtx) CMS_Signed_CTX* pCtx)
{
    MSTATUS status = OK;
    ubyte4 i;

    /* finish the hashes */
    for ( i = 0; i < pCtx->numHashes; ++i)
    {
        SignedDataHash* pCurrHash;

        pCurrHash = pCtx->pSignedHashes + i;

        pCurrHash->hashAlgo->finalFunc(MOC_HASH(hwAccelCtx)
                                       pCurrHash->bulkCtx, pCurrHash->hashData);
    }

    /* add the rest of the ASN.1: certs, crls and signer infos */
    if (OK > ( status = CMS_signedDataAddASN1Data( pCtx->pSignedData,
                                                    &pCtx->certs, 0 )))
    {
        goto exit;
    }

    if (OK > ( status = CMS_signedDataAddASN1Data( pCtx->pSignedData,
                                                    &pCtx->crls, 1 )))
    {
        goto exit;
    }

    if (OK > ( status = CMS_signedAddSignersInfo(MOC_ASYM(hwAccelCtx) pCtx)))
        goto exit;

    /* finalize the BER items */
    if (OK > ( status = DER_FinalizeBERItems( pCtx->pRoot)))
        goto exit;

    pCtx->done = 1;

exit:

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_signedGetOutputData( CMS_Signed_CTX*pCtx, ubyte** ppOutput, ubyte4* pOutputLen)
{
    MSTATUS status;

    if (OK > ( status = DER_SerializeOffset( pCtx->pRoot, pCtx->outOffset,
                                            ppOutput, pOutputLen)))
    {
        goto exit;
    }

    pCtx->outOffset += (*pOutputLen);

exit:
    return status;
}


/*-------------------------------------------------------------------------------*/


extern MSTATUS
CMS_signedUpdateContext( MOC_ASYM(hwAccelDescr hwAccelCtx)
                           CMS_signedDataContext myCtx,
                           const ubyte* data, ubyte4 dataLen,
                           ubyte** ppOutput, ubyte4* pOutputLen,
                           intBoolean finished)
{
    MSTATUS status;
    CMS_Signed_CTX* pCtx;

    if (!myCtx || !ppOutput || !pOutputLen)
    {
        return ERR_NULL_POINTER;
    }

    /* if no data is supplied, then better be finished -- degenerate case */
    if ( !data || !dataLen )
    {
        finished = TRUE;
    }

    pCtx = (CMS_Signed_CTX*) myCtx;

    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }

    if ( !pCtx->pRoot)
    {
        if (OK > (status = CMS_signedCreateDER(MOC_HASH(hwAccelCtx) pCtx, finished)))
        {
            goto exit;
        }
    }

    if (OK > ( status = CMS_signedAddDataToContext( MOC_HASH(hwAccelCtx) pCtx, data, dataLen, finished)))
        goto exit;

    if (finished)
    {
        if (OK > ( status = CMS_signedDataFinalize(MOC_ASYM(hwAccelCtx) pCtx)))
            goto exit;
    }

    if (OK > ( status = CMS_signedGetOutputData( pCtx, ppOutput, pOutputLen)))
        goto exit;


exit:
    return status;
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_envelopedNewContext( CMS_envelopedDataContext* pNewCtx,
                          const ubyte* encryptAlgoOID,
                          RNGFun rngFun, void* rngFunArg)
{
    MSTATUS status = OK;
    CMS_Enveloped_CTX* pCtx;

    if (!pNewCtx || !encryptAlgoOID )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Enveloped_CTX*) MALLOC( sizeof(CMS_Enveloped_CTX));

    if (!pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte*) pCtx, 0, sizeof( CMS_Enveloped_CTX));

    pCtx->encryptAlgoOID = encryptAlgoOID;
    pCtx->rngFun = rngFun;
    pCtx->rngFunArg = rngFunArg;

    DYNARR_Init( sizeof(CMS_Data), &pCtx->certs);
    DYNARR_Init( sizeof(CMS_KeyData), &pCtx->pubkeys);

    if (OK < ( status = DER_AddTag( NULL, 1, &pCtx->pUnauthAttributes)))
    {
        goto exit;
    }


    *pNewCtx = pCtx;
    pCtx = 0;

exit:

    return status;
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_envelopedDeleteContext(MOC_SYM(hwAccelDescr hwAccelCtx) CMS_envelopedDataContext* ppCtx)
{
    CMS_Enveloped_CTX* pCtx;

    if (!ppCtx || !*ppCtx)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Enveloped_CTX*) (*ppCtx);

    DYNARR_Uninit( &pCtx->certs);
    DYNARR_Uninit( &pCtx->pubkeys);

    TREE_DeleteTreeItem( (TreeItem*) (pCtx->pUnauthAttributes));

    TREE_DeleteTreeItem( (TreeItem*) (pCtx->pRoot));

    if (pCtx->encContext)
    {
        pCtx->pBulkEncryptionAlgo->deleteFunc(MOC_SYM(hwAccelCtx) &pCtx->encContext);
    }

    FREE( pCtx);
    *ppCtx = 0;

    return OK;
}

/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_envelopedAddRecipient( CMS_envelopedDataContext myCtx,
                           const ubyte* cert, ubyte4 certLen)
{
    CMS_Enveloped_CTX* pCtx;

    if (!myCtx || !cert )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Enveloped_CTX*) myCtx;

    if (pCtx->pRoot)
    {
        return ERR_PKCS7_ALREADY_STREAMING;
    }

    return CMS_addASN1Data(&pCtx->certs, cert, certLen);
}

/*-------------------------------------------------------------------------------*/
#ifdef __ENABLE_DIGICERT_ECC__
/**
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        cms_functions
*/
extern MSTATUS
CMS_hashOfKey(MOC_ECC(hwAccelDescr hwAccelCtx) AsymmetricKey* pKey,
              ubyte4 hashType, ubyte* result)
{
    MSTATUS (*hashFunc)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
                        ubyte4 dataLen, ubyte *pDigestOutput);

    if (!pKey)
    {
        return ERR_NULL_POINTER;
    }

    if (pKey->type != akt_ecc)
    {
        return ERR_BAD_KEY_TYPE;
    }

    switch(hashType)
    {
        case ht_sha1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            hashFunc = CRYPTO_INTERFACE_SHA1_completeDigest;
#else
            hashFunc = SHA1_completeDigest;
#endif
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            hashFunc = CRYPTO_INTERFACE_SHA224_completeDigest;
#else
            hashFunc = SHA224_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            hashFunc = CRYPTO_INTERFACE_SHA256_completeDigest;
#else
            hashFunc = SHA256_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            hashFunc = CRYPTO_INTERFACE_SHA384_completeDigest;
#else
            hashFunc = SHA384_completeDigest;
#endif
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            hashFunc = CRYPTO_INTERFACE_SHA512_completeDigest;
#else
            hashFunc = SHA512_completeDigest;
#endif
            break;
#endif

        default:
            return ERR_PKCS7_UNSUPPORTED_DIGESTALGO;
    }

    return PKCS7_HashOfEcKey(MOC_ECC(hwAccelCtx) pKey, result, hashFunc);
}
#endif


/*-------------------------------------------------------------------------------*/

/**
@todo_add_ask   (Not sure when this was added, nor why it wasn't documented.)
@ingroup        cms_functions
*/
extern MSTATUS
CMS_envelopedAddRecipientByPubKey( CMS_envelopedDataContext myCtx,
                                  const ubyte* pubkey, ubyte4 keyLen, ubyte4 hashType)
{
    CMS_Enveloped_CTX* pCtx;

    if (!myCtx || !pubkey )
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Enveloped_CTX*) myCtx;

    if (pCtx->pRoot)
    {
        return ERR_PKCS7_ALREADY_STREAMING;
    }

    return CMS_addASN1KeyData(&pCtx->pubkeys, pubkey, keyLen, hashType);
}


/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_envelopedAddUnauthAttribute( CMS_envelopedDataContext myCtx,
                                    const ubyte* typeOID,
                                    ubyte4 type, /* id|tag */
                                    const ubyte* value,
                                    ubyte4 valueLen)
{
    CMS_Enveloped_CTX* pCtx;

    if (!myCtx || !typeOID || !value)
    {
        return ERR_NULL_POINTER;
    }

    pCtx = (CMS_Enveloped_CTX*) myCtx;

    if (pCtx->pRoot)
    {
        /* we can add more attributes if there's already one
        otherwise the version number is already set */
        if (!DER_FIRST_CHILD(pCtx->pUnauthAttributes))
        {
            return ERR_PKCS7_ALREADY_STREAMING;
        }

        if (pCtx->done)
        {
            return ERR_PKCS7_CONTEXT_COMPLETED;
        }
    }

    return PKCS7_AddAttribute(pCtx->pUnauthAttributes,
            typeOID, type, value, valueLen, NULL);
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedAddRecipientInfo( MOC_HW(hwAccelDescr hwAccelCtx)
                              CMS_Enveloped_CTX* pCtx,
                              DER_ITEMPTR pRecipientInfos,
                              ubyte* encryptKey, sbyte4 keyLength,
                              CMS_Data* cert)
{
    MSTATUS status;
    CStream cs;
    MemFile mf;
    ASN1_ITEMPTR pRootItem = 0;
    ASN1_ITEMPTR pCertificate;
    AsymmetricKey key;
#ifdef __ENABLE_DIGICERT_CMS_RSA_OAEP_DEFAULT__
    ubyte isOaep = 1;
    ubyte4 oaepHashAlgo = (ubyte4) gRsaHashTable[RSA_OAEP_HASH_ALGO_DEFAULT_INDEX].hashId;
    sbyte *pOaepLabel = (sbyte *) RSA_OAEP_LABEL_DEFAULT;
#else
    ubyte isOaep = 0;
    ubyte4 oaepHashAlgo = 0;
    sbyte *pOaepLabel = NULL;
#endif

    if ( OK > ( status = CRYPTO_initAsymmetricKey( &key)))
        goto exit;

    MF_attach( &mf, cert->dataLen, (ubyte*) cert->data);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pRootItem)))
    {
        goto exit;
    }

    pCertificate = ASN1_FIRST_CHILD(pRootItem);

    if ( OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                            pCertificate,
                                                            cs, &key)))
    {
        goto exit;
    }

    if ( akt_rsa == key.type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        if (OK > ( status = PKCS7_AddRSARecipientInfo(MOC_RSA(hwAccelCtx)
                                pRecipientInfos, key.key.pRSA,
                                encryptKey, keyLength,
                                pCertificate, cs,
                                pCtx->rngFun, pCtx->rngFunArg,
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
        pCtx->version = 2;

        if (OK > ( status = PKCS7_AddECDHRecipientInfo(MOC_HW(hwAccelCtx)
                                pRecipientInfos, &key,
                                pCtx->pBulkEncryptionAlgo,
                                encryptKey, keyLength,
                                pCertificate, cs, 0,
                                pCtx->rngFun, pCtx->rngFunArg)))
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

exit:

    TREE_DeleteTreeItem( (TreeItem*) pRootItem);

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedAddRecipientInfoByPubKey( MOC_HW(hwAccelDescr hwAccelCtx)
                                      CMS_Enveloped_CTX* pCtx,
                                      DER_ITEMPTR pRecipientInfos,
                                      ubyte* encryptKey, sbyte4 keyLength,
                                      CMS_KeyData* pubkey)
{
    MSTATUS status;
    CStream cs = { 0 };
    AsymmetricKey key;

    if ( OK > ( status = CRYPTO_initAsymmetricKey( &key)))
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC__
    if (OK > ( status = SEC_getKey( MOC_ECC(hwAccelCtx) pubkey->data, pubkey->dataLen, &key)))
    {
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_ECC__
    if ( akt_ecc == key.type)
    {
        /* need to change the version */
        pCtx->version = 2;

        if (OK > ( status = PKCS7_AddECDHRecipientInfo(MOC_HW(hwAccelCtx)
                                                       pRecipientInfos, &key,
                                                       pCtx->pBulkEncryptionAlgo,
                                                       encryptKey, keyLength,
                                                       NULL, cs,
                                                       pubkey->hashType,
                                                       pCtx->rngFun, pCtx->rngFunArg)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        status = ERR_PKCS7_UNSUPPORTED_ENCRYPTALGO;
        goto exit;
    }

exit:

    CRYPTO_uninitAsymmetricKey( &key, NULL);

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedCreateDER(MOC_HW(hwAccelDescr hwAccelCtx) CMS_Enveloped_CTX* pCtx)
{
    MSTATUS status;
    DER_ITEMPTR pEnvelopedData, pTemp, pEncryptionAlgo;
    sbyte4 i, keyLength, numRecipients;
    ubyte encryptKey[MAX_ENC_KEY_LENGTH];  /* big enough for AES-256 */
    ubyte* ivCopy = 0;

    if (OK > ( status = DER_AddBERSequence( NULL, &pCtx->pRoot)))
        goto exit;

    if (OK > ( status = DER_AddOID( pCtx->pRoot, pkcs7_envelopedData_OID, NULL)))
        goto exit;

    if (OK > ( status = DER_AddBERTag( pCtx->pRoot, 0, &pTemp)))
        goto exit;

    if (OK > ( status = DER_AddBERSequence( pTemp, &pEnvelopedData)))
        goto exit;

   /* version number: the choice is either 0 or 2 depending on
    whether we have any unauthenticated attributes and any recipient info
    version is not 0 - so we cannot completely decide until we looked at
    all the recipients in detail -- ECC key ? */
    pCtx->version = DER_FIRST_CHILD(pCtx->pUnauthAttributes) ? 2 : 0;

    if ( OK > ( status = DER_AddItem( pEnvelopedData, INTEGER, 1, &pCtx->version, NULL)))
        goto exit;

    /* create the content encryption context */
    if ( OK > ( status = PKCS7_GetCryptoAlgoParams( pCtx->encryptAlgoOID,
                                                    &pCtx->pBulkEncryptionAlgo,
                                                    &keyLength)))
    {
        goto exit;
    }

    /* create the encryption context and the IV */
    if (OK > ( status = pCtx->rngFun( pCtx->rngFunArg, (ubyte4) keyLength,
                                        encryptKey)))
    {
        goto exit;
    }

    if ( pCtx->pBulkEncryptionAlgo->blockSize &&
        (OK > ( status = pCtx->rngFun( pCtx->rngFunArg,
                                        pCtx->pBulkEncryptionAlgo->blockSize,
                                        pCtx->iv))))
    {
        goto exit;
    }

    pCtx->encContext = pCtx->pBulkEncryptionAlgo->createFunc(MOC_SYM(hwAccelCtx) encryptKey, keyLength, 1);
    if (!pCtx->encContext)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* add the recipient infos */
    /* recipient information */
    if ( OK > ( status = DER_AddSet( pEnvelopedData, &pTemp)))
        goto exit;

    if (OK > ( status = DYNARR_GetElementCount( &pCtx->certs, &numRecipients)))
        goto exit;

    for (i = 0; i < numRecipients; ++i)
    {
        CMS_Data cert;

        if (OK > ( status = DYNARR_Get( &pCtx->certs, i, &cert)))
            goto exit;

        if (OK > ( status = CMS_envelopedAddRecipientInfo( MOC_HW(hwAccelCtx)
                                            pCtx, pTemp,
                                            encryptKey, keyLength,
                                            &cert)))
        {
            goto exit;
        }
    }

    if (OK > ( status = DYNARR_GetElementCount( &pCtx->pubkeys, &numRecipients)))
        goto exit;

    for (i = 0; i < numRecipients; ++i)
    {
        CMS_KeyData pubkey;

        if (OK > ( status = DYNARR_Get( &pCtx->pubkeys, i, &pubkey)))
            goto exit;

        if (OK > ( status = CMS_envelopedAddRecipientInfoByPubKey( MOC_HW(hwAccelCtx)
                                                                  pCtx, pTemp,
                                                                  encryptKey, keyLength,
                                                                  &pubkey)))
        {
            goto exit;
        }
    }

    /* add the encrypted content info */
    if (OK > ( status = DER_AddBERSequence( pEnvelopedData, &pTemp)))
        goto exit;

    /* content type */
    if ( OK > ( status = DER_AddOID( pTemp, pkcs7_data_OID, NULL)))
        goto exit;

    /* encryption algo */
    if ( OK > ( status = DER_AddSequence( pTemp, &pEncryptionAlgo)))
        goto exit;

    if ( OK > ( status = DER_AddOID( pEncryptionAlgo, pCtx->encryptAlgoOID, NULL)))
        goto exit;

    if ( pCtx->pBulkEncryptionAlgo->blockSize > 0)
    {
        /* make a copy of the IV since it can be used before we serialize */
        ivCopy = MALLOC( pCtx->pBulkEncryptionAlgo->blockSize);
        if (!ivCopy)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY( ivCopy, pCtx->iv, pCtx->pBulkEncryptionAlgo->blockSize);

        if ( OK > ( status = DER_AddItemOwnData( pEncryptionAlgo, OCTETSTRING,
                                            pCtx->pBulkEncryptionAlgo->blockSize,
                                            &ivCopy, NULL)))
        {
            goto exit;
        }
    }
    else
    {
        if ( OK > ( status = DER_AddItem( pEncryptionAlgo, NULLTAG, 0, NULL, NULL)))
            goto exit;
    }

    /* encrypted content */
    if (OK > (status = DER_AddBERTag( pTemp, 0, &pCtx->pZeroLabel)))
    {
        goto exit;
    }

    pCtx->pEnvelopedData = pEnvelopedData;

exit:

    if (ivCopy)
    {
        FREE( ivCopy);
    }

    DIGI_MEMSET( encryptKey, 0, MAX_ENC_KEY_LENGTH);

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedAddDataToContext( MOC_SYM(hwAccelDescr hwAccelCtx)
                              CMS_Enveloped_CTX* pCtx, const ubyte* data,
                              ubyte4 dataLen)
{
    MSTATUS status = OK;
    ubyte* encryptedData = 0;
    ubyte4 total, remain, toEncrypt;

    /* encrypt the data and add it as an OCTET STRING */
    if (!data || !dataLen)
    {
        goto exit; /* nothing to do */
    }

    /* encrypt as much as possible */
    total = pCtx->lastSize + dataLen;

    if (  pCtx->pBulkEncryptionAlgo->blockSize)
    {
        remain = total % pCtx->pBulkEncryptionAlgo->blockSize;
        toEncrypt = total - remain;
    }
    else
    {
        remain = 0;
        toEncrypt = total;
    }

    if (toEncrypt)
    {
        encryptedData = MALLOC( toEncrypt);
        if (!encryptedData)
        {
            return ERR_MEM_ALLOC_FAIL;
        }

        DIGI_MEMCPY( encryptedData, pCtx->last, pCtx->lastSize);
        DIGI_MEMCPY( encryptedData + pCtx->lastSize, data, toEncrypt - pCtx->lastSize);

        data += toEncrypt - pCtx->lastSize;
        dataLen -= toEncrypt - pCtx->lastSize;
        pCtx->lastSize = 0;

        if (OK > (status = pCtx->pBulkEncryptionAlgo->cipherFunc( MOC_SYM(hwAccelCtx)
                                                            pCtx->encContext,
                                                            encryptedData,
                                                            toEncrypt, 1,
                                                            pCtx->iv)))
        {
            goto exit;
        }

        if (OK > ( status = DER_AddItemOwnData( pCtx->pZeroLabel, OCTETSTRING,
                                            toEncrypt, &encryptedData, NULL)))
        {
            goto exit;
        }
    }

    if (remain)
    {
        DIGI_MEMCPY(pCtx->last + pCtx->lastSize,
                    data,
                    dataLen);
    }

    pCtx->lastSize = remain;

exit:

    if (encryptedData)
    {
        FREE(encryptedData);
    }

    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedDataFinalize(MOC_SYM(hwAccelDescr hwAccelCtx) CMS_Enveloped_CTX* pCtx)
{
    MSTATUS status;
    ubyte4 i;

    /* add padding */
    if ( pCtx->pBulkEncryptionAlgo->blockSize)
    {
        sbyte4 padSize = pCtx->pBulkEncryptionAlgo->blockSize - pCtx->lastSize;

        for (i = pCtx->lastSize; i < pCtx->pBulkEncryptionAlgo->blockSize; ++i)
        {
            pCtx->last[i] = (ubyte) padSize;
        }

        if (OK > (status = pCtx->pBulkEncryptionAlgo->cipherFunc( MOC_SYM(hwAccelCtx)
                                            pCtx->encContext,
                                            pCtx->last,
                                            pCtx->pBulkEncryptionAlgo->blockSize,
                                            1, pCtx->iv)))
        {
            goto exit;
        }

        if (OK > ( status = DER_AddItem( pCtx->pZeroLabel, OCTETSTRING,
                                         pCtx->pBulkEncryptionAlgo->blockSize,
                                         pCtx->last, NULL)))
        {
            goto exit;
        }
    }

    /* add the unprotected attributes */
    if ( DER_FIRST_CHILD(pCtx->pUnauthAttributes))
    {
        if (OK > ( status = TREE_AppendChild( (TreeItem*) pCtx->pEnvelopedData,
                                                (TreeItem*) pCtx->pUnauthAttributes) ))
        {
            goto exit;
        }
    }

    /* finalize the ASN.1 tree */
    if (OK > ( status = DER_FinalizeBERItems( pCtx->pRoot)))
        goto exit;

    pCtx->done = 1;

exit:
    return status;
}


/*-------------------------------------------------------------------------------*/

static MSTATUS
CMS_envelopedGetOutputData( CMS_Enveloped_CTX* pCtx,
                           ubyte** ppOutput, ubyte4* pOutputLen)
{
    MSTATUS status;

    if (OK > ( status = DER_SerializeOffset( pCtx->pRoot, pCtx->outOffset,
                                            ppOutput, pOutputLen)))
    {
        goto exit;
    }

    pCtx->outOffset += (*pOutputLen);


exit:
    return status;
}


/*-------------------------------------------------------------------------------*/

extern MSTATUS
CMS_envelopedUpdateContext( MOC_HW(hwAccelDescr hwAccelCtx)
                              CMS_envelopedDataContext myCtx,
                              const ubyte* data, ubyte4 dataLen,
                              ubyte** ppOutput, ubyte4* pOutputLen,
                              intBoolean finished)
{
    MSTATUS status;
    CMS_Enveloped_CTX* pCtx;

    if (!myCtx || !ppOutput || !pOutputLen)
    {
        return ERR_NULL_POINTER;
    }

    /* if no data is supplied, then better be finished -- degenerate case */
    if ( !data || !dataLen )
    {
        finished = TRUE;
    }

    pCtx = (CMS_Enveloped_CTX*) myCtx;

    if (pCtx->done)
    {
        return ERR_PKCS7_CONTEXT_COMPLETED;
    }

    if ( !pCtx->pRoot)
    {
        if (OK > (status = CMS_envelopedCreateDER(MOC_HW(hwAccelCtx) pCtx)))
        {
            goto exit;
        }
    }

    if (OK > ( status = CMS_envelopedAddDataToContext(MOC_SYM(hwAccelCtx) pCtx, data, dataLen)))
        goto exit;

    if (finished)
    {
        if (OK > ( status = CMS_envelopedDataFinalize(MOC_SYM(hwAccelCtx) pCtx)))
            goto exit;
    }

    if (OK > ( status = CMS_envelopedGetOutputData( pCtx, ppOutput, pOutputLen)))
        goto exit;

exit:
    return status;
}
