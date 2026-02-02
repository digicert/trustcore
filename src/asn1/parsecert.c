/*
 * parsecert.c
 *
 * X.509v3 Certificate Parser
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

/*------------------------------------------------------------------*/

#include "../common/moptions.h"

#ifndef __DISABLE_DIGICERT_CERTIFICATE_PARSING__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"

#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../common/memfile.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/debug_console.h"
#include "../common/sort.h"
#include "../crypto/crypto.h"
#include "../crypto/rsa.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#ifdef __ENABLE_DIGICERT_DSA__
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#endif
#include "../crypto/pubcrypto.h"
#include "../crypto/md5.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/ca_mgmt.h"
#include "../harness/harness.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/ASN1TreeWalker.h"
#include "../crypto/malgo_id.h"
#include "../crypto/pkcs1.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_pkcs1.h"
#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto/pubcrypto_data.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif
#endif

#ifdef __ENABLE_DIGICERT_CV_CERT__
#include "../crypto/cvcert.h"
#endif

/*------------------------------------------------------------------*/

#ifndef MAX_DNE_STRING_LENGTH
#define MAX_DNE_STRING_LENGTH       (128)
#endif

#ifndef MOCANA_MAX_MODULUS_SIZE
#define MOCANA_MAX_MODULUS_SIZE     (1024)
#endif

#define kCommonName                 (0x03)
#define kSerialNumber				(0x05)
#define kCountryName                (0x06)
#define kStateOrProvidenceName      (0x08)
#define kLocality                   (0x07)
#define kOrganizationName           (0x0a)
#define kOrganizationUnitName       (0x0b)

#define MAX_SUBNAME_COUNT           (16)

/*------------------------------------------------------------------*/

/* Internal structure */
typedef struct SubLabel
{
    ubyte oid[10];
    char *label;
    ubyte4 labelLen;
}SUB_LABEL;

/* Internal structure */
typedef struct SubName
{
    ubyte *oid;
    ubyte *name;
    ubyte4 nameLen;
}SUB_NAME;

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__
typedef enum
{
    CERT_OR_CSR_PARSING_STAGE_INIT,
    CERT_OR_CSR_PARSING_STAGE_VERSION,
    CERT_OR_CSR_PARSING_STAGE_SERIAL_NUMBER,
    CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM,
    CERT_OR_CSR_PARSING_STAGE_ISSUER,
    CERT_OR_CSR_PARSING_STAGE_VALIDITY,
    CERT_OR_CSR_PARSING_STAGE_SUBJECT,
    CERT_OR_CSR_PARSING_STAGE_SUBJECT_PUBLIC_KEY_INFO,
    CERT_OR_CSR_PARSING_STAGE_ATTRIBUTES,
    CERT_OR_CSR_PARSING_STAGE_EXTENSIONS,
    CERT_OR_CSR_PARSING_STAGE_SIGN,
    CERT_OR_CSR_PARSING_STAGE_DONE
} CertOrCsrParsingStage;

typedef struct
{
    CertOrCsrParsingStage stage;
    ubyte4 version;
    ubyte awaitingEnd;
    ubyte *currentOidPtr;
    ubyte4 currentOidLen;
    ubyte processingEKU;
    ubyte processingKeyUsage;
    ubyte subjectKeyIdentifier;
    ubyte authorityKeyIdentifier;
    ubyte secondSignature;
    ubyte isCsr;
} CertOrCsrParsingCtx;

#ifdef __ENABLE_DIGICERT_PQC__

/* names match up with cid_PQC_MLDSA44 to cid_SLHDSA_SHAKE_256F, ie 0x11 to 0x1f */
const ubyte *pqcName[] = {"mldsa_44", "mldsa_65", "mldsa_87",
                            "slhdsa_sha2_128s", "slhdsa_sha2_128f", "slhdsa_shake_128s", "slhdsa_shake_128f",
                            "slhdsa_sha2_192s", "slhdsa_sha2_192f", "slhdsa_shake_192s", "slhdsa_shake_192f",
                            "slhdsa_sha2_256s", "slhdsa_sha2_256f", "slhdsa_shake_256s", "slhdsa_shake_256f" };

/* Names match with order of composite OIDs with last byte 60 to 75 */
const ubyte *pqcHybridName[] = {"mldsa44_rsa2048_pss", "mldsa44_rsa2048_pkcs15", "mldsa44_ed25519", "mldsa44_ecdsa_p256",
                                "mldsa65_rsa3072_pss", "mldsa65_rsa3072_pkcs15", "mldsa65_rsa4096_pss", "mldsa65_rsa4096_pkcs15",
                                "mldsa65_ecdsa_p256", "mldsa65_ecdsa_p384", "not available", "mldsa65_ed25519",
                                "mldsa87_ecdsa_p384", "not available", "mldsa87_ed448", "mldsa87_rsa4096_pss" };

#define PQC_COMPOSITE_FIRST_OID_BYTE 60
#define PQC_COMPOSITE_LAST_OID_BYTE 75
#endif
#endif /* __ENABLE_DIGICERT_CERTIFICATE_PRINT__ */

/*------------------------------------------------------------------*/

/* routines to navigate to specific parts of the certificate */
static MSTATUS X509_getTimeElementValue( const ubyte* buffer, ubyte* value,
                                   ubyte min, ubyte max);
static MSTATUS X509_getCertOID( ASN1_ITEMPTR pAlgoId, CStream s,
                               const ubyte* whichOID, ubyte* whichOIDSubType,
                               ASN1_ITEMPTR *ppOID);
static MSTATUS X509_checkForUnknownCriticalExtensions(ASN1_ITEMPTR pExtensionsSeq,
                                                      CStream s);



/*------------------------------------------------------------------*/

extern MSTATUS
X509_parseCertificate(CStream s, ASN1_ITEM** ppRootItem)
{
    MSTATUS status = OK;
    ASN1_ITEM* pRoot = NULL;
    ASN1_ITEMPTR pCert = NULL;

    status = ASN1_Parse(s, &pRoot);
    if (OK != status)
    {
        goto exit;
    }

    pCert = ASN1_FIRST_CHILD(pRoot);
    if (!pCert || pCert->id  != (UNIVERSAL|CONSTRUCTED) || pCert->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    *ppRootItem = pRoot;

exit:
    if (OK != status && pRoot)
    {
        TREE_DeleteTreeItem((TreeItem*) pRoot);
    }

    return status;
}

extern MSTATUS
X509_getCertExtension(ASN1_ITEMPTR pExtensionsSeq, CStream s,
                      const ubyte* whichOID, intBoolean* critical,
                      ASN1_ITEMPTR* ppExtension)
{
    ASN1_ITEMPTR  pOID;
    MSTATUS     status;

    if ((NULL == pExtensionsSeq) || (NULL == whichOID) ||
    (NULL == critical) || (NULL == ppExtension))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *critical = 0;
    *ppExtension = 0;

    status = ASN1_GetChildWithOID( pExtensionsSeq, s, whichOID, &pOID);
    if (OK > status )
        goto exit;

    if (pOID)
    {
        /* Extension ::= SEQUENCE {
                extnId     EXTENSION.&id({ExtensionSet}),
                critical   BOOLEAN DEFAULT FALSE,
                extnValue  OCTET STRING }  */
        ASN1_ITEMPTR pSibling = ASN1_NEXT_SIBLING( pOID);

        status = ERR_CERT_INVALID_STRUCT;

        if (NULL == pSibling || UNIVERSAL != (pSibling->id & CLASS_MASK ))
            goto exit;

        if ( BOOLEAN == pSibling->tag)
        {
            *critical = pSibling->data.m_boolVal;
            pSibling = ASN1_NEXT_SIBLING(pSibling);
            if ( NULL == pSibling || UNIVERSAL != (pSibling->id & CLASS_MASK ))
                goto exit;
        }

        if (OCTETSTRING != pSibling->tag || !pSibling->encapsulates)
            goto exit;

        *ppExtension = ASN1_FIRST_CHILD(pSibling);

        if ( 0 == *ppExtension)
            goto exit;
    }

    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
X509_getTimeElementValue( const ubyte* buffer, ubyte* value,
                         ubyte min, ubyte max)
{
    sbyte4     i;
    ubyte2  temp = 0;
    MSTATUS status = ERR_CERT_INVALID_STRUCT;

    *value = 0;
    for (i = 0; i < 2; ++i)
    {
        if ((buffer[i] < '0') || (buffer[i] > '9'))
            goto exit;

        temp *= 10;
        temp = (ubyte2)(temp + (buffer[i] - '0'));
    }

    if (temp < (ubyte2) min || temp > (ubyte2)max)
        goto exit;

    *value = (ubyte) temp;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertTime(ASN1_ITEMPTR pTime, CStream s, TimeDate* pGMTTime)
{
    const ubyte*    buffer = 0;
    sbyte4          i;
    const ubyte*    rest;
    ubyte           ub;
    MSTATUS         status;

    if (NULL == s.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    buffer = (const ubyte*) CS_memaccess(s, (/*FSL*/sbyte4)pTime->dataOffset,
                          (/*FSL*/sbyte4)pTime->length);

    if (0 == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    switch ( pTime->tag)
    {
        case UTCTIME:
            if ( pTime->length != 13)
            {
                status = ERR_CERT_INVALID_STRUCT;
                goto exit;
            }

            pGMTTime->m_year = 0;

            status = X509_getTimeElementValue( buffer, &ub, 0, 99);
            if ( OK > status)
            {
                goto exit;
            }

            pGMTTime->m_year = ub;
            if ( pGMTTime->m_year < 50)  /* 21st century */
            {
                pGMTTime->m_year += 30;
            }
            else if ( pGMTTime->m_year >= 70) /* 20th century */
            {
                pGMTTime->m_year -= 70;
            }
            else
            {
                /* refuse dates from 1950 to 1970 */
                status = ERR_CERT_INVALID_STRUCT;
                goto exit;
            }
            rest = buffer + 2;
            break;

        case GENERALIZEDTIME:
        {
            ubyte2  temp = 0;

            if (pTime->length != 15)
            {
                status = ERR_CERT_INVALID_STRUCT;
                goto exit;
            }

            for (i = 0; i < 4; ++i)
            {
                if ( buffer[i] < '0' || buffer[i] > '9')
                {
                    status = ERR_CERT_INVALID_STRUCT;
                    goto exit;
                }
                temp *= 10;
                temp = (ubyte2)(temp + (buffer[i] - '0'));
            }
            if ( temp >= 1970)
            {
                pGMTTime->m_year = (ubyte2)(temp - 1970);
            }
            else
            {
                /* refuse dates earlier than 1970 */
                status = ERR_CERT_INVALID_STRUCT;
                goto exit;
            }
            rest = buffer + 4;
            break;
        }

        default:
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
    }

    /* read the rest: 10 bytes */
    /* month */
    status = X509_getTimeElementValue( rest, &pGMTTime->m_month, 1, 12);
    if ( OK > status)
    {
        goto exit;
    }
    rest += 2;

    /* day */
    status = X509_getTimeElementValue( rest, &pGMTTime->m_day, 1, 31);
    if ( OK > status)
    {
        goto exit;
    }
    rest += 2;

    /* hour */
    status = X509_getTimeElementValue( rest, &pGMTTime->m_hour, 0, 23);
    if ( OK > status)
    {
        goto exit;
    }
    rest += 2;

    /* minute */
    status = X509_getTimeElementValue( rest, &pGMTTime->m_minute, 0, 59);
    if ( OK > status)
    {
        goto exit;
    }
    rest += 2;

    /* second */
    status = X509_getTimeElementValue( rest, &pGMTTime->m_second, 0, 59);

exit:

    if (buffer)
    {
        CS_stopaccess(s, buffer);
    }

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS X509_getCertOIDHybrid(ASN1_ITEMPTR pAlgoId, CStream s, ubyte4 *pClAlg, ubyte4 *pQsAlg)

{
    ASN1_ITEMPTR pOID = NULL;
    MSTATUS status = OK;
    ubyte *pOidBuffer = NULL;

    status = ERR_CERT_INVALID_STRUCT;
    if ((NULL == pAlgoId) ||
        ((pAlgoId->id & CLASS_MASK) != UNIVERSAL) ||
        (pAlgoId->tag != SEQUENCE))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD( pAlgoId);
    if (NULL == pOID ||
        ( (pOID->id & CLASS_MASK) != UNIVERSAL) ||
        (pOID->tag != OID) )
    {
        goto exit;
    }

    if (0 == pOID->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the OID */
    pOidBuffer = (ubyte*) CS_memaccess( s, pOID->dataOffset, pOID->length);
    if (!pOidBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* compare OIDs */
    status = CRYPTO_getHybridCurveAlgoFromOID(pOidBuffer, pOID->length, pClAlg, pQsAlg);
    if (OK != status)
    {
        status = ERR_CERT_NOT_EXPECTED_OID; /* change back to general status as we're not yet certain this is a hybrid cert */
    }

exit:

    if (pOidBuffer)
    {
        CS_stopaccess(s, pOidBuffer);
    }

    return status;
}

static MSTATUS X509_getCertOIDqs(ASN1_ITEMPTR pAlgoId, CStream s, ubyte4 *pQsAlg)
{
    ASN1_ITEMPTR pOID = NULL;
    MSTATUS status = OK;
    ubyte *pOidBuffer = NULL;

    status = ERR_CERT_INVALID_STRUCT;
    if ((NULL == pAlgoId) ||
        ((pAlgoId->id & CLASS_MASK) != UNIVERSAL) ||
        (pAlgoId->tag != SEQUENCE))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD( pAlgoId);
    if (NULL == pOID ||
        ( (pOID->id & CLASS_MASK) != UNIVERSAL) ||
        (pOID->tag != OID) )
    {
        goto exit;
    }

    if (0 == pOID->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the OID */
    pOidBuffer = (ubyte*) CS_memaccess( s, pOID->dataOffset, pOID->length);
    if (!pOidBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* compare OIDs */
    status = CRYPTO_getQsAlgoFromOID(pOidBuffer, pOID->length, pQsAlg);
    if (OK != status)
    {
        status = ERR_CERT_NOT_EXPECTED_OID; /* change back to general status as we're not yet certain this is a qs cert */
    }

exit:

    if (pOidBuffer)
    {
        CS_stopaccess(s, pOidBuffer);
    }

    return status;
}
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertOID(ASN1_ITEMPTR pAlgoId, CStream s, const ubyte* whichOID,
                ubyte* whichOIDSubType, ASN1_ITEMPTR* ppOID)
{
    ASN1_ITEMPTR  pOID;
    ubyte4      i;
    ubyte4      oidLen;
    ubyte       digit;
    MSTATUS     status;

    /* whichOIDSubType and ppOID can be null */
    if ( NULL == whichOID)
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

    pOID = ASN1_FIRST_CHILD( pAlgoId);
    if (NULL == pOID ||
        ( (pOID->id & CLASS_MASK) != UNIVERSAL) ||
        (pOID->tag != OID) )
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
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertSignAlgoType(ASN1_ITEMPTR pSignAlgoId, CStream s,
                    ubyte4* hashType, ubyte4* pubKeyType)
{
    return X509_getCertSignAlgoTypeEx(pSignAlgoId, s, hashType, pubKeyType, NULL, NULL);
}


/*------------------------------------------------------------------*/


extern MSTATUS
X509_getCertSignAlgoTypeEx(ASN1_ITEMPTR pSignAlgoId, CStream s,
    ubyte4* hashType, ubyte4* pubKeyType, ubyte4* pClType, ubyte4 *pQsAlg)
{
    ubyte    subType;
    MSTATUS  status;

    *hashType = 0;
    *pubKeyType = 0;

    if (NULL != pClType)
        *pClType = 0;

#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pQsAlg)
        *pQsAlg = 0;
#else
    MOC_UNUSED(pQsAlg);
#endif

    status = X509_getCertOID( pSignAlgoId, s, pkcs1_OID, &subType, NULL);
    if ( OK <= status)
    {
        *hashType = subType;
        *pubKeyType = akt_rsa;
    }
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s,
                                              sha1withRsaSignature_OID,
                                              NULL, NULL)))
    {
        /* sha1withRSAEncryption_OID sub-type  */
        *hashType = sha1withRSAEncryption;
        *pubKeyType = akt_rsa;
    }
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, dsaWithSHA2_OID,
                                              &subType, NULL)))
    {
        *pubKeyType = akt_dsa;
        switch (subType)
        {
#ifndef __DISABLE_DIGICERT_SHA224__
        case 1:
            *hashType = ht_sha224;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case 2:
            *hashType = ht_sha256;
            break;
#endif
        /* DSA has same prefix as pure QS (ending in 17, 18 or 19), hence don't error */
#ifdef __ENABLE_DIGICERT_PQC__
        case 17:
        case 18:
        case 19:
            status = ERR_CERT_NOT_EXPECTED_OID;
            break;
#endif
        default:
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            break;
        }
    }
#if (defined(__ENABLE_DIGICERT_DSA__))
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, dsaWithSHA1_OID, NULL, NULL)))
    {
        *hashType = ht_sha1;
        *pubKeyType = akt_dsa;
    }
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, dsaWithSHA256_OID,
                                              &subType, NULL)))
    {
        *pubKeyType = akt_dsa;
        switch (subType)
        {
#ifndef __DISABLE_DIGICERT_SHA224__
        case 1:
            *hashType = ht_sha224;
            break;
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
        case 2:
            *hashType = ht_sha256;
            break;
#endif
       default:
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            break;
        }
    }
#endif  /* defined(__ENABLE_DIGICERT_DSA__ */
#if (defined(__ENABLE_DIGICERT_ECC__))
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, ecdsaWithSHA1_OID,
                                              NULL, NULL)))
    {
        *hashType = ht_sha1;
        *pubKeyType = akt_ecc;
    }
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, ecdsaWithSHA2_OID,
                                               &subType, NULL)))
    {
       *pubKeyType = akt_ecc;
        switch (subType)
        {
#ifndef __DISABLE_DIGICERT_SHA224__
        case 1:
            *hashType = ht_sha224;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case 2:
            *hashType = ht_sha256;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case 3:
            *hashType = ht_sha384;
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case 4:
            *hashType = ht_sha512;
            break;
#endif
        default:
            status = ERR_CERT_UNSUPPORTED_SIGNATURE_ALGO;
            break;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, ed25519sig_OID,
                                               NULL, NULL)))
    {
        *pubKeyType = akt_ecc_ed;
        *hashType = ht_none;
        if (NULL != pClType)
        {
           *pClType = cid_EC_Ed25519;
        }
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    else if ( OK <= (status = X509_getCertOID( pSignAlgoId, s, ed448sig_OID,
                                               NULL, NULL)))
    {
        *pubKeyType = akt_ecc_ed;
        *hashType = ht_none;
        if (NULL != pClType)
        {
           *pClType = cid_EC_Ed448;
        }
    }
#endif
#endif  /* defined(__ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
    else if ( OK <= (status = X509_getCertOIDHybrid(pSignAlgoId, s, pClType, pQsAlg)))
    {
        *pubKeyType = akt_hybrid;
        *hashType = ht_none; /* Hash is done in composite sign/verify APIs. Treat the hash as intrinsic. */
        /* pClType and pQsAlg set in above call */
    }
    
    /* do as an if rather than if else since we (may) have fallen into the DSA if statement above */
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        status = X509_getCertOIDqs(pSignAlgoId, s, pQsAlg);
        if (OK == status)
        {
            *pubKeyType = akt_qs;
            *hashType = ht_none; /* Must be ht_none so message does not get digested */
            /* pQsAlg set in above call */ 
        }
    }
#endif

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
X509_checkForUnknownCriticalExtensions(ASN1_ITEMPTR pExtensionsSeq, CStream s)
{
    static WalkerStep gotoExtensionOID[] =
    {
        { VerifyType, SEQUENCE, 0},
        { GoFirstChild, 0, 0},
        { VerifyType, OID, 0 },
        { Complete, 0, 0}
    };

    static const ubyte* knownExtensions[] =
    {
        basicConstraints_OID,
        keyUsage_OID,
        nameConstraints_OID,
        extendedKeyUsage_OID,
        subjectAltName_OID
    };

    ASN1_ITEMPTR pExtension;

    if ( NULL == pExtensionsSeq)
    {
        return ERR_NULL_POINTER;
    }

    pExtension = ASN1_FIRST_CHILD( pExtensionsSeq);
    while (pExtension)
    {
        ASN1_ITEMPTR pOID;
        ASN1_ITEMPTR pCritical;

        if (OK > ASN1_WalkTree( pExtension, s, gotoExtensionOID, &pOID))
        {
            return ERR_CERT_INVALID_STRUCT;
        }

        pCritical = ASN1_NEXT_SIBLING( pOID);
        /* pCritical is OPTIONAL and FALSE by default, check type */
        if ( OK == ASN1_VerifyType( pCritical, BOOLEAN) &&
         pCritical->data.m_boolVal)
        {
            /* critical extension -> look for OID we checks */
            ubyte4 i;
            for (i = 0; i < COUNTOF(knownExtensions); ++i)
            {
                if ( OK == ASN1_VerifyOID( pOID, s, knownExtensions[i]))
                {
                    break; /* found */
                }
            }

            /* found ? */
            if ( i >= COUNTOF( knownExtensions))
            {
                return ERR_CERT_UNKNOWN_CRITICAL_EXTENSION;
            }
        }

        pExtension = ASN1_NEXT_SIBLING( pExtension);
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_checkCertificateIssuerSerialNumber( ASN1_ITEMPTR pIssuer,
                                        ASN1_ITEMPTR pSerialNumber,
                                        CStream pIssuerStream,
                                        ASN1_ITEMPTR pCertificate,
                                        CStream pCertStream)
{
    ASN1_ITEMPTR pVersion;
    ASN1_ITEMPTR pCertIssuer;
    ASN1_ITEMPTR pCertSerialNumber;
    ASN1_ITEMPTR pTBSCertificate;
    MSTATUS status;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }
    /* need to see if there is the optional version (tag 0) */
    if (OK > (status = ASN1_GetChildWithTag(pTBSCertificate, 0, &pVersion)))
    {
        return status;
    }

    /* serial number is first or second child */
    if (OK > (status = ASN1_GetNthChild( pTBSCertificate, (pVersion) ? 2 : 1, &pCertSerialNumber)))
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    /* issuer is 3rd or 4th child */
    if (OK > (status = ASN1_GetNthChild( pTBSCertificate, (pVersion) ? 4 : 3, &pCertIssuer)))
    {
        return ERR_CERT_INVALID_STRUCT;
    }
    /* compare serial number if provided */
    if (pSerialNumber)
    {
        if ( OK > (status = ASN1_CompareItems(pCertSerialNumber, pCertStream,
                                              pSerialNumber, pIssuerStream)))
        {
            return status;
        }
    }

    return ASN1_CompareItems( pCertIssuer, pCertStream, pIssuer, pIssuerStream);
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertificateSubject( ASN1_ITEMPTR pCertificate, ASN1_ITEMPTR* ppSubject)
{
    ASN1_ITEMPTR pVersion;
    ASN1_ITEMPTR pTBSCertificate;
    MSTATUS status;

    if ( NULL == pCertificate)
        return ERR_NULL_POINTER;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    /* need to see if there is the optional version (tag 0) */
    if (OK > (status = ASN1_GetChildWithTag(pTBSCertificate, 0, &pVersion)))
    {
        return status;
    }

    /* subject is 5th or 6th child */
    if ( ppSubject)
    {
        if (OK > ASN1_GetNthChild( pTBSCertificate, (pVersion) ? 6 : 5, ppSubject))
        {
            return ERR_CERT_INVALID_STRUCT;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertificateIssuerSerialNumber( ASN1_ITEMPTR pCertificate,
                                      ASN1_ITEMPTR* ppIssuer,
                                      ASN1_ITEMPTR* ppSerialNumber)
{
    ASN1_ITEMPTR pVersion;
    ASN1_ITEMPTR pTBSCertificate = NULL;
    MSTATUS status;

    if ( NULL == pCertificate)
        return ERR_NULL_POINTER;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    /* need to see if there is the optional version (tag 0) */
    if (OK > (status = ASN1_GetChildWithTag(pTBSCertificate, 0, &pVersion)))
    {
        return status;
    }

    /* serial number is first or second child */
    if ( ppSerialNumber)
    {
        if (OK > ASN1_GetNthChild( pTBSCertificate, (pVersion) ? 2 : 1, ppSerialNumber))
        {
            return ERR_CERT_INVALID_STRUCT;
        }
    }

    /* issuer is 3rd or 4th child */
    if ( ppIssuer)
    {
        if (OK > ASN1_GetNthChild( pTBSCertificate, (pVersion) ? 4 : 3, ppIssuer))
        {
            return ERR_CERT_INVALID_STRUCT;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_checkCertificateIssuer(ASN1_ITEMPTR pParentCertificate,
                            CStream pParentCertStream,
                            ASN1_ITEMPTR pCertificate,
                            CStream pCertStream)
{
    /* compare issuer of prev certificate with subject of certificate */
    MSTATUS status;
    ASN1_ITEMPTR pSubject;

    if ( OK > (status = X509_getCertificateSubject(pCertificate, &pSubject)))
    {
        return status;
    }

    status = X509_checkCertificateIssuerSerialNumber( pSubject, NULL,
                                                     pCertStream,
                                                     pParentCertificate,
                                                     pParentCertStream);

    if (ERR_FALSE == status)
    {
        status = ERR_CERT_INVALID_PARENT_CERTIFICATE;
    }

    return status;
}


/*------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_RSA__
extern MSTATUS
X509_extractRSAKey(MOC_RSA(hwAccelDescr hwAccelCtx)
             ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey* pKey)
{
    ubyte4          i;
    sbyte4          startModulus;
    ubyte4          exponent, modulusLen;
    const ubyte*    modulus = 0;
    ubyte           rsaAlgoIdSubType;
    ASN1_ITEMPTR    pItem;
    MSTATUS         status;
    MAlgoId*        pAlgoId = NULL;

    pItem = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pItem)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for PKCS#1 */
    if (OK > (status = X509_getCertOID( pItem, s, pkcs1_OID,
                                       &rsaAlgoIdSubType, NULL)))
    {
        goto exit;
    }

    if (rsaEncryption == rsaAlgoIdSubType)
    {
        status = ALG_ID_deserialize(ALG_ID_RSA_ENC_OID, pItem, s, &pAlgoId);
    }
    else if (rsaSsaPss == rsaAlgoIdSubType)
    {
        status = ALG_ID_deserialize(ALG_ID_RSA_SSA_PSS_OID, pItem, s, &pAlgoId);
    }
    else
    {
        status = ERR_CERT_NOT_EXPECTED_OID;
    }
    if (OK != status)
    {
        goto exit;
    }

    /* the public key is in a bit string that encapsulates a PKCS struct */
    pItem = ASN1_NEXT_SIBLING( pItem);

    if ( NULL == pItem ||
            (pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != BITSTRING ||
            0 == pItem->encapsulates)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* extract the key parameters */
    pItem = ASN1_FIRST_CHILD( pItem);
    /* according to pkcs1-v2-1.asn the public key is a sequence of two integers
    the modulus and then the public exponent */
    if ( NULL == pItem ||
            (pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* modulus */
    pItem = ASN1_FIRST_CHILD( pItem);
    if ( NULL == pItem ||
            (pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != INTEGER)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    modulusLen = pItem->length;

    if (0 == modulusLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    modulus = (const ubyte*) CS_memaccess( s, pItem->dataOffset, pItem->length);
    if ( NULL == modulus)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* ASN1 INTEGERs are signed so it's possible 0x00 are added to make sure the
     value is represented as positive so check for that */
    startModulus = 0;
    while ((startModulus < ((sbyte4)modulusLen)) && (0 == modulus[startModulus]))
    {
        ++startModulus;
    }

    /* we support only modulus up to 1024 (8192 bits) bytes long */
    if (MOCANA_MAX_MODULUS_SIZE < (modulusLen - startModulus) )
    {
        /* prevent parasitic public key attack */
        status = ERR_CERT_RSA_MODULUS_TOO_BIG;
        goto exit;
    }

    /* exponent */
    pItem = ASN1_NEXT_SIBLING( pItem);
    if (NULL == pItem ||
            (pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != INTEGER)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* we support only exponent up to 4 bytes long */
    if (pItem->length > (ubyte4)sizeof(exponent))
    {
        status = ERR_CERT_RSA_EXPONENT_TOO_BIG;
        goto exit;
    }

    CS_seek( s, pItem->dataOffset, MOCANA_SEEK_SET);

    exponent = 0;
    for (i = 0; i < pItem->length; ++i)
    {
        ubyte digit;

        if (OK > (status = CS_getc(s, &digit)))
            goto exit;

        exponent = ((exponent << 8) | digit);
    }

    status = CRYPTO_setRSAParameters( MOC_RSA(hwAccelCtx) pKey,
                                        exponent,
                                        (ubyte*) (modulus + startModulus),
                                        modulusLen - startModulus,
                                        NULL, 0, NULL, 0,
                                        NULL);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pAlgoId)
    {
        status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
        if (OK != status)
        {
            goto exit;
        }
    }

    pKey = NULL;

exit:
    if (modulus)
    {
        CS_stopaccess(s, modulus);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
extern MSTATUS
X509_extractECCKey(MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey* pKey)
{
    ubyte           curveId;
    ASN1_ITEMPTR    pAlgorithmIdentifier, pTemp;
    const ubyte*    point = 0;
    MSTATUS         status;
    MAlgoId*        pAlgoId = NULL;

    pAlgorithmIdentifier = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pAlgorithmIdentifier)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for EC public Key */
    if (OK > (status = X509_getCertOID( pAlgorithmIdentifier, s, ecPublicKey_OID, NULL, &pTemp)))
    {
        goto exit;
    }

    /* make MAlgoId for AsymmetricKey */
    status = ALG_ID_deserialize(ALG_ID_EC_PUBLIC_KEY_OID, pAlgorithmIdentifier, s, &pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    /* get the OID for the Curve ( 2nd child of pItem) */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if ( 0 == pTemp)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* this should be one of the OID for the curves we support */
    status = ASN1_VerifyOIDRoot( pTemp, s, ansiX962CurvesPrime_OID, &curveId);
    if ( OK > status) /* try another ASN1 arc */
    {
        status = ASN1_VerifyOIDRoot( pTemp, s, certicomCurve_OID, &curveId);
    }

    if (OK > status)
    {
        goto exit;
    }

    /* then the public key is the content of the BIT string -- a point on the curve
    encoded in the usual way */
    pTemp = ASN1_NEXT_SIBLING( pAlgorithmIdentifier);
    if (!pTemp ||
        UNIVERSAL != (pTemp->id & CLASS_MASK) ||
        BITSTRING != pTemp->tag)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the BITSTRING */
    point = (const ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
    if (!point)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) pKey, curveId, point,
                                                pTemp->length, NULL, 0)))
    {
        goto exit;
    }

    if (NULL != pAlgoId)
    {
        status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
        if (OK != status)
        {
            goto exit;
        }
    }

    pKey = NULL;

exit:

    if (point)
    {
        CS_stopaccess( s, point);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
extern MSTATUS
X509_extractECCEdKey(MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey *pKey)
{
    ubyte4          curveId = cid_EC_Ed25519;
    ubyte4          algoIdFlag = ALG_ID_ECED_25519_OID;
    ASN1_ITEMPTR    pAlgorithmIdentifier, pTemp;
    const ubyte*    point = 0;
    MSTATUS         status = OK;
    MAlgoId*        pAlgoId = NULL;

    pAlgorithmIdentifier = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pAlgorithmIdentifier)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for EC public Key */
#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
    status = X509_getCertOID( pAlgorithmIdentifier, s, ed25519sig_OID, NULL, &pTemp);

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    if (ERR_CERT_NOT_EXPECTED_OID == status)
#else
    if (OK != status)
        goto exit;
#endif
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
    {
        status = X509_getCertOID( pAlgorithmIdentifier, s, ed448sig_OID, NULL, &pTemp);
        if (OK != status)
            goto exit;

        curveId = cid_EC_Ed448;
        algoIdFlag = ALG_ID_ECED_448_OID;
    }
#endif

    /* make MAlgoId for AsymmetricKey */
    status = ALG_ID_deserialize(algoIdFlag, pAlgorithmIdentifier, s, &pAlgoId);
    if (OK != status)
        goto exit;

    /* then the public key is the content of the BIT string -- a point on the curve
     encoded in the usual way */
    pTemp = ASN1_NEXT_SIBLING( pAlgorithmIdentifier);
    if (!pTemp ||
        UNIVERSAL != (pTemp->id & CLASS_MASK) ||
        BITSTRING != pTemp->tag)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the BITSTRING */
    point = (const ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
    if (!point)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_setECCParameters( MOC_ECC(hwAccelCtx) pKey, curveId, point,
                                               pTemp->length, NULL, 0)))
    {
        goto exit;
    }

    if (NULL != pAlgoId)
    {
        status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
        if (OK != status)
        {
            goto exit;
        }
    }
    pKey = NULL;

exit:

    if (point)
    {
        CS_stopaccess( s, point);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */

#ifdef __ENABLE_DIGICERT_PQC__
extern MSTATUS X509_extractHybridKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey* pKey)
{
    ASN1_ITEMPTR    pAlgorithmIdentifier, pTemp;
    const ubyte*    pPubKey = 0;
    MSTATUS         status;
    ubyte4          clAlg = 0;
    ubyte4          qsAlg = 0;

    pAlgorithmIdentifier = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pAlgorithmIdentifier)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for a hybrid Key */
    status = X509_getCertOIDHybrid(pAlgorithmIdentifier, s, &clAlg, &qsAlg);
    if (OK != status)
        goto exit;

    /* then the public key is the content of the BIT string -- a point on the curve
     encoded in the usual way followed by the QS point */
    pTemp = ASN1_NEXT_SIBLING( pAlgorithmIdentifier);
    if (!pTemp || UNIVERSAL != (pTemp->id & CLASS_MASK) || BITSTRING != pTemp->tag)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the BITSTRING */
    pPubKey = (const ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
    if (!pPubKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* Set the public key in the pKey */
    status = CRYPTO_setHybridParameters(MOC_ASYM(hwAccelCtx) pKey, clAlg, qsAlg, (ubyte *) pPubKey, (ubyte4) pTemp->length);
    if (OK != status)
        goto exit;

    /* all is good, set the pointer copy to NULL so we don't cleanup */
    pKey = NULL;

exit:

    if (pPubKey)
    {
        CS_stopaccess( s, pPubKey);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* __ENABLE_DIGICERT_ECC__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
extern MSTATUS X509_extractQsKey(MOC_ASYM(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey* pKey)
{
    ASN1_ITEMPTR    pAlgorithmIdentifier, pTemp;
    const ubyte*    pPubKey = 0;
    MSTATUS         status;
    ubyte4          qsAlg = 0;

    pAlgorithmIdentifier = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pAlgorithmIdentifier)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for a qs Key */
    status = X509_getCertOIDqs(pAlgorithmIdentifier, s, &qsAlg);
    if (OK != status)
        goto exit;

    /* then the public key is the content of the BIT string */
    pTemp = ASN1_NEXT_SIBLING( pAlgorithmIdentifier);
    if (!pTemp || UNIVERSAL != (pTemp->id & CLASS_MASK) || BITSTRING != pTemp->tag)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the BITSTRING */
    pPubKey = (const ubyte*) CS_memaccess( s, pTemp->dataOffset, pTemp->length);
    if (!pPubKey)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(hwAccelCtx) &(pKey->pQsCtx), qsAlg);
    if (OK != status)
        goto exit;

    pKey->type = akt_qs;
    status = CRYPTO_INTERFACE_QS_setPublicKey(pKey->pQsCtx, (ubyte *) pPubKey, pTemp->length);
    if (OK != status)
        goto exit;

    /* all is good, set the pointer copy to NULL so we don't cleanup */
    pKey = NULL;

exit:

    if (pPubKey)
    {
        CS_stopaccess( s, pPubKey);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
X509_extractDSAKey(MOC_DSA(hwAccelDescr hwAccelCtx)
                   ASN1_ITEMPTR pSubjectKeyInfo, CStream s, AsymmetricKey* pKey)
{
    ASN1_ITEMPTR    pAlgorithmIdentifier, pTemp;
    ASN1_ITEMPTR    pRoot = 0;
    MSTATUS         status;
    const ubyte     *p = 0,
                    *q = 0,
                    *g = 0,
                    *bitStr = 0;
    ubyte4 pLen, qLen, gLen;
    CStream s2;
    MemFile mf;
    MAlgoId*        pAlgoId = NULL;

/*
    DSAPublicKey ::= INTEGER  -- public key, y

    Dss-Parms  ::=  SEQUENCE  {
      p             INTEGER,
      q             INTEGER,
      g             INTEGER  }
*/

    pAlgorithmIdentifier = ASN1_FIRST_CHILD(pSubjectKeyInfo);
    if ( 0 == pAlgorithmIdentifier)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* verify pItem is the OID for dsa */
    if (OK > (status = X509_getCertOID( pAlgorithmIdentifier, s, dsa_OID, NULL, &pTemp)))
    {
        goto exit;
    }

    /* make MAlgoId for AsymmetricKey */
    status = ALG_ID_deserialize(ALG_ID_DSA_OID, pAlgorithmIdentifier, s, &pAlgoId);
    if (OK != status)
    {
        goto exit;
    }

    /* next item is the sequence Dss-Parms */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if ( 0 == pTemp || OK > ASN1_VerifyType( pTemp, SEQUENCE))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* p */
    pTemp = ASN1_FIRST_CHILD( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    p = CS_memaccess( s, pTemp->dataOffset, pLen = pTemp->length);
    if (!p)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* q */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    q = CS_memaccess( s, pTemp->dataOffset, qLen = pTemp->length);
    if (!q)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* g */
    pTemp = ASN1_NEXT_SIBLING( pTemp);
    if (OK > ASN1_VerifyType( pTemp, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    
    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    g = CS_memaccess( s, pTemp->dataOffset, gLen = pTemp->length);
    if (!g)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* y -- public key is a INTEGER inside a bit string */
    pTemp = ASN1_NEXT_SIBLING(pAlgorithmIdentifier);
    if ( OK > ( ASN1_VerifyType( pTemp, BITSTRING)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pTemp->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    bitStr = CS_memaccess( s, pTemp->dataOffset, pTemp->length);
    if (!bitStr)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MF_attach( &mf, pTemp->length, (ubyte*)bitStr);
    CS_AttachMemFile( &s2, &mf);
    if (OK > ( status = ASN1_Parse( s2, &pRoot)))
        goto exit;

    pTemp = ASN1_FIRST_CHILD(pRoot);
    if ( OK > ( ASN1_VerifyType( pTemp, INTEGER)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (OK > (status = CRYPTO_setDSAParameters( MOC_DSA(hwAccelCtx)
                                                pKey, p, pLen, q, qLen,
                                                g, gLen,
                                                bitStr + pTemp->dataOffset,
                                                pTemp->length, NULL, 0, NULL)))
    {
        goto exit;
    }

    if (NULL != pAlgoId)
    {
        status = CRYPTO_loadAlgoId(pKey, (void**)&pAlgoId);
        if (OK != status)
        {
            goto exit;
        }
    }

    pKey = NULL;

exit:

    if (p)
    {
        CS_stopaccess( s, p);
    }
    if (q)
    {
        CS_stopaccess( s, q);
    }
    if (g)
    {
        CS_stopaccess( s, g);
    }
    if (bitStr)
    {
        CS_stopaccess( s, bitStr);
    }

    if (pRoot)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRoot);
    }

    CRYPTO_uninitAsymmetricKey(pKey, NULL);
    if (NULL != pAlgoId)
    {
        ALG_ID_free(&pAlgoId);
    }

    return status;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                    ASN1_ITEMPTR pCertificate, CStream s,
                                    AsymmetricKey* pPubKey)
{
    /* this is the structure of a certificate = Signed Certificate Object */
    /* Certificate Object */
        /* Version */
        /* Serial Number */
        /* Signature Algorithm */
        /* Issuer */
        /* Validity */
        /* Subject */
        /* Subject Public Key Info */
    /* Signature Algorithm */
    /* Signature */
    ASN1_ITEMPTR    pSubjectKeyInfo;
    ASN1_ITEMPTR    pVersion;
    ASN1_ITEMPTR    pTBSCertificate;
    MSTATUS         status;

    if (NULL == s.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    if ((NULL == pCertificate) || (NULL == pPubKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    if (OK > (status = ASN1_GetChildWithTag( pTBSCertificate, 0, &pVersion)))
        goto exit;

    if (OK > (status = ASN1_GetNthChild( pTBSCertificate, pVersion ? 7 : 6, &pSubjectKeyInfo)))
        goto exit;

    /* verify the type */
    if ((UNIVERSAL != (pSubjectKeyInfo->id & CLASS_MASK)) || (SEQUENCE != pSubjectKeyInfo->tag))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

#ifndef __DISABLE_DIGICERT_RSA__
    status = X509_extractRSAKey(MOC_RSA(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
#else
    status = ERR_CERT_NOT_EXPECTED_OID;
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        status = X509_extractDSAKey( MOC_DSA(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
    }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        /* not a RSA or DSA key -> try a prime curve ECC key */
        status = X509_extractECCKey( MOC_ECC(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
    }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        status = X509_extractECCEdKey( MOC_ECC(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
    }
#endif

#ifdef __ENABLE_DIGICERT_PQC__
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        status = X509_extractHybridKey( MOC_ASYM(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
    }
#endif

#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_DIGICERT_PQC__
    if (ERR_CERT_NOT_EXPECTED_OID == status)
    {
        status = X509_extractQsKey( MOC_ASYM(hwAccelCtx) pSubjectKeyInfo, s, pPubKey);
    }
#endif

exit:
    return status;

} /* X509_setKeyFromSubjectPublicKeyInfo */


/*---------------------------------------------------------------------------*/

extern MSTATUS
X509_extractVersion(ASN1_ITEMPTR pCertificate, sbyte4 *pRetVersion)
{
    ASN1_ITEMPTR  pTBSCertificate;
    ASN1_ITEMPTR  pVersion;
    MSTATUS     status;

    if ((NULL == pCertificate) || (NULL == pRetVersion))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetVersion = 0;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    if (OK > (status = ASN1_GetChildWithTag( pTBSCertificate, 0, &pVersion)))
        goto exit;

    if (pVersion)
    {
        if (UNIVERSAL == (pVersion->id & CLASS_MASK) &&
            pVersion->tag == INTEGER &&
            pVersion->length <= sizeof(sbyte4))
        {
            *pRetVersion = pVersion->data.m_intVal;
        }
    }

 exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getSubjectEntryByOID( ASN1_ITEMPTR pCertificate, CStream s,
                          const ubyte* oid, ASN1_ITEMPTR* ppEntryItem)
{
    ASN1_ITEMPTR  pSubject;
    ASN1_ITEMPTR  pCurrChild;
    MSTATUS     status;

    if (OK > ( status = X509_getCertificateSubject(pCertificate, &pSubject)))
    {
        goto exit;
    }

    /* now get the child with the passed-in OID */
    /*  Name ::= SEQUENCE of RelativeDistinguishedName
        RelativeDistinguishedName = MOC_SET of AttributeValueAssertion
        AttributeValueAssertion = SEQUENCE { attributeType OID; attributeValue ANY }
    */

    /* Name is a sequence */
    if ( NULL == pSubject ||
            (pSubject->id & CLASS_MASK) != UNIVERSAL ||
            pSubject->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pCurrChild = ASN1_FIRST_CHILD( pSubject);

    while (pCurrChild)
    {
        ASN1_ITEMPTR pGrandChild;
        ASN1_ITEMPTR pOID;

        status = ERR_CERT_INVALID_STRUCT;

        /* child should be a MOC_SET */
        if ( (pCurrChild->id & CLASS_MASK) != UNIVERSAL ||
                pCurrChild->tag != MOC_SET)
        {
            goto exit;
        }

        /* GrandChild should be a SEQUENCE */
        pGrandChild = ASN1_FIRST_CHILD( pCurrChild);

        while (pGrandChild)
        {
            if ( NULL == pGrandChild ||
                 (pGrandChild->id & CLASS_MASK) != UNIVERSAL ||
                  pGrandChild->tag != SEQUENCE)
            {
                goto exit;
            }

            /* get the OID */
            pOID = ASN1_FIRST_CHILD(pGrandChild);
            if ( NULL == pOID ||
                (pOID->id & CLASS_MASK) != UNIVERSAL ||
                pOID->tag != OID )
            {
                goto exit;
            }

            /* is it the right OID ?*/
            if (OK == ASN1_VerifyOID(pOID, s, oid))
            {
                *ppEntryItem = ASN1_NEXT_SIBLING(pOID);

                status = ( *ppEntryItem) ? OK: ERR_CERT_INVALID_STRUCT;
                goto exit;
            }
            pGrandChild = ASN1_NEXT_SIBLING(pGrandChild);
        }

        pCurrChild = ASN1_NEXT_SIBLING( pCurrChild);
    }

    status = ERR_CERT_INVALID_STRUCT;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getEntryByOID( ASN1_ITEMPTR pInputItem, CStream s,
                    const ubyte* oid, ASN1_ITEMPTR* ppEntryItem)
{

    ASN1_ITEMPTR  pCurrChild;
    MSTATUS     status;

    /*  Name ::= SEQUENCE of RelativeDistinguishedName
     RelativeDistinguishedName = MOC_SET of AttributeValueAssertion
     AttributeValueAssertion = SEQUENCE { attributeType OID; attributeValue ANY }
     */

    /* Name is a sequence */
    if ( NULL == pInputItem || (pInputItem->id & CLASS_MASK) != UNIVERSAL ||
        pInputItem->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pCurrChild = ASN1_FIRST_CHILD(pInputItem);

    while (pCurrChild)
    {
        ASN1_ITEMPTR pGrandChild;
        ASN1_ITEMPTR pOID;

        status = ERR_CERT_INVALID_STRUCT;

        /* child should be a MOC_SET */
        if ( (pCurrChild->id & CLASS_MASK) != UNIVERSAL ||
            pCurrChild->tag != MOC_SET)
        {
            goto exit;
        }

        /* GrandChild should be a SEQUENCE */
        pGrandChild = ASN1_FIRST_CHILD( pCurrChild);

        while (pGrandChild)
        {
            if ( NULL == pGrandChild ||
                (pGrandChild->id & CLASS_MASK) != UNIVERSAL ||
                pGrandChild->tag != SEQUENCE)
            {
                goto exit;
            }

            /* get the OID */
            pOID = ASN1_FIRST_CHILD(pGrandChild);
            if ( NULL == pOID ||
                (pOID->id & CLASS_MASK) != UNIVERSAL ||
                pOID->tag != OID )
            {
                goto exit;
            }

            /* is it the right OID ?*/
            if (OK == ASN1_VerifyOID(pOID, s, oid))
            {
                *ppEntryItem = ASN1_NEXT_SIBLING(pOID);

                status = ( *ppEntryItem) ? OK: ERR_CERT_INVALID_STRUCT;
                goto exit;
            }
            pGrandChild = ASN1_NEXT_SIBLING(pGrandChild);
        }

        pCurrChild = ASN1_NEXT_SIBLING( pCurrChild);
    }

    status = ERR_CERT_INVALID_STRUCT;

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
X509_getSubjectCommonName( ASN1_ITEMPTR pCertificate, CStream s,
                          ASN1_ITEMPTR* ppCommonNameItem)
{
    return X509_getSubjectEntryByOID(pCertificate, s, commonName_OID,
                                     ppCommonNameItem);
}

/*------------------------------------------------------------------*/

static MSTATUS
X509_matchCommonNameSuffix( ASN1_ITEMPTR pCommonName, CStream s,
                            const sbyte* nameToMatch, ubyte4 flags)
{
    ubyte       ch;
    MSTATUS     status;
    ubyte4      index;
    ubyte4      nameToMatchLen;

    nameToMatchLen = DIGI_STRLEN( nameToMatch);

    CS_seek(s, pCommonName->dataOffset, MOCANA_SEEK_SET);

    /* the certificate common name is either a full name or
        wildcard "*.acme.com" */
    if ( OK > ( status = CS_getc( s, &ch)))
        goto exit;

     /* wild card matching */
    if ('*' == ch && (0 == (flags & matchFlagNoWildcard)))
    {
        /* match the smaller of the two */
        if ( nameToMatchLen < pCommonName->length - 1)
        {
            index = 0;
            CS_seek(s, pCommonName->length - nameToMatchLen - 1,
                    MOCANA_SEEK_CUR);
        }
        else
        {
            index = nameToMatchLen - pCommonName->length + 1;
        }
    }
    else if ( nameToMatchLen <= pCommonName->length)
    {
        /* match the end */
        index = 0;
        CS_seek(s, pCommonName->length - nameToMatchLen - 1, MOCANA_SEEK_CUR);
    }
    else
    {
        status = ERR_CERT_BAD_COMMON_NAME;
        goto exit;
    }

    if (flags & matchFlagDotSuffix)
    {
        sbyte4 dotIndex = CS_tell(s)-1;

        if (dotIndex < pCommonName->dataOffset)
        {
            status = ERR_CERT_BAD_COMMON_NAME;
            goto exit;
        }
        CS_seek(s, dotIndex, MOCANA_SEEK_SET);
        if ( OK > (status = CS_getc(s, &ch)))
            goto exit;
        if (ch != '.')
        {
            status = ERR_CERT_BAD_COMMON_NAME;
            goto exit;
        }
    }

    /* match */
    for (; index < nameToMatchLen; index++)
    {
        if (OK > (status = CS_getc(s, &ch)))
            goto exit;

        /* case insensitive comparison */
        ch = MTOLOWER(ch);

        if ((ubyte)MTOLOWER(nameToMatch[index]) != ch)
        {
            status = ERR_CERT_BAD_COMMON_NAME;
            goto exit;
        }
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS
X509_wild_cardMatch(sbyte* DNSName, ubyte4 DNSNameLen, sbyte* HostName,
                    ubyte4 flags)
{
    ubyte4   HostNameLen;
    ubyte4   i = 0;
    sbyte   *pHostName = HostName;
    sbyte   *pDNSName = DNSName;
    sbyte   *temp = NULL;
    sbyte   *dotCheck = NULL;

    HostNameLen = DIGI_STRLEN(HostName);

    if (NULL == DIGI_STRCHR(pDNSName, '*', DNSNameLen))
    {
        /* no wildcards present */
        if (DNSNameLen != HostNameLen)
            return (MSTATUS) -1;

        if (0 != DIGI_STRNICMP(pDNSName, pHostName, DNSNameLen))
            return (MSTATUS) -1;
        else
            return OK;
    }

    if (flags & noWildcardMatch)
        return (MSTATUS) -1;

    if (flags & matchFlagSuffix)
    {
        if (NULL == (pHostName = DIGI_STRCHR(pHostName, '.', HostNameLen)))
            return (MSTATUS) -1;
        if (NULL == (temp = DIGI_STRCHR(pDNSName, '.', DNSNameLen)))
            return (MSTATUS) -1;
        i = (ubyte4) (temp - pDNSName);
    }

    while((i < DNSNameLen) && (HostNameLen > (ubyte4)(pHostName - HostName)))
    {
        if (pDNSName[i] == '*')
        {
            if (DNSNameLen == (i+1))
            {
                if (NULL != DIGI_STRCHR(pHostName, '.', (HostNameLen - (ubyte4)(pHostName - HostName))))
                    return (MSTATUS) -1;
                else
                    return OK;
            }
            dotCheck = pHostName;
            while ((NULL != pHostName) && (NULL != (pHostName = DIGI_STRCHR(pHostName, pDNSName[i+1], (HostNameLen - (ubyte4)(pHostName - HostName))))))
            {
                if (NULL == (temp = DIGI_STRCHR((pDNSName+i+1), '*',(DNSNameLen - i - 1))))
                {
                    temp = pDNSName + DNSNameLen;
                }
                if (0 == DIGI_STRNICMP(pHostName, pDNSName+i+1, ((ubyte4)(temp-pDNSName) - i - 1)))
                {
                    if (NULL != DIGI_STRCHR(dotCheck, '.', (ubyte4)(pHostName - dotCheck)))
                        return (MSTATUS)-1;
                    i++;
                    break;
                }
                else
                {
                    pHostName++;
                }
            }

            if (i > DNSNameLen || pDNSName[i] == '*')
                return (MSTATUS)-1;
        }
        else if ( (NULL != pHostName) && (MTOLOWER(pDNSName[i]) == MTOLOWER(*pHostName)) )
        {
            i++;
            pHostName++;
            continue;
        }
        else
        {
            return (MSTATUS)-1;
        }
    }

    if (DNSNameLen == i &&  (HostNameLen >= ((ubyte4)(pHostName - HostName) + 1)))
    {
        return (MSTATUS) -1;
    }

    if ((DNSNameLen > i+1) && (HostNameLen == (ubyte4)(pHostName - HostName)))
        return (MSTATUS)-1;

    return OK;
}

/*------------------------------------------------------------------*/

static MSTATUS
X509_IPOctetStringToString(ubyte *pOctets, ubyte4 octetsLen, ubyte *pIP)
{
    MSTATUS status = OK;
    ubyte *pIter;
    ubyte4 i, numDigits;

    if (NULL == pOctets || NULL == pIP)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (4 != octetsLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    pIter = pIP;
    for (i = 0; i < octetsLen; i++)
    {
        DIGI_UTOA(pOctets[i], pIter, &numDigits);
        pIter += numDigits;
        *pIter++ = (i < octetsLen - 1) ? '.' : '\0';
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
X509_IPV6OctetStringToString(ubyte *pOctets, ubyte4 octetsLen, ubyte *pIP)
{
    MSTATUS status = OK;
    ubyte *pIter;
    ubyte4 i;

    if (NULL == pOctets || NULL == pIP)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (16 != octetsLen)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    pIter = pIP;
    for (i = 0; i < octetsLen; i += 2)
    {
        *pIter++ = returnHexDigit(pOctets[i] >> 4);
        *pIter++ = returnHexDigit(pOctets[i] & 0x0f);
        *pIter++ = returnHexDigit(pOctets[i+1] >> 4);
        *pIter++ = returnHexDigit(pOctets[i+1] & 0x0f);
        *pIter++ = (i < octetsLen - 2) ? ':' : '\0';
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS
X509_matchCommonName(ASN1_ITEMPTR pCommonName, CStream s,
                     const sbyte* nameToMatch, ubyte4 flags)
{
    MSTATUS     status;
    sbyte       DNSorIPName[256];
    ubyte       IPStr[40]; /* Large enough to hold IPv6 address */
    ubyte4      commonNameLengthTmp;
    ubyte4      tag;
    sbyte      *pCmp;

    DIGI_MEMSET((ubyte*)DNSorIPName, 0x00, 256);

    pCmp = DNSorIPName;
    if (pCommonName->length > 256 )
    {
        commonNameLengthTmp = 256;
    }
    else
        commonNameLengthTmp = pCommonName->length;

    CS_seek(s, pCommonName->dataOffset, MOCANA_SEEK_SET);
    if (OK > (status = (MSTATUS) CS_read(DNSorIPName, sizeof(ubyte), commonNameLengthTmp, s)))
        goto exit;

    status = ASN1_GetTag(pCommonName, &tag);
    /* If the tag is iPAddress and the provided name to match is not of length
     * 4 then assume the caller provided the nameToMatch as IP string, otherwise
     * assume the caller provided the nameToMatch as the raw hex IP values. */
    if (OK == status && 7 == tag && 4 < DIGI_STRLEN(nameToMatch))
    {
        /* For IPv4 Need exactly 4 octets, otherwise error out */
        if (4 == commonNameLengthTmp)
        {
            /* Convert octet string into C string */
            status = X509_IPOctetStringToString(
                (ubyte *) DNSorIPName, commonNameLengthTmp, IPStr);
            if (OK != status)
                goto exit;
        }
        else if (16 == commonNameLengthTmp) /* IPv6 */
        {
            /* Convert octet string into C string */
            status = X509_IPV6OctetStringToString(
                (ubyte *) DNSorIPName, commonNameLengthTmp, IPStr);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        pCmp = (sbyte *) IPStr;
        commonNameLengthTmp = DIGI_STRLEN((const sbyte *) IPStr);
    }

    if (OK != X509_wild_cardMatch(pCmp, commonNameLengthTmp,
                                (sbyte*)nameToMatch, flags))
    {
        status = ERR_CERT_BAD_COMMON_NAME;
        goto exit;
    }
    else
        status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_compSubjectAltNames(ASN1_ITEMPTR pCertificate, CStream s,
                         const sbyte* nameToMatch, ubyte4 tagMask)
{
    /* tag mask is used to limit comparison to names that have only the
        tags in the mask ex: 1<<2 as a mask makes sure only DNS names
        are used in the comparison

            subjectAltName EXTENSION ::= {
              SYNTAX         GeneralNames
              IDENTIFIED BY  id-ce-subjectAltName
            }

            GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

            GeneralName ::= CHOICE {
              otherName                  [0]  INSTANCE OF OTHER-NAME,
              rfc822Name                 [1]  IA5String,
              dNSName                    [2]  IA5String,
              x400Address                [3]  ORAddress,
              directoryName              [4]  Name,
              ediPartyName               [5]  EDIPartyName,
              uniformResourceIdentifier  [6]  IA5String,
              iPAddress                  [7]  OCTET STRING,
              registeredID               [8]  OBJECT IDENTIFIER
            }
    */

    ASN1_ITEMPTR  pExtensionsSeq;
    ASN1_ITEMPTR  pSubjectAltNames;
    ASN1_ITEMPTR  pGeneralName;
    MSTATUS     status = ERR_CERT_BAD_SUBJECT_NAME;
    intBoolean  critical;

    if ((NULL == pCertificate) || (NULL == nameToMatch))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = X509_getCertificateExtensions( pCertificate,
                                                      &pExtensionsSeq)))
    {
        goto exit;
    }

    if ( !pExtensionsSeq)
    {
        status = ERR_CERT_BAD_SUBJECT_NAME;
        goto exit;
    }

    if (OK > (status = X509_getCertExtension( pExtensionsSeq, s,
                                             subjectAltName_OID, &critical,
                                             &pSubjectAltNames)))
    {
        goto exit;
    }

    if ( !pSubjectAltNames)
    {
        status = ERR_CERT_BAD_SUBJECT_NAME;
        goto exit;
    }

    if  (OK > ( status = ASN1_VerifyType( pSubjectAltNames, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* pSubjectAltNames is a sequence of general names; filter out by tags
    and see if the name matches */
    pGeneralName = ASN1_FIRST_CHILD( pSubjectAltNames);
    while (pGeneralName)
    {
        ubyte4 tag;
        if ( OK > (status = ASN1_GetTag( pGeneralName, &tag)))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        if ( (1 << tag) & tagMask)
        {
            if ( OK == (status = X509_matchCommonName(pGeneralName, s,
                                                      nameToMatch, 0)))
            {
                goto exit;
            }
        }

        pGeneralName = ASN1_NEXT_SIBLING(pGeneralName);
    }

    status = ERR_CERT_BAD_SUBJECT_NAME;

exit:

    return status;

} /* X509_compSubjectAltNames */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_compSubjectCommonName(ASN1_ITEMPTR pCertificate, CStream s,
                           const sbyte* nameToMatch)
{
    ASN1_ITEMPTR    pCommonName;
    MSTATUS         status;

    if ((NULL == pCertificate) || (NULL == nameToMatch))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getSubjectEntryByOID( pCertificate, s,
                                                 commonName_OID, &pCommonName)))
    {
        goto exit;
    }

    status = X509_matchCommonName( pCommonName, s, nameToMatch, 0);

exit:

    return status;

} /* X509_compSubjectCommonName */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_compSubjectAltNamesEx(ASN1_ITEMPTR pCertificate, CStream s,
                           const CNMatchInfo* namesToMatch,
                           ubyte4 tagMask)
{
    /* tag mask is used to limit comparison to names that have only the
        tags in the mask ex: 1<<2 as a mask makes sure only DNS names
        are used in the comparison

            subjectAltName EXTENSION ::= {
              SYNTAX         GeneralNames
              IDENTIFIED BY  id-ce-subjectAltName
            }

            GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

            GeneralName ::= CHOICE {
              otherName                  [0]  INSTANCE OF OTHER-NAME,
              rfc822Name                 [1]  IA5String,
              dNSName                    [2]  IA5String,
              x400Address                [3]  ORAddress,
              directoryName              [4]  Name,
              ediPartyName               [5]  EDIPartyName,
              uniformResourceIdentifier  [6]  IA5String,
              iPAddress                  [7]  OCTET STRING,
              registeredID               [8]  OBJECT IDENTIFIER
            }
    */

    ASN1_ITEMPTR  pExtensionsSeq;
    ASN1_ITEMPTR  pSubjectAltNames;
    ASN1_ITEMPTR  pGeneralName;
    MSTATUS     status;
    intBoolean  critical;

    if ((NULL == pCertificate) || (NULL == namesToMatch))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = X509_getCertificateExtensions( pCertificate,
                                                      &pExtensionsSeq)))
    {
        goto exit;
    }

    if ( !pExtensionsSeq)
    {
        status = ERR_CERT_BAD_SUBJECT_NAME;
        goto exit;
    }

    if (OK > (status = X509_getCertExtension( pExtensionsSeq, s,
                                             subjectAltName_OID, &critical,
                                             &pSubjectAltNames)))
    {
        goto exit;
    }

    if ( !pSubjectAltNames)
    {
        status = ERR_CERT_BAD_SUBJECT_NAME;
        goto exit;
    }

    if  (OK > ( status = ASN1_VerifyType( pSubjectAltNames, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* pSubjectAltNames is a sequence of general names; filter out by tags
    and see if the name matches */
    pGeneralName = ASN1_FIRST_CHILD( pSubjectAltNames);
    while (pGeneralName)
    {
        ubyte4 tag;
        if ( OK > (status = ASN1_GetTag( pGeneralName, &tag)))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
        if ( (1 << tag) & tagMask)
        {
            const CNMatchInfo* tmp = namesToMatch;

            while ( tmp->name)
            {
                if ( tmp->flags & matchFlagSuffix)
                {
                    status = X509_matchCommonNameSuffix( pGeneralName, s,
                                                        tmp->name, tmp->flags);
                }
                else
                {
                    status = X509_matchCommonName( pGeneralName, s,
                                                  tmp->name, tmp->flags);
                }
                if ( OK == status)
                {
                    goto exit;
                }
                tmp++;
            }
        }
        pGeneralName = ASN1_NEXT_SIBLING(pGeneralName);
    }

    status = ERR_CERT_BAD_SUBJECT_NAME;

exit:

    return status;

} /* CERT_CompSubjectAltNamesAux */


/*------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_MULTIPLE_COMMON_NAMES__)
extern MSTATUS
X509_compSubjectCommonNameEx(ASN1_ITEMPTR pCertificate, CStream s,
                             const CNMatchInfo* namesToMatch)
{
    ASN1_ITEMPTR  pCommonName;
    MSTATUS     status;

    if ((NULL == pCertificate) || (NULL == namesToMatch))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getSubjectEntryByOID( pCertificate, s,
                                                 commonName_OID,
                                                 &pCommonName)))
    {
        goto exit;
    }

    status = ERR_CERT_BAD_COMMON_NAME;

    while ( OK > status && namesToMatch->name)
    {
        if ( namesToMatch->flags & matchFlagSuffix)
        {
            status = X509_matchCommonNameSuffix( pCommonName, s,
                                                namesToMatch->name,
                                                namesToMatch->flags);
        }
        else
        {
            status = X509_matchCommonName( pCommonName, s,
                                          namesToMatch->name,
                                          namesToMatch->flags);
        }
        namesToMatch++;
    }

exit:

    return status;
}

#endif


/*------------------------------------------------------------------*/

extern MSTATUS
X509_matchName( struct ASN1_ITEM* pCertificate, CStream cs,
               const sbyte* nameToMatch)
{
    MSTATUS status;

    /* start with AltNames to comply with RFC 2818 */
    status = X509_compSubjectAltNames(pCertificate, cs, nameToMatch,
                                      ((1 << 2) | (1 << 6) | (1 << 7))); /* 1 << 2 for DNS
                                                                            1 << 6 for URI
                                                                            1 << 7 for IP  */

    if (OK > status)
    {
        status = X509_compSubjectCommonName(pCertificate, cs, nameToMatch);
    }
    if (OK > status)
    {
        goto exit;
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

/* Function which retrieves the data that was signed. This function will either
 * return a digest or full message depending on what algorithm identifier is
 * stored in the certificate signature.
 *
 *    Certificate  ::=  SEQUENCE  {
 *       tbsCertificate       TBSCertificate,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING  }
 *
 * This function will extract information from signatureAlgorithm and return
 * either an allocated digest or a reference to the data buffer. Check
 * pFreeBuffer for whether or not to free the data.
 */
static MSTATUS
X509_extractSignatureData(MOC_HASH(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pCertificate,
                            CStream s,
                            ubyte** ppHash,
                            sbyte4* hashLen,
                            ubyte4* hashType,
                            ubyte4* pubKeyType,
                            intBoolean *pFreeBuffer)
{
    MSTATUS status;
    ASN1_ITEMPTR pTBSCertificate = NULL;
    ASN1_ITEMPTR pSeqAlgoId;
    sbyte4 bytesToHash;
    const ubyte* buffer = 0;

    if ((NULL == pCertificate) || (NULL == ppHash) || (NULL == hashType) || (NULL == pubKeyType) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == s.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    /* get the algorithm identifier */
    /* algo id is the second child of signed */
    status = ASN1_GetNthChild( pCertificate, 2, &pSeqAlgoId);
    if (OK > status)
    {
        goto exit;
    }

    /* extract key type and digest type from the signature
     */
    status = X509_getCertSignAlgoType( pSeqAlgoId, s, hashType, pubKeyType);
    if ( OK > status)
    {
        goto exit;
    }

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    /* The tbsCertificate is the portion of the certificate that the signature
     * is calculated over. This portion gets a reference to the tbsCertificate
     * and the length of the tbsCertificate.
     */
    bytesToHash = pTBSCertificate->length + pTBSCertificate->headerSize;

    if (0 == bytesToHash)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    buffer = (const ubyte*) CS_memaccess( s,
                                          pTBSCertificate->dataOffset - pTBSCertificate->headerSize,
                                          bytesToHash);
    if ( 0 == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }

    /* For RSA PSS the APIs require the full message so return the reference
     * to the tbsCertificate. For the other algorithms the sign and verify APIs
     * will take in the digest of the tbsCertificate so digest the
     * tbsCertficate and return a reference to the digest.
     */

    if (rsaSsaPss != *hashType && ht_none != *hashType)
    {
        *pFreeBuffer = TRUE;
        if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE,
                                        TRUE, ppHash)))
        {
            goto exit;
        }

        status = CRYPTO_computeBufferHash( MOC_HASH( hwAccelCtx) buffer,
                                        bytesToHash,
                                        *ppHash,
                                        hashLen,
                                        *hashType);
    }
    else
    {
        *pFreeBuffer = FALSE;
        *ppHash = (ubyte *) buffer;
        *hashLen = bytesToHash;
    }

exit:

    if (buffer)
    {
        CS_stopaccess( s, buffer);
    }
    return status;

} /* X509_extractSignatureData */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertificateExtensions(ASN1_ITEMPTR pCertificate,
                              ASN1_ITEMPTR* ppExtensions)
{
    MSTATUS status;
    ASN1_ITEMPTR pTBSCertificate = NULL;
    ASN1_ITEMPTR pItem;

    if (NULL == pCertificate || NULL == ppExtensions)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppExtensions = NULL;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* version */
    status = ASN1_GetChildWithTag( pTBSCertificate, 0, &pItem);
    if ( OK > status)
    {
        goto exit;
    }

    if ( NULL == pItem) /* not found */
    {
        /* version 1 by default nothing to do*/
        goto exit;
    }

    if ((pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != INTEGER)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if ( 2 != pItem->data.m_intVal)  /*v3 = 2 */
    {
        goto exit;
    }

    /* version 3 -> look for the CONTEXT tag = 3 */
    status = ASN1_GetChildWithTag( pTBSCertificate, 3, &pItem);
    if ( OK > status)
    {
        goto exit;
    }

    if ( NULL == pItem) /* not found */
    {
        goto exit;
    }

    if ((pItem->id & CLASS_MASK) != UNIVERSAL ||
            pItem->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    *ppExtensions = pItem;

exit:
    return status;

} /* CERT_getCertificateExtensionsAux */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertificateKeyUsage(ASN1_ITEMPTR pCertificate,
                               CStream s, ASN1_ITEMPTR* ppKeyUsage)
{
    MSTATUS status;
    ASN1_ITEMPTR pExtensions;
    ASN1_ITEMPTR pExtension;
    intBoolean criticalExtension;

    if (!ppKeyUsage || !pCertificate )
        return ERR_NULL_POINTER;

    *ppKeyUsage = 0;

    if ( OK > (status = X509_getCertificateExtensions( pCertificate,
                                                      &pExtensions)))
    {
        return status;
    }

    if ( NULL == pExtensions)
    {
        return OK;
    }

    /* look for the child with the keyUsage OID */
    status = X509_getCertExtension( pExtensions, s, keyUsage_OID,
                                   &criticalExtension, &pExtension);
    if ( OK > status)
    {
        return status;
    }

    if ( !pExtension)
    {
        return OK;
    }

    /* retrieve the key usage extension */

    /* KeyUsage ::= BIT STRING {
     digitalSignature(0), nonRepudiation(1), keyEncipherment(2),
     dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6),
     encipherOnly(7), decipherOnly(8)}

     The bit string is represented with bit 0 first.
     Examples:
     Certificate Signing, Off-line CRL Signing, CRL Signing (06)  00000110
     Digital Signature, Non-Repudiation (c0)  11000000
     Digital Signature, Key Encipherment (a0) 10100000
     Digital Signature, Non-Repudiation, Certificate Signing,
     Off-line CRL Signing, CRL Signing (c6)   11000110
     Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing (86)
     10000110
     */

    if (  (pExtension->id & CLASS_MASK) != UNIVERSAL ||
        pExtension->tag != BITSTRING)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    *ppKeyUsage = pExtension;
    return OK;

}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getCertificateKeyUsageValue(ASN1_ITEMPTR pCertificate,
                                 CStream s, ubyte2* pValue)
{
    MSTATUS status;
    ASN1_ITEMPTR pKeyUsageExtension;
    ubyte b[2];
    ubyte4 len, i;

    if (!pValue || !pCertificate )
        return ERR_NULL_POINTER;

    *pValue = 0;

    /* get key usage extension if any */
    status = X509_getCertificateKeyUsage( pCertificate, s, &pKeyUsageExtension);
    if ( OK > status)
    {
        goto exit;
    }

    if ( !pKeyUsageExtension)
    {
        *pValue = 0xFFFF; /* all usage authorized */
        return OK;
    }

    if (0 == pKeyUsageExtension->length)
    {
        *pValue = 0;
        goto exit;
    }

    /* at most two bytes */
    len = (pKeyUsageExtension->length < 2) ? pKeyUsageExtension->length : 2;

    if (OK > (status = CS_seek(s, pKeyUsageExtension->dataOffset, MOCANA_SEEK_SET)))
    {
        goto exit;
    }

    /* read the data so it can be modified */
    if (OK > ( status = (MSTATUS) CS_read(b, 1, len, s)))
    {
        goto exit;
    }

    for (i = 0; i < len; ++i)
    {
        /* reverse the 8 bits using 32 bits */
        /* http://graphics.stanford.edu/~seander/bithacks.html#ReverseByteWith32Bits */
        b[i] = (ubyte)(((b[i] * 0x0802LU & 0x22110LU) | (b[i] * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16);
    }

    if (pKeyUsageExtension->data.m_unusedBits)
    {
        if (pKeyUsageExtension->data.m_unusedBits > 7)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        b[len-1] <<= pKeyUsageExtension->data.m_unusedBits;
        b[len-1] >>= pKeyUsageExtension->data.m_unusedBits;
    }

    *pValue = 0;
    for (i = 0; i < len; ++i)
    {
        *pValue |= (b[i] << (8*i));
    }

exit:

    return status;

}


/*------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__DISABLE_DIGICERT_RSA__)
extern MSTATUS
X509_decryptRSASignatureBufferEx(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey* pRSAKey,
                            const ubyte* pSignature, ubyte4 signatureLen,
                            ubyte hash[CERT_MAXDIGESTSIZE], sbyte4 *pHashLen,
                            ubyte4* rsaAlgoIdSubType, ubyte4 keyType)
{
    ubyte*       decrypt             = NULL;
    ubyte4       plainTextLen;
    sbyte4       cipherTextLen;
    ubyte4       digestLen = 0;
    MemFile      signatureFile;
    CStream      signatureFileStream;
    ubyte        digestSubType;
    vlong*       pVlongQueue = NULL;
    ASN1_ITEMPTR   pItem;
    ASN1_ITEMPTR   pDigest;
    ASN1_ITEMPTR   pAlgoId;
    ASN1_ITEMPTR   pDecryptedSignature = NULL;

    MSTATUS      status;

    if ((NULL == pSignature) || (NULL == hash) ||
        (NULL == pRSAKey) || (NULL == rsaAlgoIdSubType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, &cipherTextLen);
    if ( OK > status)
    {
        goto exit;
    }

    if (signatureLen != (ubyte4)cipherTextLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    if (10 > cipherTextLen)     /*!-!-!-! to prevent static analyzer warnings, maybe we should have a function to sanity check cipher len?  */
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    decrypt = (ubyte*) MALLOC( (/*FSL*/ubyte4)cipherTextLen);
    if (NULL == decrypt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey,
                                                  pSignature, decrypt, &plainTextLen,
                                                  &pVlongQueue, keyType);
    if ( OK > status )
    {
        goto exit;
    }

    /* decrypt: the first plainTextLen bytes contains a ASN.1 encoded sequence */

    MF_attach( &signatureFile, (/*FSL*/sbyte4)plainTextLen, decrypt);
    CS_AttachMemFile( &signatureFileStream, &signatureFile);

    status = ASN1_Parse( signatureFileStream, &pDecryptedSignature);
    if (OK > status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD( pDecryptedSignature);
    if ( 0 == pItem)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* we need to verify that the ASN1 DER is plainTextLen bytes long...
        to defeat the BleichenBacher technique of certificate forgery --
        RSA Signature Forgery (CVE-2006-4339)
    */
    if (pItem->headerSize + pItem->length != plainTextLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pAlgoId = ASN1_FIRST_CHILD( pItem);
    if ( 0 == pAlgoId)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* REVIEW: fix this so that GetCertOID is not called several times */
    /* the signature is a again a sequence with the first item a sequence
        with an OID */

    if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                        rsaDSI_OID, &digestSubType, NULL)))
    {
        /* convert digestSubType */
        switch (digestSubType)
        {
            case md2Digest:
                *rsaAlgoIdSubType = md2withRSAEncryption;
                digestLen = MD2_RESULT_SIZE;
                break;

            case md4Digest:
                *rsaAlgoIdSubType = md4withRSAEncryption;
                digestLen = MD4_RESULT_SIZE;
                break;

            case md5Digest:
                *rsaAlgoIdSubType = md5withRSAEncryption;
                digestLen = MD5_RESULT_SIZE;
                break;

            default:
                *rsaAlgoIdSubType = (ubyte4) -1;
                break;
        }
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha2_OID, &digestSubType, NULL)))
    {
        switch (digestSubType)
        {
        case sha224Digest:
            *rsaAlgoIdSubType = sha224withRSAEncryption;
            digestLen = SHA224_RESULT_SIZE;
            break;

        case sha256Digest:
            *rsaAlgoIdSubType = sha256withRSAEncryption;
            digestLen = SHA256_RESULT_SIZE;
            break;

        case sha384Digest:
            *rsaAlgoIdSubType = sha384withRSAEncryption;
            digestLen = SHA384_RESULT_SIZE;
            break;

        case sha512Digest:
            *rsaAlgoIdSubType = sha512withRSAEncryption;
            digestLen = SHA512_RESULT_SIZE;
            break;

        default:
            *rsaAlgoIdSubType = (ubyte4) -1;
            break;
        }
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha1_OID, NULL, NULL)))
    {
        *rsaAlgoIdSubType = sha1withRSAEncryption;
        digestLen = SHA1_RESULT_SIZE;
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha1withRsaSignature_OID,
                                             NULL, NULL)))
    {
        *rsaAlgoIdSubType = sha1withRSAEncryption;
        digestLen = SHA1_RESULT_SIZE;
    }
    else /* no match */
    {
        goto exit;
    }

    status = ASN1_GetNthChild( pItem, 2, &pDigest);
    if ( OK > status)
    {
        goto exit;
    }

    if (pDigest->length != digestLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    if ((plainTextLen - pDigest->dataOffset) != digestLen)
    {
        /* Prevent Bleichenbacher's RSA signature forgery */
        /* the hash should be right-justified in the signature buffer */
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    /* copy the Hash */
    DIGI_MEMSET( hash, 0, CERT_MAXDIGESTSIZE);
    DIGI_MEMCPY( hash, decrypt + pDigest->dataOffset, (/*FSL*/sbyte4)digestLen);
    *pHashLen = (/*FSL*/sbyte4)digestLen;

exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    if ( pDecryptedSignature)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDecryptedSignature);
    }

    if (decrypt)
    {
        FREE(decrypt);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */



#ifndef __DISABLE_DIGICERT_RSA__
extern MSTATUS
X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey* pRSAKey,
                            const ubyte* pSignature, ubyte4 signatureLen,
                            ubyte hash[CERT_MAXDIGESTSIZE], sbyte4 *pHashLen,
                            ubyte4* rsaAlgoIdSubType)
{
    ubyte*       decrypt             = NULL;
    ubyte4       plainTextLen;
    sbyte4       cipherTextLen;
    ubyte4       digestLen = 0;
    MemFile      signatureFile;
    CStream      signatureFileStream;
    ubyte        digestSubType;
    vlong*       pVlongQueue = NULL;
    ASN1_ITEMPTR   pItem;
    ASN1_ITEMPTR   pDigest;
    ASN1_ITEMPTR   pAlgoId;
    ASN1_ITEMPTR   pDecryptedSignature = NULL;

    MSTATUS      status;

    if ((NULL == pSignature) || (NULL == hash) ||
        (NULL == pRSAKey) || (NULL == rsaAlgoIdSubType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, &cipherTextLen);
    if ( OK > status)
    {
        goto exit;
    }

    if (signatureLen != (ubyte4)cipherTextLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    if (10 > cipherTextLen)     /*!-!-!-! to prevent static analyzer warnings, maybe we should have a function to sanity check cipher len?  */
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    decrypt = (ubyte*) MALLOC( (/*FSL*/ubyte4)cipherTextLen);
    if (NULL == decrypt)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = RSA_verifySignature(MOC_RSA(hwAccelCtx) pRSAKey, pSignature, decrypt, &plainTextLen, &pVlongQueue);
    if ( OK > status )
    {
        goto exit;
    }

    /* decrypt: the first plainTextLen bytes contains a ASN.1 encoded sequence */

    MF_attach( &signatureFile, (/*FSL*/sbyte4)plainTextLen, decrypt);
    CS_AttachMemFile( &signatureFileStream, &signatureFile);

    status = ASN1_Parse( signatureFileStream, &pDecryptedSignature);
    if (OK > status)
    {
        goto exit;
    }

    pItem = ASN1_FIRST_CHILD( pDecryptedSignature);
    if ( 0 == pItem)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    /* we need to verify that the ASN1 DER is plainTextLen bytes long...
        to defeat the BleichenBacher technique of certificate forgery --
        RSA Signature Forgery (CVE-2006-4339)
    */
    if (pItem->headerSize + pItem->length != plainTextLen)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pAlgoId = ASN1_FIRST_CHILD( pItem);
    if ( 0 == pAlgoId)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* REVIEW: fix this so that GetCertOID is not called several times */
    /* the signature is a again a sequence with the first item a sequence
        with an OID */

    if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                        rsaDSI_OID, &digestSubType, NULL)))
    {
        /* convert digestSubType */
        switch (digestSubType)
        {
            case md2Digest:
                *rsaAlgoIdSubType = md2withRSAEncryption;
                digestLen = MD2_RESULT_SIZE;
                break;

            case md4Digest:
                *rsaAlgoIdSubType = md4withRSAEncryption;
                digestLen = MD4_RESULT_SIZE;
                break;

            case md5Digest:
                *rsaAlgoIdSubType = md5withRSAEncryption;
                digestLen = MD5_RESULT_SIZE;
                break;

            default:
                *rsaAlgoIdSubType = (ubyte4) -1;
                break;
        }
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha2_OID, &digestSubType, NULL)))
    {
        switch (digestSubType)
        {
        case sha224Digest:
            *rsaAlgoIdSubType = sha224withRSAEncryption;
            digestLen = SHA224_RESULT_SIZE;
            break;

        case sha256Digest:
            *rsaAlgoIdSubType = sha256withRSAEncryption;
            digestLen = SHA256_RESULT_SIZE;
            break;

        case sha384Digest:
            *rsaAlgoIdSubType = sha384withRSAEncryption;
            digestLen = SHA384_RESULT_SIZE;
            break;

        case sha512Digest:
            *rsaAlgoIdSubType = sha512withRSAEncryption;
            digestLen = SHA512_RESULT_SIZE;
            break;

        default:
            *rsaAlgoIdSubType = (ubyte4) -1;
            break;
        }
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha1_OID, NULL, NULL)))
    {
        *rsaAlgoIdSubType = sha1withRSAEncryption;
        digestLen = SHA1_RESULT_SIZE;
    }
    else if (OK <= (status = X509_getCertOID( pAlgoId, signatureFileStream,
                                             sha1withRsaSignature_OID,
                                             NULL, NULL)))
    {
        *rsaAlgoIdSubType = sha1withRSAEncryption;
        digestLen = SHA1_RESULT_SIZE;
    }
    else /* no match */
    {
        goto exit;
    }

    status = ASN1_GetNthChild( pItem, 2, &pDigest);
    if ( OK > status)
    {
        goto exit;
    }

    if (pDigest->length != digestLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    if ((plainTextLen - pDigest->dataOffset) != digestLen)
    {
        /* Prevent Bleichenbacher's RSA signature forgery */
        /* the hash should be right-justified in the signature buffer */
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    /* copy the Hash */
    DIGI_MEMSET( hash, 0, CERT_MAXDIGESTSIZE);
    DIGI_MEMCPY( hash, decrypt + pDigest->dataOffset, (/*FSL*/sbyte4)digestLen);
    *pHashLen = (/*FSL*/sbyte4)digestLen;

exit:
    VLONG_freeVlongQueue(&pVlongQueue);

    if ( pDecryptedSignature)
    {
        TREE_DeleteTreeItem( (TreeItem*) pDecryptedSignature);
    }

    if (decrypt)
    {
        FREE(decrypt);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*------------------------------------------------------------------*/

extern MSTATUS
X509_getSignatureItem(ASN1_ITEMPTR pCertificate, CStream s,
                      ASN1_ITEMPTR* ppSignature)
{
    static WalkerStep signatureWalkInstructions[] =
    {
        { GoNthChild, 3, 0},
        { VerifyType, BITSTRING, 0 },
        { Complete, 0, 0}
    };

    if ( OK > ASN1_WalkTree( pCertificate, s, signatureWalkInstructions, ppSignature))
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    return OK;

}


/*------------------------------------------------------------------*/

/* Get the algorithm identifier for the certificate signature.
 */
static MSTATUS X509_getSignatureAlgoItem(
    ASN1_ITEMPTR pCertificate, CStream s, ASN1_ITEMPTR* ppAlgId)
{
    static WalkerStep signatureAlgoWalkInstructions[] =
    {
        { GoNthChild, 2, 0},
        { VerifyType, SEQUENCE, 0 },
        { Complete, 0, 0}
    };

    return ASN1_WalkTree(
        pCertificate, s, signatureAlgoWalkInstructions, ppAlgId);
}


/*------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
#if !(defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
X509_decryptRSASignature(MOC_RSA(hwAccelDescr hwAccelCtx)
                         ASN1_ITEMPTR pCertificate,
                         CStream s,
                         RSAKey* pRSAKey,
                         ubyte* hash,
                         sbyte4* hashLen,
                         ubyte4* rsaAlgoIdSubType)
{
    const ubyte* buffer              = NULL;
    ASN1_ITEMPTR pSignature;
    MSTATUS      status;

    if (NULL == s.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    if ((NULL == pCertificate) || (NULL == hash) || (NULL == rsaAlgoIdSubType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get the signature */
    if (OK > ( status = X509_getSignatureItem( pCertificate, s, &pSignature)))
        goto exit;

    if (0 == pSignature->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the buffer */
    buffer = (const ubyte*) CS_memaccess( s, (/*FSL*/sbyte4)pSignature->dataOffset,
                          (/*FSL*/sbyte4)pSignature->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }
    status = X509_decryptRSASignatureBuffer(MOC_RSA(hwAccelCtx) pRSAKey, buffer,
                                            pSignature->length,
                                            hash, hashLen, rsaAlgoIdSubType);
    if ( OK > status )
    {
        goto exit;
    }

exit:

    if ( buffer)
    {
        CS_stopaccess( s, buffer);
    }

    return status;

} /* CERT_DecryptSignature */
#endif

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
static MSTATUS
X509_decryptRSASignatureEx(MOC_RSA(hwAccelDescr hwAccelCtx)
                         ASN1_ITEMPTR pCertificate,
                         CStream s,
                         RSAKey* pRSAKey,
                         ubyte* hash,
                         sbyte4* hashLen,
                         ubyte4* rsaAlgoIdSubType,
                         ubyte4 keyType)
{
    const ubyte* buffer              = NULL;
    ASN1_ITEMPTR pSignature;
    MSTATUS      status;

    if (NULL == s.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    if ((NULL == pCertificate) || (NULL == hash) || (NULL == rsaAlgoIdSubType))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* get the signature */
    if (OK > ( status = X509_getSignatureItem( pCertificate, s, &pSignature)))
        goto exit;

    if (0 == pSignature->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* access the buffer */
    buffer = (const ubyte*) CS_memaccess( s, (/*FSL*/sbyte4)pSignature->dataOffset,
                          (/*FSL*/sbyte4)pSignature->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_;
        goto exit;
    }
    status = X509_decryptRSASignatureBufferEx(MOC_RSA(hwAccelCtx) pRSAKey, buffer,
                                            pSignature->length,
                                            hash, hashLen, rsaAlgoIdSubType, keyType);
    if ( OK > status )
    {
        goto exit;
    }

exit:

    if ( buffer)
    {
        CS_stopaccess( s, buffer);
    }

    return status;

}
#endif
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

static MSTATUS X509_verifyCertSignatureMocAsymKey (
  ASN1_ITEMPTR pPrevCertificate,
  CStream pPrevCertStream,
  MocAsymKey pMocAsymKey,
  ubyte4 computedHashType,
  sbyte4 computedHashLen,
  const ubyte computedHash[CERT_MAXDIGESTSIZE]
  )
{
  MSTATUS status;
  ubyte4 vfyResult;
  ASN1_ITEMPTR pSig;
  MKeyOperatorVerifyInfo vfyInfo;

  status = ERR_NULL_POINTER;
  if (NULL == pMocAsymKey->KeyOperator)
    goto exit;

  /* Get the signature out of the tree. It is the third child of the cert.
   */
  status = X509_getSignatureItem (pPrevCertificate, pPrevCertStream, &pSig);
  if (OK != status)
    goto exit;

  if (0 == pSig->length)
  {
    status = ERR_CERT_INVALID_STRUCT;
    goto exit;
  }

  /* Get the signature out.
   */
  vfyInfo.pSignature = (ubyte *)CS_memaccess (
    pPrevCertStream, (sbyte4)(pSig->dataOffset),
    (sbyte4)(pSig->length));

  vfyInfo.signatureLen = pSig->length;
  vfyInfo.pDigest = (ubyte *)computedHash;
  vfyInfo.digestLen = computedHashLen;
  vfyInfo.digestAlgorithm = computedHashType;
  status = pMocAsymKey->KeyOperator (
    pMocAsymKey, NULL, MOC_ASYM_OP_VERIFY_DIGEST_INFO, (void *)&vfyInfo, (void *)&vfyResult, NULL);
  if (OK != status)
    goto exit;

  /* This function returns OK if the signature verifies and
   * ERR_CERT_INVALID_SIGNATURE if t does not.
   */
  status = ERR_CERT_INVALID_SIGNATURE;
  if (0 != vfyResult)
    status = OK;

exit:

  return (status);
}

#endif /* __ENABLE_DIGICERT_ASYM_KEY__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__

#ifdef __ENABLE_DIGICERT_PKCS1__
/* This method will perform RSA-PSS verification on a certificate signature
 */
static MSTATUS X509_verifyRSAPSSCertSignature(
    MOC_RSA(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pCertificate,
    CStream cs, AsymmetricKey *pKey,
    ASN1_ITEMPTR pAlgIdItem,
    ubyte4 hashType,
    sbyte4 msgLen,
    const ubyte *pMsg,
    sbyte4 *pResult)
{
    MSTATUS status;
    ASN1_ITEMPTR pSignature;
    const ubyte *pSig = NULL;
    RsaSsaPssAlgIdParams *pParams;
    intBoolean valid = FALSE;
    MAlgoId *pAlgId = NULL;

    if (NULL == cs.pFuncs->m_memaccess)
    {
        status = ERR_ASN_NULL_FUNC_PTR;
        goto exit;
    }

    if ( (NULL == pResult) || (NULL == pCertificate) || (NULL == pKey) ||
         (NULL == pMsg) || (NULL == pAlgIdItem) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pResult = ERR_RSA_DECRYPTION;

    status = ALG_ID_deserialize(
        ALG_ID_RSA_SSA_PSS_OID, pAlgIdItem, cs, &pAlgId);
    if (OK != status)
    {
        goto exit;
    }

    /* Extract the signature from the certificate.
     */
    status = X509_getSignatureItem(pCertificate, cs, &pSignature);
    if (OK != status)
    {
        goto exit;
    }

    if (0 == pSignature->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* Get a buffer to the signature data.
     */
    pSig = (const ubyte *) CS_memaccess(
        cs,  pSignature->dataOffset, pSignature->length);
    if (NULL == pSig)
    {
        status = ERR_MEM_;
        goto exit;
    }

    pParams = pAlgId->pParams;

    /* Validate the RSA-PSS parameters.
     */
    if ( (MOC_PKCS1_ALG_MGF1 != pParams->mgfAlgo) ||
         (pParams->digestId != pParams->mgfDigestId) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Verify the signature.
     */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_PKCS1_rsassaPssVerify(
        MOC_RSA(hwAccelCtx) pKey->key.pRSA, pParams->digestId, CRYPTO_INTERFACE_PKCS1_MGF1, pMsg, msgLen,
        pSig, pSignature->length, (sbyte4) pParams->saltLen, &valid);
#else
    status = PKCS1_rsassaPssVerify(
        MOC_RSA(hwAccelCtx) pKey->key.pRSA, pParams->digestId, PKCS1_MGF1_FUNC, pMsg, msgLen,
        pSig, pSignature->length, (sbyte4) pParams->saltLen, &valid);
#endif
    if (OK != status)
    {
        goto exit;
    }

    if (TRUE == valid)
    {
        *pResult = 0;
    }

exit:

    if (NULL != pAlgId)
    {
        ALG_ID_free(&pAlgId);
    }

    if (pSig)
    {
        CS_stopaccess(cs, pSig);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_PKCS1__ */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
X509_verifyRSACertSignature( MOC_RSA(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pPrevCertificate,
                            CStream pPrevCertStream,
                            AsymmetricKey *pKey,
                            ubyte4 computedHashType,
                            sbyte4 computedHashLen,
                            const ubyte *computedHash,
                            ubyte4 keyType)
#else
static MSTATUS
X509_verifyRSACertSignature( MOC_RSA(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pPrevCertificate,
                            CStream pPrevCertStream,
                            AsymmetricKey *pKey,
                            ubyte4 computedHashType,
                            sbyte4 computedHashLen,
                            const ubyte *computedHash)
#endif
{
    MSTATUS status;
    ubyte   decryptedHash[CERT_MAXDIGESTSIZE];
    ubyte4  decryptedHashType;
    sbyte4  decryptedHashLen;
    sbyte4  result;

    ASN1_ITEMPTR pItem = NULL;

    status = X509_getSignatureAlgoItem(pPrevCertificate, pPrevCertStream, &pItem);
    if (OK != status)
        return status;


    pItem = ASN1_FIRST_CHILD(pItem);
    if (NULL == pItem)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

#ifdef __ENABLE_DIGICERT_PKCS1__
    /* Validate the OID in the algorithm identifier. This method supports
     * RSA encryption and RSA PSS.
     */
    if (OK <= ASN1_VerifyOID(pItem, pPrevCertStream, rsaSsaPss_OID))
    {
        /* Verify the signature in the certificate with the key provided and the
         * algorithm identifier.
         */
        status = X509_verifyRSAPSSCertSignature(
            MOC_RSA(hwAccelCtx) pPrevCertificate, pPrevCertStream, pKey,
            ASN1_PARENT(pItem), computedHashType, computedHashLen, computedHash,
            &result);
        if (OK != status)
        {
            return status;
        }
    }
    else
#endif /* __ENABLE_DIGICERT_PKCS1__ */
    {
        /* decrypt the signature in the certificate */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if (OK > (status = X509_decryptRSASignatureEx(MOC_RSA(hwAccelCtx)
                                pPrevCertificate,
                                pPrevCertStream,
                                pKey->key.pRSA,
                                decryptedHash,
                                &decryptedHashLen,
                                &decryptedHashType,
                                keyType)))
#else
        if (OK > (status = X509_decryptRSASignature(MOC_RSA(hwAccelCtx)
                                pPrevCertificate,
                                pPrevCertStream,
                                pKey->key.pRSA,
                                decryptedHash,
                                &decryptedHashLen,
                                &decryptedHashType)))
#endif
        {
            return status;
        }
        if (decryptedHashType != computedHashType ||
            decryptedHashLen != computedHashLen)
        {
            return ERR_CERT_INVALID_SIGNATURE;
        }

        if (OK > ( status = DIGI_CTIME_MATCH( computedHash, decryptedHash,
                (/*FSL*/ubyte4)decryptedHashLen, &result)))
        {
            return status;
        }
    }


    return (( 0 == result) ? OK : ERR_CERT_INVALID_SIGNATURE);
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
/* removes or adds 0x00 padding to an integer to make it the proper outLen size */
static MSTATUS X509_formatInteger(const ubyte *pIn, ubyte4 inLen, ubyte *pOut, ubyte4 outLen)
{
    ubyte4 len = inLen;

    /* get the true len of the integer */
    while (len > outLen)
    {
        if (0x00 != *(pIn + inLen - len))
        {
            return ERR_CERT_INVALID_SIGNATURE; /* too big */
        }

        len--;
    }

    if (len < outLen)
    {
        (void) DIGI_MEMSET(pOut, 0x00, outLen - len);
        (void) DIGI_MEMCPY(pOut + outLen - len, pIn + inLen - len, len);
    }
    else
    {
        (void) DIGI_MEMCPY(pOut, pIn + inLen - len, len);
    }

    return OK;
}

/*---------------------------------------------------------------------------*/

static MSTATUS X509_decodeRSfromItem(ASN1_ITEMPTR pSigItem, CStream cs, ubyte *pR, ubyte *pS, ubyte4 elemLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    const ubyte *buffer = NULL;
    ASN1_ITEMPTR pItem = NULL;

    if (NULL == pSigItem) /* other input checks already done */
        goto exit;

    status = ASN1_VerifyType(pSigItem, SEQUENCE);
    if (OK != status)
        goto exit;

    /* Get R */
    pItem = ASN1_FIRST_CHILD(pSigItem);
    status = ASN1_VerifyType(pItem, INTEGER);
    if (OK != status)
        goto exit;

    buffer = (const ubyte*) CS_memaccess(cs, pItem->dataOffset, pItem->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = X509_formatInteger(buffer, pItem->length, pR, elemLen);
    if (OK != status)
        goto exit;

    CS_stopaccess(cs, buffer);
    
    /* Get S */
    pItem = ASN1_NEXT_SIBLING(pItem);
    status = ASN1_VerifyType(pItem, INTEGER);
    if (OK != status)
        goto exit;

    buffer = (const ubyte*) CS_memaccess(cs, pItem->dataOffset, pItem->length);
    if (NULL == buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = X509_formatInteger(buffer, pItem->length, pS, elemLen);

exit:
    
    if (NULL != buffer)
    {
        CS_stopaccess( cs, buffer);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS X509_decodeRS(ubyte *pSer, ubyte4 serLen, ubyte *pR, ubyte *pS, ubyte4 elemLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    MemFile mf;
    CStream cs;
    ASN1_ITEMPTR pSigItem = NULL;

    if (NULL == pSer || NULL == pR || NULL == pS)
        goto exit;

    (void) MF_attach( &mf, serLen, pSer);
    CS_AttachMemFile( &cs, &mf);

    if (OK > ( status = ASN1_Parse( cs, &pSigItem)))
        goto exit;

    status = X509_decodeRSfromItem(ASN1_FIRST_CHILD(pSigItem), cs, pR, pS, elemLen);

exit:
    
    if (NULL != pSigItem)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pSigItem);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
extern MSTATUS
X509_verifyECDSASignatureEx( MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSequence, CStream cs, ECCKey* pECCKey,
                            sbyte4 computedHashLen, const ubyte *computedHash,
                            ubyte4 keyType)
{
    MSTATUS         status;
    ASN1_ITEMPTR    pItem;
    ubyte4          elemLen = 0;
    ubyte4          verifyFailure = 1;
    ubyte*          pSig = NULL;
    ubyte4          sigLen = 0;
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    const ubyte *   buffer = NULL;
#endif

    if ( !pSequence || !pECCKey || !computedHash)
        return ERR_NULL_POINTER;

    /* whether ECDSA or EdDSA sigLen is twice elemLen, allocate buffer for the signature */
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elemLen);
    if (OK != status)
        goto exit;

    sigLen = 2 * elemLen;
    status = DIGI_MALLOC((void **) &pSig, sigLen);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (akt_ecc_ed == keyType)
    {
        pItem = pSequence;
        if (OK > (status = ASN1_VerifyType(pItem, BITSTRING)))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        if (0 == pItem->length)
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        buffer = (const ubyte*) CS_memaccess( cs, pItem->dataOffset, pItem->length);
        if (!buffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        status = X509_formatInteger(buffer, pItem->length, pSig, sigLen);
        if (OK != status)
            goto exit;

        /* the computedHash variable actually stores the original message */
        if (OK > (status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt(MOC_ECC(hwAccelCtx) pECCKey, 0, (ubyte *) computedHash, computedHashLen,
                                                                   pSig, sigLen, &verifyFailure, NULL)))
        {
            goto exit;
        }
    }
    else
#endif
    {
        status = X509_decodeRSfromItem(pSequence, cs, pSig, pSig + elemLen, elemLen);
        if (OK != status)
            goto exit;

        if (OK > (status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigest( MOC_ECC(hwAccelCtx) pECCKey,
                                                                        (ubyte *) computedHash,
                                                                        computedHashLen,
                                                                        pSig, elemLen,
                                                                        pSig + elemLen, elemLen,
                                                                        &verifyFailure, keyType)))
        {
            goto exit;
        }
    }

    /* if verifyFailure == 0, No failures */
    if (verifyFailure != 0)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

exit:

    if (NULL != pSig)
    {
        DIGI_MEMSET_FREE(&pSig, sigLen);
    }

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    if (NULL != buffer)
    {
        CS_stopaccess( cs, buffer);
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

extern MSTATUS
X509_verifyECDSASignature( MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pSequence, CStream cs, ECCKey* pECCKey,
                           sbyte4 computedHashLen, const ubyte computedHash[])
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    return X509_verifyECDSASignatureEx( MOC_ECC(hwAccelCtx)
        pSequence, cs, pECCKey, computedHashLen, computedHash, akt_ecc);
#else
    MSTATUS         status;
    ASN1_ITEMPTR    pItem;
    const ubyte*    buffer = 0;
    PFEPtr          r = 0, s = 0;
    PrimeFieldPtr   pPF = 0;

    if ( !pSequence || !pECCKey || !computedHash)
        return ERR_NULL_POINTER;

    pPF = EC_getUnderlyingField( pECCKey->pCurve);

    if (OK > ( status = PRIMEFIELD_newElement( pPF, &r)))
        goto exit;

    if (OK > ( status = PRIMEFIELD_newElement( pPF, &s)))
        goto exit;

    /* read R */
    pItem = ASN1_FIRST_CHILD( pSequence);
    if (OK > (status = ASN1_VerifyType(pItem, INTEGER)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    buffer = (const ubyte*) CS_memaccess( cs, pItem->dataOffset, pItem->length);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > ( status = PRIMEFIELD_setToByteString( pPF, r, buffer, pItem->length)))
        goto exit;

    CS_stopaccess( cs, buffer);
    buffer = 0;

    /* read S */
    pItem = ASN1_NEXT_SIBLING(pItem);
    if ( OK > ASN1_VerifyType( pItem, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }
    buffer = (const ubyte*) CS_memaccess( cs, pItem->dataOffset, pItem->length);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > ( status = PRIMEFIELD_setToByteString( pPF, s, buffer, pItem->length)))
        goto exit;

    CS_stopaccess( cs, buffer);
    buffer = 0;

    if ( OK > (status = ECDSA_verifySignature( MOC_ECC(hwAccelCtx) pECCKey->pCurve, pECCKey->Qx, pECCKey->Qy,
                                    computedHash, computedHashLen, r, s)))
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }
exit:

    if ( buffer)
    {
        CS_stopaccess( cs, buffer);
    }

    PRIMEFIELD_deleteElement( pPF, &r);
    PRIMEFIELD_deleteElement( pPF, &s);

    return status;
#endif
}
#endif


/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS
X509_verifyECDSACertSignature( MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pCertificate,
                            CStream pCertStream,
                            ECCKey* pECCKey,
                            ubyte4 computedHashType,
                            sbyte4 computedHashLen,
                            const ubyte *computedHash,
                            ubyte4 keyType)
#else
static MSTATUS
X509_verifyECDSACertSignature( MOC_ECC(hwAccelDescr hwAccelCtx) ASN1_ITEMPTR pCertificate,
                            CStream pCertStream,
                            ECCKey* pECCKey,
                            ubyte4 computedHashType,
                            sbyte4 computedHashLen,
                            const ubyte computedHash[CERT_MAXDIGESTSIZE])
#endif
{
    MSTATUS         status;
    ASN1_ITEMPTR      pSignature;
    ASN1_ITEMPTR      pSequence;

    MOC_UNUSED(computedHashType);

    if (OK > ( status = X509_getSignatureItem( pCertificate, pCertStream, &pSignature)))
    {
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (akt_ecc_ed == keyType)
    {
        /* it'll be just a single BITSTRING, this will be validated in the below call to X509_verifyECDSASignatureEx */
        pSequence = pSignature;
    }
    else
#endif
    {
        pSequence = ASN1_FIRST_CHILD( pSignature);
        if ( OK > ( status = ASN1_VerifyType( pSequence, SEQUENCE)))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }
    }

    /* call the exported routine */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = X509_verifyECDSASignatureEx( MOC_ECC(hwAccelCtx) pSequence, pCertStream, pECCKey,
                                          computedHashLen, computedHash, keyType);
#else
    status = X509_verifyECDSASignature( MOC_ECC(hwAccelCtx) pSequence, pCertStream, pECCKey,
                                        computedHashLen, computedHash);
#endif
exit:
    return status;
}

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS X509_verifyHybridCertSignature( MOC_ASYM(hwAccelDescr hwAccelCtx)
                                               ASN1_ITEMPTR pCertificate,
                                               CStream cs,
                                               AsymmetricKey *pKey,
                                               sbyte4 computedHashLen,
                                               ubyte *pComputedHash)
{
    MSTATUS         status = OK;
    ASN1_ITEMPTR    pSequence = NULL;
    const ubyte*    pBuffer = 0;
    ubyte4          vStatus = 1;
    ubyte*          pDomain = NULL;
    ubyte4          domainLen = 0;
    ubyte4          qsAlg = 0;
 
    if ( NULL == pCertificate || NULL == pKey)
        return ERR_NULL_POINTER;

    /* signature will be just a single item sequence and then a BITSTRING */
    if (OK > ( status = X509_getSignatureItem( pCertificate, cs, &pSequence)))
    {
        goto exit;
    }

    if (OK > (status = ASN1_VerifyType(pSequence, BITSTRING)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pSequence->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pBuffer = (const ubyte*) CS_memaccess( cs, pSequence->dataOffset, pSequence->length);
    if (!pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlg);
    if (OK != status)
        goto exit;

    status = CRYPTO_getAlgoOIDAlloc(pKey->clAlg, qsAlg, &pDomain, &domainLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeVerify(MOC_ASYM(hwAccelCtx) pKey, TRUE, pDomain, domainLen,
                                                 (ubyte *) pComputedHash, computedHashLen,
                                                 (ubyte *) pBuffer, pSequence->length, &vStatus);
    if (OK != status)
        goto exit;

    if (vStatus)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
    }

exit:

    if (NULL != pBuffer)
    {
        CS_stopaccess( cs, pBuffer);
    }

    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, domainLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* __ENABLE_DIGICERT_ECC__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
extern MSTATUS X509_verifyQsSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                      ASN1_ITEMPTR pBitString,
                                      CStream cs,
                                      QS_CTX *pCtx,
                                      sbyte4 computedHashLen,
                                      ubyte *pComputedHash)
{
    MSTATUS         status = OK;
    const ubyte*    pBuffer = 0;
    ubyte4          qsFail = 1;

    if ( NULL == pBitString || NULL == pCtx)
        return ERR_NULL_POINTER;

    if (OK > (status = ASN1_VerifyType(pBitString, BITSTRING)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pBitString->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pBuffer = (const ubyte*) CS_memaccess( cs, pBitString->dataOffset, pBitString->length);
    if (!pBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = CRYPTO_INTERFACE_QS_SIG_verify(MOC_HASH(hwAccelCtx) pCtx, (ubyte *) pComputedHash, computedHashLen,
                                                      (ubyte *) pBuffer, pBitString->length, &qsFail)))
        goto exit;

    if (qsFail)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
    }

exit:

    if (NULL != pBuffer)
    {
        CS_stopaccess( cs, pBuffer);
    }

    return status;    
}

/*---------------------------------------------------------------------------*/

static MSTATUS X509_verifyQsCertSignature( MOC_ASYM(hwAccelDescr hwAccelCtx)
                                           ASN1_ITEMPTR pCertificate,
                                           CStream cs,
                                           QS_CTX *pCtx,
                                           sbyte4 computedHashLen,
                                           ubyte *pComputedHash)
{
    MSTATUS         status = OK;
    ASN1_ITEMPTR    pSigItem = NULL;

    if ( NULL == pCertificate || NULL == pCtx)
        return ERR_NULL_POINTER;

    /* signature will be a bitstring */
    if (OK > ( status = X509_getSignatureItem( pCertificate, cs, &pSigItem)))
    {
        goto exit;
    }

    status = X509_verifyQsSignature(MOC_ASYM(hwAccelCtx) pSigItem, cs, pCtx, computedHashLen, pComputedHash);

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
extern MSTATUS
X509_verifyDSASignature(MOC_DSA(hwAccelDescr hwAccelCtx)
                        ASN1_ITEMPTR pSequence, CStream cs, DSAKey* pDSAKey,
                        sbyte4 computedHashLen, const ubyte computedHash[])
{
    MSTATUS         status;
    ASN1_ITEMPTR    pItem;
    intBoolean      good;
    const ubyte*    buffer = 0;
    vlong*          pR = 0;
    vlong*          pS = 0;

    if ( !pSequence || !pDSAKey || !computedHash)
        return ERR_NULL_POINTER;

    /* read R */
    pItem = ASN1_FIRST_CHILD( pSequence);
    if (OK > (status = ASN1_VerifyType(pItem, INTEGER)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pItem->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    buffer = CS_memaccess( cs, pItem->dataOffset, pItem->length);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > ( status = VLONG_vlongFromByteString(buffer, pItem->length, &pR, NULL)))
        goto exit;

    CS_stopaccess( cs, buffer);
    buffer = 0;

    /* read S */
    pItem = ASN1_NEXT_SIBLING(pItem);
    if ( OK > ASN1_VerifyType( pItem, INTEGER))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pItem->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    buffer = CS_memaccess( cs, pItem->dataOffset, pItem->length);
    if (!buffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > ( status = VLONG_vlongFromByteString( buffer, pItem->length, &pS, NULL)))
        goto exit;

    CS_stopaccess( cs, buffer);
    buffer = 0;

    if ( OK > (status = DSA_verifySignature2( MOC_DSA(hwAccelCtx) pDSAKey,
                                                computedHash, computedHashLen,
                                                pR, pS, &good, NULL)))
    {
        goto exit;
    }

    if (!good)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

exit:

    if ( buffer)
    {
        CS_stopaccess( cs, buffer);
    }

    VLONG_freeVlong( &pR, NULL);
    VLONG_freeVlong( &pS, NULL);

    return status;
}
#endif


/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_DSA__))
static MSTATUS
X509_verifyDSACertSignature( MOC_DSA(hwAccelDescr hwAccelCtx)
                            ASN1_ITEMPTR pCertificate,
                            CStream pCertStream,
                            DSAKey* pECCKey,
                            ubyte4 computedHashType,
                            sbyte4 computedHashLen,
                            const ubyte computedHash[CERT_MAXDIGESTSIZE])
{
    MSTATUS         status;
    ASN1_ITEMPTR      pSignature;
    ASN1_ITEMPTR      pSequence;

    MOC_UNUSED(computedHashType);

    if (OK > ( status = X509_getSignatureItem( pCertificate, pCertStream, &pSignature)))
    {
        goto exit;
    }

    pSequence = ASN1_FIRST_CHILD( pSignature);
    if ( OK > ( status = ASN1_VerifyType( pSequence, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* call the exported routine */
    status = X509_verifyDSASignature( MOC_DSA(hwAccelCtx)
                                     pSequence, pCertStream, pECCKey,
                                     computedHashLen, computedHash);
exit:
    return status;
}
#endif


/*---------------------------------------------------------------------------*/

extern MSTATUS
X509_verifySignature( MOC_ASYM(hwAccelDescr hwAccelCtx) ASN1_ITEM *pCertOrCRL,
                     CStream cs, AsymmetricKey *pIssuerPubKey)
{
    MSTATUS status = OK;
    ubyte*  pComputedHash;
    ubyte4  computedHashType;
    sbyte4  computedHashLen;
    ubyte4  pubKeyType;
    intBoolean freeBuffer = FALSE;

    /* check certificate signature */
    /* Extract the data to verify */
    if ( OK > (status = X509_extractSignatureData(MOC_HASH(hwAccelCtx)
                                                    pCertOrCRL,
                                                    cs,
                                                    &pComputedHash,
                                                    &computedHashLen,
                                                    &computedHashType,
                                                    &pubKeyType,
                                                    &freeBuffer)))
    {
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
    /* If this is a mocasym key, call the mocasym key's verify.
     */
    if (akt_moc == pIssuerPubKey->type)
    {
      status = X509_verifyCertSignatureMocAsymKey (
        pCertOrCRL, cs, pIssuerPubKey->key.pMocAsymKey,
        computedHashType, computedHashLen, pComputedHash);
      goto exit;
    }
#endif

    if (pIssuerPubKey->type != pubKeyType)
    {
        status = ERR_CERT_KEY_SIGNATURE_OID_MISMATCH;
        goto exit;
    }

    switch( pIssuerPubKey->type & 0xff)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
        {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = X509_verifyRSACertSignature( MOC_RSA(hwAccelCtx)
                                                 pCertOrCRL, cs,
                                                 pIssuerPubKey,
                                                 computedHashType,
                                                 computedHashLen,
                                                 pComputedHash,
                                                 pIssuerPubKey->type);
#else
            status = X509_verifyRSACertSignature( MOC_RSA(hwAccelCtx)
                                                 pCertOrCRL, cs,
                                                 pIssuerPubKey,
                                                 computedHashType,
                                                 computedHashLen,
                                                 pComputedHash);
#endif
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            status = X509_verifyDSACertSignature( MOC_DSA(hwAccelCtx)
                                                 pCertOrCRL,
                                                 cs,
                                                 pIssuerPubKey->key.pDSA,
                                                 computedHashType,
                                                 computedHashLen,
                                                 pComputedHash);
            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
            status = X509_verifyECDSACertSignature(MOC_ECC(hwAccelCtx) pCertOrCRL,
                                                   cs,
                                                   pIssuerPubKey->key.pECC,
                                                   computedHashType,
                                                   computedHashLen,
                                                   pComputedHash,
                                                   pIssuerPubKey->type);
#else
            status = X509_verifyECDSACertSignature(MOC_ECC(hwAccelCtx) pCertOrCRL,
                                                   cs,
                                                   pIssuerPubKey->key.pECC,
                                                   computedHashType,
                                                   computedHashLen,
                                                   pComputedHash);
#endif
            break;
        }
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:
        {
            status = X509_verifyHybridCertSignature(MOC_ASYM(hwAccelCtx) pCertOrCRL,
                                                    cs,
                                                    pIssuerPubKey,
                                                    computedHashLen,
                                                    pComputedHash);
            break;
        }
#endif
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_qs:
        {
            status = X509_verifyQsCertSignature(MOC_ASYM(hwAccelCtx) pCertOrCRL,
                                                cs,
                                                pIssuerPubKey->pQsCtx,
                                                computedHashLen,
                                                pComputedHash);
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

    /* Only free the buffer if it was allocated.
     */
    if (TRUE == freeBuffer)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, (void *)&pComputedHash);
    }
    return status;
}


/*---------------------------------------------------------------------------*/

extern MSTATUS
X509_isRootCertificate(ASN1_ITEMPTR pCertificate, CStream s)
{
    /* this functions returns OK, ERR_FALSE or an error */
    MSTATUS status;
    ASN1_ITEMPTR pExtensions;
    ASN1_ITEMPTR pSKIExtension;
    ASN1_ITEMPTR pAKIExtension;
    ASN1_ITEMPTR pAKIKeyID;
    intBoolean critical;

    /* is certificate subject equal to certificate issuer? */
    if ( OK > ( status = X509_checkCertificateIssuer( pCertificate, s,
                                                     pCertificate, s)))
    {
        return ( ERR_CERT_INVALID_PARENT_CERTIFICATE == status) ?
                ERR_FALSE: status;
    }

    /* issuer = subject so check for Authority Key Identifier and Subject Key Identifier */
    if ( OK > ( status = X509_getCertificateExtensions( pCertificate,
                                                       &pExtensions)))
    {
        return status;
    }

    /* no extensions */
    if ( !pExtensions)
    {
        return OK;
    }
    /* look for the Subject Key Extension */
    if (OK > ( status = X509_getCertExtension( pExtensions, s,
                                              subjectKeyIdentifier_OID,
                                              &critical, &pSKIExtension)))
    {
        return status;
    }

    if (!pSKIExtension)
        return OK;

    if (OK > ( status = X509_getCertExtension( pExtensions, s,
                                              authorityKeyIdentifier_OID,
                                              &critical, &pAKIExtension)))
    {
        return status;
    }

    if (!pAKIExtension)
        return OK;

    /* compare key identifiers */
    /* we can do that only if tag [0]
    KeyIdentifier ::= OCTET STRING
    AuthorityKeyIdentifier ::= SEQUENCE {
        keyIdentifier              [0]  KeyIdentifier OPTIONAL,
        authorityCertIssuer        [1]  GeneralNames OPTIONAL,
        authorityCertSerialNumber  [2]  CertificateSerialNumber OPTIONAL
    SubjectKeyIdentifier ::= KeyIdentifier
    */
    if ( OK > ( status = ASN1_GoToTag( pAKIExtension, 0, &pAKIKeyID)))
    {
        return status;
    }

    if (!pAKIKeyID)
    {
        return ERR_FALSE; /* assume different keys */
    }
    return ASN1_CompareItems( pAKIKeyID, s, pSKIExtension, s);
}

/*---------------------------------------------------------------------------*/

extern MSTATUS
X509_canSignChain(ASN1_ITEMPTR pCertificate, CStream s, sbyte4 chainLength)
{
    /* can the certificate sign a chain of length chainLength ?
     2 cases:
     1) either this is a certificate version 1 or 2 with no extensions.
     Then it needs to be a root certificate to be allowed to sign. This assumes
     that this certificate is trusted.
     2) Other certificates (version 3) will
     2a) have to have the basicConstraints extension with CA. Note: this means that
     the validation will fail if a non root certificate with version 1 and 2
     is "trusted".
     2b) Compared to the old code, we also NEVER require key usage
     but will look at it if present to verify keyCertSing is set.
     2c) If there are any critical extensions present, we will ALWAYS fail.
     All these rules are to conform to RFC 5280. p 87. */

    sbyte4 version;
    MSTATUS status;
    ASN1_ITEMPTR pExtensions;
    ASN1_ITEMPTR pExtension;
    intBoolean criticalExtension;
    ubyte keyBitString;
#ifndef __DISABLE_DIGICERT_STRICT_CERT_BASIC_CONSTRAINTS__
    ASN1_ITEMPTR pExtPart;
#endif

    if (OK > (status = X509_extractVersion( pCertificate, &version)))
    {
        return status;
    }

    /* versions are off by one */
    if (version == 0 || version == 1)
    {
        /* 1) can sign if version 1 and 2 and root certificate */
        return X509_isRootCertificate(pCertificate, s);
    }

    /* 2) version 3: look at the basic constraints which MUST be present,
    if the key usage extension is present, that the keyCertSign bit is set
    and that there's no unknown critical extensions */
    if ( OK > (status = X509_getCertificateExtensions(pCertificate,
                                                      &pExtensions)))
    {
        return status;
    }

    /* 2a) no extensions: reject it even if this is a root certificate! */
    if (!pExtensions)
    {
#if !defined(__DISABLE_DIGICERT_CERTIFICATE_EXTENSIONS_CHECK__)
        return ERR_CERT_INVALID_CERT_POLICY;
#else
        return OK;
#endif
    }

#ifndef __DISABLE_DIGICERT_STRICT_CERT_BASIC_CONSTRAINTS__
    /* look for the extension with the basicConstraint OID */
    /* BasicConstraintsSyntax ::= SEQUENCE {
     cA                 BOOLEAN DEFAULT FALSE,
     pathLenConstraint  INTEGER(0..MAX) OPTIONAL }*/
    status = X509_getCertExtension( pExtensions, s, basicConstraints_OID,
                                   &criticalExtension, &pExtension);
    if ( OK > status || !pExtension || 0 == pExtension->length)
    {
        return ERR_CERT_INVALID_CERT_POLICY;
    }

    if (  (pExtension->id & CLASS_MASK) != UNIVERSAL ||
        pExtension->tag != SEQUENCE)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    /* verify that it is for a CA */
    pExtPart = ASN1_FIRST_CHILD( pExtension);
    if ( !pExtPart)
    {
        return ERR_CERT_INVALID_CERT_POLICY; /* cA  BOOLEAN DEFAULT FALSE */
    }

    if ( (pExtPart->id & CLASS_MASK) != UNIVERSAL ||
        pExtPart->tag != BOOLEAN)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    if ( !pExtPart->data.m_boolVal) /* not a CA */
    {
        return ERR_CERT_INVALID_CERT_POLICY;
    }

    /* verify the maximum chain length if there */
    pExtPart = ASN1_NEXT_SIBLING( pExtPart);
    if ( pExtPart)
    {
        if ( (pExtPart->id & CLASS_MASK) != UNIVERSAL ||
            pExtPart->tag != INTEGER)
        {
            return ERR_CERT_INVALID_STRUCT;
        }

        if (chainLength > (sbyte4)(1 + pExtPart->data.m_intVal))   /* chain length too big */
        {
            return ERR_CERT_INVALID_CERT_POLICY;
        }
    }

#endif /* __DISABLE_DIGICERT_STRICT_CERT_BASIC_CONSTRAINTS__ */

    /* 2b) look for the child with the keyUsage OID */
    status = X509_getCertExtension( pExtensions, s, keyUsage_OID,
                                   &criticalExtension, &pExtension);
    if ( OK > status)
    {
        return status;
    }

    if ( pExtension) /* look at the key usage extension */
    {
        /* KeyUsage ::= BIT STRING {
         digitalSignature(0), nonRepudiation(1), keyEncipherment(2),
         dataEncipherment(3), keyAgreement(4), keyCertSign(5), cRLSign(6),
         encipherOnly(7), decipherOnly(8)}

         The bit string is represented with bit 0 first.
         Examples:
         Certificate Signing, Off-line CRL Signing, CRL Signing (06)  00000110
         Digital Signature, Non-Repudiation (c0)  11000000
         Digital Signature, Key Encipherment (a0) 10100000
         Digital Signature, Non-Repudiation, Certificate Signing,
         Off-line CRL Signing, CRL Signing (c6)   11000110
         Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing (86)
         10000110
         */

        if (  (pExtension->id & CLASS_MASK) != UNIVERSAL ||
            pExtension->tag != BITSTRING)
        {
            return ERR_CERT_INVALID_STRUCT;
        }

        /* we just look for the Certificate Signing bit (bit 5 => mask = 4) */
        CS_seek( s, pExtension->dataOffset, MOCANA_SEEK_SET);

        /* we only need to check the 5th bit so get just the first byte of the keyBitString */
        if (OK > (status = CS_getc(s, &keyBitString)))
        {
            return status;
        }

#ifndef __DISABLE_DIGICERT_STRICT_CERT_KEY_USAGE__
        if (0 == (keyBitString & 4))    /* not supposed to be signing certificate */
        {
            return ERR_CERT_INVALID_CERT_POLICY;
        }
#endif /* __DISABLE_DIGICERT_STRICT_CERT_KEY_USAGE__ */
    }


    /* 2c) fail if there are unknown critical extensions */
    if ( OK > (status = X509_checkForUnknownCriticalExtensions( pExtensions, s)))
    {
        return status;
    }
    return OK;
}


/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

MOC_EXTERN MSTATUS
PARSE_CV_CERT_checkCertificateIssuer(CV_CERT *pCertificate,
                                     CV_CERT *pParentCertificate)
{
    MSTATUS status;
    sbyte4 cmp = 1;

    if ((NULL == pCertificate) || (NULL == pParentCertificate))
        return ERR_NULL_POINTER;

    if (pCertificate->certAuthRefLen != pParentCertificate->certHolderRefLen)
    {
        return ERR_CERT_INVALID_PARENT_CERTIFICATE;
    }

    status = DIGI_MEMCMP (
        pCertificate->pCertAuthRef, pParentCertificate->pCertHolderRef, pCertificate->certAuthRefLen, &cmp);
    if (OK != status)
    {
        return status;
    }

    if (0 != cmp)
    {
        return ERR_CERT_INVALID_PARENT_CERTIFICATE;
    }

    return OK;
}

static MSTATUS
PARSE_CV_CERT_verifyRSACertSignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                     CV_CERT *pCertificate,
                                     AsymmetricKey *pParentCertKey,
                                     ubyte4 hashAlgo)
{
    MSTATUS status;
    sbyte4 hashLen = 0;
    ubyte4 cipherTextLen = 0;
    ubyte hash[CERT_MAXDIGESTSIZE];
    RSAKey *pKey = pParentCertKey->key.pRSA;
    intBoolean valid = FALSE;
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;

    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(MOC_RSA(hwAccelCtx) pKey, (sbyte4 *)&cipherTextLen);
    if (OK != status)
        goto exit;

    if (cipherTextLen != pCertificate->sigLen)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

    status = CRYPTO_computeBufferHash( MOC_HASH(hwAccelCtx)
        pCertificate->pCertBody, pCertificate->certBodyLen, hash, &hashLen, hashAlgo);
    if (OK != status)
        goto exit;

    status = ASN1_buildDigestInfoAlloc (hash, hashLen, hashAlgo, &pDigestInfo, &digestInfoLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_RSA_verifyDigest( MOC_RSA(hwAccelCtx)
        pKey, pDigestInfo, digestInfoLen, pCertificate->pSig, pCertificate->sigLen, &valid, NULL);
    if (OK != status)
        goto exit;

    if (TRUE != valid)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
    }

exit:

    if (NULL != pDigestInfo)
    {
        (void) DIGI_MEMSET_FREE(&pDigestInfo, digestInfoLen);
    }
    return status;
}

#ifdef __ENABLE_DIGICERT_PKCS1__
static MSTATUS
PARSE_CV_CERT_verifyRSAPSSCertSignature(MOC_RSA(hwAccelDescr hwAccelCtx) CV_CERT *pCertificate,
                                        AsymmetricKey *pParentCertKey,
                                        ubyte4 hashAlgo)
{
    MSTATUS status = OK;
    ubyte4 saltLen = 0;
    RSAKey *pKey = pParentCertKey->key.pRSA;
    ubyte4 valid = 1;

    switch(hashAlgo)
    {
        case ht_sha1:
            saltLen = 20;
            break;

        case ht_sha256:
            saltLen = 32;
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify( MOC_RSA(hwAccelCtx)
        pKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pCertificate->pCertBody,
        pCertificate->certBodyLen, pCertificate->pSig, pCertificate->sigLen, saltLen, &valid);
    if (OK != status)
        goto exit;

    if (0 != valid)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    return status;
}
#endif

#ifdef __ENABLE_DIGICERT_ECC__
static MSTATUS
PARSE_CV_CERT_verifyECDSACertSignature(MOC_ECC(hwAccelDescr hwAccelCtx) CV_CERT *pCertificate,
                                       AsymmetricKey *pParentCertKey,
                                       ubyte4 hashAlgo)
{
    MSTATUS status = OK;
    ECCKey *pKey = pParentCertKey->key.pECC;
    ubyte4 verify = 1;

    status = CRYPTO_INTERFACE_ECDSA_verifyMessageExt( MOC_ECC(hwAccelCtx)
        pKey, hashAlgo, pCertificate->pCertBody, pCertificate->certBodyLen,
        pCertificate->pSig, pCertificate->sigLen, &verify, NULL);
    if (OK != status)
        goto exit;

    if (0 != verify)
    {
        status = ERR_CERT_INVALID_SIGNATURE;
        goto exit;
    }

exit:
    return status;
}
#endif

MOC_EXTERN MSTATUS
PARSE_CV_CERT_verifySignature(MOC_ASYM(hwAccelDescr hwAccelCtx)
                              CV_CERT *pCertificate,
                              CV_CERT *pParentCertificate)
{
    AsymmetricKey   parentCertKey = {0};
    MSTATUS         status;
    ubyte4 hashAlgo = 0;
    byteBoolean isPss = FALSE;

    if ((NULL == pCertificate) || (NULL == pParentCertificate))
        return ERR_NULL_POINTER;

    /* Instantiate the key */
    status = CV_CERT_parseKey (MOC_ASYM(hwAccelCtx)
        pParentCertificate->pCvcKey, pParentCertificate->cvcKeyLen,
        &parentCertKey, &hashAlgo, &isPss);
    if (OK != status)
        goto exit;

    switch(parentCertKey.type & 0xff)
    {
        case akt_rsa:
        {
#ifdef __ENABLE_DIGICERT_PKCS1__
            if (TRUE == isPss)
            {
                status = PARSE_CV_CERT_verifyRSAPSSCertSignature (
                    MOC_RSA(hwAccelCtx) pCertificate, &parentCertKey, hashAlgo);
            }
            else
#endif
            {
                status = PARSE_CV_CERT_verifyRSACertSignature (
                    MOC_ASYM(hwAccelCtx) pCertificate, &parentCertKey, hashAlgo);
            }
            break;
        }

#ifdef __ENABLE_DIGICERT_ECC__
        case akt_ecc:
        {
            status = PARSE_CV_CERT_verifyECDSACertSignature (
                    MOC_ECC(hwAccelCtx) pCertificate, &parentCertKey, hashAlgo);
            break;
        }
#endif

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

exit:

    CRYPTO_uninitAsymmetricKey(&parentCertKey, NULL);

    return status;
}

MOC_EXTERN MSTATUS
PARSE_CV_CERT_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                           CV_CERT *pCertificate,
                           CV_CERT *pParentCertificate)
{
    MSTATUS         status;

    if ((NULL == pCertificate) || (NULL == pParentCertificate))
        return ERR_NULL_POINTER;

    /* verify CAR of pCertificate == CHR of pParentCertificate */
    status = PARSE_CV_CERT_checkCertificateIssuer(pCertificate, pParentCertificate);
    if (OK != status)
        goto exit;

    /* Verify the signature */
    status = PARSE_CV_CERT_verifySignature(MOC_ASYM(hwAccelCtx) pCertificate, pParentCertificate);
    if (OK != status)
        goto exit;

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

MOC_EXTERN MSTATUS
X509_validateLink(MOC_ASYM(hwAccelDescr hwAccelCtx)
                  ASN1_ITEMPTR pCertificate, CStream pCertStream,
                  ASN1_ITEMPTR pParentCertificate, CStream pParentCertStream,
                  sbyte4 chainLength)
{
    AsymmetricKey   parentCertKey = {0};
    MSTATUS         status;

    if ((NULL == pCertificate) || (NULL == pParentCertificate))
        return ERR_NULL_POINTER;

    /* verify issuer of pCertificate == subject of pParentCertificate */
    if (OK > (status = X509_checkCertificateIssuer(pCertificate,
                                                   pCertStream,
                                                   pParentCertificate,
                                                   pParentCertStream)))
    {
        goto exit;
    }
    /* verify that the certificate is authorized to be used to sign other certificates */
    if (OK > (status = X509_canSignChain(pParentCertificate,
                                         pParentCertStream,
                                         chainLength)))
    {
        goto exit;
    }

    if (OK > (status = X509_setKeyFromSubjectPublicKeyInfo(MOC_ASYM(hwAccelCtx)
                                                           pParentCertificate,
                                                           pParentCertStream,
                                                           &parentCertKey)))
    {
        goto exit;
    }

    /* verify the signature */
    if (OK > ( status = X509_verifySignature(MOC_ASYM(hwAccelCtx) pCertificate,
                                             pCertStream, &parentCertKey)))
    {
        goto exit;
    }

exit:

    CRYPTO_uninitAsymmetricKey(&parentCertKey, NULL);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS X509_extractDistinguishedNameFields (
  ASN1_ITEM *pOID,
  CStream s,
  nameAttr *pRetNameComponent
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 index, oidLen, dnElementLen;
  const ubyte *pOidToUse = NULL;
  ASN1_ITEM *pDistinguishedElement;
  ubyte *pDistinguishedElementCopy = NULL;
#define MOC_NAME_OID_MAX_LEN     11
  ubyte pOidData[MOC_NAME_OID_MAX_LEN];
#define MOC_NAME_OID_LIST_COUNT  18
  const ubyte *pOidList[MOC_NAME_OID_LIST_COUNT] = {
    countryName_OID,
    stateOrProvinceName_OID,
    localityName_OID,
    organizationName_OID,
    organizationalUnitName_OID,
    commonName_OID,
    serialNumber_OID,
    userID_OID,
    domainComponent_OID,
    pkcs9_emailAddress_OID,
    pkcs9_unstructuredName_OID,
    businessCategory_OID,
    postalCode_OID,
    streetAddress_OID,
    jiCountryName_OID,
    jiStateOrProvinceName_OID,
    jiLocalityName_OID,
    dnQualifier_OID
  };

  status = ERR_CERT_UNRECOGNIZED_OID;
  if (NULL == pOID)
    goto exit;

  pDistinguishedElement = ASN1_NEXT_SIBLING (pOID);

  if (NULL == pDistinguishedElement)
    goto exit;

  /* Get the OID.
   * Get it using getc in case the data is not in a buffer.
   */
  oidLen = pOID->length;

  if (MOC_NAME_OID_MAX_LEN < oidLen)
    goto exit;

  CS_seek (s, pOID->dataOffset, MOCANA_SEEK_SET);

  for (index = 0; index < oidLen; ++index)
  {
    status = CS_getc (s, pOidData + index);
    if (OK != status)
      goto exit;
  }

  /* Find the OID in the list that matches.
   */
  for (index = 0; index < MOC_NAME_OID_LIST_COUNT; ++index)
  {
    /* The first byte in an OID in the list is the length. If not the target
     * length, no need to look any further.
     */
    if ((ubyte)oidLen != pOidList[index][0])
      continue;

    status = DIGI_MEMCMP (
      (void *)pOidData, (void *)(pOidList[index] + 1), oidLen, &cmpResult);
    if (OK != status)
      goto exit;

    /* If this is not the OID move on.
     */
    if (0 != cmpResult)
      continue;

    /* If we reach this code, the OID in the ASN.1 object is the OID at index.
     * Set the OID data to the value from the list. That is actually a persistent
     * buffer.
     */
    pOidToUse = pOidList[index];
    break;
  }

  /* If we went through the list without a match, this is an unrecognized OID.
   */
  status = ERR_CERT_UNRECOGNIZED_OID;
  if (MOC_NAME_OID_LIST_COUNT <= index)
    goto exit;

  /* Copy the data.
   * Once again, use getc in case the data is not in a buffer.
   */
  dnElementLen = pDistinguishedElement->length;
  CS_seek (s, pDistinguishedElement->dataOffset, MOCANA_SEEK_SET);

  status = ERR_CERT_DNE_STRING_TOO_LONG;
  if (MAX_DNE_STRING_LENGTH < dnElementLen)
    goto exit;

  if (0 != dnElementLen)
  {
    status = DIGI_MALLOC ((void **)&pDistinguishedElementCopy, dnElementLen);
    if (OK != status)
      goto exit;

    for (index = 0; index < dnElementLen; ++index)
    {
      status = CS_getc (s, pDistinguishedElementCopy + index);
      if (OK != status)
        goto exit;
    }
  }

  pRetNameComponent->oid      = pOidToUse;
  pRetNameComponent->type     = (/*FSL*/ubyte)pDistinguishedElement->tag;
  pRetNameComponent->value    = pDistinguishedElementCopy;
  pDistinguishedElementCopy   = NULL;
  pRetNameComponent->valueLen = pDistinguishedElement->length;

  status = OK;

exit:

  if (NULL != pDistinguishedElementCopy)
  {
    DIGI_FREE ((void **)&pDistinguishedElementCopy);
  }

  return (status);
}

/*------------------------------------------------------------------*/

static ubyte4
X509_getNumberOfChild(ASN1_ITEM *pParent)
{
    ubyte4 count = 0;
    ASN1_ITEM *pItem;

    pItem = ASN1_FIRST_CHILD(pParent);
    while (NULL != pItem)
    {
        count++;
        pItem = ASN1_NEXT_SIBLING(pItem);
    }
    return count;
}


/*------------------------------------------------------------------*/

/* digicert internal API */
extern MSTATUS
X509_extractDistinguishedNamesFromName(ASN1_ITEMPTR pName, CStream s,
                                       certDistinguishedName *pRetDN)
{
    MSTATUS     status;
    ASN1_ITEMPTR  pCurrChild;
    ubyte4      rdnOffset;
    ubyte4      nameAttrOffset;

    /* now traverse each child with OID 2.5.4.n */
    /*  Name ::= SEQUENCE of RelativeDistinguishedName
        RelativeDistinguishedName = MOC_SET of AttributeValueAssertion
        AttributeValueAssertion = SEQUENCE { attributeType OID; attributeValue ANY }
    */

    /* Name is a sequence */
    if ((NULL == pName) ||
        ((pName->id & CLASS_MASK) != UNIVERSAL) ||
        (pName->tag != SEQUENCE))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pRetDN->dnCount = X509_getNumberOfChild(pName);
    if (NULL == (pRetDN->pDistinguishedName = (relativeDN*) MALLOC(pRetDN->dnCount * sizeof(relativeDN))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    DIGI_MEMSET((ubyte*)pRetDN->pDistinguishedName, 0, (/*FSL*/sbyte4)(pRetDN->dnCount * sizeof(relativeDN)));

    pCurrChild = ASN1_FIRST_CHILD( pName);

    rdnOffset = 0;
    while (pCurrChild)
    {
        ASN1_ITEMPTR pGrandChild;
        ASN1_ITEMPTR pOID;

        status = ERR_CERT_INVALID_STRUCT;

        /* child should be a MOC_SET */
        if (((pCurrChild->id & CLASS_MASK) != UNIVERSAL) ||
            (pCurrChild->tag != MOC_SET) )
        {
            goto exit;
        }
        (pRetDN->pDistinguishedName+rdnOffset)->nameAttrCount = X509_getNumberOfChild(pCurrChild);
        if (NULL == ( (pRetDN->pDistinguishedName+rdnOffset)->pNameAttr = (nameAttr*) MALLOC((pRetDN->pDistinguishedName+rdnOffset)->nameAttrCount * sizeof(nameAttr))))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMSET((ubyte*)(pRetDN->pDistinguishedName+rdnOffset)->pNameAttr, 0, (/*FSL*/sbyte4)((pRetDN->pDistinguishedName+rdnOffset)->nameAttrCount * sizeof(nameAttr)));

        /* GrandChild should be a SEQUENCE */
        nameAttrOffset = 0;
        pGrandChild = ASN1_FIRST_CHILD( pCurrChild);
        while (pGrandChild)
        {
            if ( NULL == pGrandChild ||
                (pGrandChild->id & CLASS_MASK) != UNIVERSAL ||
                pGrandChild->tag != SEQUENCE)
            {
                goto exit;
            }

            /* get the OID */
            pOID = ASN1_FIRST_CHILD( pGrandChild);

            if ((NULL == pOID) ||
                ((pOID->id & CLASS_MASK) != UNIVERSAL) ||
                (pOID->tag != OID) )
            {
                goto exit;
            }

            if (OK > (status = X509_extractDistinguishedNameFields (
              pOID, s, (pRetDN->pDistinguishedName+rdnOffset)->pNameAttr+nameAttrOffset)))
              goto exit;

            pGrandChild = ASN1_NEXT_SIBLING(pGrandChild);
            nameAttrOffset++;
        }
        pCurrChild = ASN1_NEXT_SIBLING( pCurrChild);
        rdnOffset++;
    }

    status = OK;
exit:
    return status;

}

/*------------------------------------------------------------------*/

MSTATUS funcComparisonCallback(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess)
{
    SUB_NAME *pFirstSubName = (SUB_NAME *)pFirstItem;
    SUB_NAME *pSecondSubName = (SUB_NAME *)pSecondItem;
    sbyte4 result;
    DIGI_MEMCMP(pFirstSubName->oid, pSecondSubName->oid, (*pFirstSubName->oid) + 1, &result);
    *pRetIsLess = result < 0 ? TRUE : FALSE;
    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
X509_extractDistinguishedNamesBuffer(ASN1_ITEMPTR pSubName, CStream stream,
                                     ubyte **ppNameData, ubyte4 *pCopiedDataLen)
{
    MSTATUS status;
    ASN1_ITEMPTR pSubItem = NULL, pTempItem = NULL;
    ubyte4 i = 0, subItemCount = 0, subjectStringLen = 0;
    SUB_NAME subNameArr[MAX_SUBNAME_COUNT];
    SUB_LABEL *subLabel = NULL;
    sbyte4 labelLen = 0;
    SUB_LABEL subLabels[] = {
        { { 3, 0x55, 0x04, 0x03 }, "CN=", 3},
        { { 3, 0x55, 0x04, 0x04 }, "SURNAME=", 8 },
        { { 3, 0x55, 0x04, 0x05 }, "SerialNumber=", 13 },
        { { 3, 0x55, 0x04, 0x06 }, "C=", 2 },
        { { 3, 0x55, 0x04, 0x07 }, "L=", 2 },
        { { 3, 0x55, 0x04, 0x08 }, "ST=", 3 },
        { { 3, 0x55, 0x04, 0x09 }, "STREET=", 7 },
        { { 3, 0x55, 0x04, 0x0A }, "O=", 2 },
        { { 3, 0x55, 0x04, 0x0B }, "OU=", 3 },
        { { 3, 0x55, 0x04, 0x0C }, "T=", 2 },
        { { 3, 0x55, 0x04, 0x14 }, "TelephoneNumber=", 16 },
        { { 3, 0x55, 0x04, 0x2A }, "GIVENNAME=", 10 },
        { { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01 }, "E=", 2 },
    };

    *pCopiedDataLen = 0;

    pSubItem = ASN1_FIRST_CHILD(pSubName);
    if (NULL == pSubItem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    DIGI_MEMSET((ubyte*)subNameArr, 0x00, MAX_SUBNAME_COUNT * sizeof(SUB_NAME));

    do
    {
        subLabel = NULL;
        labelLen = 0;
        pTempItem = ASN1_FIRST_CHILD(pSubItem);
        pTempItem = ASN1_FIRST_CHILD(pTempItem);

        if (MAX_SUBNAME_COUNT <= subItemCount)
        {
            status = ERR_BAD_LENGTH;
            goto exit;
        }

        /* Copy oid in SUB_NAME structure */
        if (pTempItem->tag == OID)
        {
            if (OK > (status = DIGI_MALLOC((void **)&subNameArr[subItemCount].oid, pTempItem->length + 1)))
            {
                goto exit;
            }

            const ubyte *oidData = CS_memaccess(stream, pTempItem->dataOffset - 1, pTempItem->length + 1);

            if (OK > (status = DIGI_MEMCPY(subNameArr[subItemCount].oid, oidData, pTempItem->length + 1)))
            {
                goto exit;
            }

            for (i = 0; i < COUNTOF(subLabels); i++)
            {
                if (EqualOID(oidData, subLabels[i].oid))
                {
                    subLabel = &subLabels[i];
                    break;
                }
            }
        }

        pTempItem = ASN1_NEXT_SIBLING(pTempItem);

        /* Copy name in SUB_NAME structure */
        if (pTempItem != NULL)
        {
            subNameArr[subItemCount].nameLen = pTempItem->length;
            if (subLabel)
                subNameArr[subItemCount].nameLen += subLabel->labelLen;
            subjectStringLen += subNameArr[subItemCount].nameLen;

            if (OK > (status = DIGI_MALLOC((void **)&(subNameArr[subItemCount].name), subNameArr[subItemCount].nameLen)))
            {
                goto exit;
            }

            if (subLabel)
            {
                if (OK > (status = DIGI_MEMCPY(subNameArr[subItemCount].name, subLabel->label, subLabel->labelLen)))
                {
                    goto exit;
                }
                labelLen = subLabel->labelLen;
            }

            const ubyte *nameData = CS_memaccess(stream, pTempItem->dataOffset, pTempItem->length);
            if (OK > (status = DIGI_MEMCPY(subNameArr[subItemCount].name + labelLen, nameData, pTempItem->length)))
            {
                goto exit;
            }
        }

        subItemCount++;
        pSubItem = ASN1_NEXT_SIBLING(pSubItem);

    } while (pSubItem);

    if (OK > (status = SORT_shellSort((void *)subNameArr, sizeof(SUB_NAME), 0, subItemCount - 1, funcComparisonCallback)))
    {
        goto exit;
    }

    if (OK > (status = DIGI_MALLOC((void **)ppNameData, subjectStringLen + subItemCount - 1)))
    {
        goto exit;
    }
    DIGI_MEMSET(*ppNameData, 0x00, subjectStringLen + subItemCount - 1);
    for (i = 0; i < subItemCount; i++)
    {
        DIGI_MEMCPY(*ppNameData + *pCopiedDataLen, subNameArr[i].name, subNameArr[i].nameLen);
        *pCopiedDataLen += subNameArr[i].nameLen;
        if (i < subItemCount - 1)
        {
            *(*ppNameData + *pCopiedDataLen) = ',';
            *pCopiedDataLen += 1;
        }
    }

exit:
    if (subItemCount > 0)
    {
        for (i = 0; i < subItemCount; i++)
        {
            if (subNameArr[i].oid) DIGI_FREE((void **)&subNameArr[i].oid);
            if (subNameArr[i].name) DIGI_FREE((void **)&subNameArr[i].name);
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
X509_extractDistinguishedNames(ASN1_ITEMPTR pCertificate, CStream s,
                               intBoolean isSubject,
                               certDistinguishedName *pRetDN)
{
    ASN1_ITEMPTR  pDNItem;
    MSTATUS     status;

    if ((NULL == pCertificate) || (NULL == pRetDN))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (isSubject)
    {
        status = X509_getCertificateSubject(pCertificate, &pDNItem);
    }
    else
    {
        status = X509_getCertificateIssuerSerialNumber(pCertificate, &pDNItem,
                                                       NULL);
    }
    if (OK > status) goto exit;

    status = X509_extractDistinguishedNamesFromName(pDNItem, s, pRetDN);

exit:
    return status;

} /* CERT_extractDistinguishedNamesAux */


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__
extern MSTATUS
X509_extractDistinguishedNamesBlob(ASN1_ITEMPTR pCertificate, CStream s,
                                   intBoolean isSubject,
                                   ubyte **ppRetDistinguishedName,
                                   ubyte4 *pRetDistinguishedNameLen)
{
    ASN1_ITEMPTR    pDNItem;
    ubyte*          pMemBlock = NULL;
    const ubyte*    pDNData = NULL;
    MSTATUS         status;

    if ((NULL == pCertificate) || (NULL == ppRetDistinguishedName) || (NULL == pRetDistinguishedNameLen))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (isSubject)
    {
        status = X509_getCertificateSubject(pCertificate, &pDNItem);
    }
    else
    {
        status = X509_getCertificateIssuerSerialNumber(pCertificate, &pDNItem,
                                                       NULL);
    }
    if (OK > status) goto exit;

    /* now traverse each child with OID 2.5.4.n */
    /*  Name ::= SEQUENCE of RelativeDistinguishedName
        RelativeDistinguishedName = MOC_SET of AttributeValueAssertion
        AttributeValueAssertion = SEQUENCE { attributeType OID; attributeValue ANY }
    */

    /* Name is a sequence */
    if ((NULL == pDNItem) ||
        ((pDNItem->id & CLASS_MASK) != UNIVERSAL) ||
        (pDNItem->tag != SEQUENCE))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (0 == pDNItem->length)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* allocate return memory for subject/issuer block */
    if (NULL == (pMemBlock = MALLOC(pDNItem->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (NULL == (pDNData = CS_memaccess(s, pDNItem->dataOffset, pDNItem->length)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMCPY(pMemBlock, pDNData, pDNItem->length);

    /* copy return values */
    *ppRetDistinguishedName   = pMemBlock;
    *pRetDistinguishedNameLen = pDNItem->length;

    /* for return */
    pMemBlock = NULL;
    status = OK;

exit:

    if (NULL != pMemBlock)
    {
      FREE(pMemBlock);
    }

    if (pDNData)
    {
        CS_stopaccess(s, pDNData);
    }
    return status;

} /* CERT_extractDistinguishedNamesBlob */
#endif /* __ENABLE_DIGICERT_EXTRACT_CERT_BLOB__ */


/*------------------------------------------------------------------*/

extern void
X509_convertTime(TimeDate *pTime, ubyte *pOutputTime)
{
    ubyte4  temp;

    temp = (ubyte4)(pTime->m_year + 1970);
    pOutputTime[0] = (ubyte)('0' + (temp / 1000));
    pOutputTime[1] = (ubyte)('0' + ((temp % 1000) / 100));
    pOutputTime[2] = (ubyte)('0' + ((temp % 100) / 10));
    pOutputTime[3] = (ubyte)('0' + ((temp % 10)));

    temp = pTime->m_month;

    pOutputTime[4] = (ubyte)('0' + (temp / 10));
    pOutputTime[5] = (ubyte)('0' + (temp % 10));

    temp = pTime->m_day;

    pOutputTime[6] = (ubyte)('0' + (temp / 10));
    pOutputTime[7] = (ubyte)('0' + (temp % 10));

    temp = pTime->m_hour;

    pOutputTime[8] = (ubyte)('0' + (temp / 10));
    pOutputTime[9] = (ubyte)('0' + (temp % 10));

    temp = pTime->m_minute;

    pOutputTime[10] = (ubyte)('0' + (temp / 10));
    pOutputTime[11] = (ubyte)('0' + (temp % 10));

    temp = pTime->m_second;

    pOutputTime[12] = (ubyte)('0' + (temp / 10));
    pOutputTime[13] = (ubyte)('0' + (temp % 10));

    pOutputTime[14] = (ubyte)('Z');
    pOutputTime[15] = (ubyte)('\0');
}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_getValidityTime(ASN1_ITEMPTR pCertificate,
                     ASN1_ITEMPTR* pRetStart, ASN1_ITEMPTR* pRetEnd)
{
    ASN1_ITEMPTR  pTBSCertificate;
    ASN1_ITEMPTR  pVersion;
    ASN1_ITEMPTR  pValidity;
    MSTATUS     status;

    if ((NULL == pCertificate) || (NULL == pRetStart) || (NULL == pRetEnd))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetStart = NULL;
    *pRetEnd = NULL;

    pTBSCertificate = ASN1_FIRST_CHILD(pCertificate);
    if (!pTBSCertificate)
    {
        return ERR_CERT_INVALID_STRUCT;
    }

    if (OK > (status = ASN1_GetChildWithTag( pTBSCertificate, 0, &pVersion)))
        goto exit;

    /* validity is fifth child of certificate object */
    if (OK > (status = ASN1_GetNthChild( pTBSCertificate, pVersion ? 5 : 4, &pValidity)))
        goto exit;

    /* validity is a sequence of two items */
    if ( NULL == pValidity ||
            (pValidity->id & CLASS_MASK) != UNIVERSAL ||
            pValidity->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (OK > (status = ASN1_GetNthChild( pValidity, 1, pRetStart)))
        goto exit;

    if (OK > (status = ASN1_GetNthChild( pValidity, 2, pRetEnd)))
        goto exit;

 exit:
    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS
X509_extractValidityTime(ASN1_ITEMPTR pCertificate, CStream s,
                        certDistinguishedName *pRetDN)
{
    ASN1_ITEMPTR  pStart;
    ASN1_ITEMPTR  pEnd;
    TimeDate    certTime;
    sbyte*      pAsciiStartTime = NULL;
    sbyte*      pAsciiEndTime   = NULL;
    MSTATUS     status;

    if ((NULL == pCertificate) || (NULL == pRetDN))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pAsciiStartTime = (sbyte*) MALLOC(16);
    pAsciiEndTime   = (sbyte*) MALLOC(16);

    if ((NULL == pAsciiStartTime) || (NULL == pAsciiEndTime))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = X509_getValidityTime(pCertificate, &pStart, &pEnd)))
        goto exit;

    if (OK > (status = X509_getCertTime( pStart, s, &certTime)))
        goto exit;

    X509_convertTime(&certTime, (ubyte *)pAsciiStartTime);

    if (OK > (status = X509_getCertTime( pEnd, s, &certTime)))
        goto exit;

    X509_convertTime(&certTime, (ubyte *)pAsciiEndTime);

    /* return results */
    pRetDN->pStartDate = pAsciiStartTime; pAsciiStartTime = NULL;
    pRetDN->pEndDate   = pAsciiEndTime;   pAsciiEndTime   = NULL;

    status = OK;

exit:
    if (NULL != pAsciiStartTime)
        FREE(pAsciiStartTime);

    if (NULL != pAsciiEndTime)
        FREE(pAsciiEndTime);

    return status;

}
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CV_CERT__

extern MSTATUS
PARSE_CV_CERT_verifyValidityTime(CV_CERT* pCert, const TimeDate* currTime)
{
    sbyte4      res;
    MSTATUS     status;

    if (NULL == currTime || NULL == pCert)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    res = DIGI_cmpTimeDate(&pCert->expDate, currTime);

    if ( res < 0)
    {
        status = ERR_CERT_EXPIRED;
        goto exit;
    }

    res = DIGI_cmpTimeDate(&pCert->effectiveDate, currTime);

    if (res > 0)
    {
        status = ERR_CERT_START_TIME_VALID_IN_FUTURE;
        goto exit;
    }

    status = OK;

exit:
    return status;

}

#endif /* __ENABLE_DIGICERT_CV_CERT__ */

extern MSTATUS
X509_verifyValidityTime(ASN1_ITEM* pCertificate, CStream s,
                           const TimeDate* currTime)
{
    ASN1_ITEMPTR pStartTime, pEndTime;
    TimeDate    certTime = {0};
    sbyte4      res;
    MSTATUS     status;

    if (NULL == currTime || NULL == pCertificate)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = X509_getValidityTime(pCertificate, &pStartTime, &pEndTime)))
    {
        goto exit;
    }

    if (OK > (status = X509_getCertTime( pEndTime, s, &certTime)))
        goto exit;

    res = DIGI_cmpTimeDate(&certTime, currTime);

    if ( res < 0)
    {
        status = ERR_CERT_EXPIRED;
        goto exit;
    }

    if (OK > (status = X509_getCertTime( pStartTime, s, &certTime)))
        goto exit;

    res = DIGI_cmpTimeDate(&certTime, currTime);

    if (res > 0)
    {
        status = ERR_CERT_START_TIME_VALID_IN_FUTURE;
        goto exit;
    }

    status = OK;

exit:
    return status;

}


/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__
static MSTATUS
X509_findOID(ASN1_ITEMPTR pAlgoId, CStream s, const ubyte* whichOID,
             sbyte4* oidIndex)
{
    ASN1_ITEMPTR  pOID;
    sbyte4      index;
    MSTATUS     status;

    if ((NULL == whichOID) || (NULL == oidIndex))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = ERR_CERT_INVALID_STRUCT;

    if ((NULL == pAlgoId) ||
        ((pAlgoId->id & CLASS_MASK) != UNIVERSAL) ||
        (pAlgoId->tag != SEQUENCE))
    {
        goto exit;
    }

    pOID = ASN1_FIRST_CHILD(pAlgoId);
    if (NULL == pOID)
    {
        goto exit;
    }

    status = OK;

    for (index = 0; (NULL != pOID); pOID = ASN1_NEXT_SIBLING(pOID), index++)
    {
        MSTATUS status2 = ASN1_VerifyOID( pOID, s, whichOID);

        if (OK == status2)
        {
            *oidIndex = index;
            break;
        }
    }

exit:
    return status;

} /* findOID */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_rawVerifyOID(ASN1_ITEMPTR pCertificate, CStream s,
                  const ubyte *pOidItem,
                  const ubyte *pOidValue,
                  intBoolean *pIsPresent)
{
    MSTATUS status;
    ASN1_ITEMPTR pExtensions;
    ASN1_ITEMPTR pExtension;
    intBoolean criticalExtension;
    sbyte4 oidValueIndex = -1;

    if ((NULL == pCertificate) || (NULL == pOidItem) ||
        (NULL == pOidValue) || (NULL == pIsPresent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }


    if ( OK > (status = X509_getCertificateExtensions(pCertificate,
                                                      &pExtensions)))
    {
        goto exit;
    }

    /* look for the child with OID item */
    if (OK > (status = X509_getCertExtension(pExtensions, s, pOidItem,
                                             &criticalExtension, &pExtension)))
    {
        goto exit;
    }

    if ((NULL == pExtension) || (0 == pExtension->length))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    if (  (pExtension->id & CLASS_MASK) != UNIVERSAL ||
            pExtension->tag != SEQUENCE)
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    /* look for the child with OID item */
    if (OK > (status = X509_findOID(pExtension, s, pOidValue, &oidValueIndex)))
    {
        goto exit;
    }

    if (-1 != oidValueIndex)
        *pIsPresent = TRUE;

exit:
    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_extractSerialNum(ASN1_ITEMPTR pCertificate, CStream s,
                      ubyte** ppRetSerialNum, ubyte4 *pRetSerialNumLength)
{
    MSTATUS status;
    ASN1_ITEMPTR pSerialNum;

    if ((NULL == pCertificate) || (NULL == ppRetSerialNum) || (NULL == pRetSerialNumLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetSerialNum      = NULL;
    *pRetSerialNumLength = 0;

    if (OK > (status = X509_getCertificateIssuerSerialNumber(pCertificate,
                                                             NULL, &pSerialNum)))
    {
        goto exit;
    }

    if (NULL != pSerialNum)
    {
        ubyte* pSerialNumBuf;

        if (NULL == (pSerialNumBuf = MALLOC(pSerialNum->length)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        *pRetSerialNumLength = pSerialNum->length;
        CS_seek(s, pSerialNum->dataOffset, MOCANA_SEEK_SET);

        CS_read(pSerialNumBuf, 1, pSerialNum->length, s);

        /* store for return */
        *ppRetSerialNum = pSerialNumBuf;
    }

exit:
    return status;

} /* X509_extractSerialNum */


/*------------------------------------------------------------------*/

extern MSTATUS
X509_enumerateCRL( ASN1_ITEMPTR pCertificate, CStream s,
                  EnumCallbackFun ecf, void* userArg)
{
    ASN1_ITEMPTR pItem;
    ASN1_ITEMPTR pExtension;
    ASN1_ITEMPTR pExtensions;
    ASN1_ITEMPTR pCrlItem;
    intBoolean criticalExtension;
    MSTATUS    status;
    MSTATUS    cbReturn; /* return value from callback */

   /* CRLDistPointSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint */

    /* DistributionPoint ::= SEQUENCE {
    distributionPoint [0] DistributionPointName OPTIONAL,
    reasons       [1] ReasonFlags OPTIONAL,
    cRLIssuer     [2] GeneralNames OPTIONAL } */


    /* DistributionPointName ::= CHOICE {
    fullname    [0] GeneralNames,
    nameRelativeToCRLIssuer [1] RelativeDistinguishedName } */

    /*  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    GeneralName ::= CHOICE {
        otherName                  [0]  INSTANCE OF OTHER-NAME,
        rfc822Name                 [1]  IA5String,
        dNSName                    [2]  IA5String,
        x400Address                [3]  ORAddress,
        directoryName              [4]  Name,
        ediPartyName               [5]  EDIPartyName,
        uniformResourceIdentifier  [6]  IA5String,
        iPAddress                  [7]  OCTET STRING,
        registeredID               [8]  OBJECT IDENTIFIER
    }
    */
    static WalkerStep gotoFirstCRLGeneralName[] =
    {
        { VerifyType, SEQUENCE, 0},     /* CRLDistPointSyntax */
        { GoFirstChild, 0, 0},          /* DistributionPoint */
        { VerifyType, SEQUENCE, 0 },
        { GoToTag, 0, 0 },              /* [0]DistributionPointName */
        { GoToTag, 0, 0},               /* [0]GeneralNames */
        { GoFirstChild, 0, 0 },         /* GeneralName */
        { Complete, 0, 0}
    };

    static WalkerStep gotoFirstCRLGeneralNameOfNextDistributionPoint[] =
    {
        { GoParent, 0, 0},              /* [0]GeneralNames */
        { GoParent, 0, 0},              /* [0]DistributionPointName */
        { GoParent, 0, 0},              /* DistributionPoint */
        { GoNextSibling, 0, 0},         /* DistributionPoint */
        { VerifyType, SEQUENCE, 0 },
        { GoToTag, 0, 0 },              /* [0]DistributionPointName */
        { GoToTag, 0, 0},               /* [0]GeneralNames */
        { GoFirstChild, 0, 0 },         /* GeneralName */
        { Complete, 0, 0}
    };

    if ((NULL == pCertificate) || (NULL == ecf) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > ( status = X509_getCertificateExtensions(pCertificate,
                                                      &pExtensions)))
    {
        goto exit;
    }

    /* If there are no extensions then return without an error.
     */
    if (NULL == pExtensions)
    {
        goto exit;
    }

    /* look for the child with OID item */
    if (OK > (status = X509_getCertExtension(pExtensions, s, crl_OID,
                                             &criticalExtension, &pExtension)))
    {
        goto exit;
    }

    if ((NULL == pExtension) || (0 == pExtension->length))
    {
        /* no CRL extension -> no error */
        goto exit;
    }

    if ( OK > ( status = ASN1_WalkTree( pExtension, s,
                                        gotoFirstCRLGeneralName, &pCrlItem)))
    {
        goto exit;
    }

    while ( pCrlItem)
    {
        /* call the callback */
        if (OK > (cbReturn = ecf(pCrlItem, s, userArg)))
        {
            status = OK; /* return OK */
            goto exit;
        }
        /* next sibling ? */
        pItem = ASN1_NEXT_SIBLING( pCrlItem);
        if (!pItem)
        {
            /* otherwise go to the next Distribution Point */
            if ( OK > ( status =
                        ASN1_WalkTree( pCrlItem, s,
                               gotoFirstCRLGeneralNameOfNextDistributionPoint,
                               &pItem)))
            {
                status = OK;
                goto exit;
            }
        }
        pCrlItem = pItem;
    }

exit:

    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
X509_enumerateAltName( ASN1_ITEMPTR pCertificate, CStream s, sbyte4 isSubject,
                      EnumCallbackFun ecf, void* userArg)
{
    const ubyte* altNameOID;
    ASN1_ITEMPTR   pItem;
    ASN1_ITEMPTR   pExtensions;
    ASN1_ITEMPTR   pAltName;
    ASN1_ITEMPTR   pGeneralName;
    intBoolean   critical;
    ubyte4       tag;
    MSTATUS      status;
    MSTATUS      cbReturn; /* return value from callback */

    /* SubjectAltName ::= GeneralNames */
    /* IssuerAltName  ::= GeneralNames */

    /*  GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    GeneralName ::= CHOICE {
        otherName                  [0]  INSTANCE OF OTHER-NAME,
        rfc822Name                 [1]  IA5String,
        dNSName                    [2]  IA5String,
        x400Address                [3]  ORAddress,
        directoryName              [4]  Name,
        ediPartyName               [5]  EDIPartyName,
        uniformResourceIdentifier  [6]  IA5String,
        iPAddress                  [7]  OCTET STRING,
        registeredID               [8]  OBJECT IDENTIFIER
    }
    */

    static WalkerStep findUserPrincipalName[] =
    {
        { GoFirstChild, 0, 0 },         /* type-id */
        { VerifyOID, 0, (ubyte*)userPrincipalName_OID },
        { GoNextSibling, 0, 0 },        /* value [0] */
        { GoFirstChild, 0, 0 },
        { VerifyType, UTF8STRING, 0 },
        { Complete, 0, 0 }
    };

    if ((NULL == pCertificate) || (NULL == ecf) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = X509_getCertificateExtensions(pCertificate,
                                                     &pExtensions)))
    {
        goto exit;
    }

    /* look for the child with OID item */
    altNameOID = isSubject ? subjectAltName_OID : issuerAltName_OID;


    if (OK > (status = X509_getCertExtension(pExtensions, s, altNameOID,
                                             &critical, &pAltName)))
    {
        goto exit;
    }

    if ((NULL == pAltName) || (0 == pAltName->length))
    {
        /* no alternative name extension -> no error */
        goto exit;
    }

    if  (OK > ( status = ASN1_VerifyType( pAltName, SEQUENCE)))
    {
        status = ERR_CERT_INVALID_STRUCT;
        goto exit;
    }

    pGeneralName = ASN1_FIRST_CHILD( pAltName);

    while ( pGeneralName)
    {
        pItem = pGeneralName;

        if  (OK > ( status = ASN1_GetTag( pGeneralName, &tag)))
        {
            status = ERR_CERT_INVALID_STRUCT;
            goto exit;
        }

        /* othername, current only recognizes UPN */
        if ( 0 == tag)
        {
            if (OK > (status = ASN1_WalkTree( pGeneralName, s,
                                  findUserPrincipalName, &pItem)))
            {
                /* unsupported item, let user decide what to do */
                pItem = pGeneralName;
                status = OK;
            }
        }

        /* call the callback */
        if (OK > (cbReturn = ecf( pItem, s, userArg)))
        {
            status = OK; /* return OK */
            goto exit;
        }

        /* next sibling */
        pGeneralName = ASN1_NEXT_SIBLING( pGeneralName);
    }

exit:

    return status;

}


/*--------------------------------------------------------------------------*/

extern MSTATUS
X509_getRSASignatureAlgo( ASN1_ITEMPTR pCertificate, CStream certStream,
                         ubyte* signAlgo)
{
    static WalkerStep signatureWalkInstructions[] =
    {
        { GoFirstChild, 0, 0},          /* TBSCert */
        { VerifyType, SEQUENCE, 0},
        { GoNextSibling, 0, 0},         /* Signature */
        { VerifyType, SEQUENCE, 0},
        { Complete, 0, 0}
    };

    MSTATUS status;
    ASN1_ITEMPTR pSignatureAlgo;

    if (OK > ( status = ASN1_WalkTree( pCertificate, certStream,
            signatureWalkInstructions, &pSignatureAlgo)))
    {
        return status;
    }

    if (OK > (status = X509_getCertOID(pSignatureAlgo, certStream, pkcs1_OID,
                                       signAlgo, NULL)))
    {
        if (OK <= (status = X509_getCertOID(pSignatureAlgo, certStream,
                                            sha1withRsaSignature_OID,
                                            NULL, NULL)))
        {
            *signAlgo = sha1withRSAEncryption;
        }
    }

    return status;
}


#endif /* __ENABLE_DIGICERT_CERTIFICATE_SEARCH_SUPPORT__ */

#ifdef __ENABLE_DIGICERT_CERTIFICATE_PRINT__

static void X509_printOID(ubyte *pIter, ubyte4 len)
{
    MSTATUS status;
    sbyte4 result = -1;
    ubyte4 i = 0;
    ubyte4 j = 0;
    ubyte4 value  = 0;

    if (DIGI_MEMCMP(pIter, sha256withRSAEncryption_OID + 1, sha256withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: sha256WithRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, sha1withRSAEncryption_OID + 1, sha1withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: sha1WithRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, md5withRSAEncryption_OID + 1, md5withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: md5withRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, sha384withRSAEncryption_OID + 1, sha384withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: sha384withRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, sha512withRSAEncryption_OID + 1, sha512withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: sha512withRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, sha224withRSAEncryption_OID + 1, sha224withRSAEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Signature Algorithm: sha224withRSAEncryption");
    }
    else if (DIGI_MEMCMP(pIter, ecdsaWithSHA2_OID + 1, ecdsaWithSHA2_OID[0] - 1, &result) == OK && result == 0)
    {
        switch (pIter[ecdsaWithSHA2_OID[0]])
        {
            case 0x01:
                DB_PRINT("Signature Algorithm: ecdsa-with-SHA224");
                break;
            case 0x02:
                DB_PRINT("Signature Algorithm:  ecdsa-with-SHA256");
                break;
            case 0x03:
                DB_PRINT("Signature Algorithm:  ecdsa-with-SHA384");
                break;
            case 0x04:
                DB_PRINT("Signature Algorithm:  ecdsa-with-SHA512");
                break;
            default:
                DB_PRINT("Signature Algorithm:  Unknown ECDSA variant");
                break;
        }
    }
    else if (DIGI_MEMCMP(pIter, id_kp_serverAuth_OID + 1, id_kp_serverAuth_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Server Authentication");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_clientAuth_OID + 1, id_kp_clientAuth_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Client Authentication");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_codeSigning_OID + 1, id_kp_codeSigning_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Code Signing");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_emailProtection_OID + 1, id_kp_emailProtection_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Email Protection");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_timeStamping_OID + 1, id_kp_timeStamping_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Time Stamping");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_OCSPSigning_OID + 1, id_kp_OCSPSigning_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("OCSP Signing");
    }
    else if (DIGI_MEMCMP(pIter, secp256r1_OID + 1, secp256r1_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("secp256r1");
    }
    else if (DIGI_MEMCMP(pIter, secp224r1_OID + 1, secp224r1_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("secp224r1");
    }
    else if (DIGI_MEMCMP(pIter, secp384r1_OID + 1, secp384r1_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("secp384r1");
    }
    else if (DIGI_MEMCMP(pIter, secp521r1_OID + 1, secp521r1_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("secp521r1");
    }
    else if (DIGI_MEMCMP(pIter, rsaEncryption_OID + 1, rsaEncryption_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("rsaEncryption");
    }
    else if (DIGI_MEMCMP(pIter, ecPublicKey_OID + 1, ecPublicKey_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("id-ecPublicKey");
    }
    else if (DIGI_MEMCMP(pIter, commonName_OID + 1, commonName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Common Name: ");
    }
    else if (DIGI_MEMCMP(pIter, serialNumber_OID + 1, serialNumber_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Serial Number: ");
    }
    else if (DIGI_MEMCMP(pIter, countryName_OID + 1, countryName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Country Name: ");
    }
    else if (DIGI_MEMCMP(pIter, localityName_OID + 1, localityName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Locality Name: ");
    }
    else if (DIGI_MEMCMP(pIter, stateOrProvinceName_OID + 1, stateOrProvinceName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("State or Province Name: ");
    }
    else if (DIGI_MEMCMP(pIter, organizationName_OID + 1, organizationName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Organization Name: ");
    }
    else if (DIGI_MEMCMP(pIter, organizationalUnitName_OID + 1, organizationalUnitName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Organizational Unit Name: ");
    }
    else if (DIGI_MEMCMP(pIter, pkcs9_emailAddress_OID + 1, pkcs9_emailAddress_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Email Address: ");
    }
    else if (DIGI_MEMCMP(pIter, subjectKeyIdentifier_OID + 1, subjectKeyIdentifier_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Subject Key Identifier: ");
    }
    else if (DIGI_MEMCMP(pIter, keyUsage_OID + 1, keyUsage_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Key Usage: ");
    }
    else if (DIGI_MEMCMP(pIter, subjectAltName_OID + 1, subjectAltName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Subject Alternative Name: ");
    }
    else if (DIGI_MEMCMP(pIter, issuerAltName_OID + 1, issuerAltName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Issuer Alternative Name: ");
    }
    else if (DIGI_MEMCMP(pIter, basicConstraints_OID + 1, basicConstraints_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Basic Constraints: ");
    }
    else if (DIGI_MEMCMP(pIter, crlNumber_OID + 1, crlNumber_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("CRL Number: ");
    }
    else if (DIGI_MEMCMP(pIter, crlReason_OID + 1, crlReason_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("CRL Reason: ");
    }
    else if (DIGI_MEMCMP(pIter, invalidityDate_OID + 1, invalidityDate_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Invalidity Date: ");
    }
    else if (DIGI_MEMCMP(pIter, nameConstraints_OID + 1, nameConstraints_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Name Constraints: ");
    }
    else if (DIGI_MEMCMP(pIter, crl_OID + 1, crl_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("CRL Distribution Points: ");
    }
    else if (DIGI_MEMCMP(pIter, certificatePolicies_OID + 1, certificatePolicies_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Certificate Policies: ");
    }
    else if (DIGI_MEMCMP(pIter, authorityKeyIdentifier_OID + 1, authorityKeyIdentifier_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Authority Key Identifier: ");
    }
    else if (DIGI_MEMCMP(pIter, extendedKeyUsage_OID + 1, extendedKeyUsage_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Extended Key Usage: ");
    }
    else if (DIGI_MEMCMP(pIter, id_kp_smartCardLogon_OID + 1, id_kp_smartCardLogon_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Smart Card Logon: ");
    }
    else if (DIGI_MEMCMP(pIter, userPrincipalName_OID + 1, userPrincipalName_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("User Principal Name: ");
    }
    else if (DIGI_MEMCMP(pIter, dnQualifier_OID + 1, dnQualifier_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Distinguished Name Qualifier: ");
    }
    else if (DIGI_MEMCMP(pIter, productIdentifier_OID + 1, productIdentifier_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Product Identifier: ");
    }
    else if (DIGI_MEMCMP(pIter, vendorIdentifier_OID + 1, vendorIdentifier_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Vendor Identifier: ");
    }
    else if (DIGI_MEMCMP(pIter, id_pe_authorityInfoAcess_OID + 1, id_pe_authorityInfoAcess_OID[0], &result) == OK && result == 0)
    {
        DB_PRINT("Authority Information Access: ");
    }
    else if (DIGI_MEMCMP(pIter, id_ad_ocsp + 1, id_ad_ocsp[0], &result) == OK && result == 0)
    {
        DB_PRINT("OCSP: ");
    }
#ifdef __ENABLE_DIGICERT_PQC__
    else
    {
        if (len == (ubyte4) pure_pqc_sig_OID[0] + 1)
        {
            if (DIGI_MEMCMP(pIter, pure_pqc_sig_OID + 1, pure_pqc_sig_OID[0], &result) == OK && result == 0)
            {
                if (pIter[len - 1] >= cid_PQC_MLDSA_44 && pIter[len - 1] <= cid_PQC_SLHDSA_SHAKE_256F)
                {
                    DB_PRINT("%s", pqcName[pIter[len - 1] - cid_PQC_MLDSA_44]);
                }
            }
        }
        else if (len == (ubyte4) fndsa_512_OID[0])
        {
            if (DIGI_MEMCMP(pIter, fndsa_512_OID + 1, fndsa_512_OID[0], &result) == OK && result == 0)
            {
                DB_PRINT("fndsa_512");
            }
            else if (DIGI_MEMCMP(pIter, fndsa_1024_OID + 1, fndsa_1024_OID[0], &result) == OK && result == 0)
            {
                DB_PRINT("fndsa_1024");
            }
        }
        else if (len == (ubyte4) mldsa_composite_OID[0] + 1)
        {
            if (DIGI_MEMCMP(pIter, mldsa_composite_OID + 1, mldsa_composite_OID[0], &result) == OK && result == 0)
            {
                if (pIter[len - 1] >= PQC_COMPOSITE_FIRST_OID_BYTE && pIter[len - 1] <= PQC_COMPOSITE_LAST_OID_BYTE)
                {
                    DB_PRINT("%s", pqcHybridName[pIter[len - 1] - PQC_COMPOSITE_FIRST_OID_BYTE]);
                }
            }
        }
        else
        {
            DB_PRINT("OID");
        }
    }
#else
    else
    {
        DB_PRINT("OID\n");
    }
#endif

    if (2 > len)
    {
        return;
    }
    DB_PRINT("( %d.%d", pIter[0] / 40, pIter[0] % 40);

    for (i = 1; i < len; i++)
    {
        if (pIter[i] & 0x80)
        {
            value = (value << 7) | (pIter[i] & 0x7F);
        }
        else
        {
            value = (value << 7) | pIter[i];
            DB_PRINT(".%d", value);
            value = 0;
        }
    }
    DB_PRINT(" )\n");

}

static void X509_handleKeyUsage(ubyte *pIter, ubyte4 iterLen)
{
    ubyte4 i = 0;
    const ubyte *usages[] = {
        "Digital Signature", /*0x80*/
        "Non Repudiation",   /*0x40*/
        "Key Encipherment",  /*0x20*/
        "Data Encipherment", /*0x10*/
        "Key Agreement",     /*0x08*/
        "Key Cert Sign",     /*0x04*/
        "CRL Sign",          /*0x02*/
        "Encipher Only",     /*0x01*/
        "Decipher Only"      /*0x80(second byte)*/
    };
    ubyte masks[] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01, 0x80};

    ubyte keyUsage[2] = {0};

    keyUsage[0] = pIter[0];
    if (iterLen > 1)
    {
        keyUsage[1] = pIter[1];
    }

    for (i = 0; i  < 9; i++)
    {
        if (keyUsage[i / 8] & masks[i % 8])
        {
            DB_PRINT("%s\n", usages[i]);
        }
    }
}

static void X509_isDnsName(ubyte *pIter, ubyte4 iterLen, ubyte *isDNS)
{
    ubyte4 i = 0;

    /*check if any non printable charactrs*/
    for (i = 0; i < iterLen; i++)
    {
        if (pIter[i] < 0x20 || pIter[i] > 0x7E)
        {
            *isDNS = 0;
            break;
        }
    }
    if (*isDNS) /*check if only DNS characters*/
    {
        for (i = 0; i < iterLen; i++)
        {
            if (!((pIter[i] >= 'a' && pIter[i] <= 'z') || 
                    (pIter[i] >= 'A' && pIter[i] <= 'Z') || 
                    (pIter[i] >= '0' && pIter[i] <= '9') || 
                    pIter[i] == '.' || pIter[i] == '-'))
            {
                if (!(pIter[i] == '*' && i == 0 && iterLen > 1 && pIter[1] == '.'))
                {
                    *isDNS = 0;
                    break;
                }
            }
        }
    }
}

static void X509_handleGeneralName(ubyte4 tag, ubyte *pIter, ubyte4 len)
{
    ubyte4 iterLen = 0;
    switch (tag)
    {
        case 0x02:
        {
            DB_PRINT("DNS: ");
            
            break;
        }
        case 0x06:
        {
            DB_PRINT("URI: ");
            break;
        }
        case 0x07:
        {
            DB_PRINT("IP Address: ");
            break;
        }
        case 0x08:
        {
            DB_PRINT("Registered ID: ");
            break;
        }
        default:
        {
            DB_PRINT("");
            break;
        }
    }
    if (tag == 0x07)
    {
        for (iterLen = 0; iterLen < len; iterLen++)
        {
            DB_PRINT("%d", pIter[iterLen]);
            if (iterLen < len - 1)
            {
                DB_PRINT(".");
            }
        }
    }
    else if (tag == 0x08)
    {
        X509_printOID(pIter, len);
    }
    else if (tag == 0x02 || tag == 0x06)
    {
        DB_PRINT("%.*s\n", len, pIter);
    }
    else
    {
        for (iterLen = 0; iterLen < len; iterLen++)
        {
            DB_PRINT("%02X", pIter[iterLen]);
        }
        DB_PRINT("\n");
    }
}

void asn1ProgressCallback(ASN1_ITEMPTR newAddedItem, CStream cs, void *arg)
{
    CertOrCsrParsingCtx *pCtx = (CertOrCsrParsingCtx *)arg;
    MSTATUS status = OK;
    ASN1_ITEMPTR pSerial, pIssuer;
    ubyte *pIter;
    ubyte4 iterLen = 0;
    sbyte4 result = 0;
    ubyte tag = newAddedItem->tag;
    ubyte isDNS = 1;

    switch(pCtx->stage)
    {

        case CERT_OR_CSR_PARSING_STAGE_VERSION:
        {
            if (tag == INTEGER && newAddedItem->id == 0)
            {
                if (newAddedItem->length < 3 && newAddedItem->data.m_intVal <= 2)
                {
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    DB_PRINT("Version: %d\n", pIter[0] + 1);
                    pCtx->version = pIter[0] + 1;
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SERIAL_NUMBER;
                    DB_PRINT("\n================VERSION END================\n\n");
                }
                else
                {
                    DB_PRINT("Version: 1\n");
                    pCtx->version = 1;
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    DB_PRINT("Serial Number: ");
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM;
                    DB_PRINT("\n================SERIAL NUMBER END================\n\n");
                }
            }
            else
            {
                return;
            }

            break;
        }

        case CERT_OR_CSR_PARSING_STAGE_SERIAL_NUMBER:
        {
            if (tag == INTEGER)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("Serial Number: ");
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                }
                DB_PRINT("\n");
                pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM;
                DB_PRINT("\n================SERIAL NUMBER END================\n\n");
            }
            else if (tag == OID)
            {
                /*it is a CSR*/
                pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SUBJECT;
                pCtx->isCsr = 1;
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                    {
                        DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                    }
                    else
                    {
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                        }
                        DB_PRINT("\n");
                    }
                }
            }
            break;
        }

        case CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM:
        {
            if (tag == OID)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                X509_printOID(pIter, newAddedItem->length);

                if (pCtx->secondSignature || pCtx->isCsr)
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGN;
                    DB_PRINT("\n================SIGNATURE ALGORITHM END================\n\n");
                }
                else
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_ISSUER;
                    DB_PRINT("\n================SIGNATURE ALGORITHM END================\n\n");
                }

            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                    {
                        DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                    }
                    else
                    {
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                        }
                        DB_PRINT("\n");
                    }
                }
            }
            break;
        }

        case CERT_OR_CSR_PARSING_STAGE_ISSUER:
        {
            if (tag == SEQUENCE)
            {
                if (pCtx->awaitingEnd)
                {
                    pCtx->awaitingEnd = 0;
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_VALIDITY;
                    DB_PRINT("\n================ISSUER END================\n\n");
                }
                else
                {
                    pCtx->awaitingEnd = 1;
                }

            }
            else if (tag == OID)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);

                pCtx->awaitingEnd = 0;
            }
            else if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                }
            }
            break;
        }

        case CERT_OR_CSR_PARSING_STAGE_VALIDITY:
        {
            if (tag == UTCTIME)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("Validity Time: ");
                DB_PRINT("%.*s\n", newAddedItem->length, pIter);

                if (pCtx->awaitingEnd == 1)
                {
                    pCtx->awaitingEnd = 0;
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SUBJECT;
                    DB_PRINT("\n================VALIDITY END================\n\n");
                }
                else
                {
                    pCtx->awaitingEnd = 1;
                }
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                    if (tag == OID)
                    {
                        X509_printOID(pIter, newAddedItem->length);
                    }
                    else if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                    {
                        DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                    }
                    else
                    {
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                        }
                        DB_PRINT("\n");
                    }
                }
            }

            break;
        }

        case CERT_OR_CSR_PARSING_STAGE_SUBJECT:
        {
            if (tag == SEQUENCE)
            {
                if (pCtx->awaitingEnd)
                {
                    pCtx->awaitingEnd = 0;
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SUBJECT_PUBLIC_KEY_INFO;
                    DB_PRINT("\n================SUBJECT END================\n\n");
                }
                else
                {
                    pCtx->awaitingEnd = 1;
                }
            }
            else if (tag == OID)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);
                pCtx->awaitingEnd = 0;
            }
            else if (PRINTABLESTRING == tag || UTF8STRING == tag || GRAPHICSTRING == tag || IA5STRING == tag)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                }
            }
            break;
        }
        case CERT_OR_CSR_PARSING_STAGE_SUBJECT_PUBLIC_KEY_INFO:
        {
            if (tag == OID)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);
            }
            else if (tag == BITSTRING)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                DB_PRINT("Public Key (BITSTRING):\n\t");
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                    if (iterLen < newAddedItem->length - 1)
                    {
                        DB_PRINT(":");
                    }
                    if ((iterLen % 16 == 15) && (iterLen != newAddedItem->length - 1))
                    {
                        DB_PRINT("\n\t");
                    }
                }
                DB_PRINT("\n");
                if (pCtx->isCsr)
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_ATTRIBUTES;
                }
                else if (pCtx->version == 3)
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_EXTENSIONS;
                }
                else
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM;
                    pCtx->secondSignature = 1;
                }
                DB_PRINT("\n================SUBJECT PUBLIC KEY INFO END================\n\n");

            }
            else if (tag == INTEGER)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("Public Key: \n\t");

                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                    if (iterLen < newAddedItem->length - 1)
                    {
                        DB_PRINT(":");
                    }
                    if ((iterLen % 16 == 15) && (iterLen != newAddedItem->length - 1))
                    {
                        DB_PRINT("\n\t");
                    }
                }
                DB_PRINT("\n");
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                    {
                        DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                    }
                    else
                    {
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                        }
                        DB_PRINT("\n");
                    }
                }
            }
            break;
        }
        case CERT_OR_CSR_PARSING_STAGE_EXTENSIONS:
        {
            if (tag == OID && newAddedItem->id == 0)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);

                pCtx->currentOidPtr = pIter;
                pCtx->currentOidLen = newAddedItem->length;

                if (DIGI_MEMCMP(pIter, authorityKeyIdentifier_OID + 1, authorityKeyIdentifier_OID[0], &result) == OK && result == 0)
                {
                    pCtx->authorityKeyIdentifier = 1;
                }

                pCtx->awaitingEnd = 0;
            }
            else if (tag == BOOLEAN && newAddedItem->id == 0)
            {

                DB_PRINT("Boolean Value: %s \n", newAddedItem->data.m_boolVal == -1 ? "TRUE" : "FALSE");

                pCtx->awaitingEnd = 0;
            }
            else if (INTEGER == tag && newAddedItem->id == 0)
            {
                DB_PRINT("Integer:\n\t");
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                }
                DB_PRINT("\n");

                pCtx->awaitingEnd = 0;
            }
            else if (tag == BITSTRING)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);


                if (DIGI_MEMCMP(pCtx->currentOidPtr, keyUsage_OID + 1, pCtx->currentOidLen, &result) == OK && result == 0 && !pCtx->processingKeyUsage)
                {
                    X509_handleKeyUsage(pIter, newAddedItem->length);
                    pCtx->processingKeyUsage = 1;
                }

                if (newAddedItem->id == 0)
                    pCtx->awaitingEnd = 0;

            }
            else if (tag == PRINTABLESTRING || tag == UTF8STRING || tag == GRAPHICSTRING || IA5STRING == tag)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);

               pCtx->awaitingEnd = 0;
            }
            else if (newAddedItem->id == 128)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                if (pCtx->authorityKeyIdentifier)
                {
                    if (tag == 0) /*key identifier*/
                    {
                        DB_PRINT("Key Identifier:\n\t");
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                            if (iterLen < newAddedItem->length - 1)
                            {
                                DB_PRINT(":");
                            }
                            if ((iterLen % 16 == 15) && (iterLen != newAddedItem->length - 1))
                            {
                                DB_PRINT("\n\t");
                            }
                        }
                        DB_PRINT("\n");
                    }
                    else if (tag == 2) /* authority cert serial number or DNS */
                    {
                        X509_isDnsName(pIter, newAddedItem->length, &isDNS);

                        if (isDNS)
                        {
                            DB_PRINT("DNS: ");
                            DB_PRINT("%.*s\n", newAddedItem->length, pIter);
                        }
                        else
                        {
                            DB_PRINT("Authority Cert Serial Number:\n\t");
                            for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                            {
                                DB_PRINT("%02X", pIter[iterLen]);
                            }
                            DB_PRINT("\n");
                        }
                    }
                    else
                    {
                        X509_handleGeneralName(tag, pIter, newAddedItem->length);
                    }
                }
                else
                {
                    X509_handleGeneralName(tag, pIter, newAddedItem->length);
                }

                pCtx->awaitingEnd = 0;
            }
            else if (newAddedItem->id == 160)
            {
                DB_PRINT("Context-Specific[Constructed] Tag: %d\n", tag);

                DB_PRINT("Value:\n\t");
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                    if ((iterLen % 16 == 15) && (iterLen != newAddedItem->length - 1))
                    {
                        DB_PRINT("\n\t");
                    }
                }
                DB_PRINT("\n");

                if (!pCtx->isCsr)
                {
                    pCtx->awaitingEnd = 0;
                }
            }

            else if(OCTETSTRING == tag && newAddedItem->id == 0)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                if (DIGI_MEMCMP(pCtx->currentOidPtr, subjectKeyIdentifier_OID + 1, pCtx->currentOidLen, &result) == OK
                    && result == 0 && !pCtx->subjectKeyIdentifier)
                {
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                        if (iterLen < newAddedItem->length - 1)
                        {
                            DB_PRINT(":");
                        }
                    }
                    DB_PRINT("\n");
                    pCtx->subjectKeyIdentifier = 1;
                }
                else
                {
                    DB_PRINT("OCTET STRING [HEX DUMP]:");
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n--------------------------------------------\n\n");
                }

                pCtx->authorityKeyIdentifier = 0;
                pCtx->awaitingEnd = 0;
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                }

               pCtx->awaitingEnd = 0;
            }
            if (pCtx->processingEKU)
            {
                pCtx->processingEKU = 0;
            }

            if (pCtx->awaitingEnd)
            {
                pCtx->awaitingEnd = 0;
                pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM;
                pCtx->secondSignature = 1;
                if (pCtx->isCsr)
                {
                    DB_PRINT("\n================ATTRIBUTES END================\n\n");
                }
                else
                {
                    DB_PRINT("\n================EXTENSIONS END================\n\n");
                }
            }
            else
            {
                pCtx->awaitingEnd = 1;
            }
            break;
        }
        case CERT_OR_CSR_PARSING_STAGE_SIGN:
        {
            if (tag == BITSTRING)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("Signature:\n\t");
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                    if (iterLen < newAddedItem->length - 1)
                    {
                        DB_PRINT(":");
                    }
                    if ((iterLen % 16 == 15) && (iterLen != newAddedItem->length - 1))
                    {
                        DB_PRINT("\n\t");
                    }
                }
                DB_PRINT("\n");
                DB_PRINT("================SIGNATURE END================\n\n");
                pCtx->stage = CERT_OR_CSR_PARSING_STAGE_DONE;
            }
            else if (tag == INTEGER)
            {
                DB_PRINT("Integer:\n\t");
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                }
                DB_PRINT("\n");
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                    if (tag == OID)
                    {
                        X509_printOID(pIter, newAddedItem->length);
                    }
                    else if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                    {
                        DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                    }
                    else
                    {
                        for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                        {
                            DB_PRINT("%02X", pIter[iterLen]);
                        }
                        DB_PRINT("\n");
                    }

                }
            }
            break;
        }
        case CERT_OR_CSR_PARSING_STAGE_ATTRIBUTES:
        {
            if (tag == OID && newAddedItem->id == 0)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                X509_printOID(pIter, newAddedItem->length);
                DB_PRINT("Extensions: \n\n");

                if (DIGI_MEMCMP(pIter, pkcs9_extensionRequest_OID + 1, pkcs9_extensionRequest_OID[0], &result) == OK && result == 0)
                {
                    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_EXTENSIONS;
                }

                pCtx->awaitingEnd = 0;
            }
            else if (tag == BOOLEAN)
            {

                DB_PRINT("BOOLEAN Value: %s \n", newAddedItem->data.m_boolVal == -1 ? "TRUE" : "FALSE");

                pCtx->awaitingEnd = 0;
            }
            else if (INTEGER == tag && newAddedItem->id == 0)
            {
                DB_PRINT("Integer:\n\t");
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                {
                    DB_PRINT("%02X", pIter[iterLen]);
                }
                DB_PRINT("\n");

                pCtx->awaitingEnd = 0;
            }
            else if (PRINTABLESTRING == tag || UTF8STRING == tag || GRAPHICSTRING == tag || IA5STRING == tag)
            {
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);

               pCtx->awaitingEnd = 0;
            }
            else
            {
                if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
                {
                    DB_PRINT("Found Tag: %d\n", tag);
                    DB_PRINT("Value: ");
                    pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                }
            }
            if (pCtx->awaitingEnd)
            {
                pCtx->awaitingEnd = 0;
                pCtx->stage = CERT_OR_CSR_PARSING_STAGE_SIGNATURE_ALGORITHM;
                pCtx->secondSignature = 1;
                DB_PRINT("\n================ATTRIBUTES END================\n\n");
            }
            else
            {
                pCtx->awaitingEnd = 1;
            }

            break;
        }
        default:
        {
            if (tag != MOC_SET && tag != SEQUENCE && tag != NULLTAG && tag != EOC)
            {
                DB_PRINT("Found Tag: %d\n", tag);
                DB_PRINT("Value: ");
                pIter = (ubyte *) CS_memaccess(cs, newAddedItem->dataOffset, newAddedItem->length);

                if (tag == OID)
                {
                    X509_printOID(pIter, newAddedItem->length);
                }
                else if (PRINTABLESTRING == tag || UTF8STRING == tag || IA5STRING == tag)
                {
                    DB_PRINT("%.*s\n\n", newAddedItem->length, pIter);
                }
                else
                {
                    for (iterLen = 0; iterLen < newAddedItem->length; iterLen++)
                    {
                        DB_PRINT("%02X", pIter[iterLen]);
                    }
                    DB_PRINT("\n");
                }
            }

        }

    }
}

MOC_EXTERN MSTATUS X509_printCertificateOrCsr(ubyte *pCertOrCsr, ubyte4 certOrCsrLen)
{
    MSTATUS status = OK;
    MemFile mf = {0};
    CStream cs = {0};
    ASN1_ITEMPTR pRootItem = NULL;

    MF_attach(&mf, certOrCsrLen, pCertOrCsr);
    CS_AttachMemFile(&cs, &mf);

    CertOrCsrParsingCtx *pCtx = NULL;

    if (OK > (status = DIGI_MALLOC((void **)&pCtx, sizeof(CertOrCsrParsingCtx))))
    {
        goto exit;
    }

    DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(CertOrCsrParsingCtx));

    pCtx->stage = CERT_OR_CSR_PARSING_STAGE_VERSION;

    status = ASN1_ParseEx(cs, &pRootItem, asn1ProgressCallback, pCtx);
    if (OK > status)
    {
        goto exit;
    }


exit:

    if (NULL != pCtx)
    {
        DIGI_FREE((void **)&pCtx);
    }

    if (pRootItem)
    {
        TREE_DeleteTreeItem( (TreeItem*) pRootItem);
    }

    return status;

}
#endif /* __ENABLE_DIGICERT_CERTIFICATE_PRINT__ */
#endif /* __DISABLE_DIGICERT_CERTIFICATE_PARSING__ */
